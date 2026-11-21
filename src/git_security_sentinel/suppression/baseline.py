"""
Git Security Sentinel - Baseline File Filtering and Generation.
Suppresses pre-existing technical security debt across repositories using
stable deterministic SHA-256 fingerprints resistant to line shifts.
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


def compute_fingerprint(rule_id: str, file_path: str, evidence: str) -> str:
    """
    Computes a deterministic, line-shift-resistant SHA-256 fingerprint for a finding.

    Path separators are normalized to '/', leading slashes removed, case normalized to lower.
    Evidence whitespace is normalized to single spaces.
    Line numbers are intentionally omitted so line shifts above findings do not invalidate them.
    """
    norm_path = file_path.replace("\\", "/").strip().lower()
    if norm_path.startswith("./"):
        norm_path = norm_path[2:]
    norm_path = norm_path.lstrip("/")

    norm_evidence = " ".join(evidence.strip().split())
    key = f"{rule_id}:{norm_path}:{norm_evidence}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class BaselineFilter:
    """
    Manages loading, matching, and generating .sentinel.baseline JSON files.
    """

    compute_fingerprint = staticmethod(compute_fingerprint)

    def __init__(
        self,
        baseline_path: Optional[Path] = None,
        fingerprints: Optional[Set[str]] = None,
    ):
        self.baseline_path = Path(baseline_path) if baseline_path else None
        if fingerprints is not None:
            self.fingerprints: Set[str] = set(fingerprints)
        elif self.baseline_path and self.baseline_path.is_file():
            self.fingerprints = self.load_baseline(self.baseline_path)
        else:
            self.fingerprints = set()

    @classmethod
    def load_baseline(cls, path: Path) -> Set[str]:
        """
        Reads a baseline JSON file and extracts the set of suppressed fingerprints.
        """
        p = Path(path)
        if not p.is_file():
            return set()
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            fps = set()
            for item in data.get("findings", []):
                if isinstance(item, dict) and "fingerprint" in item:
                    fps.add(item["fingerprint"])
            return fps
        except Exception:
            return set()

    def is_suppressed(self, finding: Any) -> bool:
        """
        Determines if a finding matches a suppressed fingerprint in the baseline.
        """
        if not self.fingerprints:
            return False

        if hasattr(finding, "fingerprint") and finding.fingerprint:
            return finding.fingerprint in self.fingerprints

        rule_id = getattr(finding, "rule_id", None) or (
            finding.get("rule_id") if isinstance(finding, dict) else ""
        )
        file_path = getattr(finding, "file", None) or (
            finding.get("file") if isinstance(finding, dict) else ""
        )
        evidence = getattr(finding, "evidence", None) or (
            finding.get("evidence") if isinstance(finding, dict) else ""
        )

        fp = compute_fingerprint(rule_id, file_path, evidence)
        return fp in self.fingerprints

    @classmethod
    def create_baseline(cls, path: Path, findings: List[Any]) -> None:
        """
        Generates and writes a .sentinel.baseline JSON file from a list of findings.
        """
        p = Path(path)
        entries = []
        for f in findings:
            rule_id = getattr(f, "rule_id", None) or (
                f.get("rule_id") if isinstance(f, dict) else ""
            )
            file_path = getattr(f, "file", None) or (
                f.get("file") if isinstance(f, dict) else ""
            )
            line = getattr(f, "line", None) or (
                f.get("line") if isinstance(f, dict) else 1
            )
            evidence = getattr(f, "evidence", None) or (
                f.get("evidence") if isinstance(f, dict) else ""
            )
            fp = getattr(f, "fingerprint", None) or compute_fingerprint(
                rule_id, file_path, evidence
            )

            entries.append(
                {
                    "fingerprint": fp,
                    "rule_id": rule_id,
                    "file": file_path.replace("\\", "/"),
                    "line": line,
                    "evidence": evidence,
                }
            )

        data = {
            "format_version": "1.0",
            "generator": "git-security-sentinel 1.2.0",
            "findings": entries,
        }
        if p.parent and not p.parent.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
