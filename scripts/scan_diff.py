#!/usr/bin/env python3
"""
Git Security Sentinel - Deterministic Diff Security Scanner
Zero-dependency, privacy-first pre-commit and CI scanner for Git changes.
Complies with the Agent Skills Open Standard (https://agentskills.io/specification).
"""

import argparse
from dataclasses import asdict, dataclass, field
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Pattern, Tuple

VERSION = "1.0.0"
SCANNER_NAME = "git-security-sentinel"

# Accepted root license filenames
ACCEPTED_LICENSE_NAMES = ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"]

# Severity ranking for exit-code threshold comparisons
SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


@dataclass
class Finding:
    """Represents a single detected security or compliance finding."""
    rule_id: str
    category: str
    severity: str
    confidence: str
    file: str
    line: int
    message: str
    evidence: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LicenseStatus:
    """Represents the status of repository root license compliance."""
    root_license_present: bool
    license_file: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanSummary:
    """Statistical summary of findings broken down by severity level."""
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)


@dataclass
class ScanReport:
    """Complete structured security scan report."""
    scanner: str = SCANNER_NAME
    version: str = VERSION
    status: str = "completed"
    scan_mode: str = "all"
    findings: List[Finding] = field(default_factory=list)
    license: LicenseStatus = field(default_factory=lambda: LicenseStatus(False))
    summary: ScanSummary = field(default_factory=ScanSummary)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner": self.scanner,
            "version": self.version,
            "status": self.status,
            "scan_mode": self.scan_mode,
            "findings": [f.to_dict() for f in self.findings],
            "license": self.license.to_dict(),
            "summary": self.summary.to_dict(),
            "errors": self.errors,
        }


@dataclass
class Rule:
    """Rule definition for secret and code pattern scanning."""
    rule_id: str
    category: str
    severity: str
    confidence: str
    pattern: Pattern[str]
    message: str
    recommendation: str
    validator: Optional[Callable[[re.Match, str], bool]] = None


# Detection rules definition
DETECTION_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "secret.aws_access_key",
        "category": "secrets",
        "severity": "critical",
        "confidence": "high",
        "pattern": re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
        "message": "Potential AWS Access Key ID detected.",
        "recommendation": "Never hardcode AWS keys. Use environment variables (AWS_ACCESS_KEY_ID), IAM roles, or AWS Secrets Manager.",
    },
    {
        "rule_id": "secret.aws_secret_key",
        "category": "secrets",
        "severity": "critical",
        "confidence": "high",
        "pattern": re.compile(
            r"""(?i)(?:aws_secret_access_key|aws_secret_key|aws_secret)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"""
        ),
        "message": "Potential AWS Secret Access Key assignment detected.",
        "recommendation": "Rotate immediately if active. Use AWS IAM roles, AWS Secrets Manager, or vault solutions.",
    },
    {
        "rule_id": "secret.github_token",
        "category": "secrets",
        "severity": "critical",
        "confidence": "high",
        "pattern": re.compile(
            r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b"
        ),
        "message": "Potential GitHub personal access or OAuth token detected.",
        "recommendation": "Revoke and rotate the GitHub token immediately in GitHub Settings > Developer settings.",
    },
    {
        "rule_id": "secret.slack_token",
        "category": "secrets",
        "severity": "high",
        "confidence": "high",
        "pattern": re.compile(
            r"\b(xox[baprs]-[0-9A-Za-z]{10,48}-[0-9A-Za-z]{10,48}-[0-9A-Za-z]{24,48}|xox[baprs]-[0-9A-Za-z]{10,48})\b"
        ),
        "message": "Potential Slack API bot or user token detected.",
        "recommendation": "Revoke the Slack token via the Slack API admin dashboard and use secure secret injection.",
    },
    {
        "rule_id": "secret.private_key",
        "category": "secrets",
        "severity": "critical",
        "confidence": "high",
        "pattern": re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"
        ),
        "message": "Cryptographic private key header detected.",
        "recommendation": "Never commit private keys to source control. Add the key file to .gitignore and rotate the keypair.",
    },
    {
        "rule_id": "secret.generic_credential",
        "category": "secrets",
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(
            r"""(?i)(?:password|passwd|api_key|apikey|secret_key|client_secret|auth_token|access_token)\s*[:=]\s*['"]([^'"\r\n]{8,128})['"]"""
        ),
        "message": "Potential hardcoded credential or secret assignment detected.",
        "recommendation": "Extract credentials into a .env file or cloud secret store. Load via environment variables at runtime.",
    },
    {
        "rule_id": "risk.eval_execution",
        "category": "insecure_code",
        "severity": "medium",
        "confidence": "medium",
        "pattern": re.compile(r"\b(?:eval|exec)\s*\((?!\s*['\"][^'\"]*['\"]\s*\))"),
        "message": "Potentially unsafe dynamic code execution using eval() or exec().",
        "recommendation": "Avoid eval()/exec() with dynamic or user-influenced data to prevent arbitrary code execution (CWE-95). Use ast.literal_eval() or safe parser alternatives.",
    },
    {
        "rule_id": "risk.localhost_endpoint",
        "category": "configuration",
        "severity": "low",
        "confidence": "high",
        "pattern": re.compile(
            r"""https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::[0-9]{1,5})?(?:/[^\s'"]*)?"""
        ),
        "message": "Hardcoded local loopback URL endpoint detected in code.",
        "recommendation": "Ensure development endpoints are parameterized via environment variables before deploying to production.",
    },
]

# Common benign strings / placeholders to ignore for generic credential rules
IGNORE_PLACEHOLDERS = {
    "your_api_key",
    "your_key_here",
    "your_secret_here",
    "your_password",
    "change_me",
    "changeme",
    "placeholder",
    "test_secret",
    "example_key",
    "dummy_password",
    "sample_token",
    "xxxx",
    "xxxxxx",
    "********",
    "undefined",
    "process.env",
    "os.environ",
    "${",
    "{{",
    "true",
    "false",
    "null",
    "none",
}


def is_benign_generic_value(val: str) -> bool:
    """Check if matched generic credential value is a common placeholder or template."""
    clean = val.strip().lower()
    if clean in IGNORE_PLACEHOLDERS:
        return True
    if any(clean.startswith(prefix) for prefix in ("your_", "my_", "example_", "test_")):
        return True
    if any(marker in clean for marker in ("${", "{{", "process.env", "os.environ", "os.getenv")):
        return True
    # If it contains only identical repeating characters (e.g. 'xxxxxxxx')
    if len(set(clean)) <= 2:
        return True
    return False


def redact_text(line: str) -> str:
    """
    Deterministically redacts detected secrets within a line before reporting or saving diffs.
    Returns the sanitized line with sensitive tokens replaced with [REDACTED].
    """
    sanitized = line

    # 1. Private keys
    sanitized = re.sub(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z ]+-----)?",
        "[REDACTED:PRIVATE_KEY]",
        sanitized,
    )

    # 2. AWS Access Keys
    sanitized = re.sub(
        r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b",
        "[REDACTED:AWS_KEY_ID]",
        sanitized,
    )

    # 3. AWS Secret Access Key assignment
    sanitized = re.sub(
        r"""(?i)((?:aws_secret_access_key|aws_secret_key|aws_secret)\s*[:=]\s*['"]?)[A-Za-z0-9/+=]{40}(['"]?)""",
        r"\1[REDACTED:AWS_SECRET]\2",
        sanitized,
    )

    # 4. GitHub tokens
    sanitized = re.sub(
        r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b",
        "[REDACTED:GITHUB_TOKEN]",
        sanitized,
    )

    # 5. Slack tokens
    sanitized = re.sub(
        r"\b(xox[baprs]-[0-9A-Za-z]{10,48}(?:-[0-9A-Za-z]{10,48})?(?:-[0-9A-Za-z]{24,48})?)\b",
        "[REDACTED:SLACK_TOKEN]",
        sanitized,
    )

    # 6. Generic credentials assignments
    def redact_generic_match(m: re.Match) -> str:
        val = m.group(1)
        if is_benign_generic_value(val):
            return m.group(0)
        prefix = m.group(0)[: m.start(1) - m.start(0)]
        suffix = m.group(0)[m.end(1) - m.start(0) :]
        return f"{prefix}[REDACTED:GENERIC_CREDENTIAL]{suffix}"

    sanitized = re.sub(
        r"""(?i)(?:password|passwd|api_key|apikey|secret_key|client_secret|auth_token|access_token)\s*[:=]\s*['"]([^'"\r\n]{8,128})['"]""",
        redact_generic_match,
        sanitized,
    )

    return sanitized


class UnifiedDiffParser:
    """
    Parses unified diff output to extract added lines, their target filenames,
    and accurate line numbers in the modified file.
    """

    @staticmethod
    def parse(diff_content: str) -> List[Dict[str, Any]]:
        """
        Returns a list of added line objects:
        [
            {
                "file": "path/to/file.py",
                "line": 42,
                "content": "new line content without leading '+'"
            }
        ]
        """
        added_lines: List[Dict[str, Any]] = []
        current_file: Optional[str] = None
        new_line_num: int = 0
        in_hunk: bool = False

        diff_file_pattern = re.compile(r"^diff --git a/(.*) b/(.*)$")
        hunk_header_pattern = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

        for raw_line in diff_content.splitlines():
            # Check for new file diff header
            diff_match = diff_file_pattern.match(raw_line)
            if diff_match:
                # b/ filename (spaces in filenames supported)
                current_file = diff_match.group(2)
                in_hunk = False
                continue

            if raw_line.startswith("+++ "):
                # Handle newly created files where diff --git may be followed by +++ b/filename
                plus_path = raw_line[4:].strip()
                if plus_path == "/dev/null":
                    current_file = None  # file deleted
                elif plus_path.startswith("b/"):
                    current_file = plus_path[2:]
                continue

            if raw_line.startswith("--- "):
                continue

            # Check for binary files
            if raw_line.startswith("Binary files "):
                in_hunk = False
                continue

            # Check for hunk header
            hunk_match = hunk_header_pattern.match(raw_line)
            if hunk_match:
                in_hunk = True
                new_line_num = int(hunk_match.group(1))
                continue

            if not in_hunk or not current_file:
                continue

            # Process hunk content
            if raw_line.startswith("+"):
                # Added line
                content = raw_line[1:]
                added_lines.append(
                    {
                        "file": current_file,
                        "line": new_line_num,
                        "content": content,
                    }
                )
                new_line_num += 1
            elif raw_line.startswith("-"):
                # Removed line - ignore for security scanning added changes
                pass
            elif raw_line.startswith(" "):
                # Context line
                new_line_num += 1
            elif raw_line.startswith("\\ No newline at end of file"):
                pass

        return added_lines


class GitSecurityScanner:
    """
    Deterministic static security scanner for Git diffs.
    """

    def __init__(self, repo_root: Optional[Path] = None):
        self.repo_root = repo_root or Path.cwd()

    def run_git_command(self, args: List[str], timeout_sec: int = 25) -> Tuple[int, str, str]:
        """
        Executes a git command safely without shell=True.
        Disables external diffs and color formatting.
        """
        cmd = ["git"] + args
        try:
            res = subprocess.run(
                cmd,
                cwd=str(self.repo_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_sec,
                check=False,
            )
            return res.returncode, res.stdout, res.stderr
        except FileNotFoundError:
            return 127, "", "Git executable not found in system PATH."
        except subprocess.TimeoutExpired:
            return 124, "", f"Git command timed out after {timeout_sec} seconds."
        except Exception as e:
            return 1, "", str(e)

    def check_is_git_repository(self) -> Tuple[bool, Optional[str]]:
        """Verify repository status."""
        code, out, err = self.run_git_command(["rev-parse", "--is-inside-work-tree"])
        if code != 0 or out.strip() != "true":
            return False, err.strip() or "Not a git repository (or any of the parent directories)."
        return True, None

    def check_license(self) -> Dict[str, Any]:
        """Check for root license file without modifying the repo."""
        for name in ACCEPTED_LICENSE_NAMES:
            candidate = self.repo_root / name
            if candidate.is_file():
                return {
                    "root_license_present": True,
                    "license_file": name,
                }
        return {
            "root_license_present": False,
            "license_file": None,
        }

    def get_diff(self, mode: str, base_branch: Optional[str] = None) -> Tuple[str, List[str]]:
        """
        Fetch unified git diff based on scan mode:
        - 'staged': git diff --staged --no-color --no-ext-diff
        - 'unstaged': git diff --no-color --no-ext-diff
        - 'all': staged + unstaged combined (git diff HEAD or unstaged + staged)
        - 'base': git diff $(git merge-base base_branch HEAD) HEAD --no-color --no-ext-diff
        """
        errors: List[str] = []

        if mode == "staged":
            code, out, err = self.run_git_command(["diff", "--staged", "--no-color", "--no-ext-diff"])
            if code != 0:
                errors.append(f"Failed to get staged diff: {err.strip()}")
            return out, errors

        elif mode == "unstaged":
            code, out, err = self.run_git_command(["diff", "--no-color", "--no-ext-diff"])
            if code != 0:
                errors.append(f"Failed to get unstaged diff: {err.strip()}")
            return out, errors

        elif mode == "all":
            # Check if HEAD exists (repo has at least one commit)
            code_head, _, _ = self.run_git_command(["rev-parse", "--verify", "HEAD"])
            if code_head == 0:
                # Compare against HEAD to capture both staged and unstaged working-tree changes
                code, out, err = self.run_git_command(["diff", "HEAD", "--no-color", "--no-ext-diff"])
                if code != 0:
                    errors.append(f"Failed to get all changes against HEAD: {err.strip()}")
                return out, errors
            else:
                # Initial commit in progress (no HEAD yet); combine staged diff
                code, out, err = self.run_git_command(["diff", "--staged", "--no-color", "--no-ext-diff"])
                if code != 0:
                    errors.append(f"Failed to get staged diff for initial commit: {err.strip()}")
                return out, errors

        elif mode == "base":
            if not base_branch:
                errors.append("Base branch must be specified when using --base mode.")
                return "", errors

            # Find merge-base
            code_mb, out_mb, err_mb = self.run_git_command(["merge-base", base_branch, "HEAD"])
            if code_mb != 0 or not out_mb.strip():
                errors.append(
                    f"Could not compute merge-base between '{base_branch}' and 'HEAD': {err_mb.strip()}"
                )
                return "", errors

            merge_base = out_mb.strip()
            code, out, err = self.run_git_command(
                ["diff", merge_base, "HEAD", "--no-color", "--no-ext-diff"]
            )
            if code != 0:
                errors.append(f"Failed to get diff against merge-base {merge_base}: {err.strip()}")
            return out, errors

        else:
            errors.append(f"Unknown scan mode: {mode}")
            return "", errors

    def scan_diff_content(self, diff_content: str, scan_mode: str) -> Dict[str, Any]:
        """
        Parse diff content, run rules, sanitize evidence, and assemble structured report.
        """
        parser = UnifiedDiffParser()
        added_lines = parser.parse(diff_content)
        license_info = self.check_license()

        findings: List[Dict[str, Any]] = []
        seen_finding_keys = set()

        for item in added_lines:
            file_path = item["file"]
            line_no = item["line"]
            raw_content = item["content"]

            for rule in DETECTION_RULES:
                rule_id = rule["rule_id"]
                category = rule["category"]
                severity = rule["severity"]
                confidence = rule["confidence"]
                pattern = rule["pattern"]
                message = rule["message"]
                recommendation = rule["recommendation"]

                # Apply rule pattern
                match = pattern.search(raw_content)
                if not match:
                    continue

                # Extra check for generic credential to filter benign placeholders
                if rule_id == "secret.generic_credential":
                    matched_val = match.group(1) if match.groups() else match.group(0)
                    if is_benign_generic_value(matched_val):
                        continue

                # Deduplication key: rule_id, file, line
                dup_key = (rule_id, file_path, line_no)
                if dup_key in seen_finding_keys:
                    continue
                seen_finding_keys.add(dup_key)

                # Safe evidence redaction
                redacted_evidence = redact_text(raw_content.strip())
                # If redaction did not remove the secret, redact the entire line as a fail-safe
                if rule_id.startswith("secret.") and match.group(0) in redacted_evidence:
                    redacted_evidence = "[REDACTED]"

                findings.append(
                    Finding(
                        rule_id=rule_id,
                        category=category,
                        severity=severity,
                        confidence=confidence,
                        file=file_path,
                        line=line_no,
                        message=message,
                        evidence=redacted_evidence,
                        recommendation=recommendation,
                    )
                )

        # Summary calculations
        summary = ScanSummary(
            total=len(findings),
            critical=sum(1 for f in findings if f.severity == "critical"),
            high=sum(1 for f in findings if f.severity == "high"),
            medium=sum(1 for f in findings if f.severity == "medium"),
            low=sum(1 for f in findings if f.severity == "low"),
        )

        lic_status = LicenseStatus(
            root_license_present=license_info.get("root_license_present", False),
            license_file=license_info.get("license_file"),
        )

        report = ScanReport(
            scanner=SCANNER_NAME,
            version=VERSION,
            status="completed",
            scan_mode=scan_mode,
            findings=findings,
            license=lic_status,
            summary=summary,
            errors=[],
        )
        return report.to_dict()

    def scan_diff_report(self, diff_content: str, scan_mode: str) -> ScanReport:
        """
        Parse diff content and return a typed ScanReport dataclass instance.
        """
        parser = UnifiedDiffParser()
        added_lines = parser.parse(diff_content)
        license_info = self.check_license()

        findings: List[Finding] = []
        seen_finding_keys = set()

        for item in added_lines:
            file_path = item["file"]
            line_no = item["line"]
            raw_content = item["content"]

            for rule in DETECTION_RULES:
                rule_id = rule["rule_id"]
                category = rule["category"]
                severity = rule["severity"]
                confidence = rule["confidence"]
                pattern = rule["pattern"]
                message = rule["message"]
                recommendation = rule["recommendation"]

                match = pattern.search(raw_content)
                if not match:
                    continue

                if rule_id == "secret.generic_credential":
                    matched_val = match.group(1) if match.groups() else match.group(0)
                    if is_benign_generic_value(matched_val):
                        continue

                dup_key = (rule_id, file_path, line_no)
                if dup_key in seen_finding_keys:
                    continue
                seen_finding_keys.add(dup_key)

                redacted_evidence = redact_text(raw_content.strip())
                if rule_id.startswith("secret.") and match.group(0) in redacted_evidence:
                    redacted_evidence = "[REDACTED]"

                findings.append(
                    Finding(
                        rule_id=rule_id,
                        category=category,
                        severity=severity,
                        confidence=confidence,
                        file=file_path,
                        line=line_no,
                        message=message,
                        evidence=redacted_evidence,
                        recommendation=recommendation,
                    )
                )

        summary = ScanSummary(
            total=len(findings),
            critical=sum(1 for f in findings if f.severity == "critical"),
            high=sum(1 for f in findings if f.severity == "high"),
            medium=sum(1 for f in findings if f.severity == "medium"),
            low=sum(1 for f in findings if f.severity == "low"),
        )

        lic_status = LicenseStatus(
            root_license_present=license_info.get("root_license_present", False),
            license_file=license_info.get("license_file"),
        )

        return ScanReport(
            scanner=SCANNER_NAME,
            version=VERSION,
            status="completed",
            scan_mode=scan_mode,
            findings=findings,
            license=lic_status,
            summary=summary,
            errors=[],
        )

    def generate_sanitized_diff(self, diff_content: str) -> str:
        """
        Generates a sanitized unified diff with all detected secret values redacted.
        """
        lines = diff_content.splitlines()
        sanitized_lines = []
        for line in lines:
            if line.startswith("+") and not line.startswith("+++"):
                # Redact added lines
                sanitized_lines.append("+" + redact_text(line[1:]))
            else:
                sanitized_lines.append(line)
        return "\n".join(sanitized_lines) + ("\n" if diff_content.endswith("\n") else "")


def format_text_report(report: Dict[str, Any]) -> str:
    """Format human-readable CLI summary."""
    lines = []
    lines.append("=" * 68)
    lines.append(f"  GIT SECURITY SENTINEL v{report.get('version', VERSION)}")
    lines.append("  Privacy-First Git Security Scanner")
    lines.append("=" * 68)
    lines.append(f"Status     : {report.get('status', 'unknown').upper()}")
    lines.append(f"Scan Mode  : {report.get('scan_mode', 'all')}")

    lic = report.get("license", {})
    lic_present = lic.get("root_license_present", False)
    lic_file = lic.get("license_file") or "None"
    lines.append(f"Root License : {'Found (' + lic_file + ')' if lic_present else 'MISSING'}")

    summary = report.get("summary", {})
    lines.append(
        f"Findings   : Total: {summary.get('total', 0)} | "
        f"Critical: {summary.get('critical', 0)} | "
        f"High: {summary.get('high', 0)} | "
        f"Medium: {summary.get('medium', 0)} | "
        f"Low: {summary.get('low', 0)}"
    )
    lines.append("-" * 68)

    errors = report.get("errors", [])
    if errors:
        lines.append("ERRORS ENCOUNTERED:")
        for err in errors:
            lines.append(f"  [!] {err}")
        lines.append("-" * 68)

    findings = report.get("findings", [])
    if not findings:
        lines.append("No security issues detected in the inspected diff.")
    else:
        for idx, f in enumerate(findings, start=1):
            sev = f["severity"].upper()
            lines.append(f"[{idx}] [{sev}] {f['rule_id']} ({f['category']})")
            lines.append(f"    Location   : {f['file']}:{f['line']}")
            lines.append(f"    Message    : {f['message']}")
            lines.append(f"    Evidence   : {f['evidence']}")
            lines.append(f"    Remediation: {f['recommendation']}")
            lines.append("")

    lines.append("=" * 68)
    return "\n".join(lines)


def evaluate_exit_code(report: Dict[str, Any], threshold: str) -> int:
    """
    Determine exit code:
    0: Scan completed, no findings exceed severity threshold.
    1: Scan completed, findings meet or exceed severity threshold.
    2: Scan execution or configuration error.
    """
    if report.get("status") == "failed" or report.get("errors"):
        return 2

    threshold_level = SEVERITY_ORDER.get(threshold.lower(), 3)
    findings = report.get("findings", [])

    for f in findings:
        sev = f.get("severity", "low").lower()
        if SEVERITY_ORDER.get(sev, 0) >= threshold_level:
            return 1

    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan_diff.py",
        description="Git Security Sentinel: Privacy-first Git diff security scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python scripts/scan_diff.py --staged
  python scripts/scan_diff.py --unstaged
  python scripts/scan_diff.py --all
  python scripts/scan_diff.py --base main
  python scripts/scan_diff.py --all --format json
  python scripts/scan_diff.py --all --output scan-report.json
  python scripts/scan_diff.py --all --redacted-diff-out sanitized.patch
""",
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--staged",
        action="store_true",
        help="Scan git staged (cached) changes only.",
    )
    mode_group.add_argument(
        "--unstaged",
        action="store_true",
        help="Scan git unstaged working tree changes only.",
    )
    mode_group.add_argument(
        "--all",
        action="store_true",
        help="Scan both staged and unstaged working changes.",
    )
    mode_group.add_argument(
        "--base",
        metavar="BRANCH",
        help="Scan changes against merge-base of current branch and specified base branch.",
    )
    mode_group.add_argument(
        "--diff-file",
        metavar="FILE",
        help="Scan diff from a file, or '-' to read from standard input.",
    )

    parser.add_argument(
        "--repo-root",
        metavar="PATH",
        default=".",
        help="Path to repository root (defaults to current working directory).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Console output format (default: text).",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Save structured JSON scan report to specified file.",
    )
    parser.add_argument(
        "--redacted-diff-out",
        metavar="FILE",
        help="Save sanitized diff with detected secrets redacted to specified file.",
    )
    parser.add_argument(
        "--severity-threshold",
        choices=["critical", "high", "medium", "low"],
        default="high",
        help="Minimum severity level that triggers an exit code of 1 (default: high).",
    )

    ai_group = parser.add_argument_group("AI Security Review Options")
    ai_group.add_argument(
        "--ai",
        action="store_true",
        help="Run contextual AI review on findings using local Gemma (Ollama) or configured cloud provider.",
    )
    ai_group.add_argument(
        "--provider",
        choices=["auto", "ollama", "gemini", "openai", "groq"],
        default="auto",
        help="AI provider for review (default: auto; uses GEMINI_API_KEY if present, otherwise local Ollama).",
    )
    ai_group.add_argument(
        "--model",
        metavar="MODEL_NAME",
        help="AI model name override (default: gemma3:4b for Ollama, gemma-4-26b-a4b-it for Google AI Studio).",
    )
    ai_group.add_argument(
        "--ai-endpoint",
        metavar="URL",
        help="Custom API endpoint URL for AI inference.",
    )
    ai_group.add_argument(
        "--allow-remote",
        action="store_true",
        help="Permit non-loopback endpoints for Ollama (disabled by default for privacy).",
    )
    ai_group.add_argument(
        "--ai-timeout",
        type=int,
        default=120,
        metavar="SECONDS",
        help="HTTP request timeout for AI inference in seconds (default: 120).",
    )

    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    repo_path = Path(args.repo_root).resolve()
    scanner = GitSecurityScanner(repo_root=repo_path)

    # Determine mode
    diff_content = ""
    scan_mode = "all"
    errors: List[str] = []

    if args.diff_file:
        scan_mode = "file"
        if args.diff_file == "-":
            try:
                diff_content = sys.stdin.read()
            except Exception as e:
                errors.append(f"Failed to read diff from stdin: {e}")
        else:
            diff_path = Path(args.diff_file)
            if not diff_path.is_file():
                errors.append(f"Diff file not found: {args.diff_file}")
            else:
                try:
                    diff_content = diff_path.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    errors.append(f"Failed to read diff file '{args.diff_file}': {e}")
    else:
        # Check git repo status
        is_git, git_err = scanner.check_is_git_repository()
        if not is_git:
            report = {
                "scanner": SCANNER_NAME,
                "version": VERSION,
                "status": "failed",
                "scan_mode": "unknown",
                "findings": [],
                "license": {"root_license_present": False, "license_file": None},
                "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                "errors": [git_err or "Directory is not a valid Git repository."],
            }
            if args.format == "json":
                print(json.dumps(report, indent=2))
            else:
                print(format_text_report(report))
            if args.output:
                Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
            return 2

        if args.staged:
            scan_mode = "staged"
        elif args.unstaged:
            scan_mode = "unstaged"
        elif args.base:
            scan_mode = f"base:{args.base}"
        else:
            scan_mode = "all"

        branch_arg = args.base if args.base else None
        mode_key = "base" if args.base else scan_mode
        diff_content, git_errors = scanner.get_diff(mode_key, base_branch=branch_arg)
        errors.extend(git_errors)

    if errors:
        report = {
            "scanner": SCANNER_NAME,
            "version": VERSION,
            "status": "failed",
            "scan_mode": scan_mode,
            "findings": [],
            "license": scanner.check_license(),
            "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
            "errors": errors,
        }
    else:
        report = scanner.scan_diff_content(diff_content, scan_mode=scan_mode)

    # AI Contextual Review
    ai_text_output = ""
    if args.ai and not errors:
        findings_count = report.get("summary", {}).get("total", 0)
        if findings_count == 0:
            if args.format != "json":
                ai_text_output = (
                    "====================================================================\n"
                    "  GIT SECURITY SENTINEL - AI SECURITY REVIEW\n"
                    "====================================================================\n"
                    "Status: SKIPPED (Diff is clean - zero findings require remediation)\n"
                    "===================================================================="
                )
            else:
                report["ai_review"] = {
                    "status": "skipped",
                    "reason": "Diff is clean; no findings to triage.",
                }
        else:
            sanitized_diff = scanner.generate_sanitized_diff(diff_content)
            try:
                try:
                    from scripts.ai_review import run_ai_review
                except ImportError:
                    try:
                        from ai_review import run_ai_review
                    except ImportError:
                        sys.path.insert(0, str(Path(__file__).parent))
                        from ai_review import run_ai_review

                success, ai_result, ai_formatted = run_ai_review(
                    report_data=report,
                    sanitized_diff=sanitized_diff,
                    provider=args.provider,
                    model=args.model,
                    endpoint=args.ai_endpoint,
                    allow_remote=args.allow_remote,
                    timeout_sec=args.ai_timeout,
                    format_mode=args.format,
                )
                if args.format == "json":
                    report["ai_review"] = ai_result
                else:
                    ai_text_output = ai_formatted
            except Exception as e:
                err_msg = f"Failed to execute AI contextual reviewer: {e}"
                if args.format == "json":
                    report["ai_review"] = {"status": "error", "error": err_msg}
                else:
                    ai_text_output = (
                        "====================================================================\n"
                        "  GIT SECURITY SENTINEL - AI REVIEWER ERROR\n"
                        "====================================================================\n"
                        f"{err_msg}\n"
                        "===================================================================="
                    )

    # Output sanitized diff if requested
    if args.redacted_diff_out:
        out_patch_path = args.redacted_diff_out
        sanitized = scanner.generate_sanitized_diff(diff_content)
        try:
            Path(out_patch_path).write_text(sanitized, encoding="utf-8")
        except Exception as e:
            report.setdefault("errors", []).append(f"Failed to write redacted diff: {e}")

    # Output JSON file if requested
    if args.output:
        try:
            Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        except Exception as e:
            report.setdefault("errors", []).append(f"Failed to write JSON report output: {e}")

    # Console output
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(format_text_report(report))
        if ai_text_output:
            print()
            print(ai_text_output)

    return evaluate_exit_code(report, args.severity_threshold)


if __name__ == "__main__":
    sys.exit(main())
