"""
Git Security Sentinel - Core Git Diff Security Scanner.
Deterministic diff analysis, secret detection, evidence redaction, and reporting.
"""

from pathlib import Path
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from git_security_sentinel.core.models import (
    ACCEPTED_LICENSE_NAMES,
    Finding,
    LicenseStatus,
    Rule,
    SCANNER_NAME,
    ScanReport,
    ScanSummary,
    VERSION,
)
from git_security_sentinel.core.diff_parser import UnifiedDiffParser
from git_security_sentinel.redaction.redactor import (
    IGNORE_PLACEHOLDERS,
    is_benign_generic_value,
    redact_text,
)
from git_security_sentinel.rules.catalog import (
    ALL_RULES,
    get_all_rules,
    get_rule_by_id,
)
from git_security_sentinel.suppression.comment_filter import (
    is_rule_suppressed,
    parse_inline_suppression,
)
from git_security_sentinel.suppression.ignore_filter import (
    PathFilter,
    load_sentinelignore,
)
from git_security_sentinel.suppression.baseline import (
    BaselineFilter,
    compute_fingerprint,
)

# Detection rules catalog
DETECTION_RULES: List[Rule] = get_all_rules()


class GitSecurityScanner:
    """
    Deterministic static security scanner for Git diffs.
    """

    def __init__(
        self,
        repo_root: Optional[Path] = None,
        rules: Optional[List[Any]] = None,
        path_filter: Optional[PathFilter] = None,
        baseline_filter: Optional[BaselineFilter] = None,
    ):
        self.repo_root = Path(repo_root) if repo_root else Path.cwd()
        self.rules = rules if rules is not None else DETECTION_RULES

        if path_filter is not None:
            self.path_filter = path_filter
        else:
            ignore_patterns = load_sentinelignore(self.repo_root)
            self.path_filter = PathFilter(ignore_patterns) if ignore_patterns else None

        self.baseline_filter = baseline_filter

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
                encoding="utf-8",
                errors="replace",
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
            code_head, _, _ = self.run_git_command(["rev-parse", "--verify", "HEAD"])
            if code_head == 0:
                code, out, err = self.run_git_command(["diff", "HEAD", "--no-color", "--no-ext-diff"])
                if code != 0:
                    errors.append(f"Failed to get all changes against HEAD: {err.strip()}")
                return out, errors
            else:
                code, out, err = self.run_git_command(["diff", "--staged", "--no-color", "--no-ext-diff"])
                if code != 0:
                    errors.append(f"Failed to get staged diff for initial commit: {err.strip()}")
                return out, errors

        elif mode == "base":
            if not base_branch:
                errors.append("Base branch must be specified when using --base mode.")
                return "", errors

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

    def scan_diff_report(
        self,
        diff_content: str,
        scan_mode: str,
        path_filter: Optional[PathFilter] = None,
        baseline_filter: Optional[BaselineFilter] = None,
    ) -> ScanReport:
        """
        Parse diff content, evaluate active detection rules, sanitize evidence,
        apply path exclusions, comment suppression, and baseline filtering,
        and assemble a typed ScanReport dataclass instance.
        """
        active_path_filter = path_filter if path_filter is not None else self.path_filter
        active_baseline_filter = baseline_filter if baseline_filter is not None else self.baseline_filter

        parser = UnifiedDiffParser()
        added_lines = parser.parse(diff_content)
        license_info = self.check_license()

        findings: List[Finding] = []
        suppressed_findings: List[Finding] = []
        seen_finding_keys = set()

        for item in added_lines:
            file_path = item["file"]
            line_no = item["line"]
            raw_content = item["content"]

            if active_path_filter and active_path_filter.is_ignored(file_path):
                continue

            for rule in self.rules:
                rule_id = rule.rule_id if hasattr(rule, "rule_id") else rule["rule_id"]
                category = rule.category if hasattr(rule, "category") else rule["category"]
                severity = rule.severity if hasattr(rule, "severity") else rule["severity"]
                confidence = rule.confidence if hasattr(rule, "confidence") else rule["confidence"]
                pattern = rule.pattern if hasattr(rule, "pattern") else rule["pattern"]
                message = rule.message if hasattr(rule, "message") else rule["message"]
                recommendation = rule.recommendation if hasattr(rule, "recommendation") else rule["recommendation"]

                # Category: sensitive_files target file paths rather than line content
                if category == "sensitive_files" or rule_id.startswith("file."):
                    if pattern.search(file_path):
                        dup_key = (rule_id, file_path, 1)
                        if dup_key not in seen_finding_keys:
                            seen_finding_keys.add(dup_key)
                            evidence = raw_content.strip() if raw_content.strip() else file_path
                            redacted_evidence = redact_text(evidence)
                            fp = compute_fingerprint(rule_id, file_path, redacted_evidence)

                            finding = Finding(
                                rule_id=rule_id,
                                category=category,
                                severity=severity,
                                confidence=confidence,
                                file=file_path,
                                line=1,
                                message=message,
                                evidence=redacted_evidence,
                                recommendation=recommendation,
                                fingerprint=fp,
                            )

                            inline_supp = parse_inline_suppression(raw_content)
                            is_comment_supp = is_rule_suppressed(rule_id, inline_supp)
                            is_base_supp = active_baseline_filter.is_suppressed(finding) if active_baseline_filter else False

                            if is_comment_supp or is_base_supp:
                                finding.suppressed = True
                                finding.suppression_reason = "inline_comment" if is_comment_supp else "baseline"
                                suppressed_findings.append(finding)
                            else:
                                findings.append(finding)
                else:
                    match = pattern.search(raw_content)
                    if not match:
                        continue

                    # Filter common benign placeholders and templates
                    if rule_id in (
                        "secret.generic_credential",
                        "insecure_code.temp_credential",
                        "secret.datadog_key",
                        "secret.aws_secret_key",
                    ):
                        matched_val = match.group(1) if match.groups() else match.group(0)
                        if is_benign_generic_value(matched_val):
                            continue

                    validator = getattr(rule, "validator", None) if hasattr(rule, "validator") else rule.get("validator")
                    if validator and callable(validator) and not validator(match, raw_content):
                        continue

                    dup_key = (rule_id, file_path, line_no)
                    if dup_key in seen_finding_keys:
                        continue
                    seen_finding_keys.add(dup_key)

                    redacted_evidence = redact_text(raw_content.strip())
                    if rule_id.startswith("secret.") and match.group(0) in redacted_evidence:
                        redacted_evidence = "[REDACTED]"

                    fp = compute_fingerprint(rule_id, file_path, redacted_evidence)

                    finding = Finding(
                        rule_id=rule_id,
                        category=category,
                        severity=severity,
                        confidence=confidence,
                        file=file_path,
                        line=line_no,
                        message=message,
                        evidence=redacted_evidence,
                        recommendation=recommendation,
                        fingerprint=fp,
                    )

                    inline_supp = parse_inline_suppression(raw_content)
                    is_comment_supp = is_rule_suppressed(rule_id, inline_supp)
                    is_base_supp = active_baseline_filter.is_suppressed(finding) if active_baseline_filter else False

                    if is_comment_supp or is_base_supp:
                        finding.suppressed = True
                        finding.suppression_reason = "inline_comment" if is_comment_supp else "baseline"
                        suppressed_findings.append(finding)
                    else:
                        findings.append(finding)

        summary = ScanSummary(
            total=len(findings),
            critical=sum(1 for f in findings if f.severity == "critical"),
            high=sum(1 for f in findings if f.severity == "high"),
            medium=sum(1 for f in findings if f.severity == "medium"),
            low=sum(1 for f in findings if f.severity == "low"),
            suppressed=len(suppressed_findings),
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
            suppressed_findings=suppressed_findings,
        )

    def scan_diff_content(
        self,
        diff_content: str,
        scan_mode: str,
        path_filter: Optional[PathFilter] = None,
        baseline_filter: Optional[BaselineFilter] = None,
    ) -> Dict[str, Any]:
        """
        Parse diff content, run rules, sanitize evidence, and assemble structured report dict.
        """
        return self.scan_diff_report(
            diff_content,
            scan_mode,
            path_filter=path_filter,
            baseline_filter=baseline_filter,
        ).to_dict()

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
