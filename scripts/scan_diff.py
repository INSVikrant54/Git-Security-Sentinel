#!/usr/bin/env python3
"""
Git Security Sentinel - Deterministic Diff Security Scanner
Zero-dependency, privacy-first pre-commit and CI scanner for Git changes.
Complies with the Agent Skills Open Standard (https://agentskills.io/specification).

Backwards-compatible wrapper re-exporting core modules and CLI entry points.
"""

from pathlib import Path
import sys
from typing import Any, List, Optional

# Ensure src/ is importable even if package is not pip-installed
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _REPO_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from git_security_sentinel.core.models import (
    ACCEPTED_LICENSE_NAMES,
    Finding,
    LicenseStatus,
    Rule,
    SCANNER_NAME,
    ScanReport,
    ScanSummary,
    SEVERITY_ORDER,
    VERSION,
)
from git_security_sentinel.core.diff_parser import UnifiedDiffParser
from git_security_sentinel.core.scanner import (
    GitSecurityScanner as _CoreGitSecurityScanner,
    IGNORE_PLACEHOLDERS,
    is_benign_generic_value,
    redact_text,
)
from git_security_sentinel.rules.catalog import (
    ALL_RULES,
    get_all_rules,
    get_rule_by_id,
)
from git_security_sentinel.cli import (
    build_arg_parser as _cli_build_arg_parser,
    evaluate_exit_code,
    format_text_report,
    main as _cli_main,
)
from git_security_sentinel.output.sarif import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    generate_sarif_report,
)
from git_security_sentinel.hooks.installer import install_pre_commit_hook
from git_security_sentinel.update.checker import (
    check_for_pypi_update,
    print_update_banner,
    run_self_upgrade,
)

# Baseline v1.0.0 rules for backwards-compatibility
_BASELINE_RULE_IDS = {
    "secret.aws_access_key",
    "secret.aws_secret_key",
    "secret.github_token",
    "secret.slack_token",
    "secret.private_key",
    "secret.generic_credential",
    "risk.eval_execution",
    "risk.localhost_endpoint",
}
BASELINE_RULES: List[Rule] = [r for r in get_all_rules() if r.rule_id in _BASELINE_RULE_IDS]
DETECTION_RULES: List[Rule] = BASELINE_RULES


class GitSecurityScanner(_CoreGitSecurityScanner):
    """
    Backwards-compatible scanner wrapper preserving baseline v1.0.0 rule defaults
    when invoked directly from scripts/scan_diff.py.
    """

    def __init__(
        self,
        repo_root: Optional[Path] = None,
        rules: Optional[List[Any]] = None,
        path_filter: Optional[Any] = None,
        baseline_filter: Optional[Any] = None,
        **kwargs: Any,
    ):
        if rules is None:
            rules = BASELINE_RULES
        super().__init__(
            repo_root=repo_root,
            rules=rules,
            path_filter=path_filter,
            baseline_filter=baseline_filter,
            **kwargs,
        )


def build_arg_parser():
    return _cli_build_arg_parser(prog="scan_diff.py")


def main(argv=None):
    return _cli_main(argv=argv, prog="scan_diff.py")


if __name__ == "__main__":
    sys.exit(main())
