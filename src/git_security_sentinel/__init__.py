"""
Git Security Sentinel - Deterministic Diff Security Scanner
Zero-dependency, privacy-first pre-commit and CI scanner for Git changes.
Complies with the Agent Skills Open Standard (https://agentskills.io/specification).
"""

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
    DETECTION_RULES,
    GitSecurityScanner,
    IGNORE_PLACEHOLDERS,
    is_benign_generic_value,
    redact_text,
)
from git_security_sentinel.rules.catalog import (
    ALL_RULES,
    get_all_rules,
    get_rule_by_id,
)
from git_security_sentinel.suppression import (
    BaselineFilter,
    PathFilter,
    compute_fingerprint,
    is_rule_suppressed,
    load_sentinelignore,
    parse_inline_suppression,
)
from git_security_sentinel.config import (
    load_config,
    parse_simple_yaml,
)

__version__ = VERSION

__all__ = [
    "__version__",
    "ACCEPTED_LICENSE_NAMES",
    "ALL_RULES",
    "BaselineFilter",
    "DETECTION_RULES",
    "Finding",
    "GitSecurityScanner",
    "IGNORE_PLACEHOLDERS",
    "LicenseStatus",
    "PathFilter",
    "Rule",
    "SCANNER_NAME",
    "ScanReport",
    "ScanSummary",
    "SEVERITY_ORDER",
    "UnifiedDiffParser",
    "VERSION",
    "compute_fingerprint",
    "get_all_rules",
    "get_rule_by_id",
    "is_benign_generic_value",
    "is_rule_suppressed",
    "load_config",
    "load_sentinelignore",
    "parse_inline_suppression",
    "parse_simple_yaml",
    "redact_text",
]
