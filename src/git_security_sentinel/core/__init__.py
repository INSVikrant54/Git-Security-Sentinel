"""
Git Security Sentinel - Core Module.
Exposes data models, unified diff parser, and git scanner.
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

__all__ = [
    "ACCEPTED_LICENSE_NAMES",
    "DETECTION_RULES",
    "Finding",
    "GitSecurityScanner",
    "IGNORE_PLACEHOLDERS",
    "LicenseStatus",
    "Rule",
    "SCANNER_NAME",
    "ScanReport",
    "ScanSummary",
    "SEVERITY_ORDER",
    "UnifiedDiffParser",
    "VERSION",
    "is_benign_generic_value",
    "redact_text",
]
