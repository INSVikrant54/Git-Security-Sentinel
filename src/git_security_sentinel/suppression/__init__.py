"""
Git Security Sentinel - Suppression Package.
Provides line-level comment suppression, gitignore-style path filtering,
and persistent baseline filtering.
"""

from git_security_sentinel.suppression.comment_filter import (
    SUPPRESSION_REGEX,
    is_rule_suppressed,
    normalize_rule_identifier,
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

__all__ = [
    "SUPPRESSION_REGEX",
    "parse_inline_suppression",
    "is_rule_suppressed",
    "normalize_rule_identifier",
    "PathFilter",
    "load_sentinelignore",
    "BaselineFilter",
    "compute_fingerprint",
]
