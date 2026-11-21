"""
Git Security Sentinel - Detection Rules Package.
"""

from git_security_sentinel.core.models import Rule
from git_security_sentinel.rules.catalog import (
    ALL_RULES,
    get_all_rules,
    get_rule_by_id,
)
from git_security_sentinel.rules.cloud import CLOUD_RULES
from git_security_sentinel.rules.auth import AUTH_RULES
from git_security_sentinel.rules.database import DATABASE_RULES
from git_security_sentinel.rules.sensitive_files import SENSITIVE_FILES_RULES
from git_security_sentinel.rules.insecure_code import INSECURE_CODE_RULES
from git_security_sentinel.rules.compliance import COMPLIANCE_RULES

__all__ = [
    "ALL_RULES",
    "AUTH_RULES",
    "CLOUD_RULES",
    "COMPLIANCE_RULES",
    "DATABASE_RULES",
    "INSECURE_CODE_RULES",
    "Rule",
    "SENSITIVE_FILES_RULES",
    "get_all_rules",
    "get_rule_by_id",
]
