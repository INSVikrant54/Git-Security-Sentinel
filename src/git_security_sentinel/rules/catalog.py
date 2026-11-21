"""
Git Security Sentinel - Detection Rules Catalog.
Central registry and lookup for all 47 static detection rules across 5 canonical categories.
"""

from typing import Dict, List, Optional

from git_security_sentinel.core.models import Rule
from git_security_sentinel.rules.auth import AUTH_RULES
from git_security_sentinel.rules.cloud import CLOUD_RULES
from git_security_sentinel.rules.compliance import COMPLIANCE_RULES
from git_security_sentinel.rules.database import DATABASE_RULES
from git_security_sentinel.rules.insecure_code import INSECURE_CODE_RULES
from git_security_sentinel.rules.sensitive_files import SENSITIVE_FILES_RULES

# Ensure backwards-compatible dict-like access on Rule instances
if not hasattr(Rule, "__getitem__"):
    Rule.__getitem__ = lambda self, key: getattr(self, key)
if not hasattr(Rule, "get"):
    Rule.get = lambda self, key, default=None: getattr(self, key, default)

# Master list of all 47 detection rules
ALL_RULES: List[Rule] = (
    CLOUD_RULES
    + AUTH_RULES
    + DATABASE_RULES
    + SENSITIVE_FILES_RULES
    + INSECURE_CODE_RULES
    + COMPLIANCE_RULES
)

# Internal lookup index by full ID and suffix alias
_RULES_BY_ID: Dict[str, Rule] = {}
for _r in ALL_RULES:
    _RULES_BY_ID[_r.rule_id] = _r
    _suffix = _r.rule_id.split(".")[-1]
    if _suffix not in _RULES_BY_ID:
        _RULES_BY_ID[_suffix] = _r


def get_all_rules() -> List[Rule]:
    """Returns a list of all active detection rules (47 rules total)."""
    return list(ALL_RULES)


def get_rule_by_id(rule_id: str) -> Optional[Rule]:
    """
    Lookup rule by canonical ID (e.g. 'secret.aws_access_key')
    or short alias (e.g. 'aws_access_key').
    """
    if not rule_id:
        return None
    # Exact lookup
    if rule_id in _RULES_BY_ID:
        return _RULES_BY_ID[rule_id]
    # Suffix or case-insensitive lookup
    cleaned = rule_id.strip().lower()
    for r in ALL_RULES:
        if r.rule_id.lower() == cleaned:
            return r
        if r.rule_id.split(".")[-1].lower() == cleaned:
            return r
    return None
