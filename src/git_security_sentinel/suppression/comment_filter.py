"""
Git Security Sentinel - Inline Comment Suppression Filter.
Supports line-level suppression directives (# nosec, # sentinel:ignore, //, --)
with optional rule-specific identifiers and aliases.
"""

import re
from typing import Optional, Set, Tuple

# Matches comment markers (#, //, --) followed by nosec or sentinel:ignore
# and optional rule identifiers up to end of line.
SUPPRESSION_REGEX = re.compile(
    r"""(?i)(?:#|//|--)\s*(?:nosec|sentinel:ignore)(?:[:\s]+([A-Za-z0-9_\-.,;\s]+))?\s*$"""
)


def normalize_rule_identifier(rule_id: str) -> str:
    """
    Normalizes rule identifiers to lowercase with hyphens.
    E.g., 'secret.aws_access_key' -> 'secret-aws-access-key'
          'aws-access-key' -> 'aws-access-key'
    """
    return rule_id.strip().lower().replace("_", "-").replace(".", "-")


def parse_inline_suppression(line_content: str) -> Optional[Tuple[bool, Set[str]]]:
    """
    Analyzes line content for inline suppression directives.

    Returns:
        None: No suppression directive found.
        (True, set()): Blanket suppression (all rules on this line suppressed).
        (False, {rules}): Specific rules suppressed on this line.
    """
    line = line_content.rstrip("\r\n")
    match = SUPPRESSION_REGEX.search(line)
    if not match:
        return None

    raw_rules = match.group(1)
    if not raw_rules or not raw_rules.strip():
        return (True, set())

    # Parse comma, semicolon, or space-separated rule list
    tokens = re.split(r"[,;\s]+", raw_rules)
    rules = {normalize_rule_identifier(t) for t in tokens if t.strip()}

    if not rules:
        return (True, set())

    return (False, rules)


def is_rule_suppressed(rule_id: str, suppression: Optional[Tuple[bool, Set[str]]]) -> bool:
    """
    Determines whether a specific rule_id is suppressed given parsed suppression directives.

    Normalizes rule identifiers so case, '.', '_', and '-' are treated interchangeably.
    Supports exact match, rule alias match (e.g. 'aws-access-key' matches 'secret.aws_access_key'),
    category prefix match (e.g. 'secret' matches 'secret.aws_access_key'), and reverse alias matching.
    Requires strict segment/boundary matching to prevent unbounded suffix overmatching
    (e.g. 'en' does NOT match 'secret.github_token', and 'key' does NOT match 'secret.stripe_key').
    """
    if not suppression:
        return False

    is_blanket, rules = suppression
    if is_blanket:
        return True

    norm_id = normalize_rule_identifier(rule_id)

    # Determine rule name alias without category prefix (e.g. 'aws-access-key' from 'secret.aws_access_key')
    rule_name_alias = None
    if "." in rule_id:
        rule_name_alias = normalize_rule_identifier(rule_id.split(".", 1)[1])
    else:
        for cat in ("secret-", "file-", "insecure-code-", "risk-", "compliance-"):
            if norm_id.startswith(cat):
                rule_name_alias = norm_id[len(cat):]
                break

    for raw_r in rules:
        r = normalize_rule_identifier(raw_r)
        if norm_id == r:
            return True
        # Exact rule alias match (e.g. 'aws-access-key' matches 'secret.aws_access_key')
        if rule_name_alias and r == rule_name_alias:
            return True
        # Category prefix match (e.g. 'secret' matches 'secret-aws-access-key')
        if norm_id.startswith(r + "-"):
            return True
        # Reverse alias matching: directive contains full ID while rule_id was short alias
        if rule_name_alias and (r.endswith("." + rule_name_alias) or r.endswith("-" + rule_name_alias)):
            return True
        if r.endswith("." + norm_id) or any(r == f"{c}{norm_id}" for c in ("secret-", "file-", "insecure-code-", "risk-", "compliance-")):
            return True

    return False
