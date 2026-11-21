"""
Git Security Sentinel - Compliance, Hygiene & Generic Credentials Detection Rules.
Covers cryptographic private key headers, generic credentials, security debt markers, and root license.
"""

import re
from typing import List

from git_security_sentinel.core.models import Rule

COMPLIANCE_RULES: List[Rule] = [
    Rule(
        rule_id="secret.private_key",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"
        ),
        message="Cryptographic private key header detected.",
        recommendation="Never commit private keys to source control. Add the key file to .gitignore and rotate the keypair.",
    ),
    Rule(
        rule_id="secret.generic_credential",
        category="secrets",
        severity="high",
        confidence="medium",
        pattern=re.compile(
            r"""(?i)(?:password|passwd|api_key|apikey|secret_key|client_secret|auth_token|access_token)\s*[:=]\s*['"]((?!\[REDACTED:)[^'"\r\n]{8,128})['"]"""
        ),
        message="Potential hardcoded credential or secret assignment detected.",
        recommendation="Extract credentials into a .env file or cloud secret store. Load via environment variables at runtime.",
    ),
    Rule(
        rule_id="compliance.security_todo",
        category="compliance",
        severity="low",
        confidence="high",
        pattern=re.compile(
            r"""(?i)(?:#|//|/\*)\s*(?:TODO|FIXME|HACK|XXX)\s*[:\s].*(?:security|vulnerab|cwe|cve|auth|token|credential|sanitize|exploit|leak)"""
        ),
        message="Security debt marker (TODO/FIXME/HACK) detected in comments.",
        recommendation="Resolve security debt items prior to merging into production branches.",
    ),
    Rule(
        rule_id="compliance.root_license",
        category="compliance",
        severity="low",
        confidence="high",
        pattern=re.compile(r"^LICENSE.*"),
        message="Root open-source license file missing.",
        recommendation="Add a LICENSE file to the repository root.",
    ),
]
