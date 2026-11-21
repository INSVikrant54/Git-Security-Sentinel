"""
Git Security Sentinel - Sensitive Committed Files Detection Rules.
Covers .env files, id_rsa, id_ed25519, and *.pem/key certificates.
"""

import re
from typing import List

from git_security_sentinel.core.models import Rule

SENSITIVE_FILES_RULES: List[Rule] = [
    Rule(
        rule_id="file.env_file",
        category="sensitive_files",
        severity="critical",
        confidence="high",
        pattern=re.compile(r"""(?i)(?:^|/)\.env(?:\.(?!example|template|sample|dist)[a-zA-Z0-9_\-]+)?$"""),
        message="Committed .env environment variable configuration file detected.",
        recommendation="Add .env files to .gitignore and use .env.example with dummy values for documentation.",
    ),
    Rule(
        rule_id="file.ssh_rsa_key",
        category="sensitive_files",
        severity="critical",
        confidence="high",
        pattern=re.compile(r"(?i)(?:^|/)id_rsa$"),
        message="Committed SSH RSA private key file detected.",
        recommendation="Remove id_rsa from git history immediately and regenerate SSH keypairs.",
    ),
    Rule(
        rule_id="file.ssh_ed25519_key",
        category="sensitive_files",
        severity="critical",
        confidence="high",
        pattern=re.compile(r"(?i)(?:^|/)id_ed25519$"),
        message="Committed SSH Ed25519 private key file detected.",
        recommendation="Remove id_ed25519 from git history immediately and regenerate SSH keypairs.",
    ),
    Rule(
        rule_id="file.pem_key",
        category="sensitive_files",
        severity="critical",
        confidence="high",
        pattern=re.compile(r"(?i)(?:^|/).+\.(?:pem|pkcs12|pfx|p12|key)$"),
        message="Committed cryptographic certificate/key file detected.",
        recommendation="Never commit .pem, .key, or PKCS#12 bundle files to version control.",
    ),
]
