"""
Git Security Sentinel - Redaction Engine.
Deterministically sanitizes sensitive tokens, credentials, and secrets
from diff lines, output reports, and AI review prompts.
"""

import re
from typing import Set

# Common benign strings / placeholders to ignore for generic credential rules
IGNORE_PLACEHOLDERS: Set[str] = {
    "your_api_key",
    "your_key_here",
    "your_secret_here",
    "your_password",
    "your_api_key_here",
    "change_me",
    "changeme",
    "placeholder",
    "test_secret",
    "example_key",
    "dummy_password",
    "sample_token",
    "xxxx",
    "xxxxxx",
    "********",
    "undefined",
    "process.env",
    "os.environ",
    "${",
    "{{",
    "true",
    "false",
    "null",
    "none",
}


def is_benign_generic_value(val: str) -> bool:
    """Check if matched generic credential value is a common placeholder or template."""
    clean = val.strip().lower()
    if clean in IGNORE_PLACEHOLDERS:
        return True
    if any(clean.startswith(prefix) for prefix in ("your_", "example_", "test_")):
        return True
    if any(marker in clean for marker in ("${", "{{", "process.env", "os.environ", "os.getenv")):
        return True
    # If it contains only identical repeating characters (e.g. 'xxxxxxxx')
    if len(set(clean)) <= 2:
        return True
    return False


def redact_text(line: str) -> str:
    """
    Deterministically redacts detected secrets within a line before reporting or saving diffs.
    Returns the sanitized line with sensitive tokens replaced with [REDACTED:<TYPE>].
    Ensures negative lookahead protection prevents generic credential rules from clobbering
    previously redacted vendor tokens.
    """
    sanitized = line

    # Step 1: Multi-line / Cryptographic Blocks
    sanitized = re.sub(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----(?:.*?-----END [A-Z ]+-----|[^\r\n]*)",
        "[REDACTED:PRIVATE_KEY]",
        sanitized,
        flags=re.DOTALL,
    )

    # Step 2: Multi-segment Structured Tokens
    # JSON Web Token (JWT)
    sanitized = re.sub(
        r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,})\b",
        "[REDACTED:JWT_TOKEN]",
        sanitized,
    )

    # SendGrid API Key
    sanitized = re.sub(
        r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b",
        "[REDACTED:SENDGRID_KEY]",
        sanitized,
    )

    # Firebase FCM Server Key
    sanitized = re.sub(
        r"\b(AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140})\b",
        "[REDACTED:FIREBASE_KEY]",
        sanitized,
    )

    # Discord Bot Token
    sanitized = re.sub(
        r"\b([MN][A-Za-z\d]{23,26}\.[A-Za-z\d\-_]{6}\.[A-Za-z\d\-_]{27,38})\b",
        "[REDACTED:DISCORD_TOKEN]",
        sanitized,
    )

    # Telegram Bot API Token
    sanitized = re.sub(
        r"\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b",
        "[REDACTED:TELEGRAM_TOKEN]",
        sanitized,
    )

    # Mailchimp API Key
    sanitized = re.sub(
        r"\b([0-9a-f]{32}-us[0-9]{1,2})\b",
        "[REDACTED:MAILCHIMP_KEY]",
        sanitized,
    )

    # Step 3: Vendor Prefixed Tokens
    # AWS Access Key ID
    sanitized = re.sub(
        r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b",
        "[REDACTED:AWS_KEY_ID]",
        sanitized,
    )

    # GitHub Tokens (PAT, OAuth, fine-grained)
    sanitized = re.sub(
        r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b",
        "[REDACTED:GITHUB_TOKEN]",
        sanitized,
    )

    # Slack Tokens
    sanitized = re.sub(
        r"\b(xox[baprs]-[0-9A-Za-z]{10,48}-[0-9A-Za-z]{10,48}-[0-9A-Za-z]{24,48}|xox[baprs]-[0-9A-Za-z]{10,48})\b",
        "[REDACTED:SLACK_TOKEN]",
        sanitized,
    )

    # Stripe Secret or Restricted Key
    sanitized = re.sub(
        r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99})\b",
        "[REDACTED:STRIPE_KEY]",
        sanitized,
    )

    # Twilio Account SID or API Key
    sanitized = re.sub(
        r"\b(AC[0-9a-fA-F]{32}|SK[0-9a-fA-F]{32})\b",
        "[REDACTED:TWILIO_KEY]",
        sanitized,
    )

    # Mailgun API Key
    sanitized = re.sub(
        r"\b(key-[0-9a-zA-Z]{32})\b",
        "[REDACTED:MAILGUN_KEY]",
        sanitized,
    )

    # Square Access Token / Secret
    sanitized = re.sub(
        r"\b(sq0atp-[0-9A-Za-z\-_]{22}|sq0csp-[0-9A-Za-z\-_]{43}|EAAA[a-zA-Z0-9]{60})\b",
        "[REDACTED:SQUARE_TOKEN]",
        sanitized,
    )

    # Shopify Access Token
    sanitized = re.sub(
        r"\b(shpat_[a-fA-F0-9]{32}|shpca_[a-fA-F0-9]{32}|shppa_[a-fA-F0-9]{32})\b",
        "[REDACTED:SHOPIFY_TOKEN]",
        sanitized,
    )

    # npm Access Token
    sanitized = re.sub(
        r"\b(npm_[A-Za-z0-9]{36})\b",
        "[REDACTED:NPM_TOKEN]",
        sanitized,
    )

    # PyPI Upload Token
    sanitized = re.sub(
        r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000})\b",
        "[REDACTED:PYPI_TOKEN]",
        sanitized,
    )

    # New Relic Keys (NRAK, NRII, or hex license key)
    sanitized = re.sub(
        r"(?i)\b(NRAK-[A-Z0-9]{27}|NRII-[A-Za-z0-9_-]{32})\b",
        "[REDACTED:NEWRELIC_KEY]",
        sanitized,
    )
    sanitized = re.sub(
        r"""(?i)((?:newrelic|new_relic)[\-_]?(?:license|api)?[\-_]?key\s*[:=]\s*['"]?)[a-f0-9]{40}(['"]?)""",
        r"\1[REDACTED:NEWRELIC_KEY]\2",
        sanitized,
    )

    # Step 4: Connection Strings with Embedded Credentials
    # MongoDB URI
    sanitized = re.sub(
        r"""\b(mongodb(?:\+srv)?://(?:[^:\s]+:[^@\s]+@)[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s'"]*)?)\b""",
        "[REDACTED:MONGODB_URI]",
        sanitized,
    )

    # PostgreSQL URI
    sanitized = re.sub(
        r"""\b(postgres(?:ql)?://(?:[^:\s]+:[^@\s]+@)[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s'"]*)?)\b""",
        "[REDACTED:POSTGRES_URI]",
        sanitized,
    )

    # MySQL URI
    sanitized = re.sub(
        r"""\b(mysql://(?:[^:\s]+:[^@\s]+@)[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s'"]*)?)\b""",
        "[REDACTED:MYSQL_URI]",
        sanitized,
    )

    # Redis URI
    sanitized = re.sub(
        r"""\b(rediss?://(?:[^:\s]*:[^@\s]+@)[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s'"]*)?)\b""",
        "[REDACTED:REDIS_URI]",
        sanitized,
    )

    # AMQP / RabbitMQ URI
    sanitized = re.sub(
        r"""\b(amqps?://(?:[^:\s]+:[^@\s]+@)[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s'"]*)?)\b""",
        "[REDACTED:AMQP_URI]",
        sanitized,
    )

    # Basic Auth in URL
    sanitized = re.sub(
        r"""(?i)(https?://(?![^:\s]+:[^@\s]+@(?:localhost|127\.0\.0\.1)))(?:[a-zA-Z0-9_\-\.%]+):(?:[a-zA-Z0-9_\-\.%]+)@""",
        r"\1[REDACTED:BASIC_AUTH]@",
        sanitized,
    )

    # Basic Auth in Header
    sanitized = re.sub(
        r"""(?i)(\bAuthorization\s*:\s*Basic\s+)[A-Za-z0-9+/=]{16,}""",
        r"\1[REDACTED:BASIC_AUTH]",
        sanitized,
    )

    # Bearer Token in Header
    sanitized = re.sub(
        r"""(?i)(\bBearer\s+['"]?)(?!\[REDACTED:)[A-Za-z0-9_\-\.+=]{20,}(['"]?)""",
        r"\1[REDACTED:BEARER_TOKEN]\2",
        sanitized,
    )

    # GCP Service Account Private Key ID
    sanitized = re.sub(
        r"""("private_key_id"\s*:\s*")[a-f0-9]{40}(")""",
        r"\1[REDACTED:GCP_SERVICE_ACCOUNT]\2",
        sanitized,
    )

    # Step 5: Assignment-based Secrets
    # AWS Secret Access Key assignment
    sanitized = re.sub(
        r"""(?i)((?:aws_secret_access_key|aws_secret_key|aws_secret)\s*[:=]\s*['"]?)[A-Za-z0-9/+=]{40}(['"]?)""",
        r"\1[REDACTED:AWS_SECRET]\2",
        sanitized,
    )

    # Heroku API Key
    sanitized = re.sub(
        r"""(?i)(heroku[a-z0-9_\-\.]*\s*[:=]\s*['"]?)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(['"]?)""",
        r"\1[REDACTED:HEROKU_KEY]\2",
        sanitized,
    )

    # Datadog API/App Key
    sanitized = re.sub(
        r"""(?i)((?:datadog|dd)[\-_]?(?:api|app)[\-_]?key\s*[:=]\s*['"]?)[a-f0-9]{32,40}(['"]?)""",
        r"\1[REDACTED:DATADOG_KEY]\2",
        sanitized,
    )

    # Hardcoded Temporary Credentials
    def redact_temp_match(m: re.Match) -> str:
        prefix = m.group(1)
        val = m.group(2)
        suffix = m.group(3)
        if is_benign_generic_value(val) or val.startswith("[REDACTED:"):
            return m.group(0)
        return f"{prefix}[REDACTED:TEMP_CREDENTIAL]{suffix}"

    sanitized = re.sub(
        r"""(?i)((?:temp_password|temporary_password|test_credential|staging_token|mock_secret)\s*[:=]\s*['"])((?!\[REDACTED:)[^'"\r\n]{8,64})(['"])""",
        redact_temp_match,
        sanitized,
    )

    # Step 6: Generic Credential Catch-All (with Negative Lookahead Protection)
    def redact_generic_match(m: re.Match) -> str:
        prefix = m.group(1)
        val = m.group(2)
        suffix = m.group(3)
        if is_benign_generic_value(val) or val.startswith("[REDACTED:"):
            return m.group(0)
        return f"{prefix}[REDACTED:GENERIC_CREDENTIAL]{suffix}"

    sanitized = re.sub(
        r"""(?i)((?:password|passwd|api_key|apikey|secret_key|client_secret|auth_token|access_token)\s*[:=]\s*['"])((?!\[REDACTED:)[^'"\r\n]{8,128})(['"])""",
        redact_generic_match,
        sanitized,
    )

    return sanitized
