"""
Git Security Sentinel - Authentication Tokens Detection Rules.
Covers GitHub PAT/OAuth, Slack, JWT, Bearer tokens, Basic Auth, npm, PyPI, Discord bot, Telegram bot.
"""

import re
from typing import List

from git_security_sentinel.core.models import Rule

AUTH_RULES: List[Rule] = [
    Rule(
        rule_id="secret.github_token",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(
            r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b"
        ),
        message="Potential GitHub personal access or OAuth token detected.",
        recommendation="Revoke and rotate the GitHub token immediately in GitHub Settings > Developer settings.",
    ),
    Rule(
        rule_id="secret.slack_token",
        category="secrets",
        severity="high",
        confidence="high",
        pattern=re.compile(
            r"\b(xox[baprs]-[0-9A-Za-z]{10,48}-[0-9A-Za-z]{10,48}-[0-9A-Za-z]{24,48}|xox[baprs]-[0-9A-Za-z]{10,48})\b"
        ),
        message="Potential Slack API bot or user token detected.",
        recommendation="Revoke the Slack token via the Slack API admin dashboard and use secure secret injection.",
    ),
    Rule(
        rule_id="secret.jwt_token",
        category="secrets",
        severity="high",
        confidence="high",
        pattern=re.compile(
            r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,})\b"
        ),
        message="Potential hardcoded JSON Web Token (JWT) detected.",
        recommendation="Never hardcode JWT tokens. Issue tokens dynamically and verify signature at runtime.",
    ),
    Rule(
        rule_id="secret.bearer_token",
        category="secrets",
        severity="high",
        confidence="medium",
        pattern=re.compile(r"""(?i)\bBearer\s+['"]?([A-Za-z0-9_\-\.+=]{20,})['"]?"""),
        message="Potential hardcoded Bearer token detected in HTTP authorization header or configuration.",
        recommendation="Inject bearer tokens via secure runtime environment variables or vault secrets.",
    ),
    Rule(
        rule_id="secret.basic_auth",
        category="secrets",
        severity="high",
        confidence="high",
        pattern=re.compile(
            r"""(?i)https?://(?![^:\s]+:[^@\s]+@(?:localhost|127\.0\.0\.1))([a-zA-Z0-9_\-\.%]+):([a-zA-Z0-9_\-\.%]+)@|\bAuthorization\s*:\s*Basic\s+([A-Za-z0-9+/=]{16,})"""
        ),
        message="Cleartext Basic Authentication credentials embedded in URL or header detected.",
        recommendation="Remove cleartext credentials from URLs and headers. Use credential helpers or secret injection.",
    ),
    Rule(
        rule_id="secret.npm_token",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
        message="Potential npm access token detected.",
        recommendation="Revoke npm access token immediately with 'npm token revoke' and regenerate in npmjs.com.",
    ),
    Rule(
        rule_id="secret.pypi_token",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000})\b"),
        message="Potential PyPI API upload token detected.",
        recommendation="Revoke PyPI token immediately in PyPI Account Settings > API tokens.",
    ),
    Rule(
        rule_id="secret.discord_bot_token",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(
            r"\b([MN][A-Za-z\d]{23,26}\.[A-Za-z\d\-_]{6}\.[A-Za-z\d\-_]{27,38})\b"
        ),
        message="Potential Discord Bot authentication token detected.",
        recommendation="Reset Discord bot token immediately in the Discord Developer Portal.",
    ),
    Rule(
        rule_id="secret.telegram_bot_token",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(r"\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b"),
        message="Potential Telegram Bot API HTTP token detected.",
        recommendation="Revoke Telegram bot token via BotFather with /revoke.",
    ),
]
