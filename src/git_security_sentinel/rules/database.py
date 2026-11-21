"""
Git Security Sentinel - Database and Connection Strings Detection Rules.
Covers MongoDB, PostgreSQL, MySQL, Redis, AMQP, Firebase config, GCP Service Account.
"""

import re
from typing import List

from git_security_sentinel.core.models import Rule

DATABASE_RULES: List[Rule] = [
    Rule(
        rule_id="secret.mongodb_uri",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(
            r"""\b(mongodb(?:\+srv)?://(?:[^:\s]+:[^@\s]+@)[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s'"]*)?)\b"""
        ),
        message="MongoDB connection URI with embedded credentials detected.",
        recommendation="Use environment variables for database credentials and connection strings.",
    ),
    Rule(
        rule_id="secret.postgres_uri",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(
            r"""\b(postgres(?:ql)?://(?:[^:\s]+:[^@\s]+@)[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s'"]*)?)\b"""
        ),
        message="PostgreSQL connection URI with embedded credentials detected.",
        recommendation="Store PostgreSQL credentials in environment variables or use IAM database authentication.",
    ),
    Rule(
        rule_id="secret.mysql_uri",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(
            r"""\b(mysql://(?:[^:\s]+:[^@\s]+@)[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s'"]*)?)\b"""
        ),
        message="MySQL connection URI with embedded credentials detected.",
        recommendation="Store MySQL credentials in environment variables or vault secret storage.",
    ),
    Rule(
        rule_id="secret.redis_uri",
        category="secrets",
        severity="high",
        confidence="high",
        pattern=re.compile(
            r"""\b(rediss?://(?:[^:\s]*:[^@\s]+@)[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s'"]*)?)\b"""
        ),
        message="Redis connection URI with embedded password/auth token detected.",
        recommendation="Load Redis password from environment variable REDIS_PASSWORD at runtime.",
    ),
    Rule(
        rule_id="secret.amqp_uri",
        category="secrets",
        severity="high",
        confidence="high",
        pattern=re.compile(
            r"""\b(amqps?://(?:[^:\s]+:[^@\s]+@)[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s'"]*)?)\b"""
        ),
        message="AMQP/RabbitMQ connection URI with embedded credentials detected.",
        recommendation="Store message broker credentials in environment variables or configuration files outside git.",
    ),
    Rule(
        rule_id="secret.firebase_key",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(r"\b(AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140})\b"),
        message="Firebase Cloud Messaging (FCM) legacy server key detected.",
        recommendation="Migrate from legacy FCM server key to HTTP v1 API using Google Cloud service account credentials.",
    ),
    Rule(
        rule_id="secret.gcp_service_account",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(
            r"""(?i)"type"\s*:\s*"service_account"|"private_key_id"\s*:\s*"[a-f0-9]{40}"|[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com"""
        ),
        message="GCP Service Account private key or identity definition detected.",
        recommendation="Delete leaked service account key in GCP IAM & Admin > Service Accounts > Keys and recreate.",
    ),
]
