"""
Git Security Sentinel - Cloud Provider Keys Detection Rules.
Covers AWS, Stripe, Twilio, SendGrid, Mailgun, Mailchimp, Square, Shopify, Heroku, Datadog, New Relic.
"""

import re
from typing import List

from git_security_sentinel.core.models import Rule

CLOUD_RULES: List[Rule] = [
    Rule(
        rule_id="secret.aws_access_key",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
        message="Potential AWS Access Key ID detected.",
        recommendation="Never hardcode AWS keys. Use environment variables (AWS_ACCESS_KEY_ID), IAM roles, or AWS Secrets Manager.",
    ),
    Rule(
        rule_id="secret.aws_secret_key",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(
            r"""(?i)(?:aws_secret_access_key|aws_secret_key|aws_secret)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"""
        ),
        message="Potential AWS Secret Access Key assignment detected.",
        recommendation="Rotate immediately if active. Use AWS IAM roles, AWS Secrets Manager, or vault solutions.",
    ),
    Rule(
        rule_id="secret.stripe_key",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99})\b"),
        message="Potential Stripe Secret or Restricted API Key detected.",
        recommendation="Never expose Stripe secret/restricted keys. Rotate key in Stripe dashboard and store in environment variables.",
    ),
    Rule(
        rule_id="secret.twilio_key",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(r"\b(AC[0-9a-fA-F]{32}|SK[0-9a-fA-F]{32})\b"),
        message="Potential Twilio Account SID or API Key detected.",
        recommendation="Never commit Twilio account credentials. Use environment variables (TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN).",
    ),
    Rule(
        rule_id="secret.sendgrid_key",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"),
        message="Potential SendGrid API Key detected.",
        recommendation="Rotate SendGrid API key immediately in SendGrid Console > Settings > API Keys.",
    ),
    Rule(
        rule_id="secret.mailgun_key",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(r"\b(key-[0-9a-zA-Z]{32})\b"),
        message="Potential Mailgun API Key detected.",
        recommendation="Rotate Mailgun API key in Mailgun Dashboard > Settings > API Security.",
    ),
    Rule(
        rule_id="secret.mailchimp_key",
        category="secrets",
        severity="high",
        confidence="high",
        pattern=re.compile(r"\b([0-9a-f]{32}-us[0-9]{1,2})\b"),
        message="Potential Mailchimp API Key detected.",
        recommendation="Revoke Mailchimp API key in Account & Billing > Extras > API keys.",
    ),
    Rule(
        rule_id="secret.square_token",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(
            r"\b(sq0atp-[0-9A-Za-z\-_]{22}|sq0csp-[0-9A-Za-z\-_]{43}|EAAA[a-zA-Z0-9]{60})\b"
        ),
        message="Potential Square Access Token or Secret detected.",
        recommendation="Revoke Square credentials in the Square Developer Dashboard.",
    ),
    Rule(
        rule_id="secret.shopify_token",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(
            r"\b(shpat_[a-fA-F0-9]{32}|shpca_[a-fA-F0-9]{32}|shppa_[a-fA-F0-9]{32})\b"
        ),
        message="Potential Shopify Access Token detected.",
        recommendation="Rotate Shopify app credentials in Shopify Partner Dashboard or Store Admin.",
    ),
    Rule(
        rule_id="secret.heroku_key",
        category="secrets",
        severity="critical",
        confidence="medium",
        pattern=re.compile(
            r"""(?i)(?:heroku[a-z0-9_\-\.]*)\s*[:=]\s*['"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['"]?"""
        ),
        message="Potential Heroku API Key detected.",
        recommendation="Regenerate Heroku API token via Heroku CLI (heroku authorizations:create) or Account Settings.",
    ),
    Rule(
        rule_id="secret.datadog_key",
        category="secrets",
        severity="critical",
        confidence="medium",
        pattern=re.compile(
            r"""(?i)(?:datadog|dd)[\-_]?(?:api|app)[\-_]?key\s*[:=]\s*['"]?([a-f0-9]{32,40})['"]?"""
        ),
        message="Potential Datadog API or Application Key detected.",
        recommendation="Revoke and rotate Datadog API keys in Organization Settings > API Keys.",
    ),
    Rule(
        rule_id="secret.newrelic_key",
        category="secrets",
        severity="critical",
        confidence="high",
        pattern=re.compile(
            r"""(?i)\b(NRAK-[A-Z0-9]{27}|NRII-[A-Za-z0-9_-]{32})\b|(?:newrelic|new_relic)[\-_]?(?:license|api)?[\-_]?key\s*[:=]\s*['"]?([a-f0-9]{40})['"]?"""
        ),
        message="Potential New Relic Ingest or API Key detected.",
        recommendation="Rotate New Relic API/license keys in New Relic API Keys UI.",
    ),
]
