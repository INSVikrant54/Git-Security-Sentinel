# Detection Rules Reference Catalog

Git Security Sentinel pairs a deterministic regex-based static scanner with an optional local AI contextual reviewer. This document catalogs all 47 static rules implemented across the 6 detection categories, explaining their matching logic, expected false positives, remediation recommendations, and known limitations.

---

## Important Security Disclaimer

> **Limitations of Static Analysis**  
> Static pattern matching cannot determine whether an exposed credential is valid, active, or exploitable in an external system. Similarly, regex-based analysis cannot guarantee the detection of all potential credentials (e.g., custom token formats or non-standard variable names). Static rules provide a fast, deterministic first line of defense; they do not replace comprehensive secret management and defense-in-depth security practices.

---

## Severity Taxonomy

| Severity | Definition | Default Action |
|---|---|---|
| **`critical`** | Immediate credential compromise risk (AWS keys, private keys, database URIs, payment tokens). | Halts CI pipeline / triggers exit code `1`. |
| **`high`** | High-probability credential or token leak (Slack tokens, JWTs, dangerous deserialization). | Halts CI pipeline / triggers exit code `1`. |
| **`medium`** | Dangerous coding patterns (e.g., dynamic code execution with `eval()` / `exec()`, wildcard CORS). | Informational warning; fails if threshold is set to `medium`. |
| **`low`** | Configuration hygiene and security debt warnings (e.g., hardcoded loopback URLs, security TODOs). | Informational warning; fails if threshold is set to `low`. |

---

## Category 1: Cloud Provider Keys (12 Rules)

### 1. `secret.aws_access_key`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b`
- **Redaction**: `[REDACTED:AWS_KEY_ID]`
- **Description**: Standard 20-character AWS access key identifier used by IAM users and temporary STS sessions.
- **Example True Positive**: `AWS_ACCESS_KEY_ID = "AKIA<16 uppercase alphanumerics>"`
- **Expected False Positives**: Extremely low. Coincidental 20-character uppercase strings starting with `AKIA`/`ASIA` are rare in source code.
- **Remediation**: Immediately revoke the key in AWS IAM Console. Inject credentials via `AWS_ACCESS_KEY_ID` environment variables or IAM roles.

### 2. `secret.aws_secret_key`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `(?i)(?:aws_secret_access_key|aws_secret_key|aws_secret)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`
- **Redaction**: `[REDACTED:AWS_SECRET]`
- **Description**: 40-character Base64 secret key paired with AWS Access Key ID.
- **Example True Positive**: `aws_secret_access_key = "<40-character AWS secret access key>"`
- **Expected False Positives**: Benign placeholders such as `"your_key_here"` are suppressed.
- **Remediation**: Rotate immediately via AWS IAM. Use AWS Secrets Manager or Parameter Store.

### 3. `secret.stripe_key`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99})\b`
- **Redaction**: `[REDACTED:STRIPE_KEY]`
- **Description**: Stripe API secret keys (`sk_live_`, `sk_test_`) and restricted keys (`rk_live_`, `rk_test_`) granting direct access to payment operations.
- **Example True Positive**: `stripe_secret = "sk_live_<24-99 alphanumerics>"`
- **Expected False Positives**: Variable names like `sk_live_mode = True` are excluded by word boundaries and min length (24 chars).
- **Remediation**: Rotate immediately in the Stripe Developers Dashboard > API keys. Store in environment variables.

### 4. `secret.twilio_key`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b(AC[0-9a-fA-F]{32}|SK[0-9a-fA-F]{32})\b`
- **Redaction**: `[REDACTED:TWILIO_KEY]`
- **Description**: Twilio Account SID (`AC...`) or API Key (`SK...`) granting access to SMS and Voice communications.
- **Example True Positive**: `TWILIO_SID = "AC<32 hex characters>"`
- **Expected False Positives**: Constants like `ACTION_CODE = "AC_RESET_TRIGGER"` are excluded by hexadecimal format and 34-character length constraints.
- **Remediation**: Revoke and regenerate the API Key / Auth Token in the Twilio Console. Use `TWILIO_ACCOUNT_SID` and `TWILIO_AUTH_TOKEN` environment variables.

### 5. `secret.sendgrid_key`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b`
- **Redaction**: `[REDACTED:SENDGRID_KEY]`
- **Description**: SendGrid official API key format starting with `SG.` followed by 22 characters, a dot, and 43 characters.
- **Example True Positive**: `SENDGRID_KEY = "SG.<22 chars>.<43 chars>"`
- **Expected False Positives**: Non-token text starting with `SG.` with mismatched segment lengths is ignored.
- **Remediation**: Invalidate key in SendGrid Dashboard > Settings > API Keys and generate a replacement with minimal scopes.

### 6. `secret.mailgun_key`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b(key-[0-9a-zA-Z]{32})\b`
- **Redaction**: `[REDACTED:MAILGUN_KEY]`
- **Description**: Mailgun primary API key starting with `key-` followed by 32 alphanumeric characters.
- **Example True Positive**: `MG_KEY = "key-<32 alphanumerics>"`
- **Expected False Positives**: Documentation strings like `key-sample_placeholder` are ignored due to character/length mismatch.
- **Remediation**: Rotate Mailgun API key in Mailgun Dashboard > Settings > API Security.

### 7. `secret.mailchimp_key`
- **Category**: `secrets` | **Severity**: `high` | **Confidence**: `high`
- **Pattern**: `\b([0-9a-f]{32}-us[0-9]{1,2})\b`
- **Redaction**: `[REDACTED:MAILCHIMP_KEY]`
- **Description**: Mailchimp API key composed of a 32-character MD5 hash followed by a datacenter suffix (e.g. `-us19`).
- **Example True Positive**: `MC_KEY = "<32 hex>-us<datacenter>"`
- **Expected False Positives**: Standard MD5 hashes or UUIDs lacking the `-usXX` suffix are not matched.
- **Remediation**: Revoke the API key in Mailchimp Profile > Extras > API keys.

### 8. `secret.square_token`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b(sq0atp-[0-9A-Za-z\-_]{22}|sq0csp-[0-9A-Za-z\-_]{43}|EAAA[a-zA-Z0-9]{60})\b`
- **Redaction**: `[REDACTED:SQUARE_TOKEN]`
- **Description**: Square access tokens (`sq0atp-`), client secrets (`sq0csp-`), or legacy production tokens (`EAAA`).
- **Example True Positive**: `SQ_TOKEN = "sq0atp-<22 alphanumerics>"`
- **Expected False Positives**: Short identifiers or test prefixes with incorrect length are excluded.
- **Remediation**: Revoke Square credentials in the Square Developer Dashboard.

### 9. `secret.shopify_token`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b(shpat_[a-fA-F0-9]{32}|shpca_[a-fA-F0-9]{32}|shppa_[a-fA-F0-9]{32})\b`
- **Redaction**: `[REDACTED:SHOPIFY_TOKEN]`
- **Description**: Shopify Admin API tokens (`shpat_`), Custom app secrets (`shpca_`), or Partner tokens (`shppa_`).
- **Example True Positive**: `SHOPIFY = "shpat_<32 alphanumerics>"`
- **Expected False Positives**: Truncated prefixes like `shpat_short` are ignored.
- **Remediation**: Rotate Shopify app credentials in Shopify Partner Dashboard or Store Admin.

### 10. `secret.heroku_key`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `medium`
- **Pattern**: `(?i)(?:heroku[a-z0-9_\-\.]*)\s*[:=]\s*['"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['"]?`
- **Redaction**: `[REDACTED:HEROKU_KEY]`
- **Description**: Heroku API token represented as a 36-character UUID within a Heroku variable context.
- **Example True Positive**: `heroku_api_key = "<Heroku UUID key>"`
- **Expected False Positives**: Generic UUIDs (e.g. `generic_uuid = "..."`) are not matched because the context keyword `heroku` is required.
- **Remediation**: Regenerate Heroku API token via Heroku CLI (`heroku authorizations:create`) or Account Settings.

### 11. `secret.datadog_key`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `medium`
- **Pattern**: `(?i)(?:datadog|dd)[\-_]?(?:api|app)[\-_]?key\s*[:=]\s*['"]?([a-f0-9]{32,40})['"]?`
- **Redaction**: `[REDACTED:DATADOG_KEY]`
- **Description**: Datadog 32-character API key or 40-character application key.
- **Example True Positive**: `datadog_api_key = "<32-character Datadog key>"`
- **Expected False Positives**: Placeholders like `datadog_api_key = "change_me"` are suppressed via benign check and character validation.
- **Remediation**: Revoke and rotate Datadog API keys in Organization Settings > API Keys.

### 12. `secret.newrelic_key`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `(?i)\b(NRAK-[A-Z0-9]{27}|NRII-[A-Za-z0-9_-]{32})\b|(?:newrelic|new_relic)[\-_]?(?:license|api)?[\-_]?key\s*[:=]\s*['"]?([a-f0-9]{40})['"]?`
- **Redaction**: `[REDACTED:NEWRELIC_KEY]`
- **Description**: New Relic User Keys (`NRAK-`), Ingest Keys (`NRII-`), or legacy 40-character license keys.
- **Example True Positive**: `NEW_RELIC_LICENSE_KEY = "NRAK-<license key>"`
- **Expected False Positives**: Variable names like `nrak_mode = True` are ignored.
- **Remediation**: Rotate New Relic API/license keys in New Relic API Keys UI.

---

## Category 2: Auth Tokens (9 Rules)

### 13. `secret.github_token`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b`
- **Redaction**: `[REDACTED:GITHUB_TOKEN]`
- **Description**: Modern GitHub Personal Access Tokens and OAuth tokens utilizing official prefixes.
- **Example True Positive**: `gh_token = "ghp_<36+ alphanumerics>"`
- **Expected False Positives**: Placeholders or truncated tokens like `ghp_123` are rejected.
- **Remediation**: Revoke and rotate immediately in GitHub Settings > Developer settings > Personal access tokens.

### 14. `secret.slack_token`
- **Category**: `secrets` | **Severity**: `high` | **Confidence**: `high`
- **Pattern**: `\b(xox[baprs]-[0-9A-Za-z]{10,48}-[0-9A-Za-z]{10,48}-[0-9A-Za-z]{24,48}|xox[baprs]-[0-9A-Za-z]{10,48})\b`
- **Redaction**: `[REDACTED:SLACK_TOKEN]`
- **Description**: Slack API Bot, User, or Workspace token.
- **Example True Positive**: `token = "xoxb-<team>-<channel>-<secret>"`
- **Expected False Positives**: Words starting with `xox` lacking standard dash-delimited numeric segments are ignored.
- **Remediation**: Revoke the Slack token via the Slack API admin dashboard and use environment variable injection.

### 15. `secret.jwt_token`
- **Category**: `secrets` | **Severity**: `high` | **Confidence**: `high`
- **Pattern**: `\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,})\b`
- **Redaction**: `[REDACTED:JWT_TOKEN]`
- **Description**: Hardcoded JSON Web Token containing signed claims (`header.payload.signature`).
- **Example True Positive**: `token = "<header>.<payload>.<signature>"`
- **Expected False Positives**: Three-part hostnames like `host = "api.v1.internal.service.cluster"` do not match because header and payload must begin with `eyJ`.
- **Remediation**: Issue JWT tokens dynamically at runtime and load secrets used for signing from secure secret stores.

### 16. `secret.bearer_token`
- **Category**: `secrets` | **Severity**: `high` | **Confidence**: `medium`
- **Pattern**: `(?i)\bBearer\s+['"]?([A-Za-z0-9_\-\.+=]{20,})['"]?`
- **Redaction**: `[REDACTED:BEARER_TOKEN]`
- **Description**: Hardcoded HTTP Bearer authorization token in headers or config dictionaries.
- **Example True Positive**: `headers = {"Authorization": "Bearer ya29.<OAuth token>"}`
- **Expected False Positives**: Template placeholders like `"Bearer ${AUTH_TOKEN}"` are ignored.
- **Remediation**: Inject bearer tokens via secure runtime environment variables or vault secrets.

### 17. `secret.basic_auth`
- **Category**: `secrets` | **Severity**: `high` | **Confidence**: `high`
- **Pattern**: `(?i)https?://(?![^:\s]+:[^@\s]+@(?:localhost|127\.0\.0\.1))([a-zA-Z0-9_\-\.%]+):([a-zA-Z0-9_\-\.%]+)@|\bAuthorization\s*:\s*Basic\s+([A-Za-z0-9+/=]{16,})`
- **Redaction**: `[REDACTED:BASIC_AUTH]`
- **Description**: Cleartext credentials embedded in remote URLs or RFC 7617 Basic Authentication headers.
- **Example True Positive**: `remote = "https://admin:<password>@github.com/repo.git"`
- **Expected False Positives**: Local development URLs like `http://user:pass@localhost:8080/api` are deliberately ignored via negative lookahead.
- **Remediation**: Remove embedded credentials from git remotes and configurations; use credential helpers or netrc.

### 18. `secret.npm_token`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b(npm_[A-Za-z0-9]{36})\b`
- **Redaction**: `[REDACTED:NPM_TOKEN]`
- **Description**: npm automation or publish access token starting with `npm_`.
- **Example True Positive**: `//registry.npmjs.org/:_authToken=npm_<token>`
- **Expected False Positives**: Package names like `"name": "npm_helper_package"` are ignored due to length mismatch.
- **Remediation**: Revoke the token immediately with `npm token revoke <token>` and regenerate on npmjs.com.

### 19. `secret.pypi_token`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000})\b`
- **Redaction**: `[REDACTED:PYPI_TOKEN]`
- **Description**: PyPI upload API token beginning with `pypi-AgEIcHlwaS5vcmc`.
- **Example True Positive**: `export TWINE_PASSWORD="pypi-<token>"`
- **Expected False Positives**: URLs or documentation referencing `https://pypi.org/project/sentinel` are ignored.
- **Remediation**: Revoke PyPI token immediately in PyPI Account Settings > API tokens. Use Trusted Publishing (OIDC).

### 20. `secret.discord_bot_token`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b([MN][A-Za-z\d]{23,26}\.[A-Za-z\d\-_]{6}\.[A-Za-z\d\-_]{27,38})\b`
- **Redaction**: `[REDACTED:DISCORD_TOKEN]`
- **Description**: Discord bot authentication token (User ID, timestamp, HMAC secret).
- **Example True Positive**: `BOT_TOKEN = "<discord id>.<hmac>.<nonce>"`
- **Expected False Positives**: Dotted version strings like `version = "1.2.3.4.5"` are excluded by segment lengths.
- **Remediation**: Reset Discord bot token immediately in the Discord Developer Portal.

### 21. `secret.telegram_bot_token`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b`
- **Redaction**: `[REDACTED:TELEGRAM_TOKEN]`
- **Description**: Telegram Bot API HTTP authentication token.
- **Example True Positive**: `TELEGRAM_KEY = "<bot id>:<telegram token>"`
- **Expected False Positives**: Port mappings like `port_mapping = "8080:abcdef"` are ignored due to character count mismatch.
- **Remediation**: Revoke Telegram bot token via BotFather with `/revoke`.

---

## Category 3: Database & Connection Strings (7 Rules)

### 22. `secret.mongodb_uri`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b(mongodb(?:\+srv)?://(?:[^:\s]+:[^@\s]+@)[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s'"]*)?)\b`
- **Redaction**: `[REDACTED:MONGODB_URI]`
- **Description**: MongoDB connection URI containing embedded credentials.
- **Example True Positive**: `URI = "mongodb+srv://admin:<password>@cluster0.abcde.mongodb.net/prod"`
- **Expected False Positives**: URIs without credentials like `mongodb://localhost:27017/dev` are not matched.
- **Remediation**: Extract credentials into `MONGODB_URI` environment variable loaded at runtime.

### 23. `secret.postgres_uri`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b(postgres(?:ql)?://(?:[^:\s]+:[^@\s]+@)[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s'"]*)?)\b`
- **Redaction**: `[REDACTED:POSTGRES_URI]`
- **Description**: PostgreSQL connection URI with cleartext username and password.
- **Example True Positive**: `DB = "postgresql://postgres:<password>@db.example.com:5432/main"`
- **Expected False Positives**: URIs without credentials like `postgresql://localhost:5432/test` are not matched.
- **Remediation**: Store credentials in `DATABASE_URL` environment variable or use IAM database authentication.

### 24. `secret.mysql_uri`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b(mysql://(?:[^:\s]+:[^@\s]+@)[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s'"]*)?)\b`
- **Redaction**: `[REDACTED:MYSQL_URI]`
- **Description**: MySQL connection URI containing embedded credentials.
- **Example True Positive**: `CONN = "mysql://root:<password>@db.example.org:3306/production"`
- **Expected False Positives**: `mysql://localhost/development` without credentials is not matched.
- **Remediation**: Store MySQL credentials in environment variables or vault secrets.

### 25. `secret.redis_uri`
- **Category**: `secrets` | **Severity**: `high` | **Confidence**: `high`
- **Pattern**: `\b(rediss?://(?:[^:\s]*:[^@\s]+@)[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s'"]*)?)\b`
- **Redaction**: `[REDACTED:REDIS_URI]`
- **Description**: Redis URI with authentication token or password.
- **Example True Positive**: `REDIS = "rediss://:<auth token>@cache.amazonaws.com:6380/0"`
- **Expected False Positives**: `redis://localhost:6379` without authentication is ignored.
- **Remediation**: Load Redis password from environment variable `REDIS_PASSWORD` at runtime.

### 26. `secret.amqp_uri`
- **Category**: `secrets` | **Severity**: `high` | **Confidence**: `high`
- **Pattern**: `\b(amqps?://(?:[^:\s]+:[^@\s]+@)[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s'"]*)?)\b`
- **Redaction**: `[REDACTED:AMQP_URI]`
- **Description**: AMQP URI containing embedded credentials for message brokers.
- **Example True Positive**: `BROKER = "amqp://guest:<password>@rabbit.cluster.local:5672//"`
- **Expected False Positives**: `amqp://localhost:5672` without credentials is not matched.
- **Remediation**: Store message broker credentials in environment variables outside git.

### 27. `secret.firebase_key`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b(AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140})\b`
- **Redaction**: `[REDACTED:FIREBASE_KEY]`
- **Description**: Legacy FCM server key granting administrative push notification access.
- **Example True Positive**: `FCM_SERVER_KEY = "AAAA1234567:<140-char-key>"`
- **Expected False Positives**: Client-side Firebase configuration like `apiKey = "AIzaSyD-placeholder"` is ignored.
- **Remediation**: Migrate from legacy FCM server keys to Firebase HTTP v1 API using Google Cloud service account credentials.

### 28. `secret.gcp_service_account`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `(?i)"type"\s*:\s*"service_account"|"private_key_id"\s*:\s*"[a-f0-9]{40}"|[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com`
- **Redaction**: `[REDACTED:GCP_SERVICE_ACCOUNT]`
- **Description**: GCP Service Account credentials JSON definition.
- **Example True Positive**: `{"type": "service_account", "private_key_id": "4a7b01234567890abcdef01234567890abcdef01"}`
- **Expected False Positives**: Authorized user credentials (`{"type": "authorized_user"}`) are excluded.
- **Remediation**: Delete leaked service account key in GCP IAM & Admin > Service Accounts > Keys and recreate.

---

## Category 4: Sensitive Committed Files (4 Rules)

### 29. `file.env_file`
- **Category**: `sensitive_files` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `(?i)(?:^|/)\.env(?:\.(?!example|template|sample|dist)[a-zA-Z0-9_\-]+)?$`
- **Description**: Committing `.env` configuration files exposes environment secrets and database credentials.
- **Example True Positive**: Adding `.env`, `.env.production`, `.env.local`.
- **Expected False Positives**: `.env.example`, `.env.template`, `.env.sample` are permitted via negative lookahead.
- **Remediation**: Add `.env*` to `.gitignore` and remove tracked files from version control with `git rm --cached .env`.

### 30. `file.ssh_rsa_key`
- **Category**: `sensitive_files` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `(?i)(?:^|/)id_rsa$`
- **Description**: Committing an `id_rsa` private key file directly compromises host/server authentication.
- **Example True Positive**: Adding `id_rsa`.
- **Expected False Positives**: `id_rsa.pub` (public key) is permitted via end-of-line anchor `$`.
- **Remediation**: Remove `id_rsa` from git history immediately and regenerate SSH keypairs.

### 31. `file.ssh_ed25519_key`
- **Category**: `sensitive_files` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `(?i)(?:^|/)id_ed25519$`
- **Description**: Committing an `id_ed25519` private key file.
- **Example True Positive**: Adding `id_ed25519`.
- **Expected False Positives**: `id_ed25519.pub` (public key) is permitted via end-of-line anchor `$`.
- **Remediation**: Remove `id_ed25519` from git history immediately and regenerate SSH keypairs.

### 32. `file.pem_key`
- **Category**: `sensitive_files` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `(?i)(?:^|/).+\.(?:pem|pkcs12|pfx|p12|key)$`
- **Description**: Files ending in `.pem`, `.key`, `.p12`, or `.pfx` typically contain raw private keys.
- **Example True Positive**: Adding `server.pem`, `tls.key`.
- **Expected False Positives**: Public certificates (`public.crt`, `cert.cer`) are not matched.
- **Remediation**: Store certificates and keys in a secure secret store or PKI infrastructure outside version control.

---

## Category 5: Insecure Code Patterns & CWEs (11 Rules)

### 33. `insecure_code.shell_injection`
- **Category**: `insecure_code` | **Severity**: `high` | **Confidence**: `medium`
- **Pattern**: `\b(?:subprocess\.(?:Popen|run|call|check_call|check_output)\s*\([^)]*shell\s*=\s*(?:True|1)|os\.system\s*\([^)]*\)|os\.popen\s*\([^)]*\))`
- **Description**: Invoking system shells with unsanitized arguments leads to Command Injection (CWE-78).
- **Example True Positive**: `subprocess.run(f"cat {user_file}", shell=True)`
- **Expected False Positives**: `subprocess.run(["cat", "safe_file"], shell=False)` is permitted.
- **Remediation**: Avoid `shell=True`. Pass arguments as a list of strings and sanitize inputs.

### 34. `insecure_code.pickle_deserialization`
- **Category**: `insecure_code` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `\b(?:pickle|_pickle|cPickle)\.(?:loads?|Unpickler)\s*\(`
- **Description**: Python `pickle` can execute arbitrary bytecode during deserialization (CWE-502).
- **Example True Positive**: `data = pickle.loads(untrusted_payload)`
- **Expected False Positives**: Serialization operations like `pickle.dump(data, stream)` are permitted.
- **Remediation**: Never deserialize untrusted data with pickle. Use `json`, `msgpack`, or `protobuf`.

### 35. `insecure_code.unsafe_yaml`
- **Category**: `insecure_code` | **Severity**: `high` | **Confidence**: `high`
- **Pattern**: `\byaml\.(?:load|load_all)\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader\b)|\byaml\.unsafe_load\s*\(`
- **Description**: Calling `yaml.load()` without specifying `Loader=SafeLoader` enables code execution (CWE-502).
- **Example True Positive**: `config = yaml.load(raw_yaml_string)`
- **Expected False Positives**: `config = yaml.safe_load(raw_yaml_string)` is permitted.
- **Remediation**: Use `yaml.safe_load()` or explicitly specify `Loader=yaml.SafeLoader`.

### 36. `insecure_code.sql_concatenation`
- **Category**: `insecure_code` | **Severity**: `high` | **Confidence**: `medium`
- **Pattern**: `(?i)(?:execute|cursor\.execute|session\.execute)\s*\(\s*(?:f['"]|['"].*?%|['"].*?\+\s*|[a-z0-9_]+\s*\+\s*['"]).*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|WHERE)\b`
- **Description**: Constructing SQL queries via string concatenation, `%` formatting, or f-strings leads to SQL Injection (CWE-89).
- **Example True Positive**: `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
- **Expected False Positives**: Parameterized queries like `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))` are permitted.
- **Remediation**: Use parameterized queries or an ORM.

### 37. `insecure_code.xxe_injection`
- **Category**: `insecure_code` | **Severity**: `high` | **Confidence**: `medium`
- **Pattern**: `(?i)\b(?:xml\.etree|xml\.sax|lxml\.etree|xml\.dom\.minidom)\b.*(?:parse|fromstring)\s*\(|resolve_entities\s*=\s*True|XMLParser\s*\([^)]*resolve_entities\s*=\s*True`
- **Description**: Parsing XML without disabling entity resolution exposes servers to SSRF and file disclosure (CWE-611).
- **Example True Positive**: `doc = lxml.etree.parse(xml_in, parser=XMLParser(resolve_entities=True))`
- **Expected False Positives**: Safe parsers like `defusedxml.lxml.parse(xml_in)` are permitted.
- **Remediation**: Use `defusedxml` or disable external entity resolution (`resolve_entities=False`).

### 38. `insecure_code.temp_credential`
- **Category**: `insecure_code` | **Severity**: `high` | **Confidence**: `medium`
- **Pattern**: `(?i)(?:temp_password|temporary_password|test_credential|staging_token|mock_secret)\s*[:=]\s*['"]([^'"\r\n]{8,64})['"]`
- **Redaction**: `[REDACTED:TEMP_CREDENTIAL]`
- **Description**: Committing temporary or test passwords into non-test source files.
- **Example True Positive**: `temp_password = "StagingSecret12345!"`
- **Expected False Positives**: Placeholders like `temp_password = "change_me"` are filtered by benign value checks.
- **Remediation**: Inject temporary credentials via environment variables and keep secrets out of source code.

### 39. `insecure_code.debug_enabled`
- **Category**: `insecure_code` | **Severity**: `medium` | **Confidence**: `high`
- **Pattern**: `(?i)\b(?:DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|settings\.DEBUG\s*=\s*True)\b`
- **Description**: Enabling `DEBUG = True` in production leaks interactive debuggers, stack traces, and environment variables (CWE-215).
- **Example True Positive**: `DEBUG = True`
- **Expected False Positives**: `DEBUG = False` is permitted.
- **Remediation**: Ensure `DEBUG` is set to `False` in production environments.

### 40. `insecure_code.wildcard_cors`
- **Category**: `insecure_code` | **Severity**: `medium` | **Confidence**: `high`
- **Pattern**: `(?i)(?:Access-Control-Allow-Origin['"]?\s*[:=,]\s*['"]?\*['"]?|allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]|CORS\([^)]*origins\s*=\s*['"]\*['"])`
- **Description**: Allowing `*` origin for CORS on authenticated APIs allows malicious third-party origins to perform authenticated requests (CWE-942).
- **Example True Positive**: `res.setHeader("Access-Control-Allow-Origin", "*")`
- **Expected False Positives**: Specific origins like `res.setHeader("Access-Control-Allow-Origin", "https://app.corp.internal")` are permitted.
- **Remediation**: Explicitly specify trusted origin domains instead of wildcard `*` for CORS.

### 41. `insecure_code.unverified_ssl`
- **Category**: `insecure_code` | **Severity**: `high` | **Confidence**: `high`
- **Pattern**: `(?i)\b(?:verify\s*=\s*False|ssl\._create_unverified_context|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?|check_hostname\s*=\s*False)\b`
- **Description**: Disabling SSL verification exposes HTTPS traffic to Man-in-the-Middle (MITM) attacks (CWE-295).
- **Example True Positive**: `requests.get("https://example.com", verify=False)`
- **Expected False Positives**: `requests.get("https://example.com", verify=True)` is permitted.
- **Remediation**: Enable SSL/TLS certificate verification (`verify=True`).

### 42. `risk.eval_execution`
- **Category**: `insecure_code` | **Severity**: `medium` | **Confidence**: `medium`
- **Pattern**: `\b(?:eval|exec)\s*\((?!\s*['\"][^'\"]*['\"]\s*\))`
- **Description**: Evaluating dynamic expressions can execute arbitrary commands (CWE-95).
- **Example True Positive**: `result = eval(user_expression)`
- **Expected False Positives**: Constant literal expressions like `result = eval("constant_literal")` are permitted.
- **Remediation**: Avoid `eval()`/`exec()`. Use `ast.literal_eval()` or safe parser alternatives.

### 43. `risk.localhost_endpoint`
- **Category**: `configuration` | **Severity**: `low` | **Confidence**: `high`
- **Pattern**: `https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::[0-9]{1,5})?(?:/[^\s'"]*)?`
- **Description**: Hardcoded loopback URLs should be parameterized before deploying to production.
- **Example True Positive**: `ENDPOINT = "http://localhost:8080/v1"`
- **Expected False Positives**: Production URLs like `ENDPOINT = "https://api.production.com/v1"` are permitted.
- **Remediation**: Ensure development endpoints are parameterized via environment variables before deploying.

---

## Category 6: Compliance & Hygiene (4 Rules)

### 44. `secret.private_key`
- **Category**: `secrets` | **Severity**: `critical` | **Confidence**: `high`
- **Pattern**: `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`
- **Redaction**: `[REDACTED:PRIVATE_KEY]`
- **Description**: Cryptographic private key header in PEM, RSA, OpenSSH, or PGP format.
- **Example True Positive**: `-----BEGIN RSA PRIVATE KEY-----`
- **Expected False Positives**: Public key headers (`-----BEGIN CERTIFICATE-----`) are permitted.
- **Remediation**: Never commit private keys to source control. Add key files to `.gitignore` and rotate keypairs.

### 45. `secret.generic_credential`
- **Category**: `secrets` | **Severity**: `high` | **Confidence**: `medium`
- **Pattern**: `(?i)(?:password|passwd|api_key|apikey|secret_key|client_secret|auth_token|access_token)\s*[:=]\s*['"]((?!\[REDACTED:)[^'"\r\n]{8,128})['"]`
- **Redaction**: `[REDACTED:GENERIC_CREDENTIAL]`
- **Description**: Hardcoded passwords, API keys, or secrets assigned to variable names. Protected by negative lookahead to prevent clobbering previously redacted vendor tokens.
- **Example True Positive**: `client_secret = "mY_sUp3r_s3cr3t_vAlU3!"`
- **Expected False Positives**: Benign placeholders like `client_secret = "your_api_key_here"` or `${ENV_VAR}` are suppressed via `is_benign_generic_value()`.
- **Remediation**: Extract credentials into a `.env` file or cloud secret store. Load via environment variables.

### 46. `compliance.security_todo`
- **Category**: `compliance` | **Severity**: `low` | **Confidence**: `high`
- **Pattern**: `(?i)(?:#|//|/\*)\s*(?:TODO|FIXME|HACK|XXX)\s*[:\s].*(?:security|vulnerab|cwe|cve|auth|token|credential|sanitize|exploit|leak)`
- **Description**: Security debt markers left unresolved in code comments.
- **Example True Positive**: `# TODO: fix SQL injection vulnerability before release`
- **Expected False Positives**: Non-security TODOs like `# TODO: clean up button styling layout` are permitted.
- **Remediation**: Resolve security debt items prior to merging into production branches.

### 47. `compliance.root_license`
- **Category**: `compliance` | **Severity**: `low` | **Confidence**: `high`
- **Detection**: File presence check for accepted license files (`LICENSE`, `LICENSE.md`, `LICENSE.txt`, `COPYING`).
- **Description**: Verifies presence of an open-source license file in the root repository.
- **Example True Positive**: Missing root `LICENSE`.
- **Expected False Positives**: None.
- **Remediation**: Add a `LICENSE` file to the repository root.
