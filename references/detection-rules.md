# Detection Rules Reference Catalog

Git Security Sentinel pairs a deterministic regex-based static scanner with an optional local AI contextual reviewer. This document catalogs all static rules implemented in `scripts/scan_diff.py`, explaining their matching logic, expected false positives, remediation recommendations, and known limitations.

---

## Important Security Disclaimer

> **Limitations of Static Analysis**  
> Static pattern matching cannot determine whether an exposed credential is valid, active, or exploitable in an external system. Similarly, regex-based analysis cannot guarantee the detection of all potential credentials (e.g., custom token formats or non-standard variable names). Static rules provide a fast, deterministic first line of defense; they do not replace comprehensive secret management and defense-in-depth security practices.

---

## Severity Taxonomy

| Severity | Definition | Default Action |
|---|---|---|
| **`critical`** | Immediate credential compromise risk (AWS keys, private keys, GitHub tokens). Exceeds default threshold. | Halts CI pipeline / triggers exit code `1`. |
| **`high`** | High-probability credential or authentication token leak (Slack tokens, generic credential assignments). | Halts CI pipeline / triggers exit code `1`. |
| **`medium`** | Dangerous coding patterns (e.g., dynamic code execution with `eval()` / `exec()`). | Informational warning; fails if threshold is set to `medium`. |
| **`low`** | Configuration hygiene warnings (e.g., hardcoded loopback/localhost URLs). | Informational warning; fails if threshold is set to `low`. |

---

## Rule Catalog

### 1. `secret.aws_access_key`

- **Category**: `secrets`
- **Default Severity**: `critical`
- **Confidence**: `high`
- **Detection Approach**:
  Matches standard AWS Access Key Identifiers starting with well-known AWS 4-character prefixes (`AKIA` for long-term IAM users, `ASIA` for temporary STS credentials, `ABIA`, `ACCA`) followed by 16 alphanumeric characters:
  ```regex
  \b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b
  ```
- **Example of Detected Issue**:
  ```python
  aws_key_id = "AKIA<20-CHAR-KEY-IDENTIFIER>"  # illustrative pattern placeholder
  ```
- **Expected False Positives**:
  Extremely low. Coincidental 20-character uppercase strings starting with `AKIA`/`ASIA` are rare in source code.
- **Recommended Remediation**:
  1. Immediately revoke the key in the AWS IAM Console.
  2. Use environment variables (`AWS_ACCESS_KEY_ID`), AWS IAM Roles for EC2/ECS/EKS, or AWS Secrets Manager.
  3. Inspect CloudTrail audit logs for unauthorized API calls made with the exposed key.
- **Known Limitations**:
  Does not check if the AWS key is active or has permissions attached.

---

### 2. `secret.aws_secret_key`

- **Category**: `secrets`
- **Default Severity**: `critical`
- **Confidence**: `high`
- **Detection Approach**:
  Searches for variable assignments matching `aws_secret_access_key`, `aws_secret_key`, or `aws_secret` assigned a 40-character Base64/alphanumeric string:
  ```regex
  (?i)(?:aws_secret_access_key|aws_secret_key|aws_secret)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?
  ```
- **Example of Detected Issue**:
  ```ini
  aws_secret_access_key = <40-character-secret-access-key>
  ```
- **Expected False Positives**:
  Documentation examples containing 40-character placeholder strings ending in `EXAMPLE`.
- **Recommended Remediation**:
  1. Invalidate and rotate the AWS IAM secret key immediately.
  2. Store credentials in AWS Parameter Store or AWS Secrets Manager.
- **Known Limitations**:
  Cannot detect AWS secret keys assigned to arbitrary variable names (e.g., `s = "..."`) without context indicators.

---

### 3. `secret.github_token`

- **Category**: `secrets`
- **Default Severity**: `critical`
- **Confidence**: `high`
- **Detection Approach**:
  Detects modern GitHub Personal Access Tokens and OAuth tokens utilizing GitHub's official token format prefixes (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, or fine-grained `github_pat_`):
  ```regex
  \b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b
  ```
- **Example of Detected Issue**:
  ```javascript
  const token = "ghp_<personal-access-token-string>";
  ```
- **Expected False Positives**:
  Negligible due to distinct token prefixes and standardized lengths.
- **Recommended Remediation**:
  1. Revoke the token immediately in **GitHub > Settings > Developer settings > Personal access tokens**.
  2. Use GitHub Secrets (`${{ secrets.GITHUB_TOKEN }}`) in GitHub Actions workflows.
- **Known Limitations**:
  Legacy 40-hex-character GitHub tokens lacking the `ghp_` prefix are caught under the generic credential rule rather than this specific prefix rule.

---

### 4. `secret.slack_token`

- **Category**: `secrets`
- **Default Severity**: `high`
- **Confidence**: `high`
- **Detection Approach**:
  Detects Slack bot, user, and app tokens starting with `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, or `xoxs-`:
  ```regex
  \b(xox[baprs]-[0-9A-Za-z]{10,48}-[0-9A-Za-z]{10,48}-[0-9A-Za-z]{24,48}|xox[baprs]-[0-9A-Za-z]{10,48})\b
  ```
- **Example of Detected Issue**:
  ```python
  SLACK_BOT_TOKEN = "xoxb-<team_id>-<bot_id>-<token_hash>"
  ```
- **Expected False Positives**:
  Extremely low.
- **Recommended Remediation**:
  1. Revoke the token via the **Slack API App Management Dashboard**.
  2. Supply tokens via environment variables (`SLACK_BOT_TOKEN`) or a secrets vault.
- **Known Limitations**:
  Webhook URLs (`https://hooks.slack.com/services/...`) are not matched by this specific token rule.

---

### 5. `secret.private_key`

- **Category**: `secrets`
- **Default Severity**: `critical`
- **Confidence**: `high`
- **Detection Approach**:
  Detects PEM, RSA, EC, OpenSSH, and PGP cryptographic private key headers:
  ```regex
  -----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----
  ```
- **Example of Detected Issue**:
  ```
  -----BEGIN OPENSSH PRIVATE KEY-----
  ```
- **Expected False Positives**:
  Committed mock keys used in test fixtures. Such fixtures should be excluded using `.gitignore` or synthetic in-memory generation.
- **Recommended Remediation**:
  1. Immediately consider the private key compromised and revoke the associated public key / certificate.
  2. Remove the key file from git history (`git filter-repo` or BFG Repo-Cleaner).
  3. Store private keys in secure key management infrastructure (e.g., HashiCorp Vault, AWS KMS).
- **Known Limitations**:
  Does not match raw binary DER-encoded keys without headers.

---

### 6. `secret.generic_credential`

- **Category**: `secrets`
- **Default Severity**: `high`
- **Confidence**: `medium`
- **Detection Approach**:
  Conservative matching of common credential variable names (`password`, `passwd`, `api_key`, `apikey`, `secret_key`, `client_secret`, `auth_token`, `access_token`) assigned string literals between 8 and 128 characters:
  ```regex
  (?i)(?:password|passwd|api_key|apikey|secret_key|client_secret|auth_token|access_token)\s*[:=]\s*['"]([^'"\r\n]{8,128})['"]
  ```
  Applies an exclusion filter for common template markers (`${...}`, `process.env`, `os.environ`) and placeholder words (`change_me`, `your_api_key`, `xxxx`, etc.).
- **Example of Detected Issue**:
  ```python
  client_secret = "<hardcoded_client_secret_string>"
  ```
- **Expected False Positives**:
  Test passwords, dummy mock strings in tests, or hardcoded non-sensitive development configuration.
- **Recommended Remediation**:
  Extract the secret to a `.env` file and load using `os.environ` or `dotenv`. Ensure `.env` is listed in `.gitignore`.
- **Known Limitations**:
  Variables with arbitrary or abbreviated names (e.g., `key = "..."`) are omitted to avoid unmanageable false positive rates.

---

### 7. `risk.eval_execution`

- **Category**: `insecure_code`
- **Default Severity**: `medium`
- **Confidence**: `medium`
- **Detection Approach**:
  Flags occurrences of Python's dynamic code execution functions `eval()` or `exec()` invoked with non-constant expressions:
  ```regex
  \b(?:eval|exec)\s*\((?!\s*['\"][^'\"]*['\"]\s*\))
  ```
- **Example of Detected Issue**:
  ```python
  result = eval(user_input_query)
  ```
- **Expected False Positives**:
  Legitimate mathematical expression evaluators or domain-specific language parsers with validated inputs.
- **Recommended Remediation**:
  Replace `eval()` with `ast.literal_eval()` for safely evaluating Python literals, or use structured parsers (`json.loads()`).
- **Known Limitations**:
  Does not perform full Abstract Syntax Tree (AST) taint analysis; cannot determine if input originates from an untrusted user.

---

### 8. `risk.localhost_endpoint`

- **Category**: `configuration`
- **Default Severity**: `low`
- **Confidence**: `high`
- **Detection Approach**:
  Detects hardcoded local loopback URLs:
  ```regex
  https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::[0-9]{1,5})?(?:/[^\s'"]*)?
  ```
- **Example of Detected Issue**:
  ```python
  API_URL = "http://localhost:8080/api/v1"
  ```
- **Expected False Positives**:
  Unit test configurations and local mock servers where loopback endpoints are deliberate and correct.
- **Recommended Remediation**:
  Make service endpoints configurable via environment variables (e.g., `os.getenv("SERVICE_URL", "http://localhost:8080")`).
- **Known Limitations**:
  Does not distinguish test files from production code unless file-path filters are configured.

---

## License Verification Rule

- **Identifier**: `compliance.root_license`
- **Category**: `compliance`
- **Detection Approach**:
  Inspects the repository root directory for standard open-source license filenames: `LICENSE`, `LICENSE.md`, `LICENSE.txt`, or `COPYING`.
- **Remediation**:
  Add an OSI-approved license file (e.g., `LICENSE` containing the MIT License) to the repository root to clarify open-source permissions.
