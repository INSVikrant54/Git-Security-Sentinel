# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-11-21

### Added
- **Python Packaging & Console Scripts**:
  - Packaged repository via `pyproject.toml` utilizing `setuptools` with `src/git_security_sentinel/` layout.
  - Global CLI entry points registered: `git-scan`, `git-security-sentinel`, and `git-sentinel-ai`.
  - Top-level `__main__.py` enabling direct execution via `python -m git_security_sentinel`.
- **47 Detection Rules across 6 Categories**:
  - *Cloud Provider Keys (12 rules)*: AWS Access Key ID, AWS Secret Access Key, Stripe, Twilio, SendGrid, Mailgun, Mailchimp, Square, Shopify, Heroku, Datadog, New Relic.
  - *Auth Tokens (9 rules)*: GitHub Personal Access Tokens, Slack tokens, JWT tokens, Bearer tokens, Basic Authentication headers, npm publish tokens, PyPI upload tokens, Discord bot tokens, Telegram bot tokens.
  - *Database & Connection Strings (7 rules)*: MongoDB URIs, PostgreSQL URIs, MySQL URIs, Redis URIs, AMQP connection strings, Firebase Cloud Messaging server keys, Google Cloud Service Account JSON credentials.
  - *Sensitive Committed Files (4 rules)*: `.env*` files (permitting benign `.example`/`.sample`/`.template`), `id_rsa`, `id_ed25519` private keys (permitting `.pub`), and `.pem`/`.key`/`.p12`/`.pfx` certificates.
  - *Insecure Code Patterns & CWEs (11 rules)*: Shell injection (`subprocess(..., shell=True)`, `os.system`), pickle deserialization (`pickle.loads`), unsafe YAML loading (`yaml.load` without `SafeLoader`), SQL string concatenation / f-strings, XML External Entity (XXE) injection, committed temporary credentials, production debug flags (`DEBUG` set `True`), wildcard CORS (`Access-Control-Allow-Origin` wildcard), unverified SSL (`verify` set `False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`), and dangerous dynamic code evaluation (`eval` / `exec`).
  - *Compliance & Hygiene (4 rules)*: Cryptographic private key headers, generic credential assignments, security debt TODO/FIXME markers, and root repository open-source license detection.
- **Line-Level Comment Suppression**:
  - Granular suppression directives via `# nosec` and `# sentinel:ignore`.
  - Polyglot syntax support across Python (`#`), JavaScript/C/Go/Rust (`//`), SQL/Lua (`--`), and block comments (`/* ... */`).
  - Rule-specific suppression syntax (e.g. `# nosec secret.aws_access_key` or `# sentinel:ignore risk.eval_execution`).
  - Semicolon and comma-delimited multi-rule suppression support.
- **Path Exclusions & `.sentinelignore`**:
  - Command-line glob path filtering via `--exclude <pattern>` (repeatable or comma-separated).
  - Automatic discovery and evaluation of `.sentinelignore` files using gitignore-compatible glob syntax and negation patterns (`!`).
- **Baseline Migration & Fingerprint Filtering**:
  - Baseline capture flag `--create-baseline` outputting stable JSON baseline files.
  - Stable finding suppression via `--baseline .sentinel.baseline` using SHA-256 content fingerprints resilient to line shifts and refactoring.
- **Standard Library Configuration Parsing**:
  - Pure Python standard library configuration loaders for `.sentinel.yaml` (custom lightweight parser) and `.sentinel.toml` (`tomllib` / line parser).
  - Support for `severity_threshold`, `exclude`, `rules.disable`, `ai` settings, and CLI flag precedence.
  - Zero third-party dependencies required (no PyYAML).
- **Pre-Commit Integration & Native Hook Installer**:
  - Root `.pre-commit-hooks.yaml` defining `git-security-sentinel` and `git-scan` hooks for the pre-commit framework.
  - Native installer command `git-scan --install-hook` (and `--force`) installing an executable pre-commit shell script directly into `.git/hooks/pre-commit`.
- **Self-Update Capability & PyPI Check**:
  - Self-upgrade CLI command `git-scan --upgrade` to install the latest release from PyPI.
  - 24-hour cached PyPI background version check presenting non-intrusive terminal update notifications.
  - Flag `--no-update-check` and environment variables `CI=true` / `SENTINEL_NO_UPDATE_CHECK=1` to suppress update checks in automation.
- **SARIF 2.1.0 Code Scanning Output**:
  - Fully compliant OASIS SARIF 2.1.0 output formatting via `--format sarif`.
  - GitHub Advanced Security code scanning integration with normalized physical location URIs and rule metadata.
- **Universal AI Reviewer Enhancements**:
  - Suggested remediation diff generation via `--fix` displaying clear diff snippets without modifying files on disk.
  - Token and monetary cost calculation via `--cost-estimate` across local Ollama, Google AI Studio (Gemini), OpenAI, and Groq models.
  - Expanded system and user prompts enriched with CWE guidance, threat modeling context, and safe remediation alternatives for insecure code patterns.

### Changed
- Restructured entire repository codebase into modular package architecture under `src/git_security_sentinel/`:
  - `core/`: Unified diff hunk parser, scanning engine, and immutable data models.
  - `rules/`: Modular detection rule definitions and centralized catalog.
  - `redaction/`: Sequential sanitization engine with negative lookahead token isolation.
  - `suppression/`: Comment suppression, path exclusion, and SHA-256 baseline filters.
  - `config/`: Zero-dependency YAML and TOML configuration loader.
  - `output/`: Terminal ANSI text, structured JSON, and SARIF 2.1.0 formatters.
  - `hooks/`: Native `.git/hooks/pre-commit` installer.
  - `update/`: Cached PyPI version inspector and pip upgrader.
  - `ai/`: Multi-provider LLM reviewer, remediation diff generator, and cost estimator.
- Preserved full backwards compatibility through lightweight wrapper scripts `scripts/scan_diff.py` and `scripts/ai_review.py`.
- Modernized CLI help banners, version reporting (`--version`), and diagnostic flags (`--no-color`, `--color`, `--verbose`, `--quiet`).

### Fixed
- Protected specific vendor secret tokens (e.g. `[REDACTED:STRIPE_KEY]`, `[REDACTED:TWILIO_KEY]`) from being clobbered or overwritten by broader generic credential regexes using negative lookaheads.
- Fixed line number calculations in diff hunk parsing for multiline insertions and discontinuous hunks.
- Resolved trailing comment parsing edge cases to prevent benign strings from accidentally triggering or bypassing suppression directives.

### Security
- **Zero Runtime Dependencies**: The entire core scanner and AI reviewer operate strictly using the Python standard library with zero third-party dependencies required.
- **Guaranteed In-Memory Secret Redaction**: Deterministic sanitization replaces all detected secrets with typed `[REDACTED:<TYPE>]` tokens before terminal rendering, JSON serialization, SARIF generation, or transmission to AI providers.
- **Loopback Enforcement for AI Inference**: Standalone and unified AI reviews connect strictly to local loopback endpoints (`127.0.0.1` / `localhost`) by default, preventing unintended transmission of code diffs over the network unless explicitly permitted with `--allow-remote`.

---

## [1.0.0] - 2026-10-10

### Added
- Initial release of Git Security Sentinel.
- Deterministic diff scanning for `--staged`, `--unstaged`, `--all`, and `--base <branch>` diffs.
- 9 initial detection rules covering AWS keys, GitHub tokens, Slack tokens, private keys, generic credentials, `eval()` execution, and localhost endpoints.
- Root open-source license file validation.
- Initial privacy-preserving local AI reviewer supporting Ollama (Gemma) and Google AI Studio.
- Structured JSON scan report export (`--output`) and sanitized diff generation (`--redacted-diff-out`).
- Agent Skills Open Standard v1.0 specification guide (`SKILL.md`).
- Multi-version Python GitHub Actions test pipeline.
