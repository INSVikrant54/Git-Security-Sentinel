# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.0] - 2026-11-22

### Added
- **One-Command Setup**: `git scan --init` creates `.sentinel.yaml`, `.sentinelignore`, `.env.example`, and installs the pre-commit hook. `--key NAME=VALUE` writes cloud API keys into the local gitignored `.env`, and `--force` is required to overwrite existing files.
- **Git Subcommand Alias**: `git scan ...` is equivalent to `git-scan ...`; the CLI accepts the leading `scan` token Git passes to the executable.
- **Working AI Configuration**: `.sentinel.yaml` / `.sentinel.toml` `ai` settings (`provider`, `model`, `endpoint`, `allow_remote`, `timeout`) are now applied, with `SENTINEL_AI_*` environment defaults and CLI flags taking precedence.
- **Developer-Friendly Output & Discovery**: `--oneline` for concise findings, `--explain <rule-id>` for rule guidance, `--completion {powershell,bash,zsh,fish}` for shell completions, and `--format github` for inline PR annotations.
- **Smart Default Scope**: `git scan` with no scope flag scans staged changes when any exist, otherwise all uncommitted changes.

### Fixed
- Windows scans no longer crash on non-ASCII Git output: subprocess output is decoded as UTF-8 with replacement instead of the system code page.

### Changed
- `--provider` now defaults to config/env/auto-detection instead of always `auto`; `--format` accepts `github`; `--force` applies to `--init` as well as hook installation.
- Documentation and Agent Skill now lead with the 30-second start (`pip install` → `git scan --init` → `git scan --ai`) and no longer ask developers to create files manually.

---

## [1.1.0] - 2026-11-21

### Added
- **Python Packaging & Console Scripts**:
  - Packaged repository via `pyproject.toml` utilizing `setuptools` with `src/git_security_sentinel/` layout.
  - Global CLI entry points registered: `git-scan`, `git-security-sentinel`, and `git-sentinel-ai`.
  - Top-level `__main__.py` enabling direct execution via `python -m git_security_sentinel`.
  - Git subcommand alias: `git scan --ai` is equivalent to `git-scan --ai` (Git dispatches `git scan` to the `git-scan` executable).
- **47 Detection Rules across 5 Categories**:
  - *`secrets` (30 rules)*: Cloud provider keys (AWS Access Key ID and Secret Access Key, Stripe, Twilio, SendGrid, Mailgun, Mailchimp, Square, Shopify, Heroku, Datadog, New Relic); auth tokens (GitHub PATs, Slack, JWT, Bearer, Basic Auth, npm, PyPI, Discord, Telegram); database URIs (MongoDB, PostgreSQL, MySQL, Redis, AMQP, Firebase FCM, GCP Service Account); and cryptographic private key headers and generic credential assignments.
  - *`sensitive_files` (4 rules)*: `.env*` files (permitting benign `.example`/`.sample`/`.template`), `id_rsa`, `id_ed25519` private keys (permitting `.pub`), and `.pem`/`.key`/`.p12`/`.pfx` certificates.
  - *`insecure_code` (10 rules)*: Shell injection (`subprocess(..., shell=True)`, `os.system`), pickle deserialization (`pickle.loads`), unsafe YAML loading (`yaml.load` without `SafeLoader`), SQL string concatenation / f-strings, XML External Entity (XXE) injection, committed temporary credentials, production debug flags (`DEBUG` set `True`), wildcard CORS (`Access-Control-Allow-Origin` wildcard), disabled TLS certificate verification (CWE-295), and dangerous dynamic code evaluation (`eval` / `exec`).
  - *`configuration` (1 rule)*: Hardcoded loopback endpoint URL (`risk.localhost_endpoint`).
  - *`compliance` (2 rules)*: Security debt TODO/FIXME markers and root repository open-source license detection.
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
- **Loopback Enforcement for AI Inference**: Standalone and unified AI reviews connect strictly to local loopback endpoints (`127.0.0.1` / `localhost`) by default, preventing unintended transmission of code diffs over the network unless a cloud provider is explicitly selected with `--provider` (Gemini / OpenAI / Groq) or a non-loopback Ollama endpoint is permitted with `--allow-remote`.

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
