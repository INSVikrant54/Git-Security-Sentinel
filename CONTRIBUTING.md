# Contributing to Git Security Sentinel

Thank you for your interest in contributing to **Git Security Sentinel**! Git Security Sentinel is a deterministic, privacy-first Git diff security scanner and Agent Skill designed to detect leaked secrets, insecure coding patterns, and compliance issues before code is committed or published.

We welcome contributions of all kinds: new detection rules, suppression improvements, test cases, documentation enhancements, and performance optimizations.

---

## Code of Conduct

All contributors and maintainers are expected to foster a welcoming, inclusive, and harassment-free environment. Please treat fellow community members with empathy and respect.

---

## Core Technical Principles

When contributing code, please adhere strictly to these architectural constraints:

1. **Standard Library Only (Zero Runtime Dependencies)**:
   - The core scanning engine (`src/git_security_sentinel/core/`, `rules/`, `redaction/`, `suppression/`, `config/`, `output/`, `hooks/`, `update/`) and the AI reviewer (`src/git_security_sentinel/ai/`) must rely **exclusively** on the Python standard library (Python 3.9+).
   - No external packages may be added to `dependencies` in `pyproject.toml`.
   - All HTTP communications (`ai/reviewer.py`, `update/checker.py`) must use `urllib.request`.
2. **Privacy First & Strict Secret Redaction**:
   - Never allow genuine or unmasked credentials to be printed to terminal output, serialized into JSON or SARIF reports, written to patch files, or passed to AI prompts.
   - Any new secret rule must register a corresponding redaction pattern in `src/git_security_sentinel/redaction/redactor.py`.
3. **Synthetic Test Data Only**:
   - **NEVER** commit real or live credentials, API keys, or private keys to the repository.
   - All tests in `tests/` must construct synthetic test values programmatically in memory (e.g. using base string concatenation or formatted variables) to avoid triggering security scanners.
4. **Safe Process Execution**:
   - Subprocess executions must never use `shell=True`. Always pass explicit argument lists.
5. **Backwards Compatibility**:
   - The CLI console scripts (`git-scan`, `git-security-sentinel`, `git-sentinel-ai`) are the primary entry points, but the wrapper scripts `scripts/scan_diff.py` and `scripts/ai_review.py` must remain functional for backwards compatibility.

---

## Repository Architecture & Code Layout

Git Security Sentinel follows the standard `src/` layout:

```
Git-Security-Sentinel/
├── pyproject.toml                     # PEP 621 package metadata & entry points
├── .pre-commit-hooks.yaml             # Pre-commit hook definitions
├── CHANGELOG.md                       # Keep a Changelog documentation
├── CONTRIBUTING.md                    # Developer guidelines and rule authoring
├── README.md                          # Comprehensive documentation & quick start
├── SKILL.md                           # Agent Skills v1.0 specification
├── .github/
│   └── workflows/
│       ├── security-scan.yml          # Multi-Python CI & SARIF upload
│       └── publish.yml                # PyPI Trusted Publishing workflow
├── src/
│   └── git_security_sentinel/
│       ├── __init__.py                # Package version (__version__ = "1.2.0")
│       ├── __main__.py                # python -m git_security_sentinel entry point
│       ├── cli.py                     # Main scanner CLI (git-scan, git-security-sentinel)
│       ├── ai_cli.py                  # AI reviewer CLI (git-sentinel-ai)
│       ├── core/                      # Scanner engine, models, diff parser
│       │   ├── models.py              # Dataclasses (Finding, ScanReport, etc.)
│       │   ├── diff_parser.py         # Unified diff parser with hunk line tracking
│       │   └── scanner.py             # Git diff execution and scan orchestration
│       ├── rules/                     # Detection rule definitions (47 rules)
│       │   ├── catalog.py             # Central rule registry (get_all_rules)
│       │   ├── cloud.py               # Cloud provider keys (AWS, Stripe, Twilio, etc.)
│       │   ├── auth.py                # Auth tokens (GitHub, Slack, JWT, npm, etc.)
│       │   ├── database.py            # Database URIs (MongoDB, Postgres, Redis, etc.)
│       │   ├── sensitive_files.py     # Committed file rules (.env, id_rsa, etc.)
│       │   ├── insecure_code.py       # Insecure code patterns (pickle, SQLi, XXE, etc.)
│       │   └── compliance.py          # Compliance & hygiene (TODO markers, license)
│       ├── redaction/
│       │   └── redactor.py            # In-memory regex secret redaction engine
│       ├── suppression/
│       │   ├── comment_filter.py      # Inline # nosec / # sentinel:ignore parser
│       │   ├── ignore_filter.py       # .sentinelignore and --exclude glob filter
│       │   └── baseline.py            # SHA-256 fingerprint baseline filter
│       ├── config/
│       │   └── loader.py              # Pure stdlib .sentinel.yaml & .sentinel.toml loader
│       ├── output/
│       │   ├── text_formatter.py      # Terminal ANSI output formatter
│       │   ├── json_formatter.py      # Structured JSON report generator
│       │   └── sarif.py               # OASIS SARIF 2.1.0 generator
│       ├── update/
│       │   └── checker.py             # 24-hr cached PyPI update checker & upgrader
│       ├── hooks/
│       │   └── installer.py           # Native .git/hooks/pre-commit installer
│       └── ai/
│           ├── reviewer.py            # Multi-provider AI reviewer (urllib.request)
│           ├── prompts.py             # System prompts with CWE guidance and --fix
│           └── cost.py                # Token and monetary cost calculation
├── scripts/
│   ├── scan_diff.py                   # Backwards-compatible scanner wrapper
│   └── ai_review.py                   # Backwards-compatible AI review wrapper
├── references/
│   └── detection-rules.md             # Complete 47-rule reference catalog
└── tests/
    ├── test_scan_diff.py              # Original unit and integration tests
    ├── test_e2e_cli.py                # CLI entry points and flag tests
    ├── test_e2e_rules.py              # True/false positive tests for all 47 rules
    ├── test_e2e_suppression.py        # Comment, path ignore, and baseline tests
    ├── test_e2e_sarif.py              # SARIF 2.1.0 schema compliance tests
    ├── test_e2e_config.py             # Pure stdlib configuration parser tests
    ├── test_e2e_integrations.py       # Pre-commit, updater, and multiline tests
    └── test_ai_reviewer_v2.py         # AI reviewer flags, fix mode, and cost tests
```

---

## Development Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/INSVikrant54/Git-Security-Sentinel.git
   cd Git-Security-Sentinel
   ```

2. **Verify Python Environment**:
   - Ensure you are running Python 3.9 or newer:
     ```bash
     python --version
     ```

3. **Install in Editable Mode**:
   - Install the package locally in editable development mode:
     ```bash
     pip install -e .
     ```
   - Verify that the console scripts are accessible:
     ```bash
     git-scan --version
     git-security-sentinel --version
     git-sentinel-ai --version
     ```

4. **Run the Full Test Suite**:
   - Run all test suites using Python's built-in `unittest` runner:
     ```bash
     python -m unittest discover tests -v
     ```

5. **Run Specific Test Suites**:
   ```bash
   # Test detection rules and redaction
   python -m unittest tests/test_e2e_rules.py -v

   # Test suppression, .sentinelignore, and baselines
   python -m unittest tests/test_e2e_suppression.py -v

   # Test SARIF 2.1.0 output formatting
   python -m unittest tests/test_e2e_sarif.py -v

   # Test stdlib YAML/TOML configuration parsing
   python -m unittest tests/test_e2e_config.py -v

   # Test pre-commit hooks and PyPI update checker
   python -m unittest tests/test_e2e_integrations.py -v

   # Test AI reviewer with --fix and --cost-estimate
   python -m unittest tests/test_ai_reviewer_v2.py -v
   ```

---

## Adding New Detection Rules

When adding a new detection rule, follow these five steps:

### Step 1: Define the Rule in `src/git_security_sentinel/rules/`
Select the appropriate module (`cloud.py`, `auth.py`, `database.py`, `sensitive_files.py`, `insecure_code.py`, or `compliance.py`). Create a `Rule` instance:

```python
Rule(
    id="secret.my_provider_key",
    category="secrets",
    severity="critical",       # critical, high, medium, low, info
    confidence="high",         # high, medium, low
    pattern=re.compile(r"\b(myprov_[A-Za-z0-9]{32})\b"),
    message="Potential MyProvider API key detected.",
    recommendation="Revoke and rotate the key in MyProvider dashboard. Use environment variables.",
)
```

### Step 2: Register the Rule in `src/git_security_sentinel/rules/catalog.py`
Add the rule to the catalog module's rule list so `get_all_rules()` discovers it, and update the catalog rule count documentation.

### Step 3: Register Redaction in `src/git_security_sentinel/redaction/redactor.py`
If the rule matches a sensitive secret or token, add a redaction entry to `REDACTION_PATTERNS` so secrets are scrubbed before display:

```python
(re.compile(r"\b(myprov_[A-Za-z0-9]{32})\b"), "[REDACTED:MYPROVIDER_KEY]"),
```

*Note on Negative Lookahead*: If the secret could also look like a generic assignment (e.g. `api_key = "..."`), ensure the generic credential rule in `redactor.py` includes a negative lookahead `(?!\[REDACTED:)` to protect your specific vendor token.

### Step 4: Document the Rule in `references/detection-rules.md`
Add a dedicated entry including:
- Rule ID, category, severity, confidence
- Regex pattern and redaction token
- Description and threat explanation
- Example true positive (using synthetic placeholders with angle brackets)
- Expected false positive filtering rationale
- Concrete remediation steps

### Step 5: Add Unit Tests in `tests/test_e2e_rules.py`
Every rule MUST have unit tests verifying:
- **True Positive**: Verifying synthetic matches trigger the rule and are correctly redacted.
- **False Positive**: Verifying benign variables, documentation references, or public placeholders do not trigger the rule.

---

## Pull Request Guidelines

1. **Branch Naming**:
   - `feat/<feature-name>` for new features or detection rules.
   - `fix/<bug-name>` for bug fixes or false-positive corrections.
   - `docs/<doc-name>` for documentation updates.
2. **Commit Messages**:
   - Follow Conventional Commits:
     - `feat(rules): add Square API token detection rule`
     - `fix(redactor): prevent generic credential rule from clobbering Stripe tokens`
     - `docs(readme): update quick start examples for v1.1.0`
     - `test(e2e): add boundary tests for SARIF physical locations`
3. **Continuous Integration**:
   - Ensure all tests pass locally before pushing:
     ```bash
     python -m unittest discover tests -v
     ```
   - GitHub Actions CI will automatically test your pull request across Python versions 3.9, 3.10, 3.11, 3.12, and 3.13, run SARIF analysis, and verify zero third-party dependencies.
