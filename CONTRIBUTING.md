# Contributing to Git Security Sentinel

Thank you for your interest in contributing to **Git Security Sentinel**! This project is an open-source Agent Skill and developer utility submitted to the **Best Open-Source AI Project category at Hacktoberfest Hack Day Ranchi 2026**.

We welcome contributions ranging from new detection rules and test cases to documentation improvements and performance optimizations.

---

## Code of Conduct

All contributors and maintainers are expected to foster a welcoming, inclusive, and harassment-free environment. Please treat fellow community members with respect.

---

## Core Technical Principles

When contributing code, please adhere strictly to these architectural constraints:

1. **Standard Library Only**:
   - `scripts/scan_diff.py` and `scripts/ai_review.py` must rely **exclusively** on the Python standard library (Python 3.9+).
   - Do **not** add third-party dependencies to runtime scripts (no `pip install` required for running scans).
2. **Privacy First & Strict Redaction**:
   - Never allow genuine credentials to be printed to terminal output, included in reports, exported in diffs, or passed to AI prompts.
   - Any new rule must integrate with the redaction engine.
3. **Synthetic Test Data Only**:
   - Never commit real or real-looking API keys, tokens, or private keys to the repository.
   - All tests in `tests/test_scan_diff.py` must construct synthetic test values programmatically in memory.
4. **Safe Process Execution**:
   - Subprocess calls must never use `shell=True`. Always pass an explicit argument list.

---

## Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/INSVikrant54/Git-Security-Sentinel.git
   cd Git-Security-Sentinel
   ```

2. **Verify Python Environment**:
   - Ensure you have Python 3.9 or newer installed:
     ```bash
     python --version
     ```

3. **Run the Test Suite**:
   - Run unit tests with Python's built-in `unittest` runner:
     ```bash
     python -m unittest discover -s tests -p "test_*.py" -v
     ```

4. **Verify Syntax & Compilation**:
   ```bash
   python -m py_compile scripts/scan_diff.py scripts/ai_review.py tests/test_scan_diff.py
   ```

---

## Adding New Detection Rules

When proposing a new detection rule:
1. Choose a descriptive, prefixed Rule ID (e.g., `secret.<provider>` or `risky.<pattern>`).
2. Add the rule definition to `DETECTION_RULES` in `scripts/scan_diff.py`.
3. Provide:
   - `category`: `secrets`, `risky_code`, or `compliance`.
   - `severity`: `critical`, `high`, `medium`, or `low`.
   - `confidence`: `high`, `medium`, or `low`.
   - `pattern`: A compiled regular expression.
   - `message`: Clear explanation of the detected pattern.
   - `recommendation`: Actionable remediation advice for developers.
4. Document the rule in `references/detection-rules.md` detailing logic, potential false positives, and limitations.
5. Add corresponding unit tests in `tests/test_scan_diff.py`.

---

## Pull Request Guidelines

1. **Branch Naming**: Use clear, descriptive branch names (e.g., `feat/slack-token-rule`, `fix/diff-parser-hunk`).
2. **Commit Messages**: Follow Conventional Commits format:
   - `feat(...)`: A new feature or rule
   - `fix(...)`: A bug fix in parsing or detection
   - `test(...)`: Adding or updating test cases
   - `docs(...)`: Documentation updates
   - `chore(...)`: Maintenance tasks
3. **Continuous Integration**: Ensure that all unit tests pass locally before opening a pull request. GitHub Actions CI will run across multiple Python versions (3.9 through 3.13).
