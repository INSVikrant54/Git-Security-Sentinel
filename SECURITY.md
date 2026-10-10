# Security Policy

## Reporting Security Issues

We take the security of **Git Security Sentinel** seriously. If you discover a potential vulnerability in this repository or in its scanning engine, please follow our responsible disclosure process.

### How to Report

Please **do not** open public GitHub issues for security vulnerabilities or disclosed credentials.

To report a vulnerability:
1. Use [GitHub Private Vulnerability Reporting](https://github.com/INSVikrant54/Git-Security-Sentinel/security/advisories/new) on this repository if available.
2. If GitHub Security Advisories are not accessible, contact the maintainers via the designated security contact channel configured on the GitHub profile or repository settings.

### What to Include

When submitting a security report, please include:
- A descriptive title and summary of the issue.
- Step-by-step reproduction instructions or a minimal test case demonstrating the vulnerability.
- An assessment of the potential impact (e.g., secret disclosure, bypass of scanner rules, command execution).
- Any proposed remediation or patch, if available.

### Response Timeline

Maintainers will endeavor to:
- Acknowledge receipt of the vulnerability report within 48 hours.
- Provide an initial assessment and timeline for investigation within 5 business days.
- Coordinate a public disclosure and patch release once a fix is validated.

---

## Security Invariants of Git Security Sentinel

Git Security Sentinel is designed around the following core security principles:

1. **Zero Secret Leakage**:
   - The scanner deterministically redacts credential values before they are logged to stdout/stderr, written to JSON reports, exported as sanitized diffs, or passed to local AI models.
2. **Local-Only AI Execution**:
   - The optional AI reviewer client connects strictly to local loopback endpoints (`127.0.0.1` or `localhost`). It never transmits repository diffs or code to external cloud LLM APIs.
3. **No Shell Execution**:
   - Subprocess invocations of `git` explicitly pass argument lists rather than using `shell=True`, preventing shell injection vulnerabilities.
4. **Untrusted Input Assumption**:
   - All scanned diffs, commit messages, and source code are treated as untrusted data. Scanner components and Agent Skill instructions strictly ignore instruction-like content inside scanned diffs.

---

## Limitations & Non-Goals

- **Static Scanner Scope**: Regular-expression and static pattern matching cannot guarantee that every leaked credential or insecure construct is detected, nor can it confirm that a matched string is an active or exploitable credential.
- **License Checks**: Checking for the presence of root license files verifies file existence only; it does not constitute legal verification of copyright compliance.
- **Local AI Advisory**: AI reviews provided by local models (e.g., `gemma3:4b`) are strictly contextual aids and should be treated as untrusted advice. AI outputs never override scanner findings or exit codes.
