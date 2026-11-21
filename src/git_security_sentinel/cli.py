"""
Git Security Sentinel - CLI Entry Point.
Provides git-scan, git-security-sentinel, and python -m git_security_sentinel interfaces.
"""

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

from git_security_sentinel.core.models import (
    SCANNER_NAME,
    SEVERITY_ORDER,
    VERSION,
)
from git_security_sentinel.core.scanner import GitSecurityScanner
from git_security_sentinel.config.loader import load_config
from git_security_sentinel.hooks.installer import install_pre_commit_hook
from git_security_sentinel.output.sarif import generate_sarif_report
from git_security_sentinel.rules.catalog import get_all_rules
from git_security_sentinel.suppression.baseline import BaselineFilter
from git_security_sentinel.suppression.ignore_filter import (
    PathFilter,
    load_sentinelignore,
)
from git_security_sentinel.update.checker import (
    check_for_pypi_update,
    print_update_banner,
    run_self_upgrade,
)


def format_text_report(
    report: Dict[str, Any],
    color: bool = False,
    verbose: bool = False,
) -> str:
    """Format human-readable CLI summary with optional ANSI color and verbosity."""
    if color:
        c_red = "\033[91m"
        c_yellow = "\033[93m"
        c_green = "\033[92m"
        c_cyan = "\033[96m"
        c_bold = "\033[1m"
        c_reset = "\033[0m"
    else:
        c_red = c_yellow = c_green = c_cyan = c_bold = c_reset = ""

    lines = []
    lines.append("=" * 68)
    lines.append(f"  {c_bold}GIT SECURITY SENTINEL v{report.get('version', VERSION)}{c_reset}")
    lines.append("  Privacy-First Git Security Scanner")
    lines.append("=" * 68)
    lines.append(f"Status     : {report.get('status', 'unknown').upper()}")
    lines.append(f"Scan Mode  : {report.get('scan_mode', 'all')}")

    lic = report.get("license", {})
    lic_present = lic.get("root_license_present", False)
    lic_file = lic.get("license_file") or "None"
    lic_desc = f"{c_green}Found ({lic_file}){c_reset}" if lic_present else f"{c_yellow}MISSING{c_reset}"
    lines.append(f"Root License : {lic_desc}")

    summary = report.get("summary", {})
    supp_count = summary.get("suppressed", 0)
    supp_part = f" | Suppressed: {supp_count}" if (supp_count or verbose) else ""
    lines.append(
        f"Findings   : Total: {summary.get('total', 0)} | "
        f"Critical: {summary.get('critical', 0)} | "
        f"High: {summary.get('high', 0)} | "
        f"Medium: {summary.get('medium', 0)} | "
        f"Low: {summary.get('low', 0)}"
        f"{supp_part}"
    )
    lines.append("-" * 68)

    errors = report.get("errors", [])
    if errors:
        lines.append(f"{c_red}ERRORS ENCOUNTERED:{c_reset}")
        for err in errors:
            lines.append(f"  [!] {err}")
        lines.append("-" * 68)

    findings = report.get("findings", [])
    if not findings:
        lines.append(f"{c_green}No security issues detected in the inspected diff.{c_reset}")
    else:
        for idx, f in enumerate(findings, start=1):
            sev = f["severity"].upper()
            c_sev = c_red if sev in ("CRITICAL", "HIGH") else (c_yellow if sev == "MEDIUM" else c_cyan)
            lines.append(f"[{idx}] [{c_sev}{sev}{c_reset}] {c_bold}{f['rule_id']}{c_reset} ({f['category']})")
            lines.append(f"    Location   : {f['file']}:{f['line']}")
            lines.append(f"    Message    : {f['message']}")
            lines.append(f"    Evidence   : {f['evidence']}")
            lines.append(f"    Remediation: {f['recommendation']}")
            lines.append("")

    lines.append("=" * 68)
    return "\n".join(lines)


def evaluate_exit_code(report: Dict[str, Any], threshold: str) -> int:
    """
    Determine exit code:
    0: Scan completed, no findings exceed severity threshold.
    1: Scan completed, findings meet or exceed severity threshold.
    2: Scan execution or configuration error.
    """
    if report.get("status") == "failed" or report.get("errors"):
        return 2

    threshold_level = SEVERITY_ORDER.get(threshold.lower(), 3)
    findings = report.get("findings", [])

    for f in findings:
        sev = f.get("severity", "low").lower()
        if SEVERITY_ORDER.get(sev, 0) >= threshold_level:
            return 1

    return 0


def build_arg_parser(prog: Optional[str] = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog or "git-scan",
        description="Git Security Sentinel: Privacy-first Git diff security scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  git-scan --staged
  git-scan --unstaged
  git-scan --all
  git-scan --base main
  git-scan --all --format json
  git-scan --all --output scan-report.json
  git-scan --all --redacted-diff-out sanitized.patch
  git-scan --exclude "tests/**" --baseline .sentinel.baseline
""",
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--staged",
        action="store_true",
        help="Scan git staged (cached) changes only.",
    )
    mode_group.add_argument(
        "--unstaged",
        action="store_true",
        help="Scan git unstaged working tree changes only.",
    )
    mode_group.add_argument(
        "--all",
        action="store_true",
        help="Scan both staged and unstaged working changes.",
    )
    mode_group.add_argument(
        "--base",
        metavar="BRANCH",
        help="Scan changes against merge-base of current branch and specified base branch.",
    )
    mode_group.add_argument(
        "--diff-file",
        metavar="FILE",
        help="Scan diff from a file, or '-' to read from standard input.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"git-security-sentinel {VERSION}",
        help="Show program's version number and exit.",
    )
    parser.add_argument(
        "--repo-root",
        metavar="PATH",
        default=".",
        help="Path to repository root (defaults to current working directory).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Console output format (default: text).",
    )
    parser.add_argument(
        "--install-hook",
        action="store_true",
        help="Install pre-commit hook into repository .git/hooks/pre-commit.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force overwrite of existing pre-commit hook during installation.",
    )
    parser.add_argument(
        "--upgrade",
        action="store_true",
        help="Upgrade git-security-sentinel to the latest release on PyPI.",
    )
    parser.add_argument(
        "--no-update-check",
        action="store_true",
        help="Disable automatic 24-hour background PyPI update check.",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Save structured JSON scan report to specified file.",
    )
    parser.add_argument(
        "--redacted-diff-out",
        metavar="FILE",
        help="Save sanitized diff with detected secrets redacted to specified file.",
    )
    parser.add_argument(
        "--severity-threshold",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Minimum severity level that triggers an exit code of 1 (default: high).",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        metavar="PATTERN",
        help="Glob pattern to exclude from scanning (can be repeated or comma-separated).",
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help="Path to baseline file containing suppressed finding fingerprints.",
    )
    parser.add_argument(
        "--create-baseline",
        action="store_true",
        help="Generate a baseline file from scan findings and exit with code 0.",
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="Path to project configuration file (.sentinel.yaml or .sentinel.toml).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in console output.",
    )
    parser.add_argument(
        "--color",
        action="store_true",
        help="Force ANSI color codes in console output.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose diagnostic output.",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress banner and clean scan output; print nothing on clean scans.",
    )

    ai_group = parser.add_argument_group("AI Security Review Options")
    ai_group.add_argument(
        "--ai",
        action="store_true",
        help="Run contextual AI review on findings using local Gemma (Ollama) or configured cloud provider.",
    )
    ai_group.add_argument(
        "--provider",
        choices=["auto", "ollama", "gemini", "openai", "groq"],
        default="auto",
        help="AI provider for review (default: auto; uses GEMINI_API_KEY if present, otherwise local Ollama).",
    )
    ai_group.add_argument(
        "--model",
        metavar="MODEL_NAME",
        help="AI model name override (default: gemma3:4b for Ollama, gemma-4-26b-a4b-it for Google AI Studio).",
    )
    ai_group.add_argument(
        "--ai-endpoint",
        metavar="URL",
        help="Custom API endpoint URL for AI inference.",
    )
    ai_group.add_argument(
        "--allow-remote",
        action="store_true",
        help="Permit non-loopback endpoints for Ollama (disabled by default for privacy).",
    )
    ai_group.add_argument(
        "--ai-timeout",
        type=int,
        default=120,
        metavar="SECONDS",
        help="HTTP request timeout for AI inference in seconds (default: 120).",
    )
    ai_group.add_argument(
        "--fix",
        action="store_true",
        help="Generate and display suggested remediation diffs without auto-applying to files on disk (used with --ai).",
    )
    ai_group.add_argument(
        "--cost-estimate",
        action="store_true",
        help="Display token count estimation and estimated query cost banner for AI review (used with --ai).",
    )

    return parser


def main(argv: Optional[List[str]] = None, prog: Optional[str] = None) -> int:
    parser = build_arg_parser(prog=prog)
    args = parser.parse_args(argv)

    repo_path = Path(args.repo_root).resolve()

    if args.install_hook:
        success, msg = install_pre_commit_hook(repo_root=repo_path, force=args.force)
        if success:
            print(f"[✓] {msg}")
            return 0
        else:
            sys.stderr.write(f"[✗] {msg}\n")
            return 1

    if args.upgrade:
        return run_self_upgrade()

    # Load configuration (.sentinel.yaml / .sentinel.toml)
    config_data: Dict[str, Any] = {}
    if args.config:
        cfg_file = Path(args.config)
        if not cfg_file.is_absolute():
            cfg_file = repo_path / cfg_file
        if not cfg_file.is_file():
            sys.stderr.write(f"Configuration file not found: {args.config}\n")
            return 2
        try:
            config_data = load_config(repo_path, config_path=cfg_file)
        except Exception as e:
            sys.stderr.write(f"Failed to load configuration file '{args.config}': {e}\n")
            return 2
    else:
        try:
            config_data = load_config(repo_path)
        except Exception:
            config_data = {}

    # Configuration precedence: CLI args > Config file > Defaults
    # 1. Severity threshold
    if args.severity_threshold:
        threshold = args.severity_threshold
    elif "severity_threshold" in config_data:
        threshold = str(config_data["severity_threshold"]).lower()
    else:
        threshold = "high"

    # 2. Exclude patterns
    exclude_patterns: List[str] = []
    cfg_excludes = config_data.get("exclude", [])
    if isinstance(cfg_excludes, list):
        exclude_patterns.extend(cfg_excludes)

    if args.exclude:
        for item in args.exclude:
            for part in item.split(","):
                p_str = part.strip()
                if p_str:
                    exclude_patterns.append(p_str)

    sentinelignore_patterns = load_sentinelignore(repo_path)
    exclude_patterns.extend(sentinelignore_patterns)

    path_filter = PathFilter(exclude_patterns) if exclude_patterns else None

    # 3. Baseline filter
    baseline_path_str = args.baseline or config_data.get("baseline")
    baseline_file: Optional[Path] = None
    baseline_filter: Optional[BaselineFilter] = None
    if baseline_path_str:
        baseline_file = Path(baseline_path_str)
        if not baseline_file.is_absolute():
            baseline_file = repo_path / baseline_file
        baseline_filter = BaselineFilter(baseline_file)

    # 4. Color formatting
    if args.no_color:
        color_enabled = False
    elif args.color:
        color_enabled = True
    elif "no_color" in config_data and config_data["no_color"]:
        color_enabled = False
    elif "color" in config_data and config_data["color"]:
        color_enabled = True
    elif os.environ.get("NO_COLOR"):
        color_enabled = False
    else:
        color_enabled = sys.stdout.isatty()

    # 5. Quiet and Verbose
    is_quiet = args.quiet or bool(config_data.get("quiet", False))
    is_verbose = args.verbose or bool(config_data.get("verbose", False))

    # 6. Disabled rules
    rules_cfg = config_data.get("rules", {})
    disabled_ids = set()
    if isinstance(rules_cfg, dict):
        dis_list = rules_cfg.get("disable", [])
        if isinstance(dis_list, list):
            disabled_ids = set(dis_list)

    all_rules = get_all_rules()
    active_rules = [r for r in all_rules if r.rule_id not in disabled_ids]

    scanner = GitSecurityScanner(
        repo_root=repo_path,
        rules=active_rules,
        path_filter=path_filter,
        baseline_filter=baseline_filter,
    )

    # Determine scan mode and diff content
    diff_content = ""
    scan_mode = "all"
    errors: List[str] = []

    if args.diff_file:
        scan_mode = "file"
        if args.diff_file == "-":
            try:
                diff_content = sys.stdin.read()
            except Exception as e:
                errors.append(f"Failed to read diff from stdin: {e}")
        else:
            diff_path = Path(args.diff_file)
            if not diff_path.is_file():
                errors.append(f"Diff file not found: {args.diff_file}")
            else:
                try:
                    diff_content = diff_path.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    errors.append(f"Failed to read diff file '{args.diff_file}': {e}")
    else:
        is_git, git_err = scanner.check_is_git_repository()
        if not is_git:
            report = {
                "scanner": SCANNER_NAME,
                "version": VERSION,
                "status": "failed",
                "scan_mode": "unknown",
                "findings": [],
                "license": {"root_license_present": False, "license_file": None},
                "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "suppressed": 0},
                "errors": [git_err or "Directory is not a valid Git repository."],
            }
            if args.format == "sarif":
                sarif_data = generate_sarif_report(report, active_rules)
                sarif_json = json.dumps(sarif_data, indent=2)
                print(sarif_json)
                if args.output:
                    Path(args.output).write_text(sarif_json, encoding="utf-8")
            elif args.format == "json":
                print(json.dumps(report, indent=2))
                if args.output:
                    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
            elif not is_quiet:
                print(format_text_report(report, color=color_enabled, verbose=is_verbose))
                if args.output:
                    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
            return 2

        if args.staged:
            scan_mode = "staged"
        elif args.unstaged:
            scan_mode = "unstaged"
        elif args.base:
            scan_mode = f"base:{args.base}"
        else:
            scan_mode = "all"

        branch_arg = args.base if args.base else None
        mode_key = "base" if args.base else scan_mode
        diff_content, git_errors = scanner.get_diff(mode_key, base_branch=branch_arg)
        errors.extend(git_errors)

    if errors:
        report = {
            "scanner": SCANNER_NAME,
            "version": VERSION,
            "status": "failed",
            "scan_mode": scan_mode,
            "findings": [],
            "license": scanner.check_license(),
            "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "suppressed": 0},
            "errors": errors,
        }
        if args.format == "sarif":
            sarif_data = generate_sarif_report(report, active_rules)
            sarif_json = json.dumps(sarif_data, indent=2)
            print(sarif_json)
            if args.output:
                Path(args.output).write_text(sarif_json, encoding="utf-8")
        elif args.format == "json":
            print(json.dumps(report, indent=2))
            if args.output:
                Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        elif not is_quiet:
            print(format_text_report(report, color=color_enabled, verbose=is_verbose))
            if args.output:
                Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        return 2

    # Baseline creation flag
    if args.create_baseline:
        target_baseline = baseline_file or (repo_path / ".sentinel.baseline")
        # Run report without baseline filter to collect all detected findings
        scan_rep = scanner.scan_diff_report(
            diff_content,
            scan_mode=scan_mode,
            baseline_filter=None,
        )
        all_findings = scan_rep.findings + scan_rep.suppressed_findings
        BaselineFilter.create_baseline(target_baseline, all_findings)
        if not is_quiet:
            print(f"Created baseline at {target_baseline} with {len(all_findings)} finding(s).")
        return 0

    scan_report = scanner.scan_diff_report(diff_content, scan_mode=scan_mode)
    report = scan_report.to_dict()

    # AI Contextual Review
    ai_text_output = ""
    if args.ai and not errors:
        findings_count = report.get("summary", {}).get("total", 0)
        if findings_count == 0:
            if args.format != "json":
                ai_text_output = (
                    "====================================================================\n"
                    "  GIT SECURITY SENTINEL - AI SECURITY REVIEW\n"
                    "====================================================================\n"
                    "Status: SKIPPED (Diff is clean - zero findings require remediation)\n"
                    "===================================================================="
                )
            else:
                report["ai_review"] = {
                    "status": "skipped",
                    "reason": "Diff is clean; no findings to triage.",
                }
        else:
            sanitized_diff = scanner.generate_sanitized_diff(diff_content)
            try:
                try:
                    from git_security_sentinel.ai_cli import run_ai_review
                except ImportError:
                    try:
                        from scripts.ai_review import run_ai_review
                    except ImportError:
                        from ai_review import run_ai_review

                success, ai_result, ai_formatted = run_ai_review(
                    report_data=report,
                    sanitized_diff=sanitized_diff,
                    provider=args.provider,
                    model=args.model,
                    endpoint=args.ai_endpoint,
                    allow_remote=args.allow_remote,
                    timeout_sec=args.ai_timeout,
                    format_mode=args.format,
                    fix_mode=getattr(args, "fix", False),
                    cost_estimate=getattr(args, "cost_estimate", False),
                )
                if args.format == "json":
                    report["ai_review"] = ai_result
                else:
                    ai_text_output = ai_formatted
            except Exception as e:
                err_msg = f"Failed to execute AI contextual reviewer: {e}"
                if args.format == "json":
                    report["ai_review"] = {"status": "error", "error": err_msg}
                else:
                    ai_text_output = (
                        "====================================================================\n"
                        "  GIT SECURITY SENTINEL - AI REVIEWER ERROR\n"
                        "====================================================================\n"
                        f"{err_msg}\n"
                        "===================================================================="
                    )

    # Output sanitized diff if requested
    if args.redacted_diff_out:
        out_patch_path = args.redacted_diff_out
        sanitized = scanner.generate_sanitized_diff(diff_content)
        try:
            Path(out_patch_path).write_text(sanitized, encoding="utf-8")
        except Exception as e:
            report.setdefault("errors", []).append(f"Failed to write redacted diff: {e}")

    # Generate SARIF structure if SARIF format requested or output path ends with .sarif
    sarif_data = None
    if args.format == "sarif" or (args.output and args.output.endswith(".sarif")):
        sarif_data = generate_sarif_report(report, active_rules)

    # Output report file if requested
    if args.output:
        try:
            if args.format == "sarif" or args.output.endswith(".sarif"):
                if sarif_data is None:
                    sarif_data = generate_sarif_report(report, active_rules)
                Path(args.output).write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
            else:
                Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        except Exception as e:
            report.setdefault("errors", []).append(f"Failed to write report output: {e}")

    # Console output
    if is_quiet:
        if args.format == "sarif":
            if sarif_data is None:
                sarif_data = generate_sarif_report(report, active_rules)
            print(json.dumps(sarif_data, indent=2))
        elif args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            findings_list = report.get("findings", [])
            errors_list = report.get("errors", [])
            # Clean scan prints nothing
            if findings_list or errors_list:
                for idx, f in enumerate(findings_list, start=1):
                    sev = f.get("severity", "UNKNOWN").upper()
                    print(f"[{idx}] [{sev}] {f.get('rule_id')} ({f.get('category')}) - {f.get('file')}:{f.get('line')}")
                for err in errors_list:
                    sys.stderr.write(f"[!] {err}\n")
    else:
        if args.format == "sarif":
            if sarif_data is None:
                sarif_data = generate_sarif_report(report, active_rules)
            print(json.dumps(sarif_data, indent=2))
        elif args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_text_report(report, color=color_enabled, verbose=is_verbose))
            if ai_text_output:
                print()
                print(ai_text_output)

    # PyPI background update check in non-quiet modes
    if not is_quiet and not args.no_update_check and config_data.get("update_check", True) is not False:
        try:
            latest_ver = check_for_pypi_update(VERSION, no_check=args.no_update_check)
            if latest_ver:
                print_update_banner(VERSION, latest_ver)
        except Exception:
            pass

    return evaluate_exit_code(report, threshold)


if __name__ == "__main__":
    sys.exit(main())
