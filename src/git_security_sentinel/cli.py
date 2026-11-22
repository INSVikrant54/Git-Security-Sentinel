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
from git_security_sentinel.hooks.bootstrap import bootstrap_project
from git_security_sentinel.hooks.installer import install_pre_commit_hook
from git_security_sentinel.output.sarif import generate_sarif_report
from git_security_sentinel.rules.catalog import get_all_rules, get_rule_by_id
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


def format_oneline_report(report: Dict[str, Any]) -> str:
    """Concise one-line-per-finding output for daily developer use."""
    lines: List[str] = []
    for err in report.get("errors", []):
        lines.append(f"[!] ERROR: {err}")
    for f in report.get("findings", []):
        severity = str(f.get("severity", "low")).upper()
        lines.append(
            f"{f.get('file')}:{f.get('line')}  [{severity}]  "
            f"{f.get('rule_id')}  - {f.get('message')}"
        )
    if not lines:
        return "OK: no security issues detected"
    summary = report.get("summary", {})
    lines.append(
        f"Summary: {summary.get('total', 0)} finding(s) "
        f"(critical {summary.get('critical', 0)}, high {summary.get('high', 0)}, "
        f"medium {summary.get('medium', 0)}, low {summary.get('low', 0)})"
    )
    return "\n".join(lines)


def format_github_report(report: Dict[str, Any]) -> str:
    """GitHub Actions workflow commands that annotate changed lines in a PR."""
    def escape(text: Any) -> str:
        return (
            str(text)
            .replace("%", "%25")
            .replace("\r", "%0D")
            .replace("\n", "%0A")
        )

    levels = {"critical": "error", "high": "error", "medium": "warning", "low": "notice"}
    lines: List[str] = []
    for err in report.get("errors", []):
        lines.append(f"::error::{escape(err)}")
    for f in report.get("findings", []):
        level = levels.get(str(f.get("severity", "low")).lower(), "warning")
        location = f"file={escape(f.get('file', ''))},line={f.get('line', 0)}"
        message = f"{f.get('message', '')} [{f.get('rule_id', '')}]"
        lines.append(f"::{level} {location}::{escape(message)}")
    return "\n".join(lines)


def explain_rule(rule_id: str, json_mode: bool = False) -> int:
    """Print human- or machine-readable guidance for a single detection rule."""
    rule = get_rule_by_id(rule_id)
    if rule is None:
        sys.stderr.write(f"Unknown rule: {rule_id}\n")
        return 2
    data = {
        "rule_id": rule.rule_id,
        "category": rule.category,
        "severity": rule.severity,
        "confidence": rule.confidence,
        "detects": rule.pattern.pattern,
        "message": rule.message,
        "remediation": rule.recommendation,
        "docs": "references/detection-rules.md",
    }
    if json_mode:
        print(json.dumps(data, indent=2))
        return 0
    print(f"Rule        : {data['rule_id']}")
    print(f"Category    : {data['category']}  |  Severity: {data['severity']}  |  Confidence: {data['confidence']}")
    print(f"Detects     : {data['detects']}")
    print(f"Message     : {data['message']}")
    print(f"Remediation : {data['remediation']}")
    print(f"Docs        : {data['docs']}")
    print("Suppress    : add '# nosec' to the line if it is a confirmed false positive")
    return 0


def generate_completion(parser: argparse.ArgumentParser, shell: str, prog: str) -> str:
    """Generate a small shell-completion script for the scanner CLI."""
    options = sorted(
        opt for action in parser._actions for opt in action.option_strings if opt.startswith("-")
    )
    words = " ".join(options + ["scan", "--help"])
    if shell == "powershell":
        choices = ", ".join(f"'{w}'" for w in options + ["scan", "--help"])
        return (
            "Register-ArgumentCompleter -Native -CommandName 'git-scan' -ScriptBlock {\n"
            "    param($wordToComplete, $commandAst, $cursorPosition)\n"
            f"    @({choices}) | Where-Object {{ $_ -like \"$wordToComplete*\" }} |\n"
            "        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }\n"
            "}\n"
        )
    if shell == "bash":
        return (
            f"_{prog.replace('-', '_')}_completion() {{\n"
            '    local cur="${COMP_WORDS[COMP_CWORD]}"\n'
            f'    COMPREPLY=( $(compgen -W "{words}" -- "$cur") )\n'
            "}\n"
            f"complete -F _{prog.replace('-', '_')}_completion {prog}\n"
        )
    if shell == "zsh":
        return (
            f"#compdef {prog}\n"
            f"_arguments '*: :(({words}))'\n"
        )
    return (
        f"complete -c {prog} -f -a '{words}'\n"
    )


def resolve_ai_settings(args: argparse.Namespace, config_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Resolve AI settings with precedence: CLI flags > config file > env vars > defaults.
    This lets a developer set the provider once and simply run `git scan --ai`.
    """
    cfg = (config_data or {}).get("ai", {})
    if not isinstance(cfg, dict):
        cfg = {}

    def env_flag(name: str) -> bool:
        return str(os.environ.get(name, "")).strip().lower() in {"1", "true", "yes", "on"}

    provider = args.provider or cfg.get("provider") or os.environ.get("SENTINEL_AI_PROVIDER") or "auto"
    model = args.model or cfg.get("model") or os.environ.get("SENTINEL_AI_MODEL") or None
    endpoint = args.ai_endpoint or cfg.get("endpoint") or os.environ.get("SENTINEL_AI_ENDPOINT") or None
    allow_remote = bool(
        args.allow_remote or cfg.get("allow_remote") or env_flag("SENTINEL_AI_ALLOW_REMOTE")
    )
    timeout_raw = args.ai_timeout
    if timeout_raw == 120:
        timeout_raw = cfg.get("timeout") or os.environ.get("SENTINEL_AI_TIMEOUT") or 120
    try:
        timeout = int(timeout_raw)
    except (TypeError, ValueError):
        timeout = 120
    return {
        "provider": str(provider),
        "model": str(model) if model else None,
        "endpoint": str(endpoint) if endpoint else None,
        "allow_remote": allow_remote,
        "timeout": timeout,
    }


def build_arg_parser(prog: Optional[str] = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog or "git-scan",
        description="Git Security Sentinel: Privacy-first Git diff security scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  git scan --init
  git scan --ai
  git scan --oneline
  git scan --explain secret.aws_access_key
  git scan --update
  git scan --staged
  git scan --all --format json
  git scan --all --format github
  git scan --base main --format sarif --output results.sarif
  git scan --ai --fix --cost-estimate
  git scan --exclude "tests/**" --baseline .sentinel.baseline

Note:
  Git reserves `git scan --help` for its own man-page lookup, so it never
  reaches this tool. Use `git scan -h` or `git scan help` instead.
""",
    )

    # Git dispatches `git scan ...` to the `git-scan` executable as
    # `git-scan scan ...`. Accept the optional leading token so both
    # `git scan --ai` and `git-scan --ai` work identically.
    parser.add_argument(
        "git_command",
        nargs="?",
        choices=["scan", "help"],
        default=None,
        help=argparse.SUPPRESS,
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
        action="store_true",
        help="Show version (and any available update) and exit.",
    )
    parser.add_argument(
        "--repo-root",
        metavar="PATH",
        default=".",
        help="Path to repository root (defaults to current working directory).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif", "github"],
        default="text",
        help="Console output format (github emits inline PR annotations).",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Set up this repository: starter config, ignore file, .env.example, and pre-commit hook.",
    )
    parser.add_argument(
        "--explain",
        metavar="RULE_ID",
        help="Explain a detection rule and how to fix or suppress it, then exit.",
    )
    parser.add_argument(
        "--completion",
        choices=["powershell", "bash", "zsh", "fish"],
        help="Print a shell completion script for the given shell, then exit.",
    )
    parser.add_argument(
        "--oneline",
        action="store_true",
        help="Concise one-line-per-finding output.",
    )
    parser.add_argument(
        "--key",
        metavar="NAME=VALUE",
        action="append",
        default=[],
        help="With --init, write an API key into the local gitignored .env file (repeatable).",
    )
    parser.add_argument(
        "--install-hook",
        action="store_true",
        help="Install pre-commit hook into repository .git/hooks/pre-commit.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing starter files or pre-commit hook during --init/--install-hook.",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Update to the latest release (alias of --upgrade).",
    )
    parser.add_argument(
        "--upgrade",
        action="store_true",
        help="Upgrade to the latest release from the package index.",
    )
    parser.add_argument(
        "--index-url",
        metavar="URL",
        help="Package index base URL for update checks and upgrades (e.g. TestPyPI or a private mirror).",
    )
    parser.add_argument(
        "--no-update-check",
        action="store_true",
        help="Disable automatic 24-hour background update check.",
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
        default=None,
        help="AI provider override. Default: .sentinel.yaml ai.provider, then SENTINEL_AI_PROVIDER, then auto-detect (Gemini/Groq/OpenAI keys, else Ollama).",
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

    if args.git_command == "help":
        parser.print_help()
        return 0

    repo_path = Path(args.repo_root).resolve()

    if args.version:
        print(f"git-security-sentinel {VERSION}")
        if not args.no_update_check:
            try:
                latest = check_for_pypi_update(VERSION, no_check=False, index_url=args.index_url)
                if latest:
                    print(f"Update available: {VERSION} -> {latest} (run 'git scan --update')")
            except Exception:
                pass
        return 0

    if args.explain:
        return explain_rule(args.explain, json_mode=(args.format == "json"))

    if args.completion:
        print(generate_completion(parser, args.completion, prog or "git-scan"))
        return 0

    if args.init:
        messages: List[str] = []
        if args.key:
            env_path = repo_path / ".env"
            existing_lines = (
                env_path.read_text(encoding="utf-8", errors="replace").splitlines()
                if env_path.is_file() else []
            )
            new_keys: Dict[str, str] = {}
            for item in args.key:
                if "=" not in item:
                    sys.stderr.write(f"Invalid --key format: {item} (expected NAME=VALUE)\n")
                    return 2
                name, value = item.split("=", 1)
                name, value = name.strip(), value.strip()
                if name and value:
                    new_keys[name] = value
            kept = [
                line for line in existing_lines
                if not any(line.strip().startswith(f"{name}=") for name in new_keys)
            ]
            kept.extend(f"{name}={value}" for name, value in new_keys.items())
            try:
                env_path.write_text("\n".join(kept) + "\n", encoding="utf-8")
                messages.append("[ok]   wrote local .env (gitignored)")
            except Exception as e:
                sys.stderr.write(f"Failed to write .env: {e}\n")
                return 1
        ok, init_messages = bootstrap_project(repo_path, force=args.force)
        for line in messages:
            print(line)
        print("\n".join(init_messages))
        return 0 if ok else 1

    if args.install_hook:
        success, msg = install_pre_commit_hook(repo_root=repo_path, force=args.force)
        if success:
            print(f"[OK] {msg}")
            return 0
        else:
            sys.stderr.write(f"[ERROR] {msg}\n")
            return 1

    if args.upgrade or args.update:
        return run_self_upgrade(index_url=args.index_url)

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
    auto_diff: Optional[str] = None
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
            elif args.format == "github":
                print(format_github_report(report))
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
        elif args.all:
            scan_mode = "all"
        else:
            # Smart default: review staged work first when the developer has
            # staged something, otherwise fall back to all uncommitted changes.
            candidate, candidate_errors = scanner.get_diff("staged")
            if candidate.strip() and not candidate_errors:
                scan_mode = "staged"
                auto_diff = candidate
                errors.extend(candidate_errors)
            else:
                scan_mode = "all"

        branch_arg = args.base if args.base else None
        mode_key = "base" if args.base else scan_mode
        if auto_diff is None:
            diff_content, git_errors = scanner.get_diff(mode_key, base_branch=branch_arg)
            errors.extend(git_errors)
        else:
            diff_content = auto_diff

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
        elif args.format == "github":
            print(format_github_report(report))
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
    ai_settings = resolve_ai_settings(args, config_data)

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
                    provider=ai_settings["provider"],
                    model=ai_settings["model"],
                    endpoint=ai_settings["endpoint"],
                    allow_remote=ai_settings["allow_remote"],
                    timeout_sec=ai_settings["timeout"],
                    format_mode="json" if args.format == "json" else "text",
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
        elif args.format == "github":
            print(format_github_report(report))
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
        elif args.format == "github":
            print(format_github_report(report))
        elif args.oneline:
            print(format_oneline_report(report))
            if ai_text_output:
                print()
                print(ai_text_output)
        else:
            print(format_text_report(report, color=color_enabled, verbose=is_verbose))
            if ai_text_output:
                print()
                print(ai_text_output)

    # PyPI background update check in non-quiet modes
    if not is_quiet and not args.no_update_check and config_data.get("update_check", True) is not False:
        try:
            latest_ver = check_for_pypi_update(
                VERSION,
                no_check=args.no_update_check,
                index_url=args.index_url,
            )
            if latest_ver:
                print_update_banner(VERSION, latest_ver)
        except Exception:
            pass

    return evaluate_exit_code(report, threshold)


if __name__ == "__main__":
    sys.exit(main())
