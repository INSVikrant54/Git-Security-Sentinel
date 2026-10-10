#!/usr/bin/env python3
"""
Git Security Sentinel - Local AI Security Reviewer
Optional, privacy-preserving contextual reviewer for Git Security Sentinel reports.
Connects strictly to a local Ollama instance (default: loopback only).
Complies with the Agent Skills Open Standard (https://agentskills.io/specification).
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VERSION = "1.0.0"
DEFAULT_MODEL = "gemma3:4b"
DEFAULT_ENDPOINT = "http://127.0.0.1:11434"
DEFAULT_TIMEOUT_SEC = 60

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


def is_loopback_url(url: str) -> bool:
    """Validate that the given URL resolves strictly to a loopback host."""
    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or "").lower()
    return hostname in LOOPBACK_HOSTS


def check_ollama_available(endpoint: str, timeout_sec: int = 5) -> Tuple[bool, str]:
    """Check if the local Ollama daemon is reachable and responding."""
    url = f"{endpoint.rstrip('/')}/api/tags"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": f"git-security-sentinel-ai-reviewer/{VERSION}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                models = [m.get("name") for m in data.get("models", [])]
                return True, f"Ollama available with models: {', '.join(models) if models else 'none loaded'}"
            return False, f"Ollama returned HTTP status {response.status}"
    except urllib.error.URLError as e:
        return False, f"Could not connect to Ollama at {endpoint}: {e.reason}"
    except Exception as e:
        return False, f"Ollama connection error: {e}"


def query_ollama(
    endpoint: str,
    model: str,
    prompt: str,
    system_prompt: str,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Send prompt to Ollama /api/generate without streaming.
    Returns: (success, response_text, error_message)
    """
    url = f"{endpoint.rstrip('/')}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "system": system_prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "top_p": 0.9,
        },
    }

    try:
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"git-security-sentinel-ai-reviewer/{VERSION}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            if resp.status == 200:
                resp_json = json.loads(resp.read().decode("utf-8"))
                return True, resp_json.get("response", ""), None
            return False, None, f"Ollama responded with HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode("utf-8")
        except Exception:
            pass
        return False, None, f"HTTP Error {e.code}: {e.reason}. Details: {error_body}"
    except urllib.error.URLError as e:
        return False, None, f"Connection error: {e.reason}"
    except TimeoutError:
        return False, None, f"Inference request timed out after {timeout_sec} seconds."
    except Exception as e:
        return False, None, f"Unexpected error querying Ollama: {e}"


def build_system_prompt() -> str:
    return (
        "You are an expert Application Security Engineer reviewing static security scanner findings for Git diffs. "
        "Your task is to provide concise, actionable, and contextual security triage. "
        "Distinguish probable true positives from likely false positives (such as test fixtures, mocks, or benign dev configs). "
        "Explain the real-world attack risk, suggest safer code alternatives, and provide priority remediation steps. "
        "Do NOT repeat the raw findings list verbatim. Add security engineering insight. "
        "Output your review structured with clear sections: "
        "1. Executive Summary, 2. Finding-by-Finding Triage & False-Positive Analysis, 3. Safer Code Alternatives, 4. Immediate Recommended Actions."
    )


def build_user_prompt(report_data: Dict[str, Any], sanitized_diff: Optional[str] = None) -> str:
    findings = report_data.get("findings", [])
    license_info = report_data.get("license", {})
    summary = report_data.get("summary", {})

    prompt_parts = [
        "Please review the following Git Security Sentinel scan findings:",
        f"- Scanner Version: {report_data.get('version', 'unknown')}",
        f"- Scan Mode: {report_data.get('scan_mode', 'unknown')}",
        f"- Total Findings: {summary.get('total', 0)} (Critical: {summary.get('critical', 0)}, High: {summary.get('high', 0)}, Medium: {summary.get('medium', 0)}, Low: {summary.get('low', 0)})",
        f"- Root License Present: {license_info.get('root_license_present', False)} (File: {license_info.get('license_file', 'None')})",
        "",
        "Detected Findings (Sensitive data has been deterministically redacted by the scanner):",
    ]

    if not findings:
        prompt_parts.append("No findings were detected in this diff.")
    else:
        for idx, f in enumerate(findings, start=1):
            prompt_parts.append(
                f"{idx}. [{f.get('severity', 'UNKNOWN').upper()}] Rule: {f.get('rule_id')} in {f.get('file')}:{f.get('line')}\n"
                f"   Message: {f.get('message')}\n"
                f"   Redacted Evidence: {f.get('evidence')}\n"
                f"   Scanner Recommendation: {f.get('recommendation')}"
            )

    if sanitized_diff:
        # Include a trimmed snippet of the sanitized diff (up to 3000 chars) for extra context
        trimmed_diff = sanitized_diff[:3000]
        if len(sanitized_diff) > 3000:
            trimmed_diff += "\n... [diff truncated for length] ..."
        prompt_parts.append("")
        prompt_parts.append("Sanitized Diff Context (secrets already masked):")
        prompt_parts.append("```diff")
        prompt_parts.append(trimmed_diff)
        prompt_parts.append("```")

    prompt_parts.append("")
    prompt_parts.append(
        "Provide your contextual security evaluation. For each finding, evaluate whether it is likely a true vulnerability or a false positive, explain why, and suggest the safest alternative."
    )

    return "\n".join(prompt_parts)


def format_ai_review_report(
    model: str,
    endpoint: str,
    available: bool,
    review_text: Optional[str],
    error_msg: Optional[str],
    report_data: Dict[str, Any],
) -> Dict[str, Any]:
    """Structure the combined scan and AI review output."""
    return {
        "reviewer": "git-security-sentinel-ai",
        "version": VERSION,
        "inference_engine": "ollama",
        "model": model,
        "endpoint": endpoint,
        "inference_completed": available and bool(review_text),
        "error": error_msg,
        "original_summary": report_data.get("summary", {}),
        "ai_review": review_text,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai_review.py",
        description="Git Security Sentinel: Local AI Security Reviewer via Ollama.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python scripts/ai_review.py --report scan-report.json
  python scripts/ai_review.py --report scan-report.json --model gemma3:4b
  python scripts/ai_review.py --report scan-report.json --diff sanitized.patch --output ai-review.md
""",
    )

    parser.add_argument(
        "--report",
        required=True,
        metavar="JSON_FILE",
        help="Path to JSON scan report generated by scan_diff.py.",
    )
    parser.add_argument(
        "--diff",
        metavar="DIFF_FILE",
        help="Optional path to sanitized diff patch file for contextual inspection.",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        metavar="MODEL_NAME",
        help=f"Ollama model name (default: {DEFAULT_MODEL}).",
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        metavar="URL",
        help=f"Local Ollama API endpoint (default: {DEFAULT_ENDPOINT}).",
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Explicitly permit non-loopback endpoints (disabled by default for privacy).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SEC,
        metavar="SECONDS",
        help=f"Inference HTTP request timeout in seconds (default: {DEFAULT_TIMEOUT_SEC}).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--output",
        metavar="OUT_FILE",
        help="Path to save AI review output.",
    )

    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    # 1. Privacy Check: Enforce loopback endpoint
    if not args.allow_remote and not is_loopback_url(args.endpoint):
        sys.stderr.write(
            f"Error: Non-loopback endpoint '{args.endpoint}' rejected for privacy. "
            f"By default, Git Security Sentinel only communicates with local Ollama instances (127.0.0.1 / localhost). "
            f"Use --allow-remote to explicitly override.\n"
        )
        return 2

    # 2. Read scan report
    report_path = Path(args.report)
    if not report_path.is_file():
        sys.stderr.write(f"Error: Scan report file '{args.report}' does not exist.\n")
        return 2

    try:
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as e:
        sys.stderr.write(f"Error: Failed to parse scan report JSON '{args.report}': {e}\n")
        return 2

    # 3. Read optional sanitized diff
    sanitized_diff = None
    if args.diff:
        diff_path = Path(args.diff)
        if diff_path.is_file():
            try:
                sanitized_diff = diff_path.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                sys.stderr.write(f"Warning: Could not read diff file '{args.diff}': {e}\n")

    # 4. Check Ollama availability
    available, avail_msg = check_ollama_available(args.endpoint, timeout_sec=5)
    if not available:
        error_info = (
            f"Local Ollama server is not reachable at {args.endpoint}.\n"
            f"Details: {avail_msg}\n\n"
            f"To enable AI contextual review:\n"
            f"  1. Install Ollama: https://ollama.com\n"
            f"  2. Start the Ollama daemon: `ollama serve`\n"
            f"  3. Pull the recommended open-weight model: `ollama pull {args.model}`\n"
            f"  4. Re-run this command."
        )
        out_structure = format_ai_review_report(
            model=args.model,
            endpoint=args.endpoint,
            available=False,
            review_text=None,
            error_msg=error_info,
            report_data=report_data,
        )

        if args.format == "json":
            out_str = json.dumps(out_structure, indent=2)
        else:
            out_str = (
                "====================================================================\n"
                "  GIT SECURITY SENTINEL - LOCAL AI REVIEWER\n"
                "====================================================================\n"
                f"Status: INFERENCE SKIPPED (Ollama Unavailable)\n\n"
                f"{error_info}\n"
                "====================================================================\n"
            )

        print(out_str)
        if args.output:
            Path(args.output).write_text(out_str, encoding="utf-8")
        return 0

    # 5. Build prompt and query Ollama
    system_prompt = build_system_prompt()
    user_prompt = build_user_prompt(report_data, sanitized_diff)

    print(f"Connecting to local Ollama at {args.endpoint} (model: {args.model})...", file=sys.stderr)
    success, review_text, err_msg = query_ollama(
        endpoint=args.endpoint,
        model=args.model,
        prompt=user_prompt,
        system_prompt=system_prompt,
        timeout_sec=args.timeout,
    )

    out_structure = format_ai_review_report(
        model=args.model,
        endpoint=args.endpoint,
        available=True,
        review_text=review_text if success else None,
        error_msg=err_msg if not success else None,
        report_data=report_data,
    )

    if args.format == "json":
        out_str = json.dumps(out_structure, indent=2)
    else:
        out_lines = [
            "====================================================================",
            f"  GIT SECURITY SENTINEL - LOCAL AI REVIEW ({args.model})",
            "====================================================================",
            f"Endpoint : {args.endpoint} (Privacy-Preserving Loopback)",
            f"Status   : {'COMPLETED' if success else 'FAILED'}",
            "-" * 68,
        ]
        if success and review_text:
            out_lines.append(review_text)
        else:
            out_lines.append(f"Inference Error: {err_msg}")
        out_lines.append("=" * 68)
        out_str = "\n".join(out_lines)

    print(out_str)
    if args.output:
        Path(args.output).write_text(out_str, encoding="utf-8")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
