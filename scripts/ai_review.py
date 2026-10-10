#!/usr/bin/env python3
"""
Git Security Sentinel - Universal AI Security Reviewer
Contextual security reviewer for Git Security Sentinel reports.
Supports local open-weight models via Ollama (default: loopback only) and
cloud models via Google AI Studio (Gemini), Groq, and OpenAI with pre-redacted privacy.
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
DEFAULT_TIMEOUT_SEC = 60

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}

PROVIDER_DEFAULTS = {
    "ollama": {
        "model": "gemma3:4b",
        "endpoint": "http://127.0.0.1:11434",
        "env_var": None,
    },
    "gemini": {
        "model": "gemini-1.5-flash",
        "endpoint": "https://generativelanguage.googleapis.com",
        "env_var": "GEMINI_API_KEY",
    },
    "openai": {
        "model": "gpt-4o-mini",
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "env_var": "OPENAI_API_KEY",
    },
    "groq": {
        "model": "llama-3.3-70b-versatile",
        "endpoint": "https://api.groq.com/openai/v1/chat/completions",
        "env_var": "GROQ_API_KEY",
    },
}


def load_env_file(env_path: Optional[Path] = None) -> None:
    """Load environment variables from a local .env file if it exists, without third-party packages."""
    target = env_path or (Path.cwd() / ".env")
    if not target.is_file():
        return
    try:
        for line in target.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip("'\"")
            if k and k not in os.environ:
                os.environ[k] = v
    except Exception:
        pass


def detect_provider(requested: Optional[str] = None) -> str:
    """Determine provider based on user request or environment variable detection."""
    if requested and requested.lower() != "auto":
        return requested.lower()
    if os.environ.get("GEMINI_API_KEY"):
        return "gemini"
    if os.environ.get("GROQ_API_KEY"):
        return "groq"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    return "ollama"


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
    """Send prompt to Ollama /api/generate without streaming."""
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


def query_gemini(
    api_key: str,
    model: str,
    prompt: str,
    system_prompt: str,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Query Google AI Studio Gemini API using standard library urllib.request."""
    clean_key = api_key.strip()
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={clean_key}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "generationConfig": {
            "temperature": 0.2,
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
                candidates = resp_json.get("candidates", [])
                if candidates and "content" in candidates[0]:
                    parts = candidates[0]["content"].get("parts", [])
                    if parts and "text" in parts[0]:
                        return True, parts[0]["text"], None
                return False, None, "Gemini API returned an empty candidate list."
            return False, None, f"Gemini API returned HTTP status {resp.status}"
    except urllib.error.HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode("utf-8")
        except Exception:
            pass
        return False, None, f"Gemini HTTP Error {e.code}: {e.reason}. Details: {error_body}"
    except urllib.error.URLError as e:
        return False, None, f"Connection error contacting Gemini: {e.reason}"
    except TimeoutError:
        return False, None, f"Inference request timed out after {timeout_sec} seconds."
    except Exception as e:
        return False, None, f"Unexpected error querying Gemini API: {e}"


def query_openai_compatible(
    endpoint: str,
    api_key: str,
    model: str,
    prompt: str,
    system_prompt: str,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Query OpenAI-compatible endpoint (OpenAI, Groq, Mistral, OpenRouter)."""
    clean_key = api_key.strip()
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }

    try:
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {clean_key}",
                "User-Agent": f"git-security-sentinel-ai-reviewer/{VERSION}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            if resp.status == 200:
                resp_json = json.loads(resp.read().decode("utf-8"))
                choices = resp_json.get("choices", [])
                if choices and "message" in choices[0]:
                    return True, choices[0]["message"].get("content", ""), None
                return False, None, "API returned an empty choices list."
            return False, None, f"API returned HTTP status {resp.status}"
    except urllib.error.HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode("utf-8")
        except Exception:
            pass
        return False, None, f"API HTTP Error {e.code}: {e.reason}. Details: {error_body}"
    except urllib.error.URLError as e:
        return False, None, f"Connection error: {e.reason}"
    except TimeoutError:
        return False, None, f"Inference request timed out after {timeout_sec} seconds."
    except Exception as e:
        return False, None, f"Unexpected error querying API: {e}"


def extract_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    """Extract and parse JSON object from LLM output, gracefully stripping code fences."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()

    try:
        return json.loads(cleaned)
    except Exception:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(cleaned[start : end + 1])
            except Exception:
                pass
    return None


def build_system_prompt(format_mode: str = "text") -> str:
    if format_mode == "json":
        return (
            "You are an expert Application Security Engineer reviewing static security scanner findings for Git diffs. "
            "Your task is to provide concise, actionable, and contextual security triage. "
            "Distinguish probable true positives from likely false positives (such as test fixtures, mocks, or benign dev configs). "
            "Respond ONLY with a single valid JSON object matching this schema:\n"
            "{\n"
            '  "summary": "High-level summary of risks in this diff",\n'
            '  "reviews": [\n'
            "    {\n"
            '      "rule_id": "string",\n'
            '      "file": "string",\n'
            '      "line": 0,\n'
            '      "assessment": "genuine_risk | likely_false_positive | context_dependent",\n'
            '      "risk_explanation": "string",\n'
            '      "safe_alternative": "string"\n'
            "    }\n"
            "  ]\n"
            "}\n"
            "Return valid JSON only. Do not add markdown explanation outside the JSON."
        )
    return (
        "You are an expert Application Security Engineer reviewing static security scanner findings for Git diffs. "
        "Your task is to provide concise, actionable, and contextual security triage. "
        "Distinguish probable true positives from likely false positives (such as test fixtures, mocks, or benign dev configs). "
        "Explain the real-world attack risk, suggest safer code alternatives, and provide priority remediation steps. "
        "Do NOT repeat the raw findings list verbatim. Add security engineering insight. "
        "Output your review structured with clear sections: "
        "1. Executive Summary, 2. Finding-by-Finding Triage & False-Positive Analysis, 3. Safer Code Alternatives, 4. Immediate Recommended Actions."
    )


def build_user_prompt(report_data: Dict[str, Any], sanitized_diff: Optional[str] = None, format_mode: str = "text") -> str:
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
        trimmed_diff = sanitized_diff[:3000]
        if len(sanitized_diff) > 3000:
            trimmed_diff += "\n... [diff truncated for length] ..."
        prompt_parts.append("")
        prompt_parts.append("Sanitized Diff Context (secrets already masked):")
        prompt_parts.append("```diff")
        prompt_parts.append(trimmed_diff)
        prompt_parts.append("```")

    prompt_parts.append("")
    if format_mode == "json":
        prompt_parts.append("Evaluate each finding and return the requested structured JSON object.")
    else:
        prompt_parts.append(
            "Provide your contextual security evaluation. For each finding, evaluate whether it is likely a true vulnerability or a false positive, explain why, and suggest the safest alternative."
        )

    return "\n".join(prompt_parts)


def format_ai_review_report(
    model: str,
    provider: str,
    endpoint: str,
    available: bool,
    review_text: Optional[str],
    error_msg: Optional[str],
    report_data: Dict[str, Any],
    format_mode: str = "text",
) -> Dict[str, Any]:
    """Structure the combined scan and AI review output."""
    structured_data = None
    if review_text and format_mode == "json":
        structured_data = extract_json_from_text(review_text)

    out: Dict[str, Any] = {
        "reviewer": "git-security-sentinel-ai",
        "version": VERSION,
        "provider": provider,
        "model": model,
        "endpoint": endpoint if provider == "ollama" else "[CLOUD_PROVIDER]",
        "format": format_mode,
        "inference_completed": available and bool(review_text),
        "error": error_msg,
        "original_summary": report_data.get("summary", {}),
    }

    if structured_data is not None:
        out["structured_review"] = structured_data
        out["ai_review"] = review_text
    else:
        out["ai_review"] = review_text

    return out


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai_review.py",
        description="Git Security Sentinel: Multi-Provider AI Security Reviewer.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # 1. Local Ollama (Default, 100% Private, Zero Key):
  python scripts/ai_review.py --report scan-report.json
  python scripts/ai_review.py --report scan-report.json --provider ollama --model gemma3:4b

  # 2. Google AI Studio (Gemini):
  python scripts/ai_review.py --report scan-report.json --provider gemini --model gemini-1.5-flash

  # 3. OpenAI or Groq:
  python scripts/ai_review.py --report scan-report.json --provider openai --model gpt-4o-mini
  python scripts/ai_review.py --report scan-report.json --provider groq --model llama-3.3-70b-versatile

  # 4. Machine-Readable Structured JSON Mode:
  python scripts/ai_review.py --report scan-report.json --format json --output ai-review.json
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
        "--provider",
        choices=["auto", "ollama", "gemini", "openai", "groq"],
        default="auto",
        help="Inference provider to use (default: auto detects based on API keys, or falls back to ollama).",
    )
    parser.add_argument(
        "--model",
        metavar="MODEL_NAME",
        help="Model name (defaults to provider's recommended model if omitted).",
    )
    parser.add_argument(
        "--endpoint",
        metavar="URL",
        help="Custom API endpoint (defaults to provider's standard endpoint).",
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Explicitly permit non-loopback endpoints for Ollama (disabled by default for privacy).",
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


def run_ai_review(
    report_data: Dict[str, Any],
    sanitized_diff: Optional[str] = None,
    provider: str = "auto",
    model: Optional[str] = None,
    endpoint: Optional[str] = None,
    allow_remote: bool = False,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    format_mode: str = "text",
) -> Tuple[bool, Dict[str, Any], str]:
    """
    Execute AI security review programmatically on a parsed scan report.
    Returns:
        (success: bool, structured_result: Dict[str, Any], formatted_output: str)
    """
    load_env_file()
    active_provider = detect_provider(provider)
    defaults = PROVIDER_DEFAULTS.get(active_provider, PROVIDER_DEFAULTS["ollama"])
    active_model = model or defaults["model"]
    active_endpoint = endpoint or defaults["endpoint"]

    # 1. Provider validation & authentication
    api_key: Optional[str] = None
    if active_provider == "ollama":
        if not allow_remote and not is_loopback_url(active_endpoint):
            err_msg = (
                f"Non-loopback endpoint '{active_endpoint}' rejected for privacy. "
                f"By default, Ollama requests must connect to local loopback (127.0.0.1 / localhost). "
                f"Use --allow-remote to explicitly override."
            )
            out_struct = format_ai_review_report(
                model=active_model,
                provider=active_provider,
                endpoint=active_endpoint,
                available=False,
                review_text=None,
                error_msg=err_msg,
                report_data=report_data,
                format_mode=format_mode,
            )
            return False, out_struct, f"Error: {err_msg}"
    elif active_provider == "gemini":
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            err_msg = (
                "Google AI Studio requires GEMINI_API_KEY environment variable.\n"
                "Set it via PowerShell: $env:GEMINI_API_KEY = 'your_key_here'\n"
                "Or define GEMINI_API_KEY in a local .env file."
            )
            out_struct = format_ai_review_report(
                model=active_model,
                provider=active_provider,
                endpoint=active_endpoint,
                available=False,
                review_text=None,
                error_msg=err_msg,
                report_data=report_data,
                format_mode=format_mode,
            )
            return False, out_struct, f"Error: {err_msg}"
    elif active_provider == "openai":
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            err_msg = (
                "OpenAI provider requires OPENAI_API_KEY environment variable.\n"
                "Set it via PowerShell: $env:OPENAI_API_KEY = 'your_key_here'"
            )
            out_struct = format_ai_review_report(
                model=active_model,
                provider=active_provider,
                endpoint=active_endpoint,
                available=False,
                review_text=None,
                error_msg=err_msg,
                report_data=report_data,
                format_mode=format_mode,
            )
            return False, out_struct, f"Error: {err_msg}"
    elif active_provider == "groq":
        api_key = os.environ.get("GROQ_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            err_msg = (
                "Groq provider requires GROQ_API_KEY environment variable.\n"
                "Set it via PowerShell: $env:GROQ_API_KEY = 'your_key_here'"
            )
            out_struct = format_ai_review_report(
                model=active_model,
                provider=active_provider,
                endpoint=active_endpoint,
                available=False,
                review_text=None,
                error_msg=err_msg,
                report_data=report_data,
                format_mode=format_mode,
            )
            return False, out_struct, f"Error: {err_msg}"

    # 2. Check Ollama server availability
    if active_provider == "ollama":
        available, avail_msg = check_ollama_available(active_endpoint, timeout_sec=5)
        if not available:
            error_info = (
                f"Local Ollama server is not reachable at {active_endpoint}.\n"
                f"Details: {avail_msg}\n\n"
                f"To enable local Gemma AI contextual review:\n"
                f"  1. Install Ollama: https://ollama.com\n"
                f"  2. Start the Ollama daemon: `ollama serve` (or open Ollama app)\n"
                f"  3. Pull the recommended open-weight model: `ollama pull {active_model}`\n"
                f"  4. Re-run this scan.\n\n"
                f"Alternative: If you have a Google AI Studio key, set GEMINI_API_KEY and use `--provider gemini`."
            )
            out_struct = format_ai_review_report(
                model=active_model,
                provider=active_provider,
                endpoint=active_endpoint,
                available=False,
                review_text=None,
                error_msg=error_info,
                report_data=report_data,
                format_mode=format_mode,
            )
            if format_mode == "json":
                out_str = json.dumps(out_struct, indent=2)
            else:
                out_str = (
                    "====================================================================\n"
                    "  GIT SECURITY SENTINEL - LOCAL AI REVIEWER\n"
                    "====================================================================\n"
                    f"Status: INFERENCE SKIPPED (Ollama Unavailable)\n\n"
                    f"{error_info}\n"
                    "===================================================================="
                )
            return False, out_struct, out_str

    # 3. Build prompts
    system_prompt = build_system_prompt(format_mode=format_mode)
    user_prompt = build_user_prompt(report_data, sanitized_diff, format_mode=format_mode)

    sys.stderr.write(f"Connecting to {active_provider.upper()} (model: {active_model})...\n")

    # 4. Query provider
    success: bool = False
    review_text: Optional[str] = None
    err_msg: Optional[str] = None

    if active_provider == "ollama":
        success, review_text, err_msg = query_ollama(
            endpoint=active_endpoint,
            model=active_model,
            prompt=user_prompt,
            system_prompt=system_prompt,
            timeout_sec=timeout_sec,
        )
    elif active_provider == "gemini":
        success, review_text, err_msg = query_gemini(
            api_key=api_key or "",
            model=active_model,
            prompt=user_prompt,
            system_prompt=system_prompt,
            timeout_sec=timeout_sec,
        )
    elif active_provider in {"openai", "groq"}:
        success, review_text, err_msg = query_openai_compatible(
            endpoint=active_endpoint,
            api_key=api_key or "",
            model=active_model,
            prompt=user_prompt,
            system_prompt=system_prompt,
            timeout_sec=timeout_sec,
        )

    # 5. Format results
    out_structure = format_ai_review_report(
        model=active_model,
        provider=active_provider,
        endpoint=active_endpoint,
        available=True,
        review_text=review_text if success else None,
        error_msg=err_msg if not success else None,
        report_data=report_data,
        format_mode=format_mode,
    )

    if format_mode == "json":
        out_str = json.dumps(out_structure, indent=2)
    else:
        out_lines = [
            "====================================================================",
            f"  GIT SECURITY SENTINEL - AI SECURITY REVIEW ({active_provider.upper()} - {active_model})",
            "====================================================================",
            f"Provider : {active_provider.upper()}",
            f"Status   : {'COMPLETED' if success else 'FAILED'}",
            "-" * 68,
        ]
        if success and review_text:
            out_lines.append(review_text)
        else:
            out_lines.append(f"Inference Error: {err_msg}")
        out_lines.append("=" * 68)
        out_str = "\n".join(out_lines)

    return success, out_structure, out_str


def main() -> int:
    load_env_file()
    parser = build_arg_parser()
    args = parser.parse_args()

    # Read scan report
    report_path = Path(args.report)
    if not report_path.is_file():
        sys.stderr.write(f"Error: Scan report file '{args.report}' does not exist.\n")
        return 2

    try:
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as e:
        sys.stderr.write(f"Error: Failed to parse scan report JSON '{args.report}': {e}\n")
        return 2

    # Read optional sanitized diff
    sanitized_diff = None
    if args.diff:
        diff_path = Path(args.diff)
        if diff_path.is_file():
            try:
                sanitized_diff = diff_path.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                sys.stderr.write(f"Warning: Could not read diff file '{args.diff}': {e}\n")

    success, out_struct, out_str = run_ai_review(
        report_data=report_data,
        sanitized_diff=sanitized_diff,
        provider=args.provider,
        model=args.model,
        endpoint=args.endpoint,
        allow_remote=args.allow_remote,
        timeout_sec=args.timeout,
        format_mode=args.format,
    )

    print(out_str)
    if args.output:
        Path(args.output).write_text(out_str, encoding="utf-8")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

