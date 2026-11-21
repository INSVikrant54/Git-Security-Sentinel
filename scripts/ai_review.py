#!/usr/bin/env python3
"""
Git Security Sentinel - Universal AI Security Reviewer
Contextual security reviewer for Git Security Sentinel reports.
Complies with the Agent Skills Open Standard (https://agentskills.io/specification).

Backwards-compatible wrapper re-exporting AI reviewer implementation.
"""

import sys
from pathlib import Path

# Ensure src/ is importable even if package is not pip-installed
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _REPO_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from git_security_sentinel.ai_cli import (
    DEFAULT_TIMEOUT_SEC,
    LOOPBACK_HOSTS,
    PROVIDER_DEFAULTS,
    VERSION,
    build_arg_parser as _ai_build_arg_parser,
    build_system_prompt,
    build_user_prompt,
    check_ollama_available,
    detect_provider,
    extract_json_from_text,
    format_ai_review_report,
    is_loopback_url,
    load_env_file,
    main as _ai_main,
    query_gemini,
    query_ollama,
    query_openai_compatible,
    run_ai_review,
)


def build_arg_parser():
    return _ai_build_arg_parser(prog="ai_review.py")


def main(argv=None):
    return _ai_main(argv=argv, prog="ai_review.py")


if __name__ == "__main__":
    sys.exit(main())
