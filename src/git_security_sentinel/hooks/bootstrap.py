"""
Git Security Sentinel - One-Command Project Bootstrap.

Creates the minimal starter files and installs the pre-commit hook so a
developer can go from clone to protected repository with a single command:
`git-scan --init`.
"""

from pathlib import Path
from typing import List, Optional, Tuple

from git_security_sentinel.hooks.installer import install_pre_commit_hook


CONFIG_TEMPLATE = """# Git Security Sentinel configuration
# AI defaults live here so `git scan --ai` needs no extra flags.
severity_threshold: high

ai:
  provider: auto          # auto, ollama, gemini, openai, or groq
  # model: gemma3:4b      # override the provider default model
  # allow_remote: false   # only for non-loopback Ollama endpoints
"""

IGNORE_TEMPLATE = """# Paths excluded from Git Security Sentinel scans
tests/fixtures/**
**/*.generated.py
"""

ENV_TEMPLATE = """# Add only the keys you actually use. Never commit real credentials.
# GEMINI_API_KEY=your-key
# OPENAI_API_KEY=your-key
# GROQ_API_KEY=your-key
"""

STARTER_FILES = (
    (".sentinel.yaml", CONFIG_TEMPLATE),
    (".sentinelignore", IGNORE_TEMPLATE),
    (".env.example", ENV_TEMPLATE),
)


def bootstrap_project(
    repo_root: Optional[Path] = None,
    force: bool = False,
) -> Tuple[bool, List[str]]:
    """
    Bootstrap a repository with starter config files and a pre-commit hook.

    Existing files are never overwritten unless `force` is True.

    Returns:
        (success, messages): success is False only if a write or hook install
        actually failed; skipped files are reported but are not an error.
    """
    root = (Path(repo_root) if repo_root else Path.cwd()).resolve()
    messages: List[str] = []
    ok = True

    for name, template in STARTER_FILES:
        target = root / name
        if target.exists() and not force:
            messages.append(f"[skip] {name} already exists (use --force to overwrite)")
            continue
        try:
            target.write_text(template, encoding="utf-8")
            messages.append(f"[ok]   created {name}")
        except Exception as e:
            ok = False
            messages.append(f"[fail] could not write {name}: {e}")

    hook_ok, hook_msg = install_pre_commit_hook(repo_root=root, force=force)
    if hook_ok:
        messages.append("[ok]   installed .git/hooks/pre-commit")
    elif "already exists" in hook_msg:
        messages.append(f"[skip] {hook_msg}")
    else:
        ok = False
        messages.append(f"[fail] {hook_msg}")

    if ok:
        messages.append("")
        messages.append("Done. Next: git add . && git scan --ai")
    return ok, messages
