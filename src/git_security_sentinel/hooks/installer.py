"""
Git Security Sentinel - Pre-Commit Hook Installer.
Installs executable pre-commit hook into .git/hooks/pre-commit.
Zero third-party dependencies.
"""

import os
from pathlib import Path
import subprocess
from typing import Optional, Tuple


def install_pre_commit_hook(
    repo_root: Optional[Path] = None,
    force: bool = False,
) -> Tuple[bool, str]:
    """
    Installs Git Security Sentinel pre-commit hook into repository .git/hooks/pre-commit.

    Args:
        repo_root: Optional path to repository root. Defaults to current working directory.
        force: If True, overwrites existing pre-commit hook if not a sentinel hook.

    Returns:
        Tuple[bool, str]: (success, status_message)
    """
    root = (Path(repo_root) if repo_root else Path.cwd()).resolve()

    # Discover .git directory
    git_dir: Optional[Path] = None
    dot_git = root / ".git"
    if dot_git.is_dir():
        git_dir = dot_git
    elif dot_git.is_file():
        try:
            content = dot_git.read_text(encoding="utf-8", errors="replace").strip()
            if content.startswith("gitdir:"):
                target = content.split(":", 1)[1].strip()
                git_dir = (root / target).resolve()
        except Exception:
            pass

    if git_dir is None:
        try:
            res = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=str(root),
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode != 0 or not res.stdout.strip():
                return False, f"Directory is not a Git repository: {root}"
            if Path(res.stdout.strip()).resolve() != root:
                return False, f"Directory is not a Git repository: {root}"

            res_dir = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                cwd=str(root),
                capture_output=True,
                text=True,
                check=False,
            )
            if res_dir.returncode == 0 and res_dir.stdout.strip():
                cand = Path(res_dir.stdout.strip())
                git_dir = cand if cand.is_absolute() else (root / cand).resolve()
        except Exception:
            return False, f"Directory is not a Git repository: {root}"

    if git_dir is None or not git_dir.exists():
        return False, f"Directory is not a Git repository: {root}"

    hooks_dir = git_dir / "hooks"
    hook_file = hooks_dir / "pre-commit"

    if hook_file.is_file():
        try:
            existing_content = hook_file.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return False, f"Failed to read existing pre-commit hook: {e}"

        if "git-scan" not in existing_content:
            if not force:
                return (
                    False,
                    f"A pre-commit hook already exists at {hook_file}. Use --force to overwrite it.",
                )

    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_script = "#!/bin/sh\n# Git Security Sentinel pre-commit hook\nexec git-scan --staged\n"

    try:
        hook_file.write_text(hook_script, encoding="utf-8")
        try:
            os.chmod(hook_file, 0o755)
        except Exception:
            pass
    except Exception as e:
        return False, f"Failed to write pre-commit hook: {e}"

    return True, "Hook installed successfully."
