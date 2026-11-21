"""
Git Security Sentinel - PyPI Self-Update and Cached Update Checker.
Zero external dependencies.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Optional, Tuple
import urllib.error
import urllib.request

PACKAGE_NAME = "git-security-sentinel"
PYPI_JSON_URL = f"https://pypi.org/pypi/{PACKAGE_NAME}/json"
CACHE_EXPIRY_SEC = 86400  # 24 hours


def get_cache_file_path() -> Path:
    """Returns the platform-specific path to the update check cache file."""
    if os.name == "nt":
        app_data = os.environ.get("LOCALAPPDATA")
        base = Path(app_data) if app_data else (Path.home() / "AppData" / "Local")
    else:
        xdg_cache = os.environ.get("XDG_CACHE_HOME")
        base = Path(xdg_cache) if xdg_cache else (Path.home() / ".cache")

    cache_dir = base / "git-security-sentinel"
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return cache_dir / "update_check.json"


def _is_newer_version(latest: str, current: str) -> bool:
    """Determines if latest version string is strictly newer than current."""
    try:
        def parse_v(v: str) -> Tuple[int, ...]:
            digits = re.findall(r"\d+", v)
            return tuple(int(x) for x in digits) if digits else (0,)

        return parse_v(latest) > parse_v(current)
    except Exception:
        return False


def check_for_pypi_update(current_version: str, no_check: bool = False) -> Optional[str]:
    """
    Checks if a newer version of git-security-sentinel is available on PyPI.
    Caches results for 24 hours to prevent repeated network queries.
    Never blocks or crashes on network failure.

    Returns:
        Optional[str]: latest_version string if an update is available, else None.
    """
    if no_check:
        return None

    # Bypass in CI environments and if disabled via environment variable
    if (
        os.environ.get("CI") == "true"
        or os.environ.get("GITHUB_ACTIONS") == "true"
        or os.environ.get("SENTINEL_NO_UPDATE_CHECK") == "1"
    ):
        return None

    cache_file = get_cache_file_path()
    now = time.time()
    latest_version: Optional[str] = None

    if cache_file.is_file():
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            last_checked = float(data.get("last_checked", 0))
            if now - last_checked < CACHE_EXPIRY_SEC:
                latest_version = data.get("latest_version")
        except Exception:
            pass

    if latest_version is None:
        try:
            req = urllib.request.Request(
                PYPI_JSON_URL,
                headers={"User-Agent": f"{PACKAGE_NAME}/{current_version}"},
            )
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if resp.status == 200:
                    payload = json.loads(resp.read().decode("utf-8"))
                    latest_version = payload.get("info", {}).get("version")
                    try:
                        cache_file.write_text(
                            json.dumps({
                                "last_checked": now,
                                "latest_version": latest_version,
                            }),
                            encoding="utf-8",
                        )
                    except Exception:
                        pass
        except Exception:
            return None

    if latest_version and _is_newer_version(latest_version, current_version):
        return latest_version

    return None


def print_update_banner(current_version: str, latest_version: str) -> None:
    """
    Prints a non-intrusive update notification banner strictly to sys.stderr
    so standard output (JSON / SARIF) remains pipeable and valid.
    """
    msg = (
        f"\n╭─────────────────────────────────────────────────────────────╮\n"
        f"│ Update available: {current_version} → {latest_version:<26} │\n"
        f"│ Run `git-scan --upgrade` to update to the latest release    │\n"
        f"╰─────────────────────────────────────────────────────────────╯\n"
    )
    sys.stderr.write(msg)
    sys.stderr.flush()


def run_self_upgrade() -> int:
    """
    Executes pip self-upgrade for git-security-sentinel.
    Returns pip process exit code.
    """
    print(f"[*] Upgrading {PACKAGE_NAME} via pip...")
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", PACKAGE_NAME]
    res = subprocess.run(cmd, check=False)
    if res.returncode == 0:
        print(f"[✓] {PACKAGE_NAME} upgraded successfully.")
    else:
        print(
            f"[✗] Upgrade failed with exit code {res.returncode}. "
            f"Please run: pip install --upgrade {PACKAGE_NAME}"
        )
    return res.returncode
