"""
Git Security Sentinel - PyPI Self-Update and Cached Update Checker.
Zero external dependencies.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request

PACKAGE_NAME = "git-security-sentinel"
DEFAULT_PYPI_JSON_URL = f"https://pypi.org/pypi/{PACKAGE_NAME}/json"
PYPI_JSON_URL = DEFAULT_PYPI_JSON_URL  # backwards-compatible alias
CACHE_EXPIRY_SEC = 86400  # 24 hours

_PRE_STAGES = {"dev": -1, "a": 0, "alpha": 0, "b": 1, "beta": 1, "rc": 2, "c": 2, "post": 4}
_FINAL_STAGE = 3


def pypi_json_url(index_url: Optional[str] = None) -> str:
    """Resolve the JSON metadata URL for PyPI, TestPyPI, or a custom index."""
    if not index_url:
        return DEFAULT_PYPI_JSON_URL
    cleaned = index_url.strip().rstrip("/")
    if "/pypi/" in cleaned and cleaned.endswith("/json"):
        return cleaned
    parsed = urllib.parse.urlparse(cleaned)
    if parsed.scheme and parsed.netloc:
        root = f"{parsed.scheme}://{parsed.netloc}"
    else:
        root = "https://pypi.org"
    return f"{root}/pypi/{PACKAGE_NAME}/json"


def get_cache_file_path(index_url: Optional[str] = None) -> Path:
    """Returns the platform-specific cache path, isolated per package index."""
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
    if index_url:
        host = urllib.parse.urlparse(index_url).netloc or index_url
        suffix = hashlib.sha1(host.encode("utf-8")).hexdigest()[:10]
        return cache_dir / f"update_check_{suffix}.json"
    return cache_dir / "update_check.json"


def _parse_version(value: str) -> Tuple[Tuple[int, ...], int, int]:
    """Parse a simple PEP 440-style version into (release, pre-stage, stage-number)."""
    match = re.match(
        r"^\s*(\d+(?:\.\d+)*)[-_.]?(dev|a|alpha|b|beta|rc|c|post)[-_.]?(\d*)",
        value.strip().lower(),
    )
    if not match:
        match = re.match(r"^\s*(\d+(?:\.\d+)*)", value.strip().lower())
    if not match:
        return (0,), _FINAL_STAGE, 0
    release = tuple(int(piece) for piece in match.group(1).split("."))
    release = release + (0,) * (4 - len(release)) if len(release) < 4 else release
    stage_name = match.group(2) if len(match.groups()) > 2 else None
    stage = _PRE_STAGES.get(stage_name, _FINAL_STAGE) if stage_name else _FINAL_STAGE
    number = int(match.group(3) or 0) if len(match.groups()) > 2 else 0
    return release, stage, number


def _is_newer_version(latest: str, current: str) -> bool:
    """Compare versions, treating pre-releases as older than the final release."""
    try:
        return _parse_version(latest) > _parse_version(current)
    except Exception:
        return False


def check_for_pypi_update(
    current_version: str,
    no_check: bool = False,
    index_url: Optional[str] = None,
) -> Optional[str]:
    """
    Checks if a newer version of git-security-sentinel is available on the package index.
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

    cache_file = get_cache_file_path(index_url)
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
                pypi_json_url(index_url),
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
        "\n" + "=" * 62 + "\n"
        f" Update available: {current_version} -> {latest_version:<26}\n"
        " Run 'git scan --update' to update to the latest release.\n"
        + "=" * 62 + "\n"
    )
    sys.stderr.write(msg)
    sys.stderr.flush()


def run_self_upgrade(index_url: Optional[str] = None) -> int:
    """
    Executes pip self-upgrade for git-security-sentinel.
    An optional package index URL supports TestPyPI and private mirrors.
    Returns pip process exit code.
    """
    print(f"[*] Upgrading {PACKAGE_NAME} via pip...")
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", PACKAGE_NAME]
    if index_url:
        cmd.extend(["--index-url", index_url])
    res = subprocess.run(cmd, check=False)
    if res.returncode == 0:
        print(f"[OK] {PACKAGE_NAME} upgraded successfully.")
    else:
        hint = f"pip install --upgrade {PACKAGE_NAME}"
        if index_url:
            hint += f" --index-url {index_url}"
        print(f"[ERROR] Upgrade failed with exit code {res.returncode}. Please run: {hint}")
    return res.returncode
