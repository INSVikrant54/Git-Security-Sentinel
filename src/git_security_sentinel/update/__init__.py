"""
Git Security Sentinel - PyPI Update Checker and Self-Upgrade.
"""

from git_security_sentinel.update.checker import (
    CACHE_EXPIRY_SEC,
    DEFAULT_PYPI_JSON_URL,
    PACKAGE_NAME,
    check_for_pypi_update,
    get_cache_file_path,
    print_update_banner,
    pypi_json_url,
    PYPI_JSON_URL,
    run_self_upgrade,
)

__all__ = [
    "CACHE_EXPIRY_SEC",
    "DEFAULT_PYPI_JSON_URL",
    "PACKAGE_NAME",
    "check_for_pypi_update",
    "get_cache_file_path",
    "print_update_banner",
    "pypi_json_url",
    "PYPI_JSON_URL",
    "run_self_upgrade",
]
