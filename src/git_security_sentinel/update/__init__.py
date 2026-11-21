"""
Git Security Sentinel - PyPI Update Checker and Self-Upgrade.
"""

from git_security_sentinel.update.checker import (
    CACHE_EXPIRY_SEC,
    PACKAGE_NAME,
    PYPI_JSON_URL,
    check_for_pypi_update,
    get_cache_file_path,
    print_update_banner,
    run_self_upgrade,
)

__all__ = [
    "CACHE_EXPIRY_SEC",
    "PACKAGE_NAME",
    "PYPI_JSON_URL",
    "check_for_pypi_update",
    "get_cache_file_path",
    "print_update_banner",
    "run_self_upgrade",
]
