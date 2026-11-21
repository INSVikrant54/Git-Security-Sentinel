"""
Git Security Sentinel - Git Hooks Integration.
"""

from git_security_sentinel.hooks.bootstrap import bootstrap_project
from git_security_sentinel.hooks.installer import install_pre_commit_hook

__all__ = ["bootstrap_project", "install_pre_commit_hook"]
