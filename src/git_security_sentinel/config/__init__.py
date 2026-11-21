"""
Git Security Sentinel - Configuration Package.
Provides zero-dependency YAML and TOML configuration loaders.
"""

from git_security_sentinel.config.loader import (
    load_config,
    parse_scalar,
    parse_simple_yaml,
)

__all__ = [
    "load_config",
    "parse_scalar",
    "parse_simple_yaml",
]
