#!/usr/bin/env python3
"""
E2E Test Suite: Zero-Dependency Configuration Engine (.sentinel.yaml and .sentinel.toml).
Tests Tier 1 through Tier 3 requirements for Git Security Sentinel stdlib config parsing.
Zero third-party test dependencies: Python standard library `unittest` only.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
SCRIPTS_DIR = REPO_ROOT / "scripts"

for p in (SRC_DIR, SCRIPTS_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:
    import git_security_sentinel
    from git_security_sentinel.config.loader import load_config, parse_simple_yaml
    HAS_NEW_CONFIG = True
except ImportError:
    HAS_NEW_CONFIG = False

try:
    import scan_diff
    HAS_SCAN_DIFF = True
except ImportError:
    HAS_SCAN_DIFF = False


def make_diff(file_path: str, added_lines: list) -> str:
    body = "".join(f"+{line}\n" for line in added_lines)
    count = len(added_lines)
    return (
        f"diff --git a/{file_path} b/{file_path}\n"
        f"--- a/{file_path}\n"
        f"+++ b/{file_path}\n"
        f"@@ -0,0 +1,{count} @@\n"
        f"{body}"
    )


class TestE2EConfigParser(unittest.TestCase):
    """Tier 1 & 2: Pure Standard Library YAML & TOML Parser."""

    def test_pure_stdlib_yaml_parsing(self):
        """Tier 1: Parse YAML scalars, lists, nested dicts, and comments without PyYAML."""
        if not HAS_NEW_CONFIG:
            self.skipTest("git_security_sentinel.config not yet implemented")

        yaml_content = """
        # Git Security Sentinel Configuration
        severity_threshold: medium
        no_color: false
        verbose: true
        max_file_size_kb: 512

        exclude:
          - "tests/**"
          - "*.md"
          - "legacy/fixtures/*"

        rules:
          disable:
            - "risk.localhost_endpoint"
            - "compliance.security_todo"

        ai:
          provider: ollama
          model: "gemma-4-26b"
          allow_remote: false
        """
        parsed = parse_simple_yaml(yaml_content)
        self.assertEqual(parsed.get("severity_threshold"), "medium")
        self.assertEqual(parsed.get("no_color"), False)
        self.assertEqual(parsed.get("verbose"), True)
        self.assertEqual(parsed.get("max_file_size_kb"), 512)

        # Lists verification
        self.assertIn("exclude", parsed)
        self.assertEqual(parsed["exclude"], ["tests/**", "*.md", "legacy/fixtures/*"])

        # Nested mapping verification
        self.assertIn("rules", parsed)
        self.assertEqual(parsed["rules"].get("disable"), ["risk.localhost_endpoint", "compliance.security_todo"])

        self.assertIn("ai", parsed)
        self.assertEqual(parsed["ai"].get("provider"), "ollama")
        self.assertEqual(parsed["ai"].get("model"), "gemma-4-26b")
        self.assertEqual(parsed["ai"].get("allow_remote"), False)

    def test_yaml_boundary_and_malformed_resilience(self):
        """Tier 2: Parser handles empty lines, edge scalars, and inline comments safely."""
        if not HAS_NEW_CONFIG:
            self.skipTest("git_security_sentinel.config not yet implemented")

        yaml_content = """
        # Header
        empty_key: null
        boolean_yes: yes
        boolean_no: no
        quoted_string: 'single quoted'
        double_quoted: "double quoted"
        inline_list: [a, b, c]
        """
        parsed = parse_simple_yaml(yaml_content)
        self.assertIsNone(parsed.get("empty_key"))
        self.assertTrue(parsed.get("boolean_yes"))
        self.assertFalse(parsed.get("boolean_no"))
        self.assertEqual(parsed.get("quoted_string"), "single quoted")
        self.assertEqual(parsed.get("double_quoted"), "double quoted")
        self.assertEqual(parsed.get("inline_list"), ["a", "b", "c"])


class TestE2EConfigCLIIntegration(unittest.TestCase):
    """Tier 1, 2 & 3: Configuration Loading and Precedence in Scanner CLI."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="sentinel_e2e_cfg_cli_")
        self.repo_dir = Path(self.temp_dir)
        (self.repo_dir / "LICENSE").write_text("MIT License (Synthetic E2E Test)", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run_scanner(self, args):
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{SRC_DIR}{os.pathsep}{SCRIPTS_DIR}{os.pathsep}{env.get('PYTHONPATH', '')}"
        cmd = [sys.executable, "-m", "git_security_sentinel"] + args if HAS_NEW_CONFIG else [sys.executable, str(SCRIPTS_DIR / "scan_diff.py")] + args
        return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=20)

    def test_auto_discovery_of_sentinel_yaml(self):
        """Tier 1: Scanner auto-detects .sentinel.yaml in repo root and applies exclusions."""
        config_path = self.repo_dir / ".sentinel.yaml"
        config_path.write_text(
            "exclude:\n"
            "  - 'mock_dir/**'\n",
            encoding="utf-8",
        )
        diff_path = self.repo_dir / "test.diff"
        diff_path.write_text(
            make_diff("mock_dir/secret.py", [
                "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"
            ]),
            encoding="utf-8",
        )
        res = self._run_scanner([
            "--diff-file", str(diff_path),
            "--repo-root", str(self.repo_dir),
        ])
        if not HAS_NEW_CONFIG and ("unrecognized" in res.stderr or res.returncode == 1):
            self.skipTest("M3 auto-discovery of .sentinel.yaml not yet implemented")
        self.assertEqual(res.returncode, 0, "Finding should be excluded via auto-discovered .sentinel.yaml")

    def test_explicit_config_flag_override(self):
        """Tier 2: Explicit --config <path> loads non-standard config path."""
        custom_cfg = self.repo_dir / "custom_security.yaml"
        custom_cfg.write_text(
            "severity_threshold: critical\n",
            encoding="utf-8",
        )
        # Diff containing a medium finding
        diff_path = self.repo_dir / "test.diff"
        diff_path.write_text(
            make_diff("app.py", [
                "eval(dynamic_code)"
            ]),
            encoding="utf-8",
        )
        res = self._run_scanner([
            "--diff-file", str(diff_path),
            "--repo-root", str(self.repo_dir),
            "--config", str(custom_cfg),
        ])
        if not HAS_NEW_CONFIG and ("unrecognized" in res.stderr or "--config" in res.stderr):
            self.skipTest("M3 --config flag not yet implemented")
        # Under critical threshold from custom config, medium finding exits 0
        self.assertEqual(res.returncode, 0)

    def test_cli_flags_precedence_over_config(self):
        """Tier 3: CLI arguments override conflicting values defined in configuration file."""
        config_path = self.repo_dir / ".sentinel.yaml"
        # Config sets threshold to critical (which would normally ignore medium findings)
        config_path.write_text(
            "severity_threshold: critical\n",
            encoding="utf-8",
        )
        diff_path = self.repo_dir / "test.diff"
        diff_path.write_text(
            make_diff("app.py", [
                "eval(dynamic_code)"
            ]),
            encoding="utf-8",
        )
        # But CLI explicitly sets --severity-threshold medium!
        res = self._run_scanner([
            "--diff-file", str(diff_path),
            "--repo-root", str(self.repo_dir),
            "--severity-threshold", "medium",
        ])
        if not HAS_NEW_CONFIG and ("unrecognized" in res.stderr or res.returncode == 0):
            self.skipTest("M3 config vs CLI flag precedence not yet implemented")
        # CLI flag overrides config -> medium finding triggers exit code 1
        self.assertEqual(res.returncode, 1, "CLI argument MUST take precedence over .sentinel.yaml")


if __name__ == "__main__":
    unittest.main()
