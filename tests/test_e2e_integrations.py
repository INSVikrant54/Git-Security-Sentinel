#!/usr/bin/env python3
"""
E2E Test Suite: Integrations (Pre-commit hooks, PyPI Update Checker, AI Reviewer --fix & Cost).
Tests Tier 1 through Tier 4 requirements for Git Security Sentinel integrations.
Zero third-party test dependencies: Python standard library `unittest` and `unittest.mock` only.
"""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
SCRIPTS_DIR = REPO_ROOT / "scripts"

for p in (SRC_DIR, SCRIPTS_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:
    import git_security_sentinel
    from git_security_sentinel.cli import main as cli_main
    from git_security_sentinel.hooks.installer import install_pre_commit_hook
    from git_security_sentinel.redaction.redactor import redact_text
    from git_security_sentinel.update.checker import (
        _is_newer_version,
        check_for_pypi_update,
        get_cache_file_path,
        pypi_json_url,
        run_self_upgrade,
    )
    from git_security_sentinel.ai.cost import calculate_token_estimate, estimate_query_cost
    from git_security_sentinel.ai.prompts import build_system_prompt
    HAS_NEW_INTEGRATIONS = True
except ImportError:
    HAS_NEW_INTEGRATIONS = False

try:
    import ai_review
    HAS_AI_REVIEW = True
except ImportError:
    HAS_AI_REVIEW = False


class TestE2EPreCommitHookIntegration(unittest.TestCase):
    """Tier 1 & 2: Pre-commit hook definition and CLI hook installer."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="sentinel_e2e_hook_")
        self.repo_dir = Path(self.temp_dir)
        # Initialize Git repo
        subprocess.run(["git", "init"], cwd=str(self.repo_dir), check=True, capture_output=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_pre_commit_hooks_yaml_definition(self):
        """Tier 1: .pre-commit-hooks.yaml exists at repo root and specifies git-scan --staged."""
        hook_yaml_path = REPO_ROOT / ".pre-commit-hooks.yaml"
        if not hook_yaml_path.is_file():
            self.skipTest("M4 .pre-commit-hooks.yaml not yet created")

        content = hook_yaml_path.read_text(encoding="utf-8")
        self.assertIn("id: git-security-sentinel", content)
        self.assertIn("entry: git-scan --staged", content)
        self.assertIn("language: python", content)

    def test_hook_installer_creates_pre_commit_script(self):
        """Tier 1: install_pre_commit_hook installs executable hook into .git/hooks/pre-commit."""
        if not HAS_NEW_INTEGRATIONS:
            self.skipTest("git_security_sentinel.hooks not yet implemented")

        hook_path = self.repo_dir / ".git" / "hooks" / "pre-commit"
        success, msg = install_pre_commit_hook(repo_root=self.repo_dir, force=False)
        self.assertTrue(success, f"Failed to install hook: {msg}")
        self.assertTrue(hook_path.is_file(), "pre-commit hook was not written")
        hook_text = hook_path.read_text(encoding="utf-8")
        self.assertIn("git-scan --staged", hook_text)

    def test_hook_installer_conflict_safety_without_force(self):
        """Tier 2: Installer refuses to overwrite non-sentinel hook without --force."""
        if not HAS_NEW_INTEGRATIONS:
            self.skipTest("git_security_sentinel.hooks not yet implemented")

        hook_path = self.repo_dir / ".git" / "hooks" / "pre-commit"
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_text("#!/bin/sh\n# Custom other hook\nexit 0\n", encoding="utf-8")

        # Attempt install without force
        success, msg = install_pre_commit_hook(repo_root=self.repo_dir, force=False)
        self.assertFalse(success, "Installer should refuse to overwrite custom hook without --force")
        self.assertIn("Custom other hook", hook_path.read_text(encoding="utf-8"))

        # Now attempt with force
        success_force, msg_force = install_pre_commit_hook(repo_root=self.repo_dir, force=True)
        self.assertTrue(success_force)
        self.assertIn("git-scan --staged", hook_path.read_text(encoding="utf-8"))

    def test_hook_installer_rejects_uninitialized_directory(self):
        """Tier 2: Installer rejects uninitialized directory and does not mutate ancestors."""
        if not HAS_NEW_INTEGRATIONS:
            self.skipTest("git_security_sentinel.hooks not yet implemented")

        temp_uninit = Path(tempfile.mkdtemp(prefix="sentinel_uninit_"))
        try:
            # Must fail and not create .git or hooks
            success, msg = install_pre_commit_hook(repo_root=temp_uninit, force=False)
            self.assertFalse(success)
            self.assertIn("Directory is not a Git repository", msg)
            self.assertFalse((temp_uninit / ".git").exists())

            # Even with force=True, must still fail
            success_f, msg_f = install_pre_commit_hook(repo_root=temp_uninit, force=True)
            self.assertFalse(success_f)
            self.assertIn("Directory is not a Git repository", msg_f)
        finally:
            shutil.rmtree(temp_uninit, ignore_errors=True)

    def test_cli_install_hook_on_uninitialized_directory_exits_one(self):
        """Tier 2: CLI --install-hook on uninitialized directory prints to stderr and exits 1."""
        if not HAS_NEW_INTEGRATIONS:
            self.skipTest("git_security_sentinel.cli not yet implemented")

        temp_uninit = Path(tempfile.mkdtemp(prefix="sentinel_uninit_cli_"))
        try:
            stderr_buf = io.StringIO()
            with patch("sys.stderr", stderr_buf):
                code = cli_main(["--install-hook", "--repo-root", str(temp_uninit)])
            self.assertEqual(code, 1)
            err_output = stderr_buf.getvalue()
            self.assertIn("[ERROR]", err_output)
            self.assertIn("Directory is not a Git repository", err_output)
        finally:
            shutil.rmtree(temp_uninit, ignore_errors=True)


class TestE2EPyPIUpdateChecker(unittest.TestCase):
    """Tier 1, 2 & 3: 24-hr Cached PyPI update checker and non-intrusive stderr banner."""

    def test_pre_release_and_numeric_version_comparison(self):
        """Tier 2: Pre-releases sort before finals; numeric components compare correctly."""
        if not HAS_NEW_INTEGRATIONS:
            self.skipTest("update checker not available")
        self.assertTrue(_is_newer_version("1.2.0", "1.1.0"))
        self.assertTrue(_is_newer_version("1.10.0", "1.9.0"))
        self.assertFalse(_is_newer_version("1.2.0rc1", "1.2.0"))
        self.assertTrue(_is_newer_version("1.2.0", "1.2.0rc1"))
        self.assertTrue(_is_newer_version("1.2.0.post1", "1.2.0"))

    def test_custom_index_json_url(self):
        """Tier 2: TestPyPI and custom mirrors resolve to their own JSON endpoint."""
        if not HAS_NEW_INTEGRATIONS:
            self.skipTest("update checker not available")
        self.assertEqual(
            pypi_json_url("https://test.pypi.org/simple/"),
            "https://test.pypi.org/pypi/git-security-sentinel/json",
        )
        self.assertEqual(
            pypi_json_url("https://mirror.internal.example/simple"),
            "https://mirror.internal.example/pypi/git-security-sentinel/json",
        )

    def test_self_upgrade_passes_index_url(self):
        """Tier 2: --index-url is forwarded to pip during self-upgrade."""
        if not HAS_NEW_INTEGRATIONS:
            self.skipTest("update checker not available")
        with patch("git_security_sentinel.update.checker.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            self.assertEqual(
                run_self_upgrade(index_url="https://test.pypi.org/simple/"),
                0,
            )
            cmd = mock_run.call_args.args[0]
            self.assertIn("--index-url", cmd)
            self.assertIn("https://test.pypi.org/simple/", cmd)

    def test_version_flag_reports_available_update(self):
        """Tier 1: --version shows the version and any available update hint."""
        if not HAS_NEW_INTEGRATIONS:
            self.skipTest("update checker not available")
        buf = io.StringIO()
        with patch("git_security_sentinel.cli.check_for_pypi_update", return_value="9.9.9"):
            with patch("sys.stdout", buf):
                code = cli_main(["--version"], prog="git-scan")
        self.assertEqual(code, 0)
        self.assertIn("git-security-sentinel", buf.getvalue())
        self.assertIn("git scan --update", buf.getvalue())

    def test_cached_update_check_bypassed_in_ci(self):
        """Tier 1: Update check is bypassed when CI=true or SENTINEL_NO_UPDATE_CHECK=1."""
        if not HAS_NEW_INTEGRATIONS:
            self.skipTest("git_security_sentinel.update not yet implemented")

        with patch.dict(os.environ, {"CI": "true"}):
            result = check_for_pypi_update(current_version="1.0.0", no_check=False)
            self.assertIsNone(result, "Should bypass PyPI check in CI")

        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "CI": ""}):
            result = check_for_pypi_update(current_version="1.0.0", no_check=False)
            self.assertIsNone(result, "Should bypass PyPI check on GitHub Actions")

        with patch.dict(os.environ, {"SENTINEL_NO_UPDATE_CHECK": "1", "CI": ""}):
            result = check_for_pypi_update(current_version="1.0.0", no_check=False)
            self.assertIsNone(result, "Should bypass PyPI check when SENTINEL_NO_UPDATE_CHECK=1")

    def test_cached_update_check_uses_cache_file(self):
        """Tier 2: Update check respects 24-hour cache and does not repeat network calls."""
        if not HAS_NEW_INTEGRATIONS:
            self.skipTest("git_security_sentinel.update not yet implemented")

        temp_dir = tempfile.mkdtemp(prefix="sentinel_cache_")
        try:
            cache_file = Path(temp_dir) / "update_check.json"
            now = time.time()
            cache_file.write_text(json.dumps({
                "last_checked": now,
                "latest_version": "1.2.0"
            }), encoding="utf-8")

            with patch("git_security_sentinel.update.checker.get_cache_file_path", return_value=cache_file):
                with patch.dict(os.environ, {
                    "CI": "", "GITHUB_ACTIONS": "", "SENTINEL_NO_UPDATE_CHECK": ""
                }):
                    # Should read directly from cache without urllib request
                    with patch("urllib.request.urlopen") as mock_url:
                        latest = check_for_pypi_update(current_version="1.0.0", no_check=False)
                        self.assertEqual(latest, "1.2.0")
                        mock_url.assert_not_called()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_network_failure_resilience(self):
        """Tier 2: Scanner does not crash if PyPI is unreachable / times out."""
        if not HAS_NEW_INTEGRATIONS:
            self.skipTest("git_security_sentinel.update not yet implemented")

        temp_dir = tempfile.mkdtemp(prefix="sentinel_cache_")
        try:
            cache_file = Path(temp_dir) / "update_check.json"
            with patch("git_security_sentinel.update.checker.get_cache_file_path", return_value=cache_file):
                with patch.dict(os.environ, {
                    "CI": "", "GITHUB_ACTIONS": "", "SENTINEL_NO_UPDATE_CHECK": ""
                }):
                    with patch("urllib.request.urlopen", side_effect=Exception("Network unreachable")):
                        latest = check_for_pypi_update(current_version="1.0.0", no_check=False)
                        self.assertIsNone(latest)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestE2EAIReviewerEnhancements(unittest.TestCase):
    """Tier 1 & 2: AI Reviewer --fix diff mode, prompt guidance, and --cost-estimate."""

    def test_cost_estimation_calculation(self):
        """Tier 1: Token estimation and cost calculation across providers."""
        if not HAS_NEW_INTEGRATIONS:
            self.skipTest("git_security_sentinel.ai.cost not yet implemented")

        # 4000 characters ≈ 1000 tokens
        sample_text = "a" * 4000
        tokens = calculate_token_estimate(sample_text)
        self.assertAlmostEqual(tokens, 1000, delta=50)

        # Ollama local inference cost is always $0.00
        cost_ollama = estimate_query_cost(prompt_tokens=1000, completion_tokens=500, provider="ollama")
        self.assertEqual(cost_ollama, 0.0)

        # Gemini / OpenAI cost is > 0
        cost_openai = estimate_query_cost(prompt_tokens=1000, completion_tokens=500, provider="openai")
        self.assertGreater(cost_openai, 0.0)

    def test_ai_system_prompt_guidance(self):
        """Tier 1: Expanded system prompt includes remediation guidance for insecure code patterns."""
        if not HAS_NEW_INTEGRATIONS:
            self.skipTest("git_security_sentinel.ai.prompts not yet implemented")

        prompt = build_system_prompt(json_mode=True, fix_mode=True)
        # Check CWE & insecure code mentions
        self.assertTrue(
            any(k in prompt for k in ["SQL", "injection", "parameterized", "pickle", "deserialization", "subprocess", "shell=True", "CORS"])
        )
        # Check fix mode instruction
        self.assertTrue("diff" in prompt.lower() or "suggested_fix" in prompt.lower())


class TestE2ERedactionMultilinePrivateKey(unittest.TestCase):
    """Tier 2 & 3: Redaction of multiline private key blocks with re.DOTALL."""

    def test_multiline_private_key_redaction(self):
        if not HAS_NEW_INTEGRATIONS:
            self.skipTest("redaction not yet implemented")

        raw_rsa = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0syntheticKeyPayload1234567890\n"
            "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789==\n"
            "-----END RSA PRIVATE KEY-----"
        )
        redacted = redact_text(raw_rsa)
        self.assertEqual(redacted, "[REDACTED:PRIVATE_KEY]")
        self.assertNotIn("syntheticKeyPayload", redacted)

    def test_multiline_ec_private_key_redaction(self):
        if not HAS_NEW_INTEGRATIONS:
            self.skipTest("redaction not yet implemented")

        raw_ec = (
            "-----BEGIN EC PRIVATE KEY-----\n"
            "MHcCAQEEIJ+fakeEcPayload123456789\n"
            "-----END EC PRIVATE KEY-----"
        )
        redacted = redact_text(raw_ec)
        self.assertEqual(redacted, "[REDACTED:PRIVATE_KEY]")
        self.assertNotIn("fakeEcPayload", redacted)

    def test_multiline_private_key_in_context(self):
        if not HAS_NEW_INTEGRATIONS:
            self.skipTest("redaction not yet implemented")

        payload = (
            "def get_credentials():\n"
            "    cert = '''-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0syntheticKeyPayload\n"
            "-----END RSA PRIVATE KEY-----'''\n"
            "    return cert"
        )
        redacted = redact_text(payload)
        self.assertIn("[REDACTED:PRIVATE_KEY]", redacted)
        self.assertNotIn("syntheticKeyPayload", redacted)
        self.assertIn("def get_credentials():", redacted)
        self.assertIn("return cert", redacted)


if __name__ == "__main__":
    unittest.main()
