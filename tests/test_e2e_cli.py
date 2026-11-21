#!/usr/bin/env python3
"""
E2E Test Suite: CLI Entrypoints, Flags, Packaging, and Backwards Compatibility.
Tests Tier 1 through Tier 4 requirements for Git Security Sentinel CLI interfaces.
Zero third-party test dependencies: Python standard library `unittest` only.
"""

import json
import os
import re
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

# Check for package availability
try:
    import git_security_sentinel
    from git_security_sentinel import cli as gss_cli
    HAS_PACKAGE = True
except ImportError:
    HAS_PACKAGE = False

try:
    import scan_diff
    HAS_SCAN_DIFF = True
except ImportError:
    HAS_SCAN_DIFF = False


class TestE2ECLIEntrypoints(unittest.TestCase):
    """Tier 1: Feature Coverage — CLI Entrypoints & Packaging."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="sentinel_e2e_cli_")
        self.repo_dir = Path(self.temp_dir)
        (self.repo_dir / "LICENSE").write_text("MIT License (Synthetic E2E Test)", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_backwards_compatible_scan_diff_wrapper_help(self):
        """Tier 1: python scripts/scan_diff.py --help executes successfully."""
        script_path = SCRIPTS_DIR / "scan_diff.py"
        self.assertTrue(script_path.is_file(), f"Missing wrapper {script_path}")
        result = subprocess.run(
            [sys.executable, str(script_path), "--help"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage:", result.stdout.lower())
        self.assertTrue(
            "git-security-sentinel" in result.stdout.lower() or "scan_diff" in result.stdout.lower()
        )

    def test_backwards_compatible_ai_review_wrapper_help(self):
        """Tier 1: python scripts/ai_review.py --help executes successfully."""
        script_path = SCRIPTS_DIR / "ai_review.py"
        self.assertTrue(script_path.is_file(), f"Missing wrapper {script_path}")
        result = subprocess.run(
            [sys.executable, str(script_path), "--help"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage:", result.stdout.lower())

    def test_module_entrypoint_help(self):
        """Tier 1: python -m git_security_sentinel --help executes cleanly."""
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{SRC_DIR}{os.pathsep}{env.get('PYTHONPATH', '')}"
        result = subprocess.run(
            [sys.executable, "-m", "git_security_sentinel", "--help"],
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
        )
        if result.returncode != 0 and "No module named git_security_sentinel" in result.stderr:
            self.skipTest("src/git_security_sentinel package not yet created")
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage:", result.stdout.lower())

    def test_cli_version_flag(self):
        """Tier 1: --version prints version and exits with code 0."""
        target = [sys.executable, "-m", "git_security_sentinel", "--version"]
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{SRC_DIR}{os.pathsep}{env.get('PYTHONPATH', '')}"
        result = subprocess.run(target, capture_output=True, text=True, env=env, timeout=15)
        if result.returncode != 0 and "No module named git_security_sentinel" in result.stderr:
            # Fall back to script check if package not ready
            result = subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "scan_diff.py"), "--version"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0:
                self.skipTest("--version flag not implemented yet in scripts/scan_diff.py")
        self.assertEqual(result.returncode, 0)
        combined = (result.stdout + result.stderr).strip()
        self.assertTrue(re.search(r"\d+\.\d+\.\d+", combined), f"Expected semver in output: {combined}")


class TestE2ECLIFlagsAndBehaviors(unittest.TestCase):
    """Tier 2: Boundary & Corner Cases — Flags, Formats, and Error Handling."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="sentinel_e2e_flags_")
        self.diff_path = Path(self.temp_dir) / "test.diff"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run_scanner(self, args, input_data=None):
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{SRC_DIR}{os.pathsep}{SCRIPTS_DIR}{os.pathsep}{env.get('PYTHONPATH', '')}"
        if HAS_PACKAGE:
            cmd = [sys.executable, "-m", "git_security_sentinel"] + args
        else:
            cmd = [sys.executable, str(SCRIPTS_DIR / "scan_diff.py")] + args
        return subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            env=env,
            timeout=20,
        )

    def test_clean_diff_exit_code_zero(self):
        """Tier 1: Clean diff returns exit code 0."""
        clean_diff = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -0,0 +1,2 @@\n"
            "+def greet():\n"
            "+    return 'hello world'\n"
        )
        self.diff_path.write_text(clean_diff, encoding="utf-8")
        result = self._run_scanner(["--diff-file", str(self.diff_path), "--repo-root", self.temp_dir])
        self.assertEqual(result.returncode, 0, f"Expected 0, got {result.returncode}. Output: {result.stdout}")

    def test_critical_finding_exit_code_one(self):
        """Tier 1: Diff with critical finding returns exit code 1."""
        bad_diff = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -0,0 +1,2 @@\n"
            "+# Added AWS key\n"
            "+AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        )
        self.diff_path.write_text(bad_diff, encoding="utf-8")
        result = self._run_scanner(["--diff-file", str(self.diff_path), "--repo-root", self.temp_dir])
        self.assertEqual(result.returncode, 1, f"Expected exit code 1 for finding. Output: {result.stdout}")

    def test_severity_threshold_filtering(self):
        """Tier 2: --severity-threshold critical filters out medium/low findings."""
        medium_diff = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -0,0 +1,2 @@\n"
            "+# Dynamic eval\n"
            "+eval(dynamic_code)\n"
        )
        self.diff_path.write_text(medium_diff, encoding="utf-8")
        # With threshold critical, medium finding should NOT trigger exit code 1
        result = self._run_scanner([
            "--diff-file", str(self.diff_path),
            "--repo-root", self.temp_dir,
            "--severity-threshold", "critical",
        ])
        self.assertEqual(result.returncode, 0, f"Expected exit code 0 under threshold critical. Got {result.returncode}")

        # With threshold medium, medium finding MUST trigger exit code 1
        result_med = self._run_scanner([
            "--diff-file", str(self.diff_path),
            "--repo-root", self.temp_dir,
            "--severity-threshold", "medium",
        ])
        self.assertEqual(result_med.returncode, 1, f"Expected exit code 1 under threshold medium. Got {result_med.returncode}")

    def test_missing_diff_file_exit_code_two(self):
        """Tier 2: Missing diff file returns exit code 2."""
        missing = Path(self.temp_dir) / "does_not_exist.diff"
        result = self._run_scanner(["--diff-file", str(missing), "--repo-root", self.temp_dir])
        self.assertEqual(result.returncode, 2, f"Expected exit code 2 for missing file. Got {result.returncode}")

    def test_empty_diff_file_handling(self):
        """Tier 2: Empty diff file exits 0 without error."""
        self.diff_path.write_text("", encoding="utf-8")
        result = self._run_scanner(["--diff-file", str(self.diff_path), "--repo-root", self.temp_dir])
        self.assertEqual(result.returncode, 0)

    def test_no_color_flag_suppresses_ansi(self):
        """Tier 2: --no-color flag ensures output contains no ANSI escape sequences."""
        bad_diff = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -0,0 +1,1 @@\n"
            "+AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        )
        self.diff_path.write_text(bad_diff, encoding="utf-8")
        result = self._run_scanner([
            "--diff-file", str(self.diff_path),
            "--repo-root", self.temp_dir,
            "--no-color",
        ])
        ansi_regex = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
        self.assertFalse(
            ansi_regex.search(result.stdout),
            "Found ANSI escape sequences when --no-color was specified",
        )

    def test_quiet_flag_clean_diff(self):
        """Tier 2: --quiet flag on a clean diff suppresses stdout output."""
        clean_diff = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -0,0 +1,1 @@\n"
            "+x = 1\n"
        )
        self.diff_path.write_text(clean_diff, encoding="utf-8")
        result = self._run_scanner([
            "--diff-file", str(self.diff_path),
            "--repo-root", self.temp_dir,
            "--quiet",
        ])
        if "--quiet" in result.stderr and "unrecognized" in result.stderr:
            self.skipTest("--quiet flag not yet implemented")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "")


class TestE2ECLICrossFeatureAndScenarios(unittest.TestCase):
    """Tier 3 & 4: Cross-Feature Combinations & Real-World Repository Scenarios."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="sentinel_e2e_scenarios_")
        self.repo_dir = Path(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run_scanner(self, args):
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{SRC_DIR}{os.pathsep}{SCRIPTS_DIR}{os.pathsep}{env.get('PYTHONPATH', '')}"
        if HAS_PACKAGE:
            cmd = [sys.executable, "-m", "git_security_sentinel"] + args
        else:
            cmd = [sys.executable, str(SCRIPTS_DIR / "scan_diff.py")] + args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

    def test_json_and_output_file_combination(self):
        """Tier 3: --format json --output <path> writes valid JSON to disk."""
        diff_path = self.repo_dir / "patch.diff"
        diff_path.write_text(
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -0,0 +1,1 @@\n"
            "+KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
            encoding="utf-8",
        )
        out_file = self.repo_dir / "report.json"
        result = self._run_scanner([
            "--diff-file", str(diff_path),
            "--repo-root", str(self.repo_dir),
            "--format", "json",
            "--output", str(out_file),
        ])
        self.assertEqual(result.returncode, 1)
        self.assertTrue(out_file.is_file(), "Report file was not created")
        data = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertIn("findings", data)
        self.assertIn("summary", data)
        self.assertGreaterEqual(len(data["findings"]), 1)

    def test_redacted_diff_out_flag(self):
        """Tier 3: --redacted-diff-out produces sanitized diff patch."""
        diff_path = self.repo_dir / "patch.diff"
        diff_path.write_text(
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -0,0 +1,1 @@\n"
            "+aws_secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n",
            encoding="utf-8",
        )
        redacted_patch = self.repo_dir / "sanitized.patch"
        result = self._run_scanner([
            "--diff-file", str(diff_path),
            "--repo-root", str(self.repo_dir),
            "--redacted-diff-out", str(redacted_patch),
        ])
        self.assertTrue(redacted_patch.is_file(), "Redacted diff file was not generated")
        content = redacted_patch.read_text(encoding="utf-8")
        self.assertNotIn("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", content)
        self.assertIn("[REDACTED", content)

    def test_real_git_repository_staged_scan(self):
        """Tier 4: End-to-end staged scan in initialized git repository."""
        # Initialize Git repo
        subprocess.run(["git", "init"], cwd=str(self.repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Sentinel Test"], cwd=str(self.repo_dir), check=True)
        subprocess.run(["git", "config", "user.email", "test@sentinel.local"], cwd=str(self.repo_dir), check=True)

        # Create initial clean commit with license
        (self.repo_dir / "LICENSE").write_text("MIT License", encoding="utf-8")
        (self.repo_dir / "README.md").write_text("# Project", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(self.repo_dir), check=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(self.repo_dir), check=True)

        # Clean staged change -> exit code 0
        (self.repo_dir / "main.py").write_text("print('hello')", encoding="utf-8")
        subprocess.run(["git", "add", "main.py"], cwd=str(self.repo_dir), check=True)
        res_clean = self._run_scanner(["--staged", "--repo-root", str(self.repo_dir)])
        self.assertEqual(res_clean.returncode, 0, f"Expected 0 on clean staged change. Output: {res_clean.stdout}")

        # Dirty staged change with secret -> exit code 1
        (self.repo_dir / "main.py").write_text("AWS = 'AKIAIOSFODNN7EXAMPLE'", encoding="utf-8")
        subprocess.run(["git", "add", "main.py"], cwd=str(self.repo_dir), check=True)
        res_dirty = self._run_scanner(["--staged", "--repo-root", str(self.repo_dir)])
        self.assertEqual(res_dirty.returncode, 1, f"Expected 1 on dirty staged change. Output: {res_dirty.stdout}")


if __name__ == "__main__":
    unittest.main()
