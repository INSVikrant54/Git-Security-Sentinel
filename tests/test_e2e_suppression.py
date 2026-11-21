#!/usr/bin/env python3
"""
E2E Test Suite: False-Positive Suppression (Comments, Path Exclusions, and Baseline).
Tests Tier 1 through Tier 4 requirements for Git Security Sentinel suppression.
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
    from git_security_sentinel.suppression.comment_filter import parse_inline_suppression, is_rule_suppressed
    from git_security_sentinel.suppression.ignore_filter import PathFilter
    from git_security_sentinel.suppression.baseline import BaselineFilter, compute_fingerprint
    HAS_NEW_SUPPRESSION = True
except ImportError:
    HAS_NEW_SUPPRESSION = False

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


class TestE2EInlineCommentSuppression(unittest.TestCase):
    """Tier 1 & 2: Line-Level Comment Suppression (#nosec and #sentinel:ignore)."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="sentinel_e2e_suppress_")
        self.repo_dir = Path(self.temp_dir)
        (self.repo_dir / "LICENSE").write_text("MIT License (Synthetic E2E Test)", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run_scanner(self, args):
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{SRC_DIR}{os.pathsep}{SCRIPTS_DIR}{os.pathsep}{env.get('PYTHONPATH', '')}"
        cmd = [sys.executable, "-m", "git_security_sentinel"] + args if HAS_NEW_SUPPRESSION else [sys.executable, str(SCRIPTS_DIR / "scan_diff.py")] + args
        return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=20)

    def test_unit_parse_inline_suppression(self):
        """Tier 1: Unit parser for inline suppression directives."""
        if not HAS_NEW_SUPPRESSION:
            self.skipTest("git_security_sentinel.suppression not yet implemented")

        # Blanket # nosec
        res = parse_inline_suppression("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE' # nosec")
        self.assertIsNotNone(res)
        is_blanket, rules = res
        self.assertTrue(is_blanket)
        self.assertTrue(is_rule_suppressed("secret.aws_access_key", res))

        # Blanket # sentinel:ignore
        res = parse_inline_suppression("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE' # sentinel:ignore")
        self.assertIsNotNone(res)
        is_blanket, rules = res
        self.assertTrue(is_blanket)

        # Polyglot comment markers // nosec and -- nosec
        res_slash = parse_inline_suppression("const key = 'AKIAIOSFODNN7EXAMPLE'; // nosec")
        self.assertIsNotNone(res_slash)
        self.assertTrue(res_slash[0])

        res_dash = parse_inline_suppression("SELECT * FROM credentials; -- nosec")
        self.assertIsNotNone(res_dash)
        self.assertTrue(res_dash[0])

        # Rule-specific suppression
        res_rule = parse_inline_suppression("key = 'AKIAIOSFODNN7EXAMPLE' # nosec secret.aws_access_key")
        self.assertIsNotNone(res_rule)
        is_blanket, rules = res_rule
        self.assertFalse(is_blanket)
        self.assertTrue(is_rule_suppressed("secret.aws_access_key", res_rule))
        self.assertFalse(is_rule_suppressed("secret.stripe_key", res_rule))

        # Normalized alias match (aws-access-key matching secret.aws_access_key)
        res_alias = parse_inline_suppression("key = 'AKIAIOSFODNN7EXAMPLE' # sentinel:ignore aws-access-key")
        self.assertTrue(is_rule_suppressed("secret.aws_access_key", res_alias))

    def test_unit_comment_suppression_boundary_precision(self):
        """Tier 2 (Remediation): Suffix boundary precision prevents partial word overmatching."""
        if not HAS_NEW_SUPPRESSION:
            self.skipTest("git_security_sentinel.suppression not yet implemented")

        # 'en' must NOT match 'secret.github_token'
        res_en = parse_inline_suppression("token = 'ghp_123456789012345678901234567890123456' # nosec: en")
        self.assertFalse(is_rule_suppressed("secret.github_token", res_en))

        # 'key' must NOT match 'secret.stripe_key' or 'secret.aws_access_key'
        res_key = parse_inline_suppression("token = '" + "sk_" + "live_" + "123456789012345678901234" + "' # nosec: key")
        self.assertFalse(is_rule_suppressed("secret.stripe_key", res_key))
        self.assertFalse(is_rule_suppressed("secret.aws_access_key", res_key))

        # 'token' must NOT match 'secret.github_token'
        res_token = parse_inline_suppression("token = 'ghp_123456789012345678901234567890123456' # nosec: token")
        self.assertFalse(is_rule_suppressed("secret.github_token", res_token))

        # Valid aliases MUST match
        res_aws = parse_inline_suppression("key = 'AKIAIOSFODNN7EXAMPLE' # nosec: aws-access-key")
        self.assertTrue(is_rule_suppressed("secret.aws_access_key", res_aws))

        res_stripe = parse_inline_suppression("key = 'sk_live_12345' # nosec: stripe-key")
        self.assertTrue(is_rule_suppressed("secret.stripe_key", res_stripe))

    def test_unit_semicolon_delimited_suppression(self):
        """Tier 2 (Remediation): Semicolon-delimited rule lists in suppression directives."""
        if not HAS_NEW_SUPPRESSION:
            self.skipTest("git_security_sentinel.suppression not yet implemented")

        res = parse_inline_suppression("k = '...' # nosec: secret.aws_access_key; secret.stripe_key")
        self.assertIsNotNone(res)
        self.assertFalse(res[0])
        self.assertTrue(is_rule_suppressed("secret.aws_access_key", res))
        self.assertTrue(is_rule_suppressed("secret.stripe_key", res))
        self.assertFalse(is_rule_suppressed("secret.github_token", res))

        # Polyglot comment with mixed comma and semicolon
        res_mixed = parse_inline_suppression("val = 1 // nosec: aws-access-key; stripe-key, github-token")
        self.assertTrue(is_rule_suppressed("secret.aws_access_key", res_mixed))
        self.assertTrue(is_rule_suppressed("secret.stripe_key", res_mixed))
        self.assertTrue(is_rule_suppressed("secret.github_token", res_mixed))

    def test_e2e_blanket_nosec_suppression_cli(self):
        """Tier 1: Scanning diff with # nosec suppresses finding and returns exit code 0."""
        diff_path = self.repo_dir / "suppressed.diff"
        diff_path.write_text(
            make_diff("app.py", [
                "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE' # nosec"
            ]),
            encoding="utf-8",
        )
        res = self._run_scanner(["--diff-file", str(diff_path), "--repo-root", str(self.repo_dir), "--format", "json"])
        if not HAS_NEW_SUPPRESSION and res.returncode == 1:
            self.skipTest("M3 line comment suppression not yet implemented in scanner")
        self.assertEqual(res.returncode, 0, f"Expected 0 due to # nosec suppression. Got {res.returncode}")
        data = json.loads(res.stdout)
        self.assertEqual(len(data.get("findings", [])), 0)
        self.assertGreaterEqual(data.get("summary", {}).get("suppressed", 0), 1)

    def test_e2e_mismatched_rule_specific_nosec_not_suppressed(self):
        """Tier 2: Finding on line with non-matching rule-specific # nosec is NOT suppressed."""
        diff_path = self.repo_dir / "mismatch.diff"
        diff_path.write_text(
            make_diff("app.py", [
                "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE' # nosec secret.github_token"
            ]),
            encoding="utf-8",
        )
        res = self._run_scanner(["--diff-file", str(diff_path), "--repo-root", str(self.repo_dir), "--format", "json"])
        self.assertEqual(res.returncode, 1, "Expected exit code 1 because rule ID does not match suppression")


class TestE2EPathExclusions(unittest.TestCase):
    """Tier 1 & 2: Path Exclusions via --exclude and .sentinelignore."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="sentinel_e2e_paths_")
        self.repo_dir = Path(self.temp_dir)
        (self.repo_dir / "LICENSE").write_text("MIT License (Synthetic E2E Test)", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run_scanner(self, args):
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{SRC_DIR}{os.pathsep}{SCRIPTS_DIR}{os.pathsep}{env.get('PYTHONPATH', '')}"
        cmd = [sys.executable, "-m", "git_security_sentinel"] + args if HAS_NEW_SUPPRESSION else [sys.executable, str(SCRIPTS_DIR / "scan_diff.py")] + args
        return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=20)

    def test_unit_path_filter(self):
        """Tier 1: PathFilter matching against globs and .sentinelignore rules."""
        if not HAS_NEW_SUPPRESSION:
            self.skipTest("git_security_sentinel.suppression not yet implemented")

        patterns = [
            "# Comment line",
            "tests/**",
            "*.md",
            "fixtures/dummy.py",
            "/build/**",
        ]
        pf = PathFilter(patterns)
        self.assertTrue(pf.is_ignored("tests/unit/test_app.py"))
        self.assertTrue(pf.is_ignored("README.md"))
        self.assertTrue(pf.is_ignored("fixtures/dummy.py"))
        self.assertTrue(pf.is_ignored("build/dist/package.whl"))
        self.assertFalse(pf.is_ignored("src/app.py"))
        self.assertFalse(pf.is_ignored("subfolder/build/app.py"))

    def test_unit_bare_directory_matching(self):
        """Tier 2 (Remediation): Bare directory names match nested files."""
        if not HAS_NEW_SUPPRESSION:
            self.skipTest("git_security_sentinel.suppression not yet implemented")

        pf = PathFilter(["vendor", "node_modules", "build/"])
        self.assertTrue(pf.is_ignored("vendor/pkg/auth.py"))
        self.assertTrue(pf.is_ignored("node_modules/express/index.js"))
        self.assertTrue(pf.is_ignored("src/vendor/pkg/auth.py"))
        self.assertTrue(pf.is_ignored("vendor"))
        self.assertTrue(pf.is_ignored("build/dist/output.whl"))
        self.assertFalse(pf.is_ignored("vendor_extra/file.py"))
        self.assertFalse(pf.is_ignored("app/main.py"))

    def test_unit_negation_patterns(self):
        """Tier 2 (Remediation): Gitignore-style negation patterns with sequential evaluation."""
        if not HAS_NEW_SUPPRESSION:
            self.skipTest("git_security_sentinel.suppression not yet implemented")

        pf = PathFilter(["tests/**", "!tests/keep.py"])
        self.assertTrue(pf.is_ignored("tests/unit/test.py"))
        self.assertTrue(pf.is_ignored("tests/sub/deep/test.py"))
        self.assertFalse(pf.is_ignored("tests/keep.py"))
        self.assertFalse(pf.is_ignored("src/keep.py"))

        # Sequential re-exclusion
        pf_reexclude = PathFilter(["*.py", "!special.py", "special.py"])
        self.assertTrue(pf_reexclude.is_ignored("special.py"))

        # Sequential override
        pf_unignore = PathFilter(["*.py", "special.py", "!special.py"])
        self.assertFalse(pf_unignore.is_ignored("special.py"))

    def test_e2e_exclude_flag_cli(self):
        """Tier 1: --exclude flag skips matching paths in diff."""
        diff_path = self.repo_dir / "excluded.diff"
        diff_path.write_text(
            make_diff("tests/fixtures/mock_secret.py", [
                "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"
            ]),
            encoding="utf-8",
        )
        res = self._run_scanner([
            "--diff-file", str(diff_path),
            "--repo-root", str(self.repo_dir),
            "--exclude", "tests/**",
        ])
        if not HAS_NEW_SUPPRESSION and ("unrecognized" in res.stderr or res.returncode in (1, 2)):
            self.skipTest("M3 --exclude flag not yet implemented")
        self.assertEqual(res.returncode, 0, f"Expected 0 because path was excluded. Got {res.returncode}")

    def test_e2e_sentinelignore_file_cli(self):
        """Tier 1: .sentinelignore skips matching paths without explicit CLI flag."""
        ignore_file = self.repo_dir / ".sentinelignore"
        ignore_file.write_text("# Ignore mock files\nmocks/**\n*.test.py\n", encoding="utf-8")

        diff_path = self.repo_dir / "mock_test.diff"
        diff_path.write_text(
            make_diff("mocks/credentials.py", [
                "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"
            ]),
            encoding="utf-8",
        )
        res = self._run_scanner([
            "--diff-file", str(diff_path),
            "--repo-root", str(self.repo_dir),
        ])
        if not HAS_NEW_SUPPRESSION and res.returncode == 1:
            self.skipTest("M3 .sentinelignore not yet implemented")
        self.assertEqual(res.returncode, 0, f"Expected 0 because .sentinelignore excluded file. Got {res.returncode}")


class TestE2EBaselineFiltering(unittest.TestCase):
    """Tier 3 & 4: Baseline Filtering via --baseline and --create-baseline."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="sentinel_e2e_baseline_")
        self.repo_dir = Path(self.temp_dir)
        (self.repo_dir / "LICENSE").write_text("MIT License (Synthetic E2E Test)", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run_scanner(self, args):
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{SRC_DIR}{os.pathsep}{SCRIPTS_DIR}{os.pathsep}{env.get('PYTHONPATH', '')}"
        cmd = [sys.executable, "-m", "git_security_sentinel"] + args if HAS_NEW_SUPPRESSION else [sys.executable, str(SCRIPTS_DIR / "scan_diff.py")] + args
        return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=20)

    def test_e2e_baseline_creation_and_filtering(self):
        """Tier 3: Create baseline from initial scan and verify subsequent run suppresses findings."""
        diff_path = self.repo_dir / "initial.diff"
        diff_path.write_text(
            make_diff("legacy/db.py", [
                "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"
            ]),
            encoding="utf-8",
        )
        baseline_file = self.repo_dir / ".sentinel.baseline"

        # 1. First run: without baseline -> exit code 1
        res1 = self._run_scanner(["--diff-file", str(diff_path), "--repo-root", str(self.repo_dir)])
        self.assertEqual(res1.returncode, 1)

        # 2. Run with --create-baseline
        res_create = self._run_scanner([
            "--diff-file", str(diff_path),
            "--repo-root", str(self.repo_dir),
            "--baseline", str(baseline_file),
            "--create-baseline",
        ])
        if not HAS_NEW_SUPPRESSION and res_create.returncode != 0:
            self.skipTest("M3 --baseline / --create-baseline not yet implemented")
        self.assertEqual(res_create.returncode, 0)
        self.assertTrue(baseline_file.is_file(), "Baseline file was not created")

        # 3. Second run: with baseline -> legacy finding suppressed, exit code 0
        res2 = self._run_scanner([
            "--diff-file", str(diff_path),
            "--repo-root", str(self.repo_dir),
            "--baseline", str(baseline_file),
        ])
        self.assertEqual(res2.returncode, 0, f"Expected 0 with baseline. Got {res2.returncode}")

    def test_e2e_baseline_fingerprint_stability_with_line_shift(self):
        """Tier 4: Baseline fingerprint remains valid even when line numbers shift above the finding."""
        diff_shifted = (
            "diff --git a/legacy/db.py b/legacy/db.py\n"
            "--- a/legacy/db.py\n"
            "+++ b/legacy/db.py\n"
            "@@ -10,3 +10,6 @@\n"
            "+# Line shift header\n"
            "+# Another line added\n"
            "+AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        )
        diff_path = self.repo_dir / "shifted.diff"
        diff_path.write_text(diff_shifted, encoding="utf-8")
        baseline_file = self.repo_dir / ".sentinel.baseline"

        # Create baseline from original diff
        res_create = self._run_scanner([
            "--diff-file", str(diff_path),
            "--repo-root", str(self.repo_dir),
            "--baseline", str(baseline_file),
            "--create-baseline",
        ])
        if not HAS_NEW_SUPPRESSION and res_create.returncode != 0:
            self.skipTest("M3 --baseline / --create-baseline not yet implemented")

        # Now scan a new diff with different hunk offset, but identical file, rule, and evidence
        diff_further_shifted = (
            "diff --git a/legacy/db.py b/legacy/db.py\n"
            "--- a/legacy/db.py\n"
            "+++ b/legacy/db.py\n"
            "@@ -50,3 +50,4 @@\n"
            "+AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        )
        diff_path_shifted = self.repo_dir / "further_shifted.diff"
        diff_path_shifted.write_text(diff_further_shifted, encoding="utf-8")

        res_check = self._run_scanner([
            "--diff-file", str(diff_path_shifted),
            "--repo-root", str(self.repo_dir),
            "--baseline", str(baseline_file),
        ])
        self.assertEqual(res_check.returncode, 0, "Shifted line finding should still match baseline fingerprint")


if __name__ == "__main__":
    unittest.main()
