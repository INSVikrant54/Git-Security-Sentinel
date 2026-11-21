#!/usr/bin/env python3
"""
E2E Test Suite: SARIF 2.1.0 Schema Compliance and Secret Redaction Guarantee.
Tests Tier 1 through Tier 4 requirements for Git Security Sentinel SARIF output.
Zero third-party test dependencies: Python standard library `unittest` and `json` only.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# SYNTHETIC FIXTURES: assembled at runtime so no literal secret-shaped string
# appears in source (CONTRIBUTING.md: construct synthetic values in memory).
AWS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_KEY = "sk_live_" + "51Abcdefghijklmnopqrstuvwxy" + "123456"
TWILIO_SID = "AC" + "0123456789abcdef0123456789abcdef"
SENDGRID_KEY = "SG." + "1234567890123456789012" + "." + "1234567890123456789012345678901234567890123"
MAILGUN_KEY = "key-" + "0123456789abcdef0123456789abcdef"
MAILCHIMP_KEY = "4f8a92b10c3d5e7f1234567890abcdef" + "-us19"
SQUARE_TOKEN = "sq0atp-" + "1234567890abcdefghijkl"
SHOPIFY_TOKEN = "shpat_" + "38b1a8c8e1f045239a5c8e3124567890"
HEROKU_KEY = "12345678-1234-1234-1234-" + "123456789abc"
DATADOG_KEY = "a1b2c3d4" + "e5f60718293a4b5c6d7e8f90"
NEWRELIC_KEY = "NRAK-" + "1234567890ABCDEF1234567890A"
GITHUB_TOKEN = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
SLACK_TOKEN = "xoxb-" + "123456789012" + "-" + "1234567890123" + "-" + "abcdefghijklmnopqrstuvwx"
BEARER_TOKEN = "ya29." + "a0AfH6SMDh1234567890abcdef"
NPM_TOKEN = "npm_" + "1234567890abcdefghijklmnopqrstuvwxyz"
PYPI_TOKEN = "pypi-" + "AgEIcHlwaS5vcmcCJDFhMmIzYzRkLTVlNmYxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA"
BASIC_AUTH_URL = "https://admin:" + "SuperSecret123" + "@github.com/repo.git"


REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
SCRIPTS_DIR = REPO_ROOT / "scripts"

for p in (SRC_DIR, SCRIPTS_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:
    import git_security_sentinel
    from git_security_sentinel.output.sarif import generate_sarif_report, SARIF_SCHEMA_URI, SARIF_VERSION
    HAS_NEW_SARIF = True
except ImportError:
    HAS_NEW_SARIF = False

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


class TestE2ESarifOutput(unittest.TestCase):
    """Tier 1, 2, 3: SARIF 2.1.0 Format Generation, Structure, and Secret Redaction."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="sentinel_e2e_sarif_")
        self.repo_dir = Path(self.temp_dir)
        (self.repo_dir / "LICENSE").write_text("MIT License (Synthetic E2E Test)", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run_scanner(self, args):
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{SRC_DIR}{os.pathsep}{SCRIPTS_DIR}{os.pathsep}{env.get('PYTHONPATH', '')}"
        cmd = [sys.executable, "-m", "git_security_sentinel"] + args if HAS_NEW_SARIF else [sys.executable, str(SCRIPTS_DIR / "scan_diff.py")] + args
        return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=20)

    def test_sarif_schema_compliance_structure(self):
        """Tier 1: SARIF output adheres to OASIS SARIF 2.1.0 top-level and driver specification."""
        diff_path = self.repo_dir / "sample.diff"
        diff_path.write_text(
            make_diff("src/service.py", [
                f"AWS_KEY = '{AWS_KEY_ID}'",
                f"stripe_key = '{STRIPE_KEY}'",
            ]),
            encoding="utf-8",
        )
        sarif_out = self.repo_dir / "output.sarif"
        res = self._run_scanner([
            "--diff-file", str(diff_path),
            "--repo-root", str(self.repo_dir),
            "--format", "sarif",
            "--output", str(sarif_out),
        ])
        if not HAS_NEW_SARIF and ("unrecognized" in res.stderr or "--format" in res.stderr or not sarif_out.is_file()):
            self.skipTest("M4 SARIF 2.1.0 output not yet implemented")

        self.assertTrue(sarif_out.is_file(), "SARIF output file was not created")
        content = sarif_out.read_text(encoding="utf-8")
        sarif_data = json.loads(content)

        # 1. Top-level keys
        self.assertEqual(sarif_data.get("version"), "2.1.0")
        self.assertIn("sarif-schema-2.1.0", sarif_data.get("$schema", ""))
        self.assertIn("runs", sarif_data)
        self.assertIsInstance(sarif_data["runs"], list)
        self.assertGreaterEqual(len(sarif_data["runs"]), 1)

        run = sarif_data["runs"][0]
        # 2. Tool & Driver keys
        self.assertIn("tool", run)
        self.assertIn("driver", run["tool"])
        driver = run["tool"]["driver"]
        self.assertIn("name", driver)
        self.assertTrue("Git Security Sentinel" in driver["name"] or "git-security-sentinel" in driver["name"].lower())
        self.assertIn("rules", driver)
        self.assertIsInstance(driver["rules"], list)

        # 3. Rules definition schema
        for rule in driver["rules"]:
            self.assertIn("id", rule)
            self.assertIn("shortDescription", rule)
            self.assertIn("text", rule["shortDescription"])
            self.assertIn("defaultConfiguration", rule)
            self.assertIn("level", rule["defaultConfiguration"])
            self.assertIn(rule["defaultConfiguration"]["level"], ["error", "warning", "note"])

    def test_sarif_results_and_locations(self):
        """Tier 2: Results contain valid ruleId, level, message, and normalized URI."""
        diff_path = self.repo_dir / "findings.diff"
        diff_path.write_text(
            make_diff("nested/path/config.py", [
                f"AWS_KEY = '{AWS_KEY_ID}'",
            ]),
            encoding="utf-8",
        )
        sarif_out = self.repo_dir / "results.sarif"
        res = self._run_scanner([
            "--diff-file", str(diff_path),
            "--repo-root", str(self.repo_dir),
            "--format", "sarif",
            "--output", str(sarif_out),
        ])
        if not HAS_NEW_SARIF and ("unrecognized" in res.stderr or not sarif_out.is_file()):
            self.skipTest("M4 SARIF 2.1.0 output not yet implemented")

        data = json.loads(sarif_out.read_text(encoding="utf-8"))
        results = data["runs"][0].get("results", [])
        self.assertGreaterEqual(len(results), 1)

        finding = results[0]
        self.assertEqual(finding.get("ruleId"), "secret.aws_access_key")
        self.assertIn(finding.get("level"), ["error", "warning"])
        self.assertIn("message", finding)
        self.assertIn("text", finding["message"])

        # Locations check
        self.assertIn("locations", finding)
        self.assertGreaterEqual(len(finding["locations"]), 1)
        loc = finding["locations"][0]["physicalLocation"]
        uri = loc["artifactLocation"]["uri"]

        # Forward slash verification (no backslashes even on Windows!)
        self.assertNotIn("\\", uri)
        self.assertTrue(uri.endswith("nested/path/config.py"))

        # Region line check
        self.assertGreaterEqual(loc["region"]["startLine"], 1)

    def test_sarif_secret_redaction_guarantee(self):
        """Tier 3: Guarantee that NO raw secret exists in any SARIF field."""
        raw_aws_key = AWS_KEY_ID
        diff_path = self.repo_dir / "secret.diff"
        diff_path.write_text(
            make_diff("app.py", [
                f"AWS_KEY = '{raw_aws_key}'",
            ]),
            encoding="utf-8",
        )
        sarif_out = self.repo_dir / "redacted.sarif"
        res = self._run_scanner([
            "--diff-file", str(diff_path),
            "--repo-root", str(self.repo_dir),
            "--format", "sarif",
            "--output", str(sarif_out),
        ])
        if not HAS_NEW_SARIF and ("unrecognized" in res.stderr or not sarif_out.is_file()):
            self.skipTest("M4 SARIF 2.1.0 output not yet implemented")

        raw_sarif_text = sarif_out.read_text(encoding="utf-8")

        # Zero raw secrets in raw SARIF file
        self.assertNotIn(
            raw_aws_key,
            raw_sarif_text,
            "CRITICAL SECURITY DEFECT: Raw secret leaked into SARIF output file!",
        )
        # Redacted token MUST be present
        self.assertIn("[REDACTED:AWS_KEY_ID]", raw_sarif_text)

    def test_sarif_clean_diff_empty_results(self):
        """Tier 2: Clean diff produces SARIF report with empty results array and exit code 0."""
        diff_path = self.repo_dir / "clean.diff"
        diff_path.write_text(
            make_diff("app.py", [
                "def hello(): return 'world'",
            ]),
            encoding="utf-8",
        )
        sarif_out = self.repo_dir / "clean.sarif"
        res = self._run_scanner([
            "--diff-file", str(diff_path),
            "--repo-root", str(self.repo_dir),
            "--format", "sarif",
            "--output", str(sarif_out),
        ])
        if not HAS_NEW_SARIF and ("unrecognized" in res.stderr or not sarif_out.is_file()):
            self.skipTest("M4 SARIF 2.1.0 output not yet implemented")

        self.assertEqual(res.returncode, 0)
        data = json.loads(sarif_out.read_text(encoding="utf-8"))
        self.assertEqual(len(data["runs"][0].get("results", [])), 0)


if __name__ == "__main__":
    unittest.main()
