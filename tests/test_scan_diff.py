#!/usr/bin/env python3
"""
Unit and Integration Test Suite for Git Security Sentinel.
Zero third-party test dependencies: uses Python standard library `unittest` only.
Programmatically constructs synthetic test fixtures in-memory to prevent false-positive credential leaks.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
import urllib.error

# Ensure scripts directory is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import scan_diff
import ai_review


class TestGitSecurityScanner(unittest.TestCase):
    """Unit tests for deterministic scanner, diff parsing, detection rules, and redaction."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="gss_test_")
        self.repo_path = Path(self.temp_dir)
        self.scanner = scan_diff.GitSecurityScanner(repo_root=self.repo_path)

        # Create a mock root LICENSE file
        (self.repo_path / "LICENSE").write_text("MIT License (Synthetic Test)", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # 1. Clean Diff Test
    def test_clean_diff(self):
        diff = (
            "diff --git a/app.py b/app.py\n"
            "index 0000000..1111111 100644\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -0,0 +1,3 @@\n"
            "+def greet():\n"
            "+    return 'Hello, World!'\n"
            "+print(greet())\n"
        )
        report = self.scanner.scan_diff_content(diff, scan_mode="unstaged")
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["summary"]["total"], 0)
        self.assertEqual(len(report["findings"]), 0)
        self.assertTrue(report["license"]["root_license_present"])
        self.assertEqual(report["license"]["license_file"], "LICENSE")

    # 2. Synthetic AWS Access Key Test
    def test_aws_access_key_detection(self):
        synthetic_key = "AKIA" + "IOSFODNN7EXAMPLE"
        diff = (
            "diff --git a/config.py b/config.py\n"
            "--- a/config.py\n"
            "+++ b/config.py\n"
            "@@ -0,0 +1,1 @@\n"
            f"+AWS_KEY = '{synthetic_key}'\n"
        )
        report = self.scanner.scan_diff_content(diff, scan_mode="staged")
        self.assertEqual(report["summary"]["total"], 1)
        self.assertEqual(report["summary"]["critical"], 1)
        finding = report["findings"][0]
        self.assertEqual(finding["rule_id"], "secret.aws_access_key")
        self.assertEqual(finding["severity"], "critical")
        self.assertNotIn(synthetic_key, finding["evidence"])
        self.assertIn("[REDACTED:AWS_KEY_ID]", finding["evidence"])

    # 3. Synthetic AWS Secret Key Assignment Test
    def test_aws_secret_key_detection(self):
        synthetic_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        diff = (
            "diff --git a/aws.ini b/aws.ini\n"
            "--- a/aws.ini\n"
            "+++ b/aws.ini\n"
            "@@ -0,0 +1,1 @@\n"
            f"+aws_secret_access_key = '{synthetic_secret}'\n"
        )
        report = self.scanner.scan_diff_content(diff, scan_mode="all")
        self.assertEqual(report["summary"]["total"], 1)
        finding = report["findings"][0]
        self.assertEqual(finding["rule_id"], "secret.aws_secret_key")
        self.assertEqual(finding["severity"], "critical")
        self.assertNotIn(synthetic_secret, finding["evidence"])

    # 4. Synthetic GitHub Token Detection
    def test_github_token_detection(self):
        synthetic_token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
        diff = (
            "diff --git a/client.js b/client.js\n"
            "--- a/client.js\n"
            "+++ b/client.js\n"
            "@@ -0,0 +1,1 @@\n"
            f"+const token = '{synthetic_token}';\n"
        )
        report = self.scanner.scan_diff_content(diff, scan_mode="staged")
        self.assertEqual(report["summary"]["total"], 1)
        finding = report["findings"][0]
        self.assertEqual(finding["rule_id"], "secret.github_token")
        self.assertEqual(finding["severity"], "critical")
        self.assertNotIn(synthetic_token, finding["evidence"])
        self.assertIn("[REDACTED:GITHUB_TOKEN]", finding["evidence"])

    # 5. Synthetic Slack Token Detection
    def test_slack_token_detection(self):
        synthetic_slack = "xoxb-" + "123456789012-" + "1234567890123-" + "abcdefghijklmnopqrstuvwx"
        diff = (
            "diff --git a/bot.py b/bot.py\n"
            "--- a/bot.py\n"
            "+++ b/bot.py\n"
            "@@ -0,0 +1,1 @@\n"
            f"+SLACK_BOT_TOKEN = '{synthetic_slack}'\n"
        )
        report = self.scanner.scan_diff_content(diff, scan_mode="all")
        self.assertEqual(report["summary"]["total"], 1)
        finding = report["findings"][0]
        self.assertEqual(finding["rule_id"], "secret.slack_token")
        self.assertEqual(finding["severity"], "high")
        self.assertNotIn(synthetic_slack, finding["evidence"])

    # 6. Generic Credential Assignment Test
    def test_generic_credential_detection(self):
        synthetic_pwd = "sUpEr" + "S3crEt" + "PaSsWoRd!"
        diff = (
            "diff --git a/db.py b/db.py\n"
            "--- a/db.py\n"
            "+++ b/db.py\n"
            "@@ -0,0 +1,1 @@\n"
            f"+db_password = '{synthetic_pwd}'\n"
        )
        report = self.scanner.scan_diff_content(diff, scan_mode="all")
        self.assertEqual(report["summary"]["total"], 1)
        finding = report["findings"][0]
        self.assertEqual(finding["rule_id"], "secret.generic_credential")
        self.assertEqual(finding["severity"], "high")
        self.assertNotIn(synthetic_pwd, finding["evidence"])
        self.assertIn("[REDACTED:GENERIC_CREDENTIAL]", finding["evidence"])

    # 7. Synthetic Private Key Material Test
    def test_private_key_detection(self):
        pk_header = "-----BEGIN " + "RSA PRIVATE KEY-----"
        diff = (
            "diff --git a/id_rsa b/id_rsa\n"
            "--- a/id_rsa\n"
            "+++ b/id_rsa\n"
            "@@ -0,0 +1,2 @@\n"
            f"+{pk_header}\n"
            "+MIIEowIBAAKCAQEA0syntheticKeyContent...\n"
        )
        report = self.scanner.scan_diff_content(diff, scan_mode="all")
        self.assertEqual(report["summary"]["total"], 1)
        finding = report["findings"][0]
        self.assertEqual(finding["rule_id"], "secret.private_key")
        self.assertEqual(finding["severity"], "critical")
        self.assertNotIn(pk_header, finding["evidence"])

    # 8. Risky Dynamic Execution Test (eval / exec)
    def test_risky_eval_detection(self):
        diff = (
            "diff --git a/calc.py b/calc.py\n"
            "--- a/calc.py\n"
            "+++ b/calc.py\n"
            "@@ -0,0 +1,2 @@\n"
            "+val = eval(user_supplied_string)\n"
            "+exec(untrusted_code)\n"
        )
        report = self.scanner.scan_diff_content(diff, scan_mode="all")
        self.assertGreaterEqual(report["summary"]["total"], 1)
        eval_findings = [f for f in report["findings"] if f["rule_id"] == "risk.eval_execution"]
        self.assertTrue(len(eval_findings) >= 1)
        self.assertEqual(eval_findings[0]["severity"], "medium")

    # 9. Risky Localhost Hardcoding Test
    def test_risky_localhost_detection(self):
        diff = (
            "diff --git a/api.py b/api.py\n"
            "--- a/api.py\n"
            "+++ b/api.py\n"
            "@@ -0,0 +1,1 @@\n"
            "+BACKEND_URL = 'http://localhost:8080/v1'\n"
        )
        report = self.scanner.scan_diff_content(diff, scan_mode="all")
        self.assertEqual(report["summary"]["total"], 1)
        finding = report["findings"][0]
        self.assertEqual(finding["rule_id"], "risk.localhost_endpoint")
        self.assertEqual(finding["severity"], "low")

    # 10. Benign Placeholder False-Positive Suppression
    def test_benign_placeholder_suppression(self):
        diff = (
            "diff --git a/settings.py b/settings.py\n"
            "--- a/settings.py\n"
            "+++ b/settings.py\n"
            "@@ -0,0 +1,3 @@\n"
            "+api_key = 'your_api_key_here'\n"
            "+password = 'change_me'\n"
            "+token = process.env.TOKEN\n"
        )
        report = self.scanner.scan_diff_content(diff, scan_mode="all")
        # None of these benign placeholders should trigger a secret.generic_credential finding
        generic_findings = [f for f in report["findings"] if f["rule_id"] == "secret.generic_credential"]
        self.assertEqual(len(generic_findings), 0)

    # 11. Accurate Line Number and Added vs Removed Lines
    def test_diff_hunk_line_number_tracking(self):
        diff = (
            "diff --git a/module.py b/module.py\n"
            "--- a/module.py\n"
            "+++ b/module.py\n"
            "@@ -10,3 +10,4 @@\n"
            "-old_line_removed = True\n"
            " context_line_preserved = True\n"
            "+first_added_line = 'harmless'\n"
            f"+AWS_KEY = 'AKIA{'1234567890ABCDEF'}'\n"
        )
        report = self.scanner.scan_diff_content(diff, scan_mode="unstaged")
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        # In hunk @@ -10,3 +10,4 @@:
        # line 10: context_line_preserved
        # line 11: first_added_line
        # line 12: AWS_KEY
        self.assertEqual(finding["line"], 12)
        self.assertEqual(finding["file"], "module.py")

    # 12. Multiple Changed Files in Single Diff
    def test_multiple_files_diff(self):
        diff = (
            "diff --git a/a.py b/a.py\n"
            "--- a/a.py\n"
            "+++ b/a.py\n"
            "@@ -0,0 +1,1 @@\n"
            "+eval(cmd)\n"
            "diff --git a/b.py b/b.py\n"
            "--- a/b.py\n"
            "+++ b/b.py\n"
            "@@ -0,0 +1,1 @@\n"
            "+TARGET = 'http://127.0.0.1:5000'\n"
        )
        report = self.scanner.scan_diff_content(diff, scan_mode="all")
        self.assertEqual(report["summary"]["total"], 2)
        files = {f["file"] for f in report["findings"]}
        self.assertEqual(files, {"a.py", "b.py"})

    # 13. Empty Diff Handling
    def test_empty_diff(self):
        report = self.scanner.scan_diff_content("", scan_mode="all")
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["summary"]["total"], 0)
        self.assertEqual(len(report["findings"]), 0)

    # 14. License Check Variations
    def test_license_variations(self):
        # Remove LICENSE created in setUp
        (self.repo_path / "LICENSE").unlink()

        # No license present
        lic_info = self.scanner.check_license()
        self.assertFalse(lic_info["root_license_present"])
        self.assertIsNone(lic_info["license_file"])

        # Test each accepted variation
        for valid_name in ["LICENSE.md", "LICENSE.txt", "COPYING"]:
            file_path = self.repo_path / valid_name
            file_path.write_text("License content", encoding="utf-8")
            lic_info = self.scanner.check_license()
            self.assertTrue(lic_info["root_license_present"], f"Failed for {valid_name}")
            self.assertEqual(lic_info["license_file"], valid_name)
            file_path.unlink()

    # 15. Sanitized Diff Patch Generation
    def test_generate_sanitized_diff(self):
        secret_tok = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
        raw_diff = (
            "diff --git a/auth.py b/auth.py\n"
            "--- a/auth.py\n"
            "+++ b/auth.py\n"
            "@@ -0,0 +1,2 @@\n"
            f"+token = '{secret_tok}'\n"
            "+print('initialized')\n"
        )
        sanitized = self.scanner.generate_sanitized_diff(raw_diff)
        self.assertNotIn(secret_tok, sanitized)
        self.assertIn("[REDACTED:GITHUB_TOKEN]", sanitized)
        self.assertIn("+print('initialized')", sanitized)

    # 16. Exit Code Evaluation
    def test_evaluate_exit_code(self):
        # High finding with default threshold (high) -> exit code 1
        report_high = {
            "status": "completed",
            "findings": [{"severity": "high"}],
        }
        self.assertEqual(scan_diff.evaluate_exit_code(report_high, threshold="high"), 1)

        # Medium finding with high threshold -> exit code 0
        report_med = {
            "status": "completed",
            "findings": [{"severity": "medium"}],
        }
        self.assertEqual(scan_diff.evaluate_exit_code(report_med, threshold="high"), 0)
        # Medium finding with medium threshold -> exit code 1
        self.assertEqual(scan_diff.evaluate_exit_code(report_med, threshold="medium"), 1)

        # Failed report -> exit code 2
        report_fail = {
            "status": "failed",
            "errors": ["Git execution failure"],
            "findings": [],
        }
        self.assertEqual(scan_diff.evaluate_exit_code(report_fail, threshold="high"), 2)


class TestIntegrationGitOperations(unittest.TestCase):
    """Integration tests running Git CLI in a temporary initialized repository."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="gss_git_repo_")
        self.repo_path = Path(self.temp_dir)

        # Initialize temporary Git repo
        subprocess.run(["git", "init"], cwd=str(self.repo_path), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=str(self.repo_path), check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(self.repo_path), check=True)

        # Ensure main branch name is standardized
        subprocess.run(["git", "branch", "-M", "main"], cwd=str(self.repo_path), check=True)
        # Create root LICENSE and initial commit
        (self.repo_path / "LICENSE").write_text("MIT License", encoding="utf-8")
        (self.repo_path / "README.md").write_text("# Test Repo", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(self.repo_path), check=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(self.repo_path), check=True)

        self.scanner = scan_diff.GitSecurityScanner(repo_root=self.repo_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # 17. Staged vs Unstaged Diff Retrieval
    def test_staged_and_unstaged_modes(self):
        # 1. Unstaged change
        (self.repo_path / "README.md").write_text("# Test Repo\n\neval(cmd)", encoding="utf-8")

        diff_unstaged, errs = self.scanner.get_diff("unstaged")
        self.assertIn("eval(cmd)", diff_unstaged)

        diff_staged, errs = self.scanner.get_diff("staged")
        self.assertEqual(diff_staged.strip(), "")

        # 2. Stage the change
        subprocess.run(["git", "add", "README.md"], cwd=str(self.repo_path), check=True)
        diff_staged, errs = self.scanner.get_diff("staged")
        self.assertIn("eval(cmd)", diff_staged)

        # 3. All mode
        diff_all, errs = self.scanner.get_diff("all")
        self.assertIn("eval(cmd)", diff_all)

    # 18. Branch Base Comparison Mode
    def test_base_branch_diff(self):
        # Create a new feature branch
        subprocess.run(["git", "checkout", "-b", "feature"], cwd=str(self.repo_path), check=True)
        (self.repo_path / "feature.py").write_text("val = 'http://localhost:3000'", encoding="utf-8")
        subprocess.run(["git", "add", "feature.py"], cwd=str(self.repo_path), check=True)
        subprocess.run(["git", "commit", "-m", "Feature commit"], cwd=str(self.repo_path), check=True)

        # Diff against main branch
        diff_base, errs = self.scanner.get_diff("base", base_branch="main")
        self.assertEqual(len(errs), 0)
        self.assertIn("http://localhost:3000", diff_base)


class TestAIReviewer(unittest.TestCase):
    """Unit tests for local AI reviewer loopback validation, error recovery, and mocked inference."""

    # 19. Loopback URL Validation
    def test_loopback_url_validation(self):
        self.assertTrue(ai_review.is_loopback_url("http://127.0.0.1:11434"))
        self.assertTrue(ai_review.is_loopback_url("http://localhost:11434"))
        self.assertTrue(ai_review.is_loopback_url("http://0.0.0.0:11434"))
        self.assertTrue(ai_review.is_loopback_url("http://[::1]:11434"))

        self.assertFalse(ai_review.is_loopback_url("https://api.openai.com/v1"))
        self.assertFalse(ai_review.is_loopback_url("http://192.168.1.100:11434"))
        self.assertFalse(ai_review.is_loopback_url("http://remote-server.org"))

    # 20. Ollama Offline / Unavailable Handling
    def test_ollama_unavailable_graceful_handling(self):
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            available, msg = ai_review.check_ollama_available("http://127.0.0.1:11434")
            self.assertFalse(available)
            self.assertIn("Could not connect to Ollama", msg)

    # 21. Mocked Successful Ollama Inference
    def test_mocked_successful_inference(self):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "response": "## Contextual Security Review\nThe detected finding appears to be a legitimate AWS key exposure."
        }).encode("utf-8")

        mock_context = MagicMock()
        mock_context.__enter__.return_value = mock_response

        with patch("urllib.request.urlopen", return_value=mock_context):
            success, text, err = ai_review.query_ollama(
                endpoint="http://127.0.0.1:11434",
                model="gemma3:4b",
                prompt="Review finding",
                system_prompt="You are a security reviewer",
            )
            self.assertTrue(success)
            self.assertIn("Contextual Security Review", text)
            self.assertIsNone(err)

    # 22. Mocked Malformed / Error Response
    def test_mocked_error_response(self):
        with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
            url="http://127.0.0.1:11434/api/generate",
            code=404,
            msg="Model Not Found",
            hdrs={},
            fp=None,
        )):
            success, text, err = ai_review.query_ollama(
                endpoint="http://127.0.0.1:11434",
                model="nonexistent-model",
                prompt="test",
                system_prompt="test",
            )
            self.assertFalse(success)
            self.assertIsNone(text)
            self.assertIn("HTTP Error 404", err)

    # 23. Dataclass Models and ScanReport Tests
    def test_dataclass_models(self):
        finding = scan_diff.Finding(
            rule_id="secret.aws_access_key",
            category="secrets",
            severity="critical",
            confidence="high",
            file="app.py",
            line=10,
            message="Test message",
            evidence="[REDACTED:AWS_KEY_ID]",
            recommendation="Rotate key",
        )
        self.assertEqual(finding.rule_id, "secret.aws_access_key")
        d = finding.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["file"], "app.py")

        summary = scan_diff.ScanSummary(total=1, critical=1)
        self.assertEqual(summary.to_dict()["critical"], 1)

        lic = scan_diff.LicenseStatus(root_license_present=True, license_file="LICENSE")
        self.assertTrue(lic.to_dict()["root_license_present"])

        report = scan_diff.ScanReport(
            findings=[finding],
            summary=summary,
            license=lic,
        )
        report_dict = report.to_dict()
        self.assertEqual(report_dict["summary"]["total"], 1)
        self.assertEqual(len(report_dict["findings"]), 1)

    # 24. Structured AI Review JSON Mode Extraction
    def test_ai_review_structured_json_mode(self):
        sample_json_str = json.dumps({
            "summary": "High risk AWS key found",
            "reviews": [{
                "rule_id": "secret.aws_access_key",
                "file": "app.py",
                "line": 10,
                "assessment": "genuine_risk",
                "risk_explanation": "Exposed cloud credential",
                "safe_alternative": "Use AWS IAM roles"
            }]
        })

        # Test extraction from raw json string
        parsed = ai_review.extract_json_from_text(sample_json_str)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["summary"], "High risk AWS key found")

        # Test extraction from markdown code fences
        fenced_json = f"```json\n{sample_json_str}\n```"
        parsed_fenced = ai_review.extract_json_from_text(fenced_json)
        self.assertIsNotNone(parsed_fenced)
        self.assertEqual(len(parsed_fenced["reviews"]), 1)

        # Test formatting structured report
        report_data = {"summary": {"total": 1}}
        formatted = ai_review.format_ai_review_report(
            model="gemma3:4b",
            provider="ollama",
            endpoint="http://127.0.0.1:11434",
            available=True,
            review_text=fenced_json,
            error_msg=None,
            report_data=report_data,
            format_mode="json",
        )
        self.assertIn("structured_review", formatted)
        self.assertEqual(formatted["structured_review"]["reviews"][0]["assessment"], "genuine_risk")

    # 25. Provider Detection Logic Test
    def test_provider_detection(self):
        # Default with no keys set
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(ai_review.detect_provider("auto"), "ollama")
            self.assertEqual(ai_review.detect_provider(), "ollama")

        # Gemini key set
        with patch.dict(os.environ, {"GEMINI_API_KEY": "dummy_key"}, clear=True):
            self.assertEqual(ai_review.detect_provider("auto"), "gemini")

        # Groq key set
        with patch.dict(os.environ, {"GROQ_API_KEY": "dummy_key"}, clear=True):
            self.assertEqual(ai_review.detect_provider("auto"), "groq")

        # OpenAI key set
        with patch.dict(os.environ, {"OPENAI_API_KEY": "dummy_key"}, clear=True):
            self.assertEqual(ai_review.detect_provider("auto"), "openai")

        # Explicit request overrides environment
        with patch.dict(os.environ, {"GEMINI_API_KEY": "dummy_key"}, clear=True):
            self.assertEqual(ai_review.detect_provider("openai"), "openai")
            self.assertEqual(ai_review.detect_provider("ollama"), "ollama")

    # 26. Mocked Google AI Studio Gemini API Test
    def test_mocked_gemini_inference(self):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "candidates": [{
                "content": {
                    "parts": [{"text": "Gemini review: Risk verified."}]
                }
            }]
        }).encode("utf-8")

        mock_context = MagicMock()
        mock_context.__enter__.return_value = mock_response

        with patch("urllib.request.urlopen", return_value=mock_context):
            success, text, err = ai_review.query_gemini(
                api_key="synthetic_test_key",
                model="gemini-1.5-flash",
                prompt="test prompt",
                system_prompt="test system",
            )
            self.assertTrue(success)
            self.assertEqual(text, "Gemini review: Risk verified.")
            self.assertIsNone(err)

    # 27. Mocked OpenAI-Compatible API Test
    def test_mocked_openai_inference(self):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "choices": [{
                "message": {"content": "OpenAI review: Potential vulnerability."}
            }]
        }).encode("utf-8")

        mock_context = MagicMock()
        mock_context.__enter__.return_value = mock_response

        with patch("urllib.request.urlopen", return_value=mock_context):
            success, text, err = ai_review.query_openai_compatible(
                endpoint="https://api.openai.com/v1/chat/completions",
                api_key="synthetic_test_key",
                model="gpt-4o-mini",
                prompt="test prompt",
                system_prompt="test system",
            )
            self.assertTrue(success)
            self.assertEqual(text, "OpenAI review: Potential vulnerability.")
            self.assertIsNone(err)


if __name__ == "__main__":
    unittest.main()
