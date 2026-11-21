#!/usr/bin/env python3
"""
Unit Test Suite: AI Reviewer Enhancements v2 (--fix, --cost-estimate, prompts & backwards compatibility).
Tests Tier 1 through Tier 4 specifications for the Git Security Sentinel AI contextual review engine.
Strictly zero external test dependencies: pure Python standard library `unittest` and `unittest.mock` only.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure src/ and scripts/ are importable
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _REPO_ROOT / "src"
_SCRIPTS_DIR = _REPO_ROOT / "scripts"
for d in [str(_SRC_DIR), str(_SCRIPTS_DIR)]:
    if d not in sys.path:
        sys.path.insert(0, d)

from git_security_sentinel.ai.cost import (
    PRICING_TABLE,
    calculate_token_estimate,
    estimate_query_cost,
)
from git_security_sentinel.ai.prompts import build_system_prompt
from git_security_sentinel.ai_cli import (
    build_arg_parser as build_ai_cli_parser,
    build_user_prompt,
    format_ai_review_report,
    format_cost_banner,
    main as ai_cli_main,
    run_ai_review,
)
from git_security_sentinel.cli import build_arg_parser as build_scanner_cli_parser
import ai_review


class TestAIReviewerPromptsAndCost(unittest.TestCase):
    """Test system prompts, user prompts, token counting, and cost estimation."""

    def test_token_estimate_calculation(self):
        self.assertEqual(calculate_token_estimate(""), 0)
        self.assertEqual(calculate_token_estimate("abc"), 1)
        # ~4 chars per token: 4000 chars should be ~1000 tokens
        text = "def calculate_risk(input_str):\n    return hash(input_str)\n" * 100
        tokens = calculate_token_estimate(text)
        self.assertAlmostEqual(tokens, len(text) // 4, delta=5)

    def test_pricing_table_and_query_cost_providers(self):
        # Ollama local inference is always $0.00
        self.assertEqual(estimate_query_cost(1000, 500, provider="ollama"), 0.0)
        self.assertEqual(estimate_query_cost(1000, 500, provider="OLLAMA"), 0.0)

        # Gemini
        cost_gemini = estimate_query_cost(1_000_000, 1_000_000, provider="gemini")
        expected_gemini = PRICING_TABLE["gemini"]["input"] * 1_000_000 + PRICING_TABLE["gemini"]["output"] * 1_000_000
        self.assertAlmostEqual(cost_gemini, expected_gemini, places=6)
        self.assertGreater(cost_gemini, 0.0)

        # OpenAI
        cost_openai = estimate_query_cost(1_000_000, 1_000_000, provider="openai")
        expected_openai = PRICING_TABLE["openai"]["input"] * 1_000_000 + PRICING_TABLE["openai"]["output"] * 1_000_000
        self.assertAlmostEqual(cost_openai, expected_openai, places=6)

        # Groq
        cost_groq = estimate_query_cost(1_000_000, 1_000_000, provider="groq")
        expected_groq = PRICING_TABLE["groq"]["input"] * 1_000_000 + PRICING_TABLE["groq"]["output"] * 1_000_000
        self.assertAlmostEqual(cost_groq, expected_groq, places=6)

        # Unknown provider defaults to Ollama ($0.00)
        self.assertEqual(estimate_query_cost(1000, 500, provider="unknown_provider"), 0.0)

    def test_build_system_prompt_default_and_cwe_guidance(self):
        prompt = build_system_prompt()
        self.assertIn("Application Security Engineer", prompt)
        # Check insecure code patterns & CWE guidance
        for term in ["SQL Injection", "Shell Injection", "Insecure Deserialization", "XML External Entities", "Wildcard CORS", "Unverified SSL", "Debug Flags"]:
            self.assertIn(term, prompt)
        # Without fix mode, remediation diff mode is not enabled
        self.assertNotIn("Remediation Diff Mode Enabled", prompt)

    def test_build_system_prompt_fix_mode(self):
        prompt = build_system_prompt(fix_mode=True)
        self.assertIn("Remediation Diff Mode Enabled", prompt)
        self.assertIn("unified diff", prompt.lower())
        self.assertIn("Do NOT apply changes directly to files on disk", prompt)

    def test_build_system_prompt_json_mode(self):
        prompt_json = build_system_prompt(json_mode=True, fix_mode=False)
        self.assertIn("Respond ONLY with a single valid JSON object", prompt_json)
        self.assertIn('"reviews":', prompt_json)
        self.assertNotIn('"suggested_fix_diff":', prompt_json)

        prompt_json_fix = build_system_prompt(json_mode=True, fix_mode=True)
        self.assertIn('"suggested_fix_diff":', prompt_json_fix)

    def test_build_system_prompt_format_mode_compat(self):
        prompt_text = build_system_prompt(format_mode="text")
        self.assertIn("1. Executive Summary", prompt_text)

        prompt_json = build_system_prompt(format_mode="json")
        self.assertIn("Respond ONLY with a single valid JSON object", prompt_json)

    def test_build_user_prompt_with_and_without_fix(self):
        report = {
            "version": "1.1.0",
            "scan_mode": "staged",
            "findings": [
                {
                    "rule_id": "risky.sql_concatenation",
                    "category": "insecure_code",
                    "severity": "critical",
                    "confidence": "high",
                    "file": "app/db.py",
                    "line": 42,
                    "message": "Potential SQL injection",
                    "evidence": 'query = "SELECT * FROM users WHERE id = " + user_id',
                    "recommendation": "Use parameterized queries",
                }
            ],
            "license": {"root_license_present": True, "license_file": "LICENSE"},
            "summary": {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0},
        }

        # Normal prompt
        user_prompt = build_user_prompt(report, format_mode="text", fix_mode=False)
        self.assertIn("risky.sql_concatenation", user_prompt)
        self.assertNotIn("Remediation Diff Requirement", user_prompt)

        # Fix mode prompt
        user_prompt_fix = build_user_prompt(report, format_mode="text", fix_mode=True)
        self.assertIn("risky.sql_concatenation", user_prompt_fix)
        self.assertIn("Remediation Diff Requirement", user_prompt_fix)
        self.assertIn("Do NOT write or apply files to disk", user_prompt_fix)

    def test_format_cost_banner(self):
        cost_data = {
            "provider": "ollama",
            "model": "gemma3:4b",
            "prompt_tokens": 1250,
            "completion_tokens": 500,
            "total_tokens": 1750,
            "estimated_cost_usd": 0.0,
        }
        banner = format_cost_banner(cost_data)
        self.assertIn("COST ESTIMATION BANNER", banner)
        self.assertIn("OLLAMA (gemma3:4b)", banner)
        self.assertIn("1,250", banner)
        self.assertIn("500", banner)
        self.assertIn("$0.000000 (Free / Local)", banner)

        # Cloud banner
        cloud_cost_data = {
            "provider": "gemini",
            "model": "gemma-4-26b-a4b-it",
            "prompt_tokens": 10000,
            "completion_tokens": 1000,
            "total_tokens": 11000,
            "estimated_cost_usd": 0.00105,
        }
        cloud_banner = format_cost_banner(cloud_cost_data)
        self.assertIn("GEMINI (gemma-4-26b-a4b-it)", cloud_banner)
        self.assertIn("$0.001050", cloud_banner)
        self.assertNotIn("Free / Local", cloud_banner)


class TestAIReviewerCLIFlagsAndExecution(unittest.TestCase):
    """Test CLI argument registration, --fix, --cost-estimate execution and output formatting."""

    def test_cli_flags_registration_ai_cli(self):
        parser = build_ai_cli_parser()
        # Verify --fix and --cost-estimate flags
        parsed = parser.parse_args(["--report", "dummy.json", "--fix", "--cost-estimate"])
        self.assertTrue(parsed.fix)
        self.assertTrue(parsed.cost_estimate)

    def test_cli_flags_registration_scanner_cli(self):
        parser = build_scanner_cli_parser()
        parsed = parser.parse_args(["--ai", "--fix", "--cost-estimate"])
        self.assertTrue(parsed.ai)
        self.assertTrue(parsed.fix)
        self.assertTrue(parsed.cost_estimate)

    def test_run_ai_review_with_fix_and_cost_mocked_ollama(self):
        sample_report = {
            "version": "1.1.0",
            "scan_mode": "staged",
            "findings": [
                {
                    "rule_id": "risky.sql_concatenation",
                    "category": "insecure_code",
                    "severity": "critical",
                    "confidence": "high",
                    "file": "db.py",
                    "line": 10,
                    "message": "Potential SQL injection",
                    "evidence": "SELECT * FROM users",
                    "recommendation": "Use parameter substitution",
                }
            ],
            "license": {"root_license_present": True},
            "summary": {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0},
        }

        mock_diff = (
            "--- a/db.py\n"
            "+++ b/db.py\n"
            "@@ -10,1 +10,1 @@\n"
            "-    cursor.execute('SELECT * FROM users WHERE id = ' + user_id)\n"
            "+    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
        )
        mock_response = (
            "1. Executive Summary: Detected SQL concatenation in db.py.\n\n"
            "2. Finding-by-Finding Triage: Genuine critical risk.\n\n"
            "3. Safer Code Alternatives & Suggested Remediation Diffs:\n"
            "```diff\n" + mock_diff + "```\n\n"
            "4. Immediate Recommended Actions: Apply parameterized query."
        )

        with patch("git_security_sentinel.ai_cli.check_ollama_available", return_value=(True, "Ready")):
            with patch("git_security_sentinel.ai_cli.query_ollama", return_value=(True, mock_response, None)):
                success, out_struct, out_str = run_ai_review(
                    report_data=sample_report,
                    provider="ollama",
                    fix_mode=True,
                    cost_estimate=True,
                    format_mode="text",
                )

        self.assertTrue(success)
        self.assertTrue(out_struct["fix_mode"])
        self.assertIn("cost_estimate", out_struct)
        self.assertEqual(out_struct["cost_estimate"]["provider"], "ollama")
        self.assertEqual(out_struct["cost_estimate"]["estimated_cost_usd"], 0.0)

        # Check visual text output
        self.assertIn("COST ESTIMATION BANNER", out_str)
        self.assertIn("OLLAMA", out_str)
        self.assertIn("Safer Code Alternatives & Suggested Remediation Diffs", out_str)
        self.assertIn("--- a/db.py", out_str)

    def test_run_ai_review_json_mode_with_fix_and_cost(self):
        sample_report = {
            "version": "1.1.0",
            "findings": [],
            "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        }

        mock_json_content = {
            "summary": "Clean diff with no security vulnerabilities found.",
            "reviews": [],
        }

        with patch("git_security_sentinel.ai_cli.check_ollama_available", return_value=(True, "Ready")):
            with patch("git_security_sentinel.ai_cli.query_ollama", return_value=(True, json.dumps(mock_json_content), None)):
                success, out_struct, out_str = run_ai_review(
                    report_data=sample_report,
                    provider="ollama",
                    fix_mode=True,
                    cost_estimate=True,
                    format_mode="json",
                )

        self.assertTrue(success)
        self.assertTrue(out_struct["fix_mode"])
        self.assertIn("cost_estimate", out_struct)
        self.assertIn("structured_review", out_struct)
        self.assertEqual(out_struct["structured_review"]["summary"], "Clean diff with no security vulnerabilities found.")

        # Ensure valid JSON output string
        parsed_out = json.loads(out_str)
        self.assertEqual(parsed_out["cost_estimate"]["estimated_cost_usd"], 0.0)
        self.assertTrue(parsed_out["fix_mode"])

    def test_no_disk_mutation_in_fix_mode(self):
        """Invariant: --fix mode displays remediation diffs but NEVER mutates files on disk."""
        with tempfile.TemporaryDirectory(prefix="sentinel_no_mutate_") as tmpdir:
            file_path = Path(tmpdir) / "vuln.py"
            original_content = "import os\nos.system('echo ' + user_input)\n"
            file_path.write_text(original_content, encoding="utf-8")

            sample_report = {
                "version": "1.1.0",
                "findings": [
                    {
                        "rule_id": "risky.shell_injection",
                        "category": "insecure_code",
                        "severity": "critical",
                        "file": str(file_path),
                        "line": 2,
                        "message": "Potential shell injection",
                        "evidence": "os.system('echo ' + user_input)",
                        "recommendation": "Use subprocess.run without shell",
                    }
                ],
                "summary": {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0},
            }

            mock_diff = (
                f"--- a/{file_path.name}\n"
                f"+++ b/{file_path.name}\n"
                "@@ -2,1 +2,1 @@\n"
                "-os.system('echo ' + user_input)\n"
                "+subprocess.run(['echo', user_input], check=True)\n"
            )

            with patch("git_security_sentinel.ai_cli.check_ollama_available", return_value=(True, "Ready")):
                with patch("git_security_sentinel.ai_cli.query_ollama", return_value=(True, f"Suggested fix:\n```diff\n{mock_diff}```", None)):
                    success, _, out_str = run_ai_review(
                        report_data=sample_report,
                        provider="ollama",
                        fix_mode=True,
                        format_mode="text",
                    )

            self.assertTrue(success)
            # The file on disk MUST NOT be changed
            self.assertEqual(file_path.read_text(encoding="utf-8"), original_content)
            self.assertIn(mock_diff, out_str)

    def test_cloud_provider_cost_estimation_gemini_mocked(self):
        sample_report = {"version": "1.1.0", "findings": [], "summary": {"total": 0}}
        with patch.dict(os.environ, {"GEMINI_API_KEY": "fake-test-key-123"}):
            with patch("git_security_sentinel.ai_cli.query_gemini", return_value=(True, "Review content", None)):
                success, out_struct, out_str = run_ai_review(
                    report_data=sample_report,
                    provider="gemini",
                    cost_estimate=True,
                    format_mode="text",
                )

        self.assertTrue(success)
        self.assertEqual(out_struct["cost_estimate"]["provider"], "gemini")
        self.assertGreater(out_struct["cost_estimate"]["estimated_cost_usd"], 0.0)
        self.assertIn("COST ESTIMATION BANNER", out_str)
        self.assertIn("GEMINI", out_str)

    def test_cloud_provider_cost_estimation_openai_mocked(self):
        sample_report = {"version": "1.1.0", "findings": [], "summary": {"total": 0}}
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-fake-openai-test-key"}):
            with patch("git_security_sentinel.ai_cli.query_openai_compatible", return_value=(True, "OpenAI review", None)):
                success, out_struct, out_str = run_ai_review(
                    report_data=sample_report,
                    provider="openai",
                    cost_estimate=True,
                    format_mode="text",
                )

        self.assertTrue(success)
        self.assertEqual(out_struct["cost_estimate"]["provider"], "openai")
        self.assertGreater(out_struct["cost_estimate"]["estimated_cost_usd"], 0.0)
        self.assertIn("OPENAI", out_str)

    def test_cloud_provider_cost_estimation_groq_mocked(self):
        sample_report = {"version": "1.1.0", "findings": [], "summary": {"total": 0}}
        with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_fake_groq_test_key"}):
            with patch("git_security_sentinel.ai_cli.query_openai_compatible", return_value=(True, "Groq review", None)):
                success, out_struct, out_str = run_ai_review(
                    report_data=sample_report,
                    provider="groq",
                    cost_estimate=True,
                    format_mode="text",
                )

        self.assertTrue(success)
        self.assertEqual(out_struct["cost_estimate"]["provider"], "groq")
        self.assertGreater(out_struct["cost_estimate"]["estimated_cost_usd"], 0.0)
        self.assertIn("GROQ", out_str)


class TestAIReviewerErrorHandlingAndBackwardsCompat(unittest.TestCase):
    """Test CLI error handling and backwards compatibility wrapper scripts/ai_review.py."""

    def test_missing_report_file_exits_code_2(self):
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            code = ai_cli_main(["--report", "non_existent_scan_report_12345.json"])
        self.assertEqual(code, 2)
        self.assertIn("does not exist", stderr_buf.getvalue())

    def test_corrupt_report_json_exits_code_2(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as f:
            f.write("{invalid json content")
            f_path = f.name
        try:
            stderr_buf = io.StringIO()
            with patch("sys.stderr", stderr_buf):
                code = ai_cli_main(["--report", f_path])
            self.assertEqual(code, 2)
            self.assertIn("Failed to parse scan report JSON", stderr_buf.getvalue())
        finally:
            os.unlink(f_path)

    def test_missing_api_keys_returns_graceful_error(self):
        sample_report = {"version": "1.1.0", "findings": [], "summary": {"total": 0}}
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}, clear=True):
            success, out_struct, out_str = run_ai_review(
                report_data=sample_report,
                provider="gemini",
            )
            self.assertFalse(success)
            self.assertIn("requires GEMINI_API_KEY", out_struct["error"])

    def test_ollama_unreachable_displays_guidance_and_cost_banner(self):
        sample_report = {"version": "1.1.0", "findings": [], "summary": {"total": 0}}
        with patch("git_security_sentinel.ai_cli.check_ollama_available", return_value=(False, "Connection refused")):
            success, out_struct, out_str = run_ai_review(
                report_data=sample_report,
                provider="ollama",
                cost_estimate=True,
                format_mode="text",
            )
            self.assertFalse(success)
            self.assertIn("INFERENCE SKIPPED", out_str)
            self.assertIn("Local Ollama server is not reachable", out_str)
            self.assertIn("COST ESTIMATION BANNER", out_str)

    def test_backwards_compatibility_wrapper_exports_and_runs(self):
        # Verify scripts/ai_review.py re-exports new functions
        self.assertTrue(hasattr(ai_review, "calculate_token_estimate"))
        self.assertTrue(hasattr(ai_review, "estimate_query_cost"))
        self.assertTrue(hasattr(ai_review, "PRICING_TABLE"))
        self.assertTrue(hasattr(ai_review, "build_system_prompt"))
        self.assertTrue(hasattr(ai_review, "run_ai_review"))
        self.assertTrue(hasattr(ai_review, "main"))

        # Verify executing scripts/ai_review.py parser handles --fix and --cost-estimate
        parser = ai_review.build_arg_parser()
        args = parser.parse_args(["--report", "dummy.json", "--fix", "--cost-estimate"])
        self.assertTrue(args.fix)
        self.assertTrue(args.cost_estimate)


if __name__ == "__main__":
    unittest.main()
