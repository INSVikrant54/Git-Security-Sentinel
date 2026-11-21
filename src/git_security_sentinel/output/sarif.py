"""
Git Security Sentinel - SARIF 2.1.0 Output Formatter.
Strictly adheres to OASIS SARIF 2.1.0 schema and GitHub Advanced Security specifications.
Zero third-party dependencies.
"""

from typing import Any, Dict, List, Optional

from git_security_sentinel.core.models import VERSION
from git_security_sentinel.redaction.redactor import redact_text

SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

SEVERITY_LEVEL_MAP: Dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def generate_sarif_report(
    report_data: Any,
    rules_catalog: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    """
    Converts internal scan report (ScanReport object or dict) to standard SARIF 2.1.0 format.
    Ensures strict schema compliance and complete secret redaction.
    """
    if hasattr(report_data, "to_dict"):
        report_dict = report_data.to_dict()
    elif isinstance(report_data, dict):
        report_dict = report_data
    else:
        report_dict = {}

    if rules_catalog is None:
        try:
            from git_security_sentinel.rules.catalog import get_all_rules
            rules_catalog = get_all_rules()
        except Exception:
            rules_catalog = []

    # Build driver rules list
    rules_dict: Dict[str, int] = {}
    driver_rules: List[Dict[str, Any]] = []

    for idx, rule in enumerate(rules_catalog):
        r_id = getattr(rule, "rule_id", None) or (rule.get("rule_id", "") if isinstance(rule, dict) else "")
        r_cat = getattr(rule, "category", None) or (rule.get("category", "secrets") if isinstance(rule, dict) else "secrets")
        r_sev = getattr(rule, "severity", None) or (rule.get("severity", "high") if isinstance(rule, dict) else "high")
        r_conf = getattr(rule, "confidence", None) or (rule.get("confidence", "high") if isinstance(rule, dict) else "high")
        r_msg = getattr(rule, "message", None) or (rule.get("message", "Security rule finding") if isinstance(rule, dict) else "Security rule finding")
        r_rec = getattr(rule, "recommendation", None) or (rule.get("recommendation", "Remediate finding safely.") if isinstance(rule, dict) else "Remediate finding safely.")

        level = SEVERITY_LEVEL_MAP.get(str(r_sev).lower(), "warning")
        rule_name = r_id.replace(".", "_").replace("-", "_")

        rule_obj = {
            "id": r_id,
            "name": rule_name,
            "shortDescription": {"text": str(r_msg)},
            "fullDescription": {"text": str(r_msg)},
            "defaultConfiguration": {"level": level},
            "help": {
                "text": str(r_rec),
                "markdown": f"**Remediation**: {r_rec}",
            },
            "properties": {
                "category": str(r_cat),
                "severity": str(r_sev),
                "confidence": str(r_conf),
                "tags": ["security", str(r_cat)],
            },
        }
        driver_rules.append(rule_obj)
        rules_dict[r_id] = idx

    # Build results list
    findings = report_dict.get("findings", [])
    results: List[Dict[str, Any]] = []

    for f in findings:
        r_id = f.get("rule_id", "unknown") if isinstance(f, dict) else getattr(f, "rule_id", "unknown")
        sev = f.get("severity", "high") if isinstance(f, dict) else getattr(f, "severity", "high")
        level = SEVERITY_LEVEL_MAP.get(str(sev).lower(), "warning")

        # Map to ruleIndex if present
        if r_id in rules_dict:
            rule_idx = rules_dict[r_id]
        else:
            # Dynamically append rule if not in catalogue
            rule_idx = len(driver_rules)
            driver_rules.append({
                "id": r_id,
                "name": r_id.replace(".", "_").replace("-", "_"),
                "shortDescription": {"text": "Security rule finding"},
                "fullDescription": {"text": "Security rule finding"},
                "defaultConfiguration": {"level": level},
                "help": {"text": "Remediate finding safely.", "markdown": "**Remediation**: Remediate finding safely."},
                "properties": {"category": "secrets", "severity": str(sev), "confidence": "high", "tags": ["security"]},
            })
            rules_dict[r_id] = rule_idx

        raw_file = f.get("file", "") if isinstance(f, dict) else getattr(f, "file", "")
        norm_file = str(raw_file).replace("\\", "/").lstrip("/")

        raw_line = f.get("line", 1) if isinstance(f, dict) else getattr(f, "line", 1)
        try:
            line_num = max(1, int(raw_line))
        except (ValueError, TypeError):
            line_num = 1

        raw_ev = f.get("evidence", "") if isinstance(f, dict) else getattr(f, "evidence", "")
        raw_msg = f.get("message", "") if isinstance(f, dict) else getattr(f, "message", "")
        raw_rec = f.get("recommendation", "") if isinstance(f, dict) else getattr(f, "recommendation", "")
        raw_cat = f.get("category", "secrets") if isinstance(f, dict) else getattr(f, "category", "secrets")

        # PRIVACY GUARANTEE: Redact any sensitive secret values from all text fields
        redacted_evidence = redact_text(str(raw_ev))
        redacted_msg = redact_text(str(raw_msg))

        if redacted_evidence and redacted_evidence not in redacted_msg:
            full_msg = f"{redacted_msg} Evidence: {redacted_evidence}"
        else:
            full_msg = redacted_msg

        result_obj = {
            "ruleId": r_id,
            "ruleIndex": rule_idx,
            "level": level,
            "message": {
                "text": full_msg,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": norm_file,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": line_num,
                            "startColumn": 1,
                            "snippet": {
                                "text": redacted_evidence,
                            },
                        },
                    }
                }
            ],
            "properties": {
                "recommendation": str(raw_rec),
                "category": str(raw_cat),
            },
        }
        results.append(result_obj)

    driver_version = str(report_dict.get("version", VERSION))

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Git Security Sentinel",
                        "semanticVersion": driver_version,
                        "informationUri": "https://github.com/INSVikrant54/Git-Security-Sentinel",
                        "rules": driver_rules,
                    }
                },
                "results": results,
            }
        ],
    }
