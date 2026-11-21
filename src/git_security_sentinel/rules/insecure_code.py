"""
Git Security Sentinel - Insecure Code Patterns & CWEs Detection Rules.
Covers Shell injection, pickle, unsafe YAML, SQL injection, XXE, temp credentials,
debug flags, wildcard CORS, unverified SSL, eval execution, and localhost endpoints.
"""

import re
from typing import List

from git_security_sentinel.core.models import Rule

INSECURE_CODE_RULES: List[Rule] = [
    Rule(
        rule_id="insecure_code.shell_injection",
        category="insecure_code",
        severity="high",
        confidence="medium",
        pattern=re.compile(
            r"\b(?:subprocess\.(?:Popen|run|call|check_call|check_output)\s*\([^)]*shell\s*=\s*(?:True|1)|os\.system\s*\([^)]*\)|os\.popen\s*\([^)]*\))"
        ),
        message="Subprocess invocation with shell=True or os.system() detected (potential command injection CWE-78).",
        recommendation="Avoid shell=True. Pass arguments as a list of strings and sanitize inputs.",
    ),
    Rule(
        rule_id="insecure_code.pickle_deserialization",
        category="insecure_code",
        severity="critical",
        confidence="high",
        pattern=re.compile(r"\b(?:pickle|_pickle|cPickle)\.(?:loads?|Unpickler)\s*\("),
        message="Unsafe object deserialization using pickle detected (CWE-502).",
        recommendation="Never deserialize untrusted data with pickle. Use json, msgpack, or protobuf instead.",
    ),
    Rule(
        rule_id="insecure_code.unsafe_yaml",
        category="insecure_code",
        severity="high",
        confidence="high",
        pattern=re.compile(
            r"\byaml\.(?:load|load_all)\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader\b)|\byaml\.unsafe_load\s*\("
        ),
        message="Unsafe YAML deserialization without SafeLoader detected (CWE-502).",
        recommendation="Use yaml.safe_load() or specify Loader=yaml.SafeLoader when loading YAML data.",
    ),
    Rule(
        rule_id="insecure_code.sql_concatenation",
        category="insecure_code",
        severity="high",
        confidence="medium",
        pattern=re.compile(
            r"""(?i)(?:execute|cursor\.execute|session\.execute)\s*\(\s*(?:f['"]|['"].*?%|['"].*?\+\s*|[a-z0-9_]+\s*\+\s*['"]).*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|WHERE)\b"""
        ),
        message="Potential SQL Injection via string formatting or concatenation (CWE-89).",
        recommendation="Use parameterized queries (e.g. cursor.execute('SELECT * FROM t WHERE id = %s', (id,))) or an ORM.",
    ),
    Rule(
        rule_id="insecure_code.xxe_injection",
        category="insecure_code",
        severity="high",
        confidence="medium",
        pattern=re.compile(
            r"""(?i)\b(?:xml\.etree|xml\.sax|lxml\.etree|xml\.dom\.minidom)\b.*(?:parse|fromstring)\s*\(|resolve_entities\s*=\s*True|XMLParser\s*\([^)]*resolve_entities\s*=\s*True"""
        ),
        message="XML parser with external entity resolution or standard parser without entity protection detected (CWE-611).",
        recommendation="Use defusedxml or disable external entity resolution (resolve_entities=False).",
    ),
    Rule(
        rule_id="insecure_code.temp_credential",
        category="insecure_code",
        severity="high",
        confidence="medium",
        pattern=re.compile(
            r"""(?i)(?:temp_password|temporary_password|test_credential|staging_token|mock_secret)\s*[:=]\s*['"]([^'"\r\n]{8,64})['"]"""
        ),
        message="Hardcoded temporary or staging credential detected in source code.",
        recommendation="Inject temporary credentials via environment variables and keep secrets out of source.",
    ),
    Rule(
        rule_id="insecure_code.debug_enabled",
        category="insecure_code",
        severity="medium",
        confidence="high",
        pattern=re.compile(
            r"(?i)\b(?:DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|settings\.DEBUG\s*=\s*True)\b"
        ),
        message="Application debug mode enabled (CWE-215).",
        recommendation="Ensure DEBUG is set to False in production environments.",
    ),
    Rule(
        rule_id="insecure_code.wildcard_cors",
        category="insecure_code",
        severity="medium",
        confidence="high",
        pattern=re.compile(
            r"""(?i)(?:Access-Control-Allow-Origin['"]?\s*[:=,]\s*['"]?\*['"]?|allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]|CORS\([^)]*origins\s*=\s*['"]\*['"])"""
        ),
        message="Permissive wildcard CORS header ('*') detected (CWE-942).",
        recommendation="Explicitly specify trusted origin domains instead of wildcard '*' for CORS.",
    ),
    Rule(
        rule_id="insecure_code.unverified_ssl",
        category="insecure_code",
        severity="high",
        confidence="high",
        pattern=re.compile(
            r"""(?i)\b(?:verify\s*=\s*False|ssl\._create_unverified_context|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?|check_hostname\s*=\s*False)\b"""
        ),
        message="Disabled SSL/TLS certificate verification detected (CWE-295).",
        recommendation="Enable SSL/TLS certificate verification (verify=True) to prevent Man-in-the-Middle (MITM) attacks.",
    ),
    Rule(
        rule_id="risk.eval_execution",
        category="insecure_code",
        severity="medium",
        confidence="medium",
        pattern=re.compile(r"\b(?:eval|exec)\s*\((?!\s*['\"][^'\"]*['\"]\s*\))"),
        message="Potentially unsafe dynamic code execution using eval() or exec().",
        recommendation="Avoid eval()/exec() with dynamic or user-influenced data to prevent arbitrary code execution (CWE-95). Use ast.literal_eval() or safe parser alternatives.",
    ),
    Rule(
        rule_id="risk.localhost_endpoint",
        category="configuration",
        severity="low",
        confidence="high",
        pattern=re.compile(
            r"""https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::[0-9]{1,5})?(?:/[^\s'"]*)?"""
        ),
        message="Hardcoded local loopback URL endpoint detected in code.",
        recommendation="Ensure development endpoints are parameterized via environment variables before deploying to production.",
    ),
]
