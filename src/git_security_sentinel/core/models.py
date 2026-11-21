"""
Git Security Sentinel - Core Data Models and Constants.
"""

from dataclasses import asdict, dataclass, field
import re
from typing import Any, Callable, Dict, List, Optional, Pattern

VERSION = "1.2.0"
SCANNER_NAME = "git-security-sentinel"

# Accepted root license filenames
ACCEPTED_LICENSE_NAMES = ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"]

# Severity ranking for exit-code threshold comparisons
SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


@dataclass
class Finding:
    """Represents a single detected security or compliance finding."""

    rule_id: str
    category: str
    severity: str
    confidence: str
    file: str
    line: int
    message: str
    evidence: str
    recommendation: str
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    fingerprint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LicenseStatus:
    """Represents the status of repository root license compliance."""

    root_license_present: bool
    license_file: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanSummary:
    """Statistical summary of findings broken down by severity level."""

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    suppressed: int = 0

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)


@dataclass
class ScanReport:
    """Complete structured security scan report."""

    scanner: str = SCANNER_NAME
    version: str = VERSION
    status: str = "completed"
    scan_mode: str = "all"
    findings: List[Finding] = field(default_factory=list)
    license: LicenseStatus = field(default_factory=lambda: LicenseStatus(False))
    summary: ScanSummary = field(default_factory=ScanSummary)
    errors: List[str] = field(default_factory=list)
    suppressed_findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner": self.scanner,
            "version": self.version,
            "status": self.status,
            "scan_mode": self.scan_mode,
            "findings": [f.to_dict() for f in self.findings],
            "license": self.license.to_dict(),
            "summary": self.summary.to_dict(),
            "errors": self.errors,
            "suppressed_findings": [f.to_dict() for f in self.suppressed_findings],
        }


@dataclass
class Rule:
    """Rule definition for secret and code pattern scanning."""

    rule_id: str
    category: str
    severity: str
    confidence: str
    pattern: Pattern[str]
    message: str
    recommendation: str
    validator: Optional[Callable[[re.Match, str], bool]] = None
