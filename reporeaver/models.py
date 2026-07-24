"""Data models. Nothing fancy, just the shapes we pass around."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    ERROR = "error"


SEVERITY_ORDER = {s: i for i, s in enumerate(Severity)}


class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# These map to specific detection types. Used for policy rules and SARIF output.
class Category(Enum):
    SVG_SCRIPT = "svg_script"
    SVG_EVENT_HANDLER = "svg_event_handler"
    SVG_XXE = "svg_xxe"
    SVG_DATA_URI = "svg_data_uri"
    SVG_FOREIGN_OBJECT = "svg_foreign_object"
    UNICODE_TRICK = "unicode_trick"
    ZERO_WIDTH_CHAR = "zero_width_char"
    HOMOGLYPH = "homoglyph"
    BIDI_OVERRIDE = "bidi_override"
    OBFUSCATED_SCRIPT = "obfuscated_script"
    OBFUSCATED_ENCODING = "obfuscation_encoding"
    HIGH_ENTROPY = "high_entropy"
    ENCODED_PAYLOAD = "encoded_payload"
    SUSPICIOUS_JS_API = "suspicious_js_api"
    SUSPICIOUS_NODE_API = "suspicious_node_api"
    LIFECYCLE_HOOK = "lifecycle_hook"
    SUSPICIOUS_COMMAND = "suspicious_command"
    CREDENTIAL_THEFT = "credential_theft"
    EXTERNAL_DOWNLOAD = "external_download"
    C2_CALLBACK = "c2_callback"
    RUNTIME_NETWORK_CALL = "runtime_network_call"
    UNPINNED_ACTION = "unpinned_action"
    CI_REMOTE_EXEC = "ci_remote_exec"
    CI_SECRET_EXPOSURE = "ci_secret_exposure"
    POSTINSTALL_CHAIN = "postinstall_chain"
    SUSPICIOUS_DEPENDENCY = "suspicious_dependency"
    URL_DEPENDENCY = "url_dependency"
    MIME_MISMATCH = "mime_mismatch"
    POLYGLOT_FILE = "polyglot_file"
    BEHAVIORAL_NETWORK = "behavioral_network"
    BEHAVIORAL_EXEC = "behavioral_exec"
    BEHAVIORAL_PERSISTENCE = "behavioral_persistence"
    BEHAVIORAL_EXFIL = "behavioral_exfil"
    POLICY_VIOLATION = "policy_violation"
    INFO = "info"
    PARSE_ERROR = "parse_error"


@dataclass
class Finding:
    """One finding. Has file, severity, what we found, and how bad it is."""
    file_path: str
    severity: Severity
    confidence: Confidence
    category: Category
    title: str
    description: str
    attack_path: Optional[str] = None
    remediation: Optional[str] = None
    line_number: Optional[int] = None
    snippet: Optional[str] = None
    decoded: Optional[str] = None
    raw_value: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file_path,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "attack_path": self.attack_path,
            "remediation": self.remediation,
            "line": self.line_number,
            "snippet": _trunc(self.snippet, 300),
            "decoded": _trunc(self.decoded, 500),
            "raw": _trunc(self.raw_value, 200),
        }

    def __repr__(self) -> str:
        loc = f":{self.line_number}" if self.line_number else ""
        return f"[{self.severity.value}] {self.file_path}{loc} - {self.title}"


@dataclass
class RiskScore:
    """Aggregated risk. 0-10 scale, higher = worse."""
    score: float
    max_severity: Severity
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 1),
            "max_severity": self.max_severity.value,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "total": self.total,
        }

    @classmethod
    def compute(cls, findings: List[Finding]) -> "RiskScore":
        c = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        h = sum(1 for f in findings if f.severity == Severity.HIGH)
        m = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        l = sum(1 for f in findings if f.severity == Severity.LOW)
        # rough heuristic: 3 pts per critical, 1.5 per high, 0.5 per medium
        score = min(10.0, c * 3.0 + h * 1.5 + m * 0.5)
        max_sev = Severity.CRITICAL if c else Severity.HIGH if h else Severity.MEDIUM if m else Severity.LOW if l else Severity.INFO
        return cls(score, max_sev, c, h, m, l, len(findings))


@dataclass
class FileEntry:
    """Normalized file info. Used by analyzers to decide if they care."""
    path: str
    size: int
    detected_mime: Optional[str] = None
    declared_ext: Optional[str] = None
    is_text: bool = False
    is_svg: bool = False
    is_script: bool = False
    is_config: bool = False
    is_binary: bool = False
    is_executable: bool = False
    language: Optional[str] = None
    hash_sha256: Optional[str] = None


@dataclass
class ScanResult:
    """Complete scan result. Gets serialized to JSON/SARIF/HTML."""
    target: str
    scan_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
    tool: str = "reporeaver"
    version: str = "0.2.0"
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    risk_score: Optional[RiskScore] = None
    summary: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scan_time": self.scan_time,
            "tool": self.tool,
            "version": self.version,
            "files_scanned": self.files_scanned,
            "risk_score": self.risk_score.to_dict() if self.risk_score else None,
            "summary": self.summary,
            "findings": [f.to_dict() for f in sorted(
                self.findings,
                key=lambda x: (SEVERITY_ORDER.get(x.severity, 99), x.file_path or "", x.line_number or 0),
            )],
        }


def _trunc(s: Optional[str], n: int) -> Optional[str]:
    if s is None:
        return None
    return s[:n] + "..." if len(s) > n else s
