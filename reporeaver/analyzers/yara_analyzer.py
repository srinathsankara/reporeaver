"""YARA rule engine — matches files against YARA rules for malware detection.

Provides:
  - Built-in rules (basic malware patterns)
  - Custom rules from a provided directory or file
  - yara-python integration (optional; works without it)

Uses yara-python if installed; falls back to a simple regex-based engine.
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import Category, Confidence, FileEntry, Finding, Severity
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer

# Minimal built-in YARA-like rules (regex-based, no yara-python dependency)
BUILTIN_RULES = [
    {
        "rule": "reporeaver_base64_payload",
        "description": "Large base64-encoded blob with executable indicators",
        "pattern": r'[A-Za-z0-9+/]{100,}={0,2}',
        "severity": Severity.MEDIUM,
        "condition": lambda m: m.count("=") < 5,
    },
    {
        "rule": "reporeaver_powershell_encoded",
        "description": "PowerShell encoded command detected",
        "pattern": r'(?i)powershell\s+.*(?:-e|-enc|-encodedcommand)\s+[A-Za-z0-9+/]{20,}',
        "severity": Severity.CRITICAL,
    },
    {
        "rule": "reporeaver_reverse_shell",
        "description": "Reverse shell command detected",
        "pattern": r'(?i)(?:bash|sh|nc|ncat)\s+-(?:i|e)\s*(?:\d+\s+)?(?:>&|>|<\s*/dev/tcp/)',
        "severity": Severity.CRITICAL,
    },
    {
        "rule": "reporeaver_vba_macro",
        "description": "VBA macro or AutoOpen detected",
        "pattern": r'(?i)(?:Sub\s+AutoOpen|Sub\s+Auto_Open|Workbook_Open|Document_Open|VBA\.)',
        "severity": Severity.HIGH,
    },
    {
        "rule": "reporeaver_php_webshell",
        "description": "PHP webshell indicator",
        "pattern": r'(?i)(?:system\(|shell_exec\(|passthru\(|exec\(|assert\(|eval\s*\(\s*\$_)',
        "severity": Severity.CRITICAL,
    },
    {
        "rule": "reporeaver_sql_injection",
        "description": "SQL injection pattern in code",
        "pattern": r'(?i)(?:SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=\s*["\']\s*["\']?\s*\+|UNION\s+SELECT\s+--\s|exec\s*\(\s*["\']SELECT)',
        "severity": Severity.HIGH,
    },
    {
        "rule": "reporeaver_dynamic_import",
        "description": "Dynamically constructed import/require",
        "pattern": r'(?i)(?:require|import)\s*\(\s*(?:[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+|`.*\$\{)',
        "severity": Severity.HIGH,
    },
    {
        "rule": "reporeaver_hidden_process",
        "description": "Process hiding technique",
        "pattern": r'(?i)(?:CreateProcessWithLogon|CreateProcessAsUser|NtUnmapViewOfSection|Process\.Start\s*\(\s*[^)]*\s*\)\s*\.\s*Start)',
        "severity": Severity.CRITICAL,
    },
    {
        "rule": "reporeaver_scheduled_task",
        "description": "Scheduled task creation for persistence",
        "pattern": r'(?i)(?:schtasks\s*/create|schtasks\s*/change|ScheduledTasks|Register-ScheduledJob)',
        "severity": Severity.HIGH,
    },
    {
        "rule": "reporeaver_ioc_http_user_agent",
        "description": "Custom User-Agent header — possible C2 communication",
        "pattern": r'(?i)(?:User-Agent|useragent)\s*:\s*["\'](?:Mozilla|curl|wget)[^"\']{0,10}',
        "severity": Severity.MEDIUM,
    },
]

YARA_RULE_DIRS = [
    os.path.expanduser("~/.reporeaver/yara"),
    "/etc/reporeaver/yara",
]


@register_analyzer
class YaraAnalyzer(BaseAnalyzer):
    name = "yara"
    description = "YARA rule matching — built-in + custom rules for malware detection"
    priority = 7

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self._yara_compiled = None
        self._init_yara()

    def _init_yara(self):
        """Try to load yara-python if available. If not, use built-in rules."""
        try:
            import yara
            rules = self._load_yara_files()
            if rules:
                self._yara_compiled = yara.compile(filepaths=rules)
        except ImportError:
            pass

    def _load_yara_files(self) -> Optional[Dict[str, str]]:
        """Load custom .yar/.yara files from known directories."""
        rules: Dict[str, str] = {}
        for d in YARA_RULE_DIRS:
            p = Path(d)
            if p.is_dir():
                for f in sorted(p.glob("*.yar")) + sorted(p.glob("*.yara")):
                    namespace = f.stem.replace(" ", "_")
                    rules[namespace] = str(f)
        return rules if rules else None

    def should_analyze(self, entry: FileEntry) -> bool:
        return entry.is_text and entry.size < 1_000_000

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        if self._yara_compiled is not None:
            return self._analyze_yara(entry, content)
        return self._analyze_builtin(entry, content)

    def _analyze_yara(self, entry: FileEntry, content: str) -> AnalyzerResult:
        """Use yara-python to match rules."""
        findings: List[Finding] = []
        try:
            matches = self._yara_compiled.match(data=content)
            for m in matches:
                findings.append(Finding(
                    entry.path, Severity.HIGH, Confidence.HIGH, Category.POLICY_VIOLATION,
                    title=f"YARA match: {m.rule}",
                    description=f"Matched YARA rule '{m.rule}' in {entry.path}",
                    attack_path="YARA rule triggered -> known malware pattern detected",
                    remediation="Review the matched content. Quarantine if confirmed malicious.",
                    raw_value=m.rule,
                ))
        except Exception:
            pass
        return AnalyzerResult(findings)

    def _analyze_builtin(self, entry: FileEntry, content: str) -> AnalyzerResult:
        """Built-in regex-based rules (no yara-python dependency)."""
        findings: List[Finding] = []

        for rule in BUILTIN_RULES:
            try:
                for match in re.finditer(rule["pattern"], content):
                    condition = rule.get("condition")
                    if condition and not condition(match.group(0)):
                        continue
                    line_no = content[:match.start()].count("\n") + 1
                    findings.append(Finding(
                        entry.path, rule["severity"], Confidence.MEDIUM, Category.POLICY_VIOLATION,
                        title=f"Pattern match: {rule['rule']}",
                        description=rule["description"],
                        attack_path="Built-in detection pattern triggered -> potential malware",
                        remediation="Review matched content manually.",
                        line_number=line_no,
                        snippet=_trunc(content[max(0, match.start()-20):match.end()+40], 150),
                    ))
            except re.error:
                pass

        return AnalyzerResult(findings)


def _trunc(s: str, n: int) -> str:
    return s[:n] + "..." if len(s) > n else s
