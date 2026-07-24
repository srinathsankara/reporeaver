"""Behavioral analysis — looks for code patterns that match malware behaviors.

Groups findings into: network calls, code execution, persistence, data exfiltration.
"""

import re
from typing import List

from ..models import Category, Confidence, FileEntry, Finding, Severity
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer

# Each behavior group has a list of (regex_pattern, severity) tuples.
# These get checked against file contents with re.IGNORECASE.
BEHAVIOR_PATTERNS = {
    "network_behavior": {
        "patterns": [
            (r"https?://[^\s\"'<>)]+(?:download|payload|shell|backdoor|beacon|callback)", Severity.CRITICAL),
            (r"(?:curl|wget|fetch|http\.get|https\.get)\s*\(.*(?:http|https)", Severity.HIGH),
            (r"new\s+XMLHttpRequest|new\s+WebSocket|new\s+EventSource", Severity.HIGH),
            (r"(?:nslookup|dig|ping)\s+[^\s]", Severity.MEDIUM),
            (r"/dev/tcp/|/dev/udp/", Severity.CRITICAL),
            (r"(?:socket|connect|send|dgram)", Severity.MEDIUM),
        ],
        "category": Category.BEHAVIORAL_NETWORK,
        "title": "Network communication — may phone home or download payloads",
    },
    "execution_behavior": {
        "patterns": [
            (r"(?:eval|exec)\s*\([\"'].*[\"']\s*\)", Severity.CRITICAL),
            (r"(?:child_process|execSync|spawn|spawnSync|execFile|fork)", Severity.CRITICAL),
            (r"(?:os\.system|subprocess\.(?:call|Popen|run)|popen)", Severity.CRITICAL),
            (r"(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)", Severity.CRITICAL),
            (r"Function\s*\([\"'].*[\"']\)", Severity.CRITICAL),
            (r"setTimeout\s*\([\"'].*[\"']", Severity.MEDIUM),
            (r"node\s+(?:-e|--eval)\s+[\"']", Severity.HIGH),
            (r"python\s+-c\s+[\"']", Severity.HIGH),
        ],
        "category": Category.BEHAVIORAL_EXEC,
        "title": "Code execution — runs commands or evaluates strings as code",
    },
    "persistence_behavior": {
        "patterns": [
            (r"(?:writeFile|writeFileSync|appendFile|createWriteStream|fwrite)", Severity.HIGH),
            (r"(?:chmod|chown|attrib)\s+\+", Severity.MEDIUM),
            (r"(?:crontab|schtasks|at\s+|systemd)", Severity.HIGH),
            (r"(?:reg\s+add|REG ADD)", Severity.HIGH),
            (r"(?:nssm|srvany|winsw)", Severity.HIGH),
            (r"(?:Startup|StartupFolder|AutoRun)", Severity.MEDIUM),
            (r"(?:\.bashrc|\.bash_profile|\.profile|\.zshrc)", Severity.MEDIUM),
        ],
        "category": Category.BEHAVIORAL_PERSISTENCE,
        "title": "Persistence mechanism — writes to disk or installs auto-start",
    },
    "exfiltration_behavior": {
        "patterns": [
            (r"(?:https?://[^\s\"'<>)]+\?(?:[^\s]*)(?:token|key|secret|pass|credential)=)", Severity.CRITICAL),
            (r"(?:cat|type|Get-Content)\s+.*(?:\.env|\.ssh|id_rsa|credential)", Severity.CRITICAL),
            (r"(?:env|printenv|echo)\s+\$?[A-Z_]*SECRET", Severity.CRITICAL),
            (r"(?:process\.env\[|process\.env\.)", Severity.MEDIUM),
            (r"environ\[.*(?:TOKEN|KEY|SECRET|PASS)", Severity.HIGH),
            (r"(?:ftp|sftp|scp)\s+[^\s]+@", Severity.HIGH),
        ],
        "category": Category.BEHAVIORAL_EXFIL,
        "title": "Data exfiltration — reads secrets or sends data externally",
    },
}


@register_analyzer
class BehavioralAnalyzer(BaseAnalyzer):
    name = "behavioral"
    description = "Flags code patterns matching malware behaviors: net, exec, persist, exfil"
    priority = 45

    def should_analyze(self, entry: FileEntry) -> bool:
        return entry.is_text and entry.size < 2_000_000

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        findings = []
        for name, cfg in BEHAVIOR_PATTERNS.items():
            check_behavior(content, entry.path, findings, name, cfg)
        return AnalyzerResult(findings)


def check_behavior(content: str, path: str, findings: List[Finding],
                   behavior_name: str, config: dict):
    for pat, severity in config["patterns"]:
        for match in re.finditer(pat, content, re.IGNORECASE):
            line = content[:match.start()].count("\n") + 1
            ctx = content[max(0, match.start() - 20):match.end() + 40]
            findings.append(Finding(
                path, severity, Confidence.MEDIUM, config["category"],
                title=config["title"],
                description=f"Pattern '{behavior_name}': {trunc(match.group(0), 120)}",
                attack_path=f"Code executes -> {config['title']} -> system compromised",
                remediation="Audit this code. If legit, run it in an isolated environment.",
                line_number=line, snippet=trunc(ctx, 200),
            ))


def trunc(s: str, n: int) -> str:
    return s[:n] + "..." if len(s) > n else s
