"""Script Analyzer — inspects package.json, Makefile, Dockerfile, shell scripts for build-time abuse."""

import json
import re
from typing import Dict, List, Optional, Set

from ..models import Category, Confidence, FileEntry, Finding, Severity
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer

HIGH_RISK_LIFECYCLE = {"preinstall", "install", "postinstall", "preuninstall", "uninstall"}
HIGH_RISK_SCRIPTS = {"preinstall", "install", "postinstall", "prepublish", "prebuild", "build", "pretest"}

SUSPICIOUS_PATTERNS = [
    (r"curl\s+[-]\w*\s*[SO]", Severity.HIGH, "Curl with silent/output flags"),
    (r"wget\s+[-]\w*\s*[qO]", Severity.HIGH, "Wget with quiet/output flags"),
    (r"(?:curl|wget)\s+.*\|\s*(?:bash|sh|powershell|cmd|python)", Severity.CRITICAL,
     "Remote script piped directly to shell"),
    (r"node\s+-(?:e|eval)\s+[\"']", Severity.HIGH, "Node inline evaluation"),
    (r"python\s+-c\s+[\"']", Severity.MEDIUM, "Python inline code execution"),
    (r"(?:child_process|execSync|exec\s*\()", Severity.CRITICAL, "Node.js process execution"),
    (r"(?:fs\.writeFile|writeFileSync|appendFile|createWriteStream)", Severity.HIGH,
     "File write from script"),
    (r"(?:chmod\s+777|chmod\s+\+x)", Severity.HIGH, "Permission modification"),
    (r"(?:base64|atob|btoa|fromCharCode)", Severity.MEDIUM, "Encoding/obfuscation functions"),
    (r"(?:env\.(?:SECRET|TOKEN|KEY|PASS|CREDENTIAL))", Severity.CRITICAL,
     "Access to environment secrets"),
    (r"(?:process\.env)", Severity.LOW, "Environment variable access"),
    (r"(?:sudo)", Severity.MEDIUM, "Sudo execution"),
    (r"(?:git\s+clone\s+https?://[^@]+@)", Severity.CRITICAL,
     "Git clone with embedded credentials"),
    (r"(?:npx|npm)\s+(?:exec|run)\s+.*(?:https?://)", Severity.HIGH,
     "Package execution from remote URL"),
    (r"(?:docker\s+run|docker\s+build)", Severity.MEDIUM, "Container execution"),
    (r"(?:/dev/tcp/|/dev/udp/)", Severity.CRITICAL, "Bash TCP/UDP redirection"),
    (r"(?:powershell\s+-(?:EncodedCommand|e)\s+)", Severity.HIGH, "PowerShell encoded command"),
]

CREDENTIAL_EXFIL = [
    (r"(?:cat|type|Get-Content)\s+.*(?:\.env|\.ssh|id_rsa|credentials|token|secret)",
     Severity.CRITICAL, "Credential file exfiltration"),
    (r"(?:env|printenv|echo)\s+.*(?:SECRET|TOKEN|PASS|API_KEY)",
     Severity.CRITICAL, "Environment variable exfiltration"),
    (r"(?:ls\s+-la\s+~/.ssh|cat\s+~/.ssh/authorized_keys)",
     Severity.CRITICAL, "SSH key enumeration"),
]

URL_DOWNLOAD = re.compile(r'(?:https?://[^\s"\'<>)]+)')


@register_analyzer
class ScriptAnalyzer(BaseAnalyzer):
    name = "script_analyzer"
    description = "Build script analysis: package.json, Makefile, Dockerfile, shell scripts"
    priority = 20

    def should_analyze(self, entry: FileEntry) -> bool:
        name = entry.path.rsplit("/", 1)[-1].lower()
        return name in ("package.json", "makefile", "dockerfile", "docker-compose.yml",
                        "docker-compose.yaml", "install.sh", "build.sh", "deploy.sh",
                        "entrypoint.sh") or entry.path.endswith((".sh", ".bash", ".ps1", ".bat"))

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        findings: List[Finding] = []
        path = entry.path
        name = entry.path.rsplit("/", 1)[-1].lower()

        if name == "package.json":
            self._check_package_json(content, path, findings)
        elif name in ("makefile", "dockerfile", "docker-compose.yml", "docker-compose.yaml"):
            self._check_build_file(content, path, findings)
        else:
            self._check_script_file(content, path, findings)

        return AnalyzerResult(findings)

    def _check_package_json(self, content: str, path: str, findings: List[Finding]):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        scripts = data.get("scripts", {})
        if not isinstance(scripts, dict):
            return

        for name, cmd in scripts.items():
            if not isinstance(cmd, str):
                continue
            if name in HIGH_RISK_LIFECYCLE:
                findings.append(Finding(
                    path, Severity.INFO, Confidence.HIGH, Category.LIFECYCLE_HOOK,
                    title=f"Package has '{name}' lifecycle script",
                    description=f"This script runs automatically during npm install: {_trunc(cmd, 200)}",
                    attack_path=f"npm install -> {name} script -> {_trunc(cmd, 100)}",
                    remediation="Audit lifecycle scripts carefully. Use `npm install --ignore-scripts` for inspection.",
                    snippet=cmd,
                ))

            self._match_patterns(cmd, path, findings, script_name=name)

        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for dep_name, dep_version in deps.items():
            if not isinstance(dep_version, str):
                continue
            if dep_version.startswith(("http://", "https://", "git+")):
                findings.append(Finding(
                    path, Severity.CRITICAL, Confidence.HIGH, Category.URL_DEPENDENCY,
                    title=f"Dependency '{dep_name}' resolved from URL: {_trunc(dep_version, 100)}",
                    description="URL-resolved dependencies bypass package registry security and can change at any time.",
                    attack_path=f"npm install -> fetches {dep_version} -> arbitrary code execution",
                    remediation="Use registry versions with lockfiles. Pin exact versions.",
                    raw_value=dep_version,
                ))

    def _check_build_file(self, content: str, path: str, findings: List[Finding]):
        self._match_patterns(content, path, findings)

    def _check_script_file(self, content: str, path: str, findings: List[Finding]):
        self._match_patterns(content, path, findings)

    def _match_patterns(self, text: str, path: str, findings: List[Finding],
                        script_name: Optional[str] = None):
        low = text.lower()
        for pat, severity, description in SUSPICIOUS_PATTERNS + CREDENTIAL_EXFIL:
            for match in re.finditer(pat, low):
                line_no = _line_of(text, match.start())
                findings.append(Finding(
                    path, severity, Confidence.MEDIUM, Category.SUSPICIOUS_COMMAND,
                    title=description,
                    description=f"Matched pattern: {_trunc(match.group(0), 120)}",
                    attack_path=f"Build executes -> {description} -> potential compromise",
                    remediation="Review and remove this command. Use safer alternatives.",
                    line_number=line_no, snippet=_trunc(text[max(0, match.start()-30):match.end()+30], 200),
                ))


def _line_of(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _trunc(s: str, n: int) -> str:
    return s[:n] + "..." if len(s) > n else s
