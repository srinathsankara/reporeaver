"""Workflow Analyzer — inspects GitHub Actions, CI/CD pipelines for unpinned actions, remote exec, secrets exposure."""

import re
from typing import Dict, List, Optional

from ..models import Category, Confidence, FileEntry, Finding, Severity
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer

WORKFLOW_FILES = {".github/workflows/"}
WORKFLOW_NAMES = {"action.yml", "action.yaml"}

SUSPICIOUS_ACTIONS = [
    (r"uses:\s+[^@]+@main", Severity.MEDIUM, "Action pinned to 'main' branch — mutable reference"),
    (r"uses:\s+[^@]+@master", Severity.MEDIUM, "Action pinned to 'master' branch — mutable reference"),
    (r"uses:\s+[^@]+@\d+", Severity.LOW, "Action pinned only by major version — may auto-update"),
    (r"uses:\s+[^@]+@[0-9a-f]{7}\b", Severity.LOW, "Short commit hash — may be ambiguous"),
]

REMOTE_EXEC_PATTERNS = [
    (r"run:\s*.*(?:curl|wget)\s+.*\|\s*(?:bash|sh|powershell)", Severity.CRITICAL,
     "Remote script piped to shell in CI"),
    (r"run:\s*.*(?:curl|wget)\s+-[SO].*\s*&&\s*(?:bash|sh|./)", Severity.CRITICAL,
     "Download then execute pattern in CI"),
    (r"run:\s*.*(?:npx|npm)\s+exec\s+.*https?://", Severity.HIGH,
     "Package execution from URL in CI"),
    (r"run:\s*.*docker\s+run\s+.*(?:bash|sh|curl)", Severity.MEDIUM,
     "Container execution in CI step"),
    (r"run:\s*.*(?:chmod\s+\+x|chmod\s+777)", Severity.MEDIUM,
     "Permission modification in CI"),
]

SECRETS_EXPOSURE = [
    (r"run:\s*.*echo\s+\${\{?\s*secrets\.", Severity.CRITICAL,
     "Secrets printed to CI logs"),
    (r"env:\s*\n.*(?:SECRET|TOKEN|KEY|PASS|CREDENTIAL)\s*:", Severity.HIGH,
     "Secret-like environment variable defined in workflow"),
    (r"\${\{?\s*secrets\.\w+\s*\}?}\s*\|", Severity.CRITICAL,
     "Secret piped to other commands — potential exfiltration"),
]

SUSPICIOUS_ACTIONS_LIST = [
    (r"actions/checkout@", Severity.INFO, "Standard checkout action"),
    (r"actions/upload-artifact@", Severity.LOW, "Artifact upload — verify what's uploaded"),
    (r"actions/download-artifact@", Severity.LOW, "Artifact download — verify source"),
    (r"docker://", Severity.MEDIUM, "Docker-based action — verify image source"),
]


@register_analyzer
class WorkflowAnalyzer(BaseAnalyzer):
    name = "workflow"
    description = "CI/CD pipeline analysis: GitHub Actions, unpinned actions, remote exec, secrets"
    priority = 30

    def should_analyze(self, entry: FileEntry) -> bool:
        name = entry.path.rsplit("/", 1)[-1].lower()
        path_lower = entry.path.lower()
        return name in WORKFLOW_NAMES or ".github/workflows/" in path_lower or \
               name in (".gitlab-ci.yml", ".gitlab-ci.yaml", "Jenkinsfile",
                        "azure-pipelines.yml", ".circleci/config.yml")

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        findings: List[Finding] = []
        path = entry.path
        yaml_lines = content.splitlines()
        joined = content

        self._check_pinning(joined, path, findings)
        self._check_remote_exec(joined, path, findings)
        self._check_secrets(joined, path, findings)
        self._check_actions(joined, path, findings)
        self._check_scheduled_triggers(joined, path, findings)

        return AnalyzerResult(findings)

    def _check_pinning(self, content: str, path: str, findings: List[Finding]):
        for line_no, line in enumerate(content.splitlines(), 1):
            for pat, severity, desc in SUSPICIOUS_ACTIONS:
                if re.search(pat, line):
                    findings.append(Finding(
                        path, severity, Confidence.MEDIUM, Category.UNPINNED_ACTION,
                        title=f"Unpinned action reference: {desc}",
                        description=f"Line: {_trunc(line.strip(), 150)}",
                        attack_path="CI runs -> unpinned action updated by attacker -> supply-chain compromise",
                        remediation="Pin actions to full commit SHA (40 char hex) for immutability.",
                        line_number=line_no, snippet=line.strip(),
                    ))

    def _check_remote_exec(self, content: str, path: str, findings: List[Finding]):
        for line_no, line in enumerate(content.splitlines(), 1):
            for pat, severity, desc in REMOTE_EXEC_PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append(Finding(
                        path, severity, Confidence.HIGH, Category.CI_REMOTE_EXEC,
                        title=f"CI remote execution: {desc}",
                        description=f"CI step downloads and/or executes code from network: {_trunc(line.strip(), 200)}",
                        attack_path="CI pipeline -> remote fetch -> execute untrusted code -> compromise",
                        remediation="Avoid downloading and executing remote content in CI. Use pinned actions with checksums.",
                        line_number=line_no, snippet=line.strip(),
                    ))

    def _check_secrets(self, content: str, path: str, findings: List[Finding]):
        for line_no, line in enumerate(content.splitlines(), 1):
            for pat, severity, desc in SECRETS_EXPOSURE:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append(Finding(
                        path, severity, Confidence.HIGH, Category.CI_SECRET_EXPOSURE,
                        title=f"CI secrets exposure: {desc}",
                        description=f"Potential secret exposure: {_trunc(line.strip(), 200)}",
                        attack_path="CI step runs -> secrets leaked in logs or exfiltrated -> credential theft",
                        remediation="Use GitHub Actions secrets securely. Avoid echoing or piping secrets.",
                        line_number=line_no, snippet=line.strip(),
                    ))

    def _check_actions(self, content: str, path: str, findings: List[Finding]):
        for line_no, line in enumerate(content.splitlines(), 1):
            for pat, severity, desc in SUSPICIOUS_ACTIONS_LIST:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append(Finding(
                        path, severity, Confidence.LOW, Category.INFO,
                        title=f"CI action: {desc}",
                        description=f"Action reference: {_trunc(line.strip(), 100)}",
                        attack_path="CI executes action -> behavior depends on action trustworthiness",
                        remediation="Verify action source and pin to SHA.",
                        line_number=line_no, snippet=line.strip(),
                    ))

    def _check_scheduled_triggers(self, content: str, path: str, findings: List[Finding]):
        if re.search(r"schedule:\s*\n", content) and re.search(r"cron:", content):
            findings.append(Finding(
                path, Severity.LOW, Confidence.LOW, Category.INFO,
                title="CI workflow has scheduled (cron) trigger",
                description="Scheduled workflows run automatically and could be used for persistence or data exfiltration.",
                attack_path="Scheduled trigger -> periodic execution -> persistence / beaconing",
                remediation="Review scheduled workflows. Ensure they're necessary and properly secured.",
            ))


def _trunc(s: str, n: int) -> str:
    return s[:n] + "..." if len(s) > n else s
