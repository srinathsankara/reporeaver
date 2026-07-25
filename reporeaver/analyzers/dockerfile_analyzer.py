"""Dockerfile analyzer — checks for unsafe patterns in container builds."""

import re
from typing import List

from ..models import Category, Confidence, FileEntry, Finding, Severity
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer

DANGEROUS_INSTRUCTIONS = [
    (r'^\s*FROM\s+.*:\s*(?:latest|$(?:[^/]|$))', Severity.MEDIUM,
     "FROM uses 'latest' tag — mutable and unpredictable"),
    (r'^\s*COPY\s+--from\s*=\s*[^s][^t][^a][^g][^e]', Severity.MEDIUM,
     "COPY from a named stage — verify stage is trustworthy"),
    (r'^\s*ADD\s+https?://[^\s]+', Severity.HIGH,
     "ADD from URL — automatically extracts archives (potential zip slip)"),
    (r'^\s*RUN\s+.*(?:curl|wget)\s+.*[\|>]', Severity.CRITICAL,
     "Download and pipe/save in RUN — remote code in build step"),
    (r'^\s*(?:USER\s+root|USER\s+0\s*$)', Severity.MEDIUM,
     "Runs as root — containers should use least-privilege user"),
    (r'^\s*ENV\s+(?:NODE_ENV|PYTHON_ENV|RAILS_ENV)\s*=\s*production',
     Severity.LOW, "Production env var — verify this is intentional"),
    (r'^\s*RUN\s+.*chmod\s+[-]?[0-9]{0,2}777\s', Severity.HIGH,
     "World-writable permissions created during build"),
    (r'^\s*RUN\s+.*apt-get\s+install\s+.*?(?:netcat|telnet|nmap|tcpdump|openssh-server)',
     Severity.HIGH, "Installing network/debug tools — potential for post-exploitation"),
    (r'^\s*RUN\s+.*npm\s+(?:i|install)\s+--unsafe-perm', Severity.MEDIUM,
     "npm install with --unsafe-perm — disables security checks"),
    (r'^\s*RUN\s+.*pip\s+install\s+--no-binary', Severity.LOW,
     "pip with --no-binary compiles from source — slow + risky"),
    (r'^\s*RUN\s+.*\|\s*(?:bash|sh)\b', Severity.CRITICAL,
     "Pipe to shell in RUN — downloads and executes remote script"),
    (r'^\s*RUN\s+.*(?:--security-opt|--privileged|--cap-add)', Severity.CRITICAL,
     "Container runs with elevated privileges (docker-in-docker style)"),
    (r'^\s*EXPOSE\s+22\b', Severity.MEDIUM,
     "Exposes SSH port (22) — unnecessary in most containers"),
    (r'^\s*RUN\s+.*((?:[\$]ENV|\$\{ENV\})[A-Z_]+)', Severity.HIGH,
     "Build-time secret potentially leaked via --build-arg"),
]

BEST_PRACTICE_CHECKS = [
    (r'HEALTHCHECK', Severity.LOW, "No HEALTHCHECK defined — useful for production"),
    (r'SHELL\s+\[', Severity.INFO, "Custom SHELL configured"),
]

# Checks that give a pass/fail per file — these become findings only when ABSENT
EXPECTED_GOOD_PRACTICES = {
    "USER": (Severity.MEDIUM, "No USER directive — container runs as root by default"),
    "WORKDIR": (Severity.LOW, "No WORKDIR set — uses / as default, risky"),
}


@register_analyzer
class DockerfileAnalyzer(BaseAnalyzer):
    name = "dockerfile_analyzer"
    description = "Dockerfile security analysis: unsafe patterns, privilege escalation, supply-chain risks"
    priority = 22

    def should_analyze(self, entry: FileEntry) -> bool:
        name = entry.path.rsplit("/", 1)[-1].lower()
        return name in ("dockerfile", "docker-compose.yml", "docker-compose.yaml",
                        ".dockerfile", "containerfile")

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        findings: List[Finding] = []
        path = entry.path
        lines = content.splitlines()

        has_user = has_workdir = False

        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped.upper().startswith("USER "):
                has_user = True
            if stripped.upper().startswith("WORKDIR "):
                has_workdir = True

            for pat, severity, desc in DANGEROUS_INSTRUCTIONS:
                if re.search(pat, stripped, re.IGNORECASE):
                    findings.append(Finding(
                        path, severity, Confidence.HIGH, Category.SUSPICIOUS_COMMAND,
                        title=f"Dockerfile: {desc}",
                        description=f"Line {line_no}: {_trunc(stripped, 200)}",
                        attack_path="docker build -> layer executes -> potentially dangerous instruction",
                        remediation="Review and replace with safer alternatives.",
                        line_number=line_no, snippet=_trunc(stripped, 150),
                    ))

        if not has_user:
            findings.append(Finding(
                path, Severity.MEDIUM, Confidence.HIGH, Category.INFO,
                title="Dockerfile runs as root — missing USER directive",
                description="No USER instruction found. Container will run as root by default.",
                attack_path="Container compromised -> root access in container -> full system access if privileged",
                remediation="Add USER <non-root> before the final RUN/CMD/ENTRYPOINT.",
            ))

        if not has_workdir:
            findings.append(Finding(
                path, Severity.LOW, Confidence.MEDIUM, Category.INFO,
                title="Dockerfile missing WORKDIR — defaults to /",
                description="No WORKDIR directive found. Commands run from / which can scatter files.",
                remediation="Set WORKDIR /app or similar early in the Dockerfile.",
            ))

        return AnalyzerResult(findings)


def _trunc(s: str, n: int) -> str:
    return s[:n] + "..." if len(s) > n else s
