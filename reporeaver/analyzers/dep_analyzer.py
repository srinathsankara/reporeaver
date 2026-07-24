"""Dependency Analyzer — inspects transitive deps, postinstall chains, and malicious package indicators."""

import json
import re
from typing import Dict, List, Optional

from ..models import Category, Confidence, FileEntry, Finding, Severity
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer

SUSPICIOUS_PKG_NAMES = [
    "postinstall-", "preinstall-", "install-", "*-backdoor",
    "electron-native-", "node-native-", "*-malware", "payload-",
    "crypto-", "crypt-", "decrypt-", "decoding-",
]

SUSPICIOUS_VERSION_PATTERNS = [
    (r'https?://[^\s"\']+', Severity.CRITICAL, "URL-resolved package version"),
    (r'git\+https?://[^\s"\']+', Severity.CRITICAL, "Git URL dependency (unpinned)"),
    (r'file://[^\s"\']+', Severity.HIGH, "Local file dependency"),
    (r'^\*$', Severity.LOW, "Wildcard version (unstable)"),
    (r'^[A-Za-z0-9+/]{40,}=*$', Severity.CRITICAL, "Base64 version string"),
    (r'[|;&`$]', Severity.CRITICAL, "Shell metacharacters in version string"),
]


@register_analyzer
class DepAnalyzer(BaseAnalyzer):
    name = "dependency"
    description = "Dependency manifest analysis: transitive deps, lifecycle hooks, malicious indicators"
    priority = 25

    def should_analyze(self, entry: FileEntry) -> bool:
        name = entry.path.rsplit("/", 1)[-1].lower()
        return name in ("package.json", "package-lock.json", "yarn.lock",
                        "requirements.txt", "Pipfile", "Pipfile.lock",
                        "Gemfile", "Gemfile.lock", "go.mod", "go.sum")

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        findings: List[Finding] = []
        path = entry.path
        name = entry.path.rsplit("/", 1)[-1].lower()

        if name == "package.json":
            self._analyze_node(content, path, findings)
        elif name in ("requirements.txt", "Pipfile"):
            self._analyze_python(content, path, findings)
        elif name in ("Gemfile",):
            self._analyze_ruby(content, path, findings)

        return AnalyzerResult(findings)

    def _analyze_node(self, content: str, path: str, findings: List[Finding]):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        all_deps = {
            **data.get("dependencies", {}),
            **data.get("devDependencies", {}),
            **data.get("peerDependencies", {}),
            **data.get("optionalDependencies", {}),
        }

        for dep_name, dep_version in all_deps.items():
            if not isinstance(dep_version, str):
                continue

            # Check package name
            for suspicious in SUSPICIOUS_PKG_NAMES:
                if suspicious.endswith("*"):
                    if suspicious[:-1].lower() in dep_name.lower():
                        self._report(dep_name, dep_version, path, findings,
                                     f"Package name contains suspicious pattern '{suspicious}'")
                elif suspicious in dep_name.lower():
                    self._report(dep_name, dep_version, path, findings,
                                 f"Package name contains suspicious pattern '{suspicious}'")

            # Check version string
            for pat, severity, desc in SUSPICIOUS_VERSION_PATTERNS:
                if re.search(pat, dep_version):
                    findings.append(Finding(
                        path, severity, Confidence.HIGH, Category.SUSPICIOUS_DEPENDENCY,
                        title=f"{dep_name}: {desc}",
                        description=f"Dependency '{dep_name}' version '{dep_version}' triggered: {desc}",
                        attack_path=f"npm install -> {dep_name}@{dep_version} -> arbitrary code risk",
                        remediation="Pin to a specific registry version and verify integrity.",
                        raw_value=dep_version,
                    ))

        # Check for postinstall chains
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            for hook in ("postinstall", "preinstall", "install"):
                if hook in scripts:
                    findings.append(Finding(
                        path, Severity.INFO, Confidence.HIGH, Category.POSTINSTALL_CHAIN,
                        title=f"Package has '{hook}' script",
                        description=f"This script executes during install. Review: {_trunc(scripts[hook], 200)}",
                        attack_path=f"npm install -> {hook} -> {_trunc(scripts[hook], 100)}",
                        remediation="Audit lifecycle scripts. Consider `--ignore-scripts`.",
                        snippet=scripts[hook],
                    ))

    def _analyze_python(self, content: str, path: str, findings: List[Finding]):
        for line_no, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-", "//")):
                continue
            if "@" in stripped and "://" in stripped:
                findings.append(Finding(
                    path, Severity.HIGH, Confidence.MEDIUM, Category.URL_DEPENDENCY,
                    title=f"Python dependency from URL: {_trunc(stripped, 100)}",
                    description="URL-based pip dependencies bypass PyPI security guarantees.",
                    attack_path=f"pip install -> URL dependency -> arbitrary code",
                    remediation="Use PyPI versions with hash verification.",
                    line_number=line_no, snippet=stripped,
                ))

    def _analyze_ruby(self, content: str, path: str, findings: List[Finding]):
        for line_no, line in enumerate(content.splitlines(), 1):
            if "git:" in line or "github:" in line or "path:" in line:
                findings.append(Finding(
                    path, Severity.MEDIUM, Confidence.LOW, Category.SUSPICIOUS_DEPENDENCY,
                    title=f"Ruby gem from non-standard source: {_trunc(line.strip(), 100)}",
                    description="Non-registry gem sources can introduce untrusted code.",
                    attack_path="bundle install -> gem from external source -> potential compromise",
                    remediation="Use rubygems.org sources with lockfiles.",
                    line_number=line_no, snippet=line.strip(),
                ))

    def _report(self, dep_name: str, dep_version: str, path: str,
                findings: List[Finding], reason: str):
        findings.append(Finding(
            path, Severity.HIGH, Confidence.MEDIUM, Category.SUSPICIOUS_DEPENDENCY,
            title=f"{dep_name}: {reason}",
            description=f"Dependency '{dep_name}'@{dep_version}: {reason}",
            attack_path=f"npm install -> {dep_name} executes -> compromise",
            remediation="Remove or replace this dependency with a trusted alternative.",
            raw_value=f"{dep_name}@{dep_version}",
        ))


def _trunc(s: str, n: int) -> str:
    return s[:n] + "..." if len(s) > n else s
