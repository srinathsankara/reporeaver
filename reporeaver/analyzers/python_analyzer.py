# SPDX-License-Identifier: MIT
"""Python packaging analyzer — checks setup.py, pyproject.toml, setup.cfg for build-time abuse."""

import re
from typing import List

from ..models import Category, Confidence, FileEntry, Finding, Severity
from ..utils.text import line_of, trunc
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer

SUSPICIOUS_SETUP_CALLS = [
    (r'cmdclass\s*=\s*\{', Severity.HIGH, "Custom command classes override setuptools commands"),
    (r'distutils\.core\.setup|setuptools\.setup', Severity.INFO, "Standard setup call"),
    (r'setup_requires\s*=\s*\[', Severity.HIGH, "Build-time dependency — runs during install"),
    (r'use_scm_version\s*=', Severity.MEDIUM, "Dynamic version from git — may fetch remote"),
    (r'build_backend\s*=\s*["\']', Severity.MEDIUM, "Custom build backend — runs during build"),
    (r'os\.system\(|subprocess\.|shutil\.rmtree|shutil\.move|shutil\.copy', Severity.CRITICAL,
     "System command execution in setup"),
    (r'requests\.get|urllib\.request|urllib2\.urlopen', Severity.CRITICAL,
     "Network request in install script — potential C2/downloader"),
    (r'base64\.b64decode|base64\.b64encode', Severity.HIGH,
     "Base64 encoding in setup — obfuscation indicator"),
    (r'eval\(|exec\(|compile\(', Severity.CRITICAL,
     "Dynamic code execution in setup script"),
    (r'__import__\(|importlib\.import_module\s*\(', Severity.HIGH,
     "Dynamic import — may load hidden modules"),
    (r'data_files\s*=\s*\[', Severity.MEDIUM, "Installs files to arbitrary system paths"),
]

PYPROJECT_BUILD_KEYS = [
    (r'build-backend\s*=\s*["\']setuptools[^"\']*["\']', Severity.INFO, "Standard setuptools backend"),
    (r'build-backend\s*=\s*["\'](?!setuptools)', Severity.HIGH, "Non-standard build backend — verify"),
    (r'requires\s*=\s*\[["\'].*setup\.py', Severity.HIGH, "Build req includes setup.py — circular risk"),
]


@register_analyzer
class PythonAnalyzer(BaseAnalyzer):
    name = "python_analyzer"
    description = "Python packaging abuse: setup.py/pyproject.toml/setup.cfg build-time attack detection"
    priority = 26

    def should_analyze(self, entry: FileEntry) -> bool:
        name = entry.path.rsplit("/", 1)[-1].lower()
        return name in ("setup.py", "setup.cfg", "pyproject.toml", "install.py")

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        name = entry.path.rsplit("/", 1)[-1].lower()
        if name == "setup.py":
            return _check_setup_py(content, entry.path)
        elif name == "pyproject.toml":
            return _check_pyproject_toml(content, entry.path)
        return AnalyzerResult([])


def _check_setup_py(content: str, path: str) -> AnalyzerResult:
    findings: List[Finding] = []

    for line_no, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue

        for pat, severity, desc in SUSPICIOUS_SETUP_CALLS:
            if re.search(pat, stripped):
                findings.append(Finding(
                    path, severity, Confidence.MEDIUM, Category.SUSPICIOUS_COMMAND,
                    title=f"setup.py: {desc}",
                    description=f"Line {line_no} in setup.py: {trunc(stripped, 150)}",
                    attack_path="pip install -> setup.py runs -> build-time code executes -> compromise",
                    remediation="Remove suspicious operations from setup.py. Use declarative config in pyproject.toml.",
                    line_number=line_no, snippet=trunc(stripped, 200),
                ))

    return AnalyzerResult(findings)


def _check_pyproject_toml(content: str, path: str) -> AnalyzerResult:
    findings: List[Finding] = []

    for pat, severity, desc in PYPROJECT_BUILD_KEYS:
        for match in re.finditer(pat, content):
            findings.append(Finding(
                path, severity, Confidence.MEDIUM, Category.SUSPICIOUS_COMMAND,
                title=f"pyproject.toml: {desc}",
                description=f"Found: {trunc(match.group(0), 100)}",
                attack_path="pip install -> build backend runs -> arbitrary build code executes",
                remediation="Use well-known build backends (setuptools, poetry, flit). Pin versions.",
                line_number=line_of(content, match.start()),
            ))

    return AnalyzerResult(findings)



