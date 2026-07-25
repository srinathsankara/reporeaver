"""Secrets scanner — flags hardcoded credentials, API keys, tokens, private keys.

Checks for common formats: AWS keys, GitHub tokens, Slack tokens, JWTs, SSH keys,
generic passwords, database connection strings. Uses entropy gating to reduce FPs.

Inspired by truffleHog, Gitleaks, and similar tools.
"""

import math
import re
from typing import Dict, List, Optional, Tuple

from ..models import Category, Confidence, FileEntry, Finding, Severity
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer

SECRET_PATTERNS: List[Tuple[str, str, str, Severity, bool]] = [
    # (regex, name, description, severity, requires_high_entropy)
    (r'(?i)(?:aws|amazon)[_-]?(?:access|secret|key|id)?[_-]?(?:key|id|token|secret)\s*[:=]\s*["\']?(AKIA[0-9A-Z]{16})["\'\s]',
     "AWS Access Key ID", "Starts with AKIA — AWS IAM user key", Severity.CRITICAL, False),
    (r'(?i)(?:aws|amazon)[_-]?(?:secret|key)?[_-]?(?:key|access)[_-]?(?:secret|token)\s*[:=]\s*["\']?([A-Za-z0-9/+]{40})["\'\s]',
     "AWS Secret Access Key", "40-char base64 — AWS secret key", Severity.CRITICAL, False),
    (r'(?i)github[_-]?(?:token|pat|key|secret)\s*[:=]\s*["\']?(ghp_[A-Za-z0-9]{36,})["\'\s]',
     "GitHub Personal Access Token", "ghp_ prefix — GitHub PAT", Severity.CRITICAL, False),
    (r'(?i)github[_-]?(?:oauth|app)[_-]?(?:token|key|secret|id)\s*[:=]\s*["\']?(gh[osu]_[A-Za-z0-9]{36,})["\'\s]',
     "GitHub OAuth/App Token", "ghs_/ghu_ prefix — GitHub token", Severity.CRITICAL, False),
    (r'(?i)(?:slack|discord)[_-]?(?:token|key|webhook|secret|bot)\s*[:=]\s*["\']?(xox[abpors]-[A-Za-z0-9-]{24,})["\'\s]',
     "Slack Token", "xox* prefix — Slack API token", Severity.CRITICAL, False),
    (r'(?i)(?:sk-)[A-Za-z0-9_-]{20,}(?:[A-Za-z0-9_-]{20,})?',
     "OpenAI API Key", "sk- prefix — OpenAI key", Severity.HIGH, False),
    (r'(?i)(?:AKIA|ASIA)[0-9A-Z]{16}',
     "AWS Key (bare)", "Standalone AWS access key ID", Severity.CRITICAL, False),
    (r'(?i)-----BEGIN\s+\w+(?:\s+\w+)?\s+PRIVATE\s+(?:KEY|BLOCK)-----',
     "Private Key", "Contains an encoded private key", Severity.CRITICAL, False),
    (r'(?i)-----BEGIN\s+CERTIFICATE-----',
     "Certificate", "Contains a certificate (may include private data)", Severity.MEDIUM, False),
    (r'(?i)(?:jwt|bearer)\s*[:=]\s*["\']?([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["\'\s]',
     "JWT Token", "JSON Web Token — encoded auth token", Severity.HIGH, False),
    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']?([^"\';\s]{8,})["\'\s]',
     "Hardcoded Password", "Password assignment in code", Severity.HIGH, True),
    (r'(?i)(?:secret|token|api[_-]?key)\s*[:=]\s*["\']?([A-Za-z0-9_\-=+/]{16,64})["\'\s]',
     "Generic Secret/Token", "Secret-like value in assignment", Severity.MEDIUM, True),
    (r'(?:postgresql|mysql|mongodb|redis|amqp|rabbitmq)://[^@]+@',
     "Database Connection String", "DB connection with embedded credentials", Severity.HIGH, False),
    (r'(?i)https?://[^:]+:[^@]+@[^\s"\']+',
     "URL with Credentials", "URL containing username:password", Severity.CRITICAL, False),
    (r'(?i)(?:sf_username|sf_password|salesforce)[_-]?(?:username|password|token)\s*[:=]\s*["\']?([^"\';\s]{4,})["\'\s]',
     "Salesforce Credential", "Salesforce API credential", Severity.HIGH, False),
    (r'(?i)(?:twilio|sendgrid|mailgun|stripe|paypal)[_-]?(?:api[_-]?key|secret|token|sid)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\'\s]',
     "SaaS API Key", "Known SaaS platform API key", Severity.CRITICAL, False),
    (r'(?i)(?:google|gcp|firebase)[_-]?(?:api[_-]?key|secret|token|json|credentials)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\'\s]',
     "Google Cloud Key", "GCP/Firebase credential", Severity.CRITICAL, False),
    (r'(?i)(?:azure|ms)[_-]?(?:api[_-]?key|secret|token|connection[_-]?string)\s*[:=]\s*["\']?([A-Za-z0-9_\-=+/]{20,})["\'\s]',
     "Azure Key", "Azure service credential", Severity.CRITICAL, False),
    (r'(?i)heroku[_-]?(?:api[_-]?key|token)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\'\s]',
     "Heroku API Key", "Heroku platform credential", Severity.HIGH, False),
    (r'(?i)(?:PASSWORD|SECRET|TOKEN|API_KEY)\s*=\s*["\']?([A-Za-z0-9_\-=+/]{16,})["\'\s]',
     "Environment Secret Value", "Secret-like environment variable value", Severity.MEDIUM, True),
]

# High-entropy check threshold
ENTROPY_FLOOR = 4.0

# Files to skip entirely (lockfiles, minified bundles, etc.)
SKIP_PATHS = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Gemfile.lock",
              "poetry.lock", "composer.lock"}

# Skip lines that are clearly hashes, not secrets
HASH_LINE = re.compile(r'^[A-Fa-f0-9]{32,}$')


@register_analyzer
class SecretsAnalyzer(BaseAnalyzer):
    name = "secrets"
    description = "Hardcoded credentials, API keys, tokens, private keys, connection strings"
    priority = 5

    def should_analyze(self, entry: FileEntry) -> bool:
        name = entry.path.rsplit("/", 1)[-1].lower()
        if name in SKIP_PATHS:
            return False
        return entry.is_text and entry.size < 500_000

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        return _scan_text(content, entry.path)


def _scan_text(content: str, path: str) -> AnalyzerResult:
    findings: List[Finding] = []
    lines = content.splitlines()

    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or len(stripped) < 6:
            continue
        if HASH_LINE.match(stripped):
            continue

        # Compute line entropy once if we need it for gating
        line_entropy = None

        for pat, name, desc, severity, high_entropy in SECRET_PATTERNS:
            for m in re.finditer(pat, stripped):
                # If pattern requires high entropy, gate on it
                if high_entropy:
                    if line_entropy is None:
                        line_entropy = _shannon(stripped)
                    if line_entropy < ENTROPY_FLOOR:
                        continue

                value = m.group(0).strip()
                # Snip a safe display of the secret
                safe = value[:12] + "..." if len(value) > 15 else value

                findings.append(Finding(
                    path, severity, Confidence.HIGH, Category.CREDENTIAL_THEFT,
                    title=f"Hardcoded {name}",
                    description=f"Found {name.lower()} in source code: {safe}",
                    attack_path=f"Source leaked -> {name} extracted -> unauthorized access to cloud/service",
                    remediation="Rotate this credential immediately. Use environment variables or a secrets manager.",
                    line_number=line_no, raw_value=safe,
                ))

    return AnalyzerResult(findings)


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())
