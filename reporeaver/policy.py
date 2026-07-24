"""Policy engine — allow/deny rules and compliance checks."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .models import Category, Confidence, Finding, Severity

DEFAULT_POLICY_YAML = """
# reporeaver default policy
# Severity threshold: findings at or above this level cause exit code 1
severity_threshold: high

# Auto-block these categories at any severity
block_categories:
  - c2_callback
  - credential_theft
  - ci_remote_exec
  - behavioral_exfil
  - encoded_payload

# Always allow these (safe patterns)
allow_paths:
  - "node_modules/"
  - ".git/"
  - "__pycache__/"
  - "vendor/"
  - ".venv/"
  - "dist/"
  - "build/"
"""


@dataclass
class Policy:
    severity_threshold: str = "high"
    block_categories: List[str] = field(default_factory=lambda: [
        "c2_callback", "credential_theft", "ci_remote_exec",
        "behavioral_exfil", "encoded_payload",
    ])
    allow_paths: List[str] = field(default_factory=lambda: [
        "node_modules/", ".git/", "__pycache__/",
        "vendor/", ".venv/", "dist/", "build/",
    ])

    def evaluate(self, findings: List[Finding]) -> List[Finding]:
        """Apply policy rules and return policy-violation findings."""
        policy_findings = []
        threshold_val = _severity_value(self.severity_threshold)

        for f in findings:
            if any(f.file_path.startswith(p) for p in self.allow_paths):
                continue
            if f.category.value in self.block_categories:
                policy_findings.append(Finding(
                    file_path=f.file_path,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category=Category.POLICY_VIOLATION,
                    title="Policy violation: blocked category",
                    description=f"Finding category '{f.category.value}' is blocked by policy",
                    attack_path=f.attack_path,
                    remediation="Remove or quarantine the offending file",
                    line_number=f.line_number,
                ))

        return policy_findings

    def is_blocked(self, finding: Finding) -> bool:
        if any(finding.file_path.startswith(p) for p in self.allow_paths):
            return False
        return finding.category.value in self.block_categories


def _severity_value(s: str) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(s.lower(), 2)


def load_policy(path: str) -> Policy:
    import yaml
    with open(path) as f:
        data = yaml.safe_load(f)
    return Policy(
        severity_threshold=data.get("severity_threshold", "high"),
        block_categories=data.get("block_categories", []),
        allow_paths=data.get("allow_paths", []),
    )
