# SPDX-License-Identifier: MIT
"""Policy engine — allow/deny rules and compliance checks."""

from dataclasses import dataclass, field
from typing import List, Optional

from .models import Category, Confidence, Finding, Severity


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


def evaluate_policy(policy_path: Optional[str], findings: List[Finding]) -> bool:
    """Evaluate findings against a policy file. Returns True if scan should be blocked."""
    if not policy_path:
        return False
    policy = load_policy(policy_path)
    policy_findings = policy.evaluate(findings)
    return len(policy_findings) > 0


def _severity_value(s: str) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(s.lower(), 2)


def load_policy(path: str) -> Policy:
    import yaml
    with open(path, encoding="utf-8", errors="replace") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Policy file {path} must contain a mapping, got {type(data).__name__}")
    valid_thresholds = {"info", "low", "medium", "high", "critical"}
    threshold = data.get("severity_threshold", "high")
    if threshold not in valid_thresholds:
        raise ValueError(f"severity_threshold must be one of {valid_thresholds}, got {threshold!r}")
    categories = data.get("block_categories", [])
    if not isinstance(categories, list):
        raise ValueError(f"block_categories must be a list, got {type(categories).__name__}")
    paths = data.get("allow_paths", [])
    if not isinstance(paths, list):
        raise ValueError(f"allow_paths must be a list, got {type(paths).__name__}")
    return Policy(
        severity_threshold=threshold,
        block_categories=categories,
        allow_paths=paths,
    )
