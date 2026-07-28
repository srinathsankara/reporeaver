"""Tests for the policy engine and YAML config."""

from reporeaver.models import Category, Confidence, Finding, Severity
from reporeaver.policy import Policy, load_policy


def _finding(category="c2_callback", severity=Severity.CRITICAL):
    return Finding(
        file_path="src/main.js",
        severity=severity,
        confidence=Confidence.HIGH,
        category=Category(category),
        title="test",
        description="test finding",
    )


class TestPolicy:
    def test_default_policy_blocks_c2(self):
        p = Policy()
        f = _finding("c2_callback")
        result = p.evaluate([f])
        assert len(result) == 1
        assert result[0].category == Category.POLICY_VIOLATION

    def test_default_policy_allows_low(self):
        p = Policy()
        f = _finding("info", Severity.INFO)
        result = p.evaluate([f])
        assert len(result) == 0

    def test_allow_paths_override(self):
        p = Policy(allow_paths=["node_modules/"])
        f = _finding("c2_callback")
        f.file_path = "node_modules/evil/index.js"
        result = p.evaluate([f])
        assert len(result) == 0

    def test_allow_paths_no_match(self):
        p = Policy(allow_paths=["node_modules/"])
        f = _finding("c2_callback")
        f.file_path = "src/evil.js"
        result = p.evaluate([f])
        assert len(result) == 1

    def test_is_blocked(self):
        p = Policy(block_categories=["c2_callback"])
        f = _finding("c2_callback")
        assert p.is_blocked(f)

    def test_is_not_blocked_for_allowed(self):
        p = Policy(block_categories=["c2_callback"], allow_paths=["node_modules/"])
        f = _finding("c2_callback")
        f.file_path = "node_modules/test.js"
        assert not p.is_blocked(f)


def test_severity_threshold_filters_below_threshold():
    p = Policy(severity_threshold="critical")
    low = _finding("c2_callback", Severity.LOW)
    critical = _finding("c2_callback", Severity.CRITICAL)
    result = p.evaluate([low, critical])
    assert len(result) == 1
    assert result[0].severity == Severity.CRITICAL


def test_severity_threshold_allows_all_when_threshold_low():
    p = Policy(severity_threshold="info")
    low = _finding("c2_callback", Severity.LOW)
    high = _finding("c2_callback", Severity.HIGH)
    result = p.evaluate([low, high])
    assert len(result) == 2


def test_load_policy_from_yaml(tmp_path):
    yaml_file = tmp_path / "test_policy.yaml"
    yaml_file.write_text("""
severity_threshold: critical
block_categories:
  - encoded_payload
allow_paths:
  - vendor/
""")
    p = load_policy(str(yaml_file))
    assert p.severity_threshold == "critical"
    assert "encoded_payload" in p.block_categories
    assert "vendor/" in p.allow_paths
