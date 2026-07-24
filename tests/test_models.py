"""Tests for core data models."""

from reporeaver.models import (
    Category, Confidence, FileEntry, Finding, RiskScore, ScanResult, Severity,
)


class TestFinding:
    def test_creation(self):
        f = Finding(
            file_path="test.svg",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=Category.SVG_SCRIPT,
            title="Critical finding",
            description="Test",
        )
        assert f.severity == Severity.CRITICAL
        assert f.confidence == Confidence.HIGH
        assert f.category == Category.SVG_SCRIPT

    def test_to_dict(self):
        f = Finding(
            file_path="test.svg",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category=Category.SVG_XXE,
            title="XXE",
            description="XXE test",
            line_number=5,
        )
        d = f.to_dict()
        assert d["severity"] == "high"
        assert d["confidence"] == "medium"
        assert d["category"] == "svg_xxe"
        assert d["line"] == 5

    def test_repr(self):
        f = Finding(
            file_path="test.svg",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=Category.SVG_SCRIPT,
            title="Bad thing",
            description="Something bad happened",
        )
        r = repr(f)
        assert "CRITICAL" in r or "critical" in r
        assert "test.svg" in r
        assert "Bad thing" in r


class TestRiskScore:
    def test_compute_empty(self):
        rs = RiskScore.compute([])
        assert rs.score == 0.0
        assert rs.total == 0

    def test_compute_critical(self):
        findings = [
            Finding("f", Severity.CRITICAL, Confidence.HIGH, Category.SVG_SCRIPT, "t", "d"),
        ]
        rs = RiskScore.compute(findings)
        assert rs.score >= 3.0
        assert rs.critical == 1
        assert rs.max_severity == Severity.CRITICAL

    def test_compute_mixed(self):
        findings = [
            Finding("f1", Severity.CRITICAL, Confidence.HIGH, Category.C2_CALLBACK, "t1", "d1"),
            Finding("f2", Severity.HIGH, Confidence.MEDIUM, Category.SUSPICIOUS_COMMAND, "t2", "d2"),
            Finding("f3", Severity.LOW, Confidence.LOW, Category.INFO, "t3", "d3"),
        ]
        rs = RiskScore.compute(findings)
        assert rs.critical == 1
        assert rs.high == 1
        assert rs.low == 1
        assert rs.total == 3

    def test_to_dict(self):
        rs = RiskScore(5.0, Severity.HIGH, 1, 2, 0, 0, 3)
        d = rs.to_dict()
        assert d["score"] == 5.0
        assert d["max_severity"] == "high"


class TestFileEntry:
    def test_creation(self):
        fe = FileEntry(path="test.svg", size=1000, is_svg=True, is_text=True)
        assert fe.path == "test.svg"
        assert fe.is_svg
        assert fe.is_text


class TestScanResult:
    def test_basic(self):
        sr = ScanResult(target="/test", files_scanned=10)
        assert sr.target == "/test"
        assert sr.files_scanned == 10
        assert sr.tool == "reporeaver"

    def test_to_dict(self):
        sr = ScanResult(target="/test", files_scanned=5)
        d = sr.to_dict()
        assert d["target"] == "/test"
        assert d["files_scanned"] == 5
        assert d["tool"] == "reporeaver"
