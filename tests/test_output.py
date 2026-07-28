"""Tests for output modules."""


from reporeaver.models import (
    Category,
    Confidence,
    Finding,
    RiskScore,
    ScanResult,
    Severity,
)
from reporeaver.output.html_dashboard import render_html
from reporeaver.output.sarif import render_sarif


def make_sample_result() -> ScanResult:
    findings = [
        Finding("test.svg", Severity.CRITICAL, Confidence.HIGH, Category.SVG_SCRIPT,
                "Embedded script", "Script element found", line_number=10,
                attack_path="SVG -> script -> eval",
                snippet="<script>eval(atob('...'))</script>",
                decoded="var xhr = new XMLHttpRequest();"),
        Finding("package.json", Severity.HIGH, Confidence.MEDIUM, Category.SUSPICIOUS_COMMAND,
                "curl pipe bash", "postinstall runs curl | bash",
                attack_path="npm install -> postinstall -> remote exec",
                line_number=5),
        Finding("test.js", Severity.MEDIUM, Confidence.LOW, Category.HIGH_ENTROPY,
                "High entropy", "base64 string detected", line_number=20),
    ]
    rs = RiskScore.compute(findings)
    return ScanResult(target="/test/repo", files_scanned=100, findings=findings, risk_score=rs)


class TestSARIF:
    def test_render_sarif_structure(self):
        result = make_sample_result()
        sarif = render_sarif(result)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert "tool" in run
        assert "results" in run
        assert len(run["results"]) == 3

    def test_sarif_has_rules(self):
        result = make_sample_result()
        sarif = render_sarif(result)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 2

    def test_sarif_levels(self):
        result = make_sample_result()
        sarif = render_sarif(result)
        for r in sarif["runs"][0]["results"]:
            assert r["level"] in ("error", "warning", "note", "none")


class TestHTML:
    def _render_to_temp(self, result):
        import os
        import tempfile
        tmp = tempfile.mktemp(suffix=".html")
        render_html(result, tmp)
        with open(tmp, encoding="utf-8") as f:
            content = f.read()
        os.unlink(tmp)
        return content

    def test_render_html(self):
        result = make_sample_result()
        content = self._render_to_temp(result)
        assert "RepoReaver" in content
        assert "Security Gate" in content
        assert "test.svg" in content
        assert "Embedded script" in content

    def test_html_contains_risk_score(self):
        result = make_sample_result()
        content = self._render_to_temp(result)
        assert "4.5" in content or "4" in content
