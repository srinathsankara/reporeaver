"""Additional Python analyzer tests — pyproject.toml, setup.cfg, edge cases."""

from reporeaver.analyzers.python_analyzer import PythonAnalyzer
from reporeaver.models import FileEntry


def _entry(path="test.py", is_text=True, size=100):
    return FileEntry(path=path, size=size, is_text=is_text, detected_mime="text/plain")


class TestPythonAnalyzerExtra:
    a = PythonAnalyzer()

    def test_pyproject_toml_custom_backend(self):
        entry = _entry("pyproject.toml")
        content = '[build-system]\nrequires = ["setuptools", "wheel"]\nbuild-backend = "flit_core.buildapi"\n'
        res = self.a.analyze(entry, content)
        high = [f for f in res.findings if f.severity.name in ("HIGH", "MEDIUM", "CRITICAL")]
        assert len(high) >= 1

    def test_pyproject_standard_backend(self):
        entry = _entry("pyproject.toml")
        content = '[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n'
        res = self.a.analyze(entry, content)
        info = [f for f in res.findings if f.severity.name == "INFO"]
        assert len(info) >= 1

    def test_setup_cfg_returns_no_findings(self):
        entry = _entry("setup.cfg")
        content = "[metadata]\nname = my-package\nversion = 1.0\n"
        res = self.a.analyze(entry, content)
        assert len(res.findings) == 0

    def test_install_py_returns_no_findings(self):
        entry = _entry("install.py")
        content = "print('installing')\n"
        res = self.a.analyze(entry, content)
        assert len(res.findings) == 0

    def test_empty_lines_skipped(self):
        entry = _entry("setup.py")
        content = "\n\n\n\n"
        res = self.a.analyze(entry, content)
        assert len(res.findings) == 0

    def test_should_analyze_filters(self):
        assert self.a.should_analyze(_entry("setup.py")) is True
        assert self.a.should_analyze(_entry("pyproject.toml")) is True
        assert self.a.should_analyze(_entry("random.txt")) is False
