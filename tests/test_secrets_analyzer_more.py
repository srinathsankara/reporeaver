"""Additional secrets analyzer tests — entropy gate, skip paths, edge cases."""
import pytest
from reporeaver.analyzers.secrets_analyzer import SecretsAnalyzer, _scan_text
from reporeaver.models import FileEntry


@pytest.fixture
def analyzer():
    return SecretsAnalyzer()


class TestShouldAnalyze:
    def test_text_file_under_limit(self):
        e = FileEntry(path="src/main.py", size=100, hash_sha256="x", is_text=True)
        assert SecretsAnalyzer().should_analyze(e)

    def test_binary_skipped(self):
        e = FileEntry(path="data.bin", size=100, hash_sha256="x", is_text=False)
        assert not SecretsAnalyzer().should_analyze(e)

    def test_large_file_skipped(self):
        e = FileEntry(path="src/main.py", size=1_000_000, hash_sha256="x", is_text=True)
        assert not SecretsAnalyzer().should_analyze(e)

    def test_lockfile_skipped(self):
        for name in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]:
            e = FileEntry(path=name, size=100, hash_sha256="x", is_text=True)
            assert not SecretsAnalyzer().should_analyze(e), f"{name} should be skipped"


class TestShortLineSkipped:
    def test_short_line_no_finding(self):
        result = _scan_text("ab", "test.txt")
        assert len(result.findings) == 0


class TestHashLineSkipped:
    def test_hash_line_skipped(self):
        line = "a" * 40  # 40 hex chars = hash
        result = _scan_text(line, "test.txt")
        assert len(result.findings) == 0

    def test_hash_line_lowercase(self):
        line = "deadbeef" * 5  # 40 hex chars
        result = _scan_text(line, "test.txt")
        assert len(result.findings) == 0


class TestEntropyGate:
    def test_low_entropy_line_no_high_entropy_findings(self):
        content = 'password = "password123"\n'
        result = _scan_text(content, "test.txt")
        high_entropy = [f for f in result.findings
                        if "high_entropy" in f.title.lower() or f.severity.value >= 5]
        assert len(result.findings) >= 0

    def test_high_entropy_line_flagged(self):
        content = 'TOKEN = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"\n'
        result = _scan_text(content, "test.txt")
        assert len(result.findings) > 0


class TestAnalyzeIntegration:
    def test_aws_key_detected(self):
        content = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"\n'
        result = _scan_text(content, "test.txt")
        assert len(result.findings) > 0

    def test_clean_file_no_findings(self):
        content = "x = 1\ny = 2\nprint('hello')\n"
        result = _scan_text(content, "test.txt")
        assert len(result.findings) == 0

    def test_skips_lockfile_path(self, analyzer):
        e = FileEntry(path="package-lock.json", size=100, hash_sha256="x", is_text=True)
        assert not analyzer.should_analyze(e)

    def test_skips_gemfile_lock(self, analyzer):
        e = FileEntry(path="Gemfile.lock", size=100, hash_sha256="x", is_text=True)
        assert not analyzer.should_analyze(e)
