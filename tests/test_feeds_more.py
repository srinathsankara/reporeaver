"""Additional tests for feeds module — C2 feed and check_known_vulnerable."""

import urllib.error
from unittest.mock import MagicMock, patch
from reporeaver.feeds import get_known_c2_domains, check_known_vulnerable


class TestC2Feed:
    @patch("reporeaver.feeds._get_cached", return_value=None)
    @patch("reporeaver.feeds.urllib.request.urlopen")
    def test_fetch_parses_ips(self, mock_urlopen, mock_cache):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"1.2.3.4 12345\n5.6.7.8 54321\n# comment\n9.10.11.12 99999\n"
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp
        domains = get_known_c2_domains()
        assert "1.2.3.4" in domains
        assert "5.6.7.8" in domains
        assert "9.10.11.12" in domains
        assert len(domains) == 3

    @patch("reporeaver.feeds._get_cached", return_value=None)
    @patch("reporeaver.feeds.urllib.request.urlopen", side_effect=urllib.error.URLError("fail"))
    def test_fetch_network_error(self, mock_urlopen, mock_cache):
        domains = get_known_c2_domains()
        assert domains == []

    @patch("reporeaver.feeds._get_cached", return_value=None)
    @patch("reporeaver.feeds.urllib.request.urlopen", side_effect=OSError("timeout"))
    def test_fetch_os_error(self, mock_urlopen, mock_cache):
        domains = get_known_c2_domains()
        assert domains == []


class TestCheckKnownVulnerable:
    @patch("reporeaver.feeds.query_osv")
    def test_returns_advisories(self, mock_osv):
        mock_osv.return_value = [{
            "id": "GHSA-xxx",
            "aliases": ["CVE-2024-0001"],
            "summary": "critical vuln",
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"}],
        }]
        results = check_known_vulnerable("lodash", "4.17.20")
        assert len(results) == 1
        assert "CVE-2024-0001" in results[0]["id"]
        assert results[0]["severity"] == "high"

    @patch("reporeaver.feeds.query_osv")
    def test_no_vulns_returns_empty(self, mock_osv):
        mock_osv.return_value = []
        results = check_known_vulnerable("lodash", "4.17.21")
        assert results == []
