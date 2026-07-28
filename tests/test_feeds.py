"""Tests for threat intelligence feed integration."""

import urllib.error
from unittest.mock import MagicMock, patch

from reporeaver.feeds import get_known_c2_domains, query_malwarebazaar, query_osv


class TestFeeds:
    @patch("reporeaver.feeds._get_cached", return_value=None)
    @patch("reporeaver.feeds._urlopen")
    def test_query_osv_returns_vulns(self, mock_urlopen, mock_cache):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"vulns": [{"id": "GHSA-xxx", "aliases": ["CVE-2024-0001"], "summary": "test vuln"}]}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp
        vulns = query_osv("lodash")
        assert len(vulns) == 1
        assert vulns[0]["id"] == "GHSA-xxx"

    @patch("reporeaver.feeds._get_cached", return_value=None)
    @patch("reporeaver.feeds._urlopen", side_effect=urllib.error.URLError("timeout"))
    def test_query_osv_network_error_returns_empty(self, mock_urlopen, mock_cache):
        assert query_osv("lodash") == []

    @patch("reporeaver.feeds._get_cached", return_value=[{"id": "CACHED"}])
    def test_query_osv_uses_cache(self, mock_cache):
        vulns = query_osv("lodash")
        assert len(vulns) == 1
        assert vulns[0]["id"] == "CACHED"

    @patch("reporeaver.feeds._get_cached", return_value=None)
    @patch("reporeaver.feeds._urlopen")
    def test_query_malwarebazaar_found(self, mock_urlopen, mock_cache):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"query_status": "ok", "data": [{"sha256_hash": "abc", "malware": "trojan"}]}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp
        info = query_malwarebazaar("abc")
        assert info is not None
        assert info["sha256_hash"] == "abc"

    @patch("reporeaver.feeds._get_cached", return_value=None)
    @patch("reporeaver.feeds._urlopen", side_effect=urllib.error.URLError("timeout"))
    def test_query_malwarebazaar_network_error(self, mock_urlopen, mock_cache):
        assert query_malwarebazaar("abc") is None

    @patch("reporeaver.feeds._get_cached", return_value=["1.2.3.4"])
    def test_get_known_c2_domains_cached(self, mock_cache):
        domains = get_known_c2_domains()
        assert domains == ["1.2.3.4"]
