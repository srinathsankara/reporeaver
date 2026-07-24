"""URL/Network Analyzer — detects external callbacks, C2 indicators, and suspicious URLs."""

import ipaddress
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..models import Category, Confidence, FileEntry, Finding, Severity
from .base import AnalyzerResult, BaseAnalyzer, register_analyzer

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "pw", "top", "icu",
    "xyz", "work", "loan", "date", "men", "click",
    "download", "review", "stream", "trade", "win",
    "bid", "loan", "men", "date", "racing",
}

SUSPICIOUS_KEYWORDS = [
    "payload", "shell", "backdoor", "exploit", "malware",
    "c2", "cnc", "command", "control", "beacon",
    "reverse", "connect", "tunnel", "proxy", "stager",
    "dropper", "update", "upgrade", "patch",
    "callback", "webhook", "tracker", "beacon",
    "exfil", "exfiltrate", "collect", "telemetry",
]

KNOWN_C2_DOMAINS = {
    "pastebin.com", "raw.githubusercontent.com", "ngrok.io",
    "serveo.net", "localtunnel.me", "requestbin",
    "hookbin.com", "webhook.site", "pipedream.com",
    "cloudfront.net", "s3.amazonaws.com",
}

SAFE_PACKAGE_REGISTRIES = {
    "github.com", "gitlab.com", "bitbucket.org",
    "npmjs.org", "npmjs.com", "yarnpkg.com",
    "registry.npmjs.org", "registry.yarnpkg.com",
    "unpkg.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
    "fonts.googleapis.com", "fonts.gstatic.com",
    "nodejs.org", "python.org", "pypi.org",
    "rubygems.org", "crates.io", "nuget.org",
    "maven.org", "mvnrepository.com",
}

URL_PATTERN = re.compile(r'https?://[^\s"\'<>(){}|;`\[\]\\,]+', re.IGNORECASE)
NETWORK_API_CALLS = [
    (r'fetch\s*\(\s*["\']https?://[^"\']+["\']', "fetch()"),
    (r'XMLHttpRequest\s*\(', "XMLHttpRequest"),
    (r'(?:axios|got|request|superagent)\s*[.\(]', "HTTP library"),
    (r'new\s+WebSocket\s*\(\s*["\']wss?://', "WebSocket"),
    (r'new\s+EventSource\s*\(\s*["\']https?://', "EventSource"),
    (r'import\s*\(\s*["\']https?://[^"\']+["\']', "dynamic import"),
    (r'require\s*\(\s*["\']https?://[^"\']+["\']', "require URL"),
    (r'new\s+Worker\s*\(\s*["\']https?://', "Worker from URL"),
]


@register_analyzer
class URLNetworkAnalyzer(BaseAnalyzer):
    name = "url_network"
    description = "Detects external URLs, C2 callbacks, and network API usage"
    priority = 40

    def should_analyze(self, entry: FileEntry) -> bool:
        return entry.is_text and entry.size < 2_000_000

    def analyze(self, entry: FileEntry, content: str) -> AnalyzerResult:
        findings: List[Finding] = []
        path = entry.path

        urls = self._extract_urls(content)
        seen_urls: set = set()
        for url, line_no in urls:
            if url in seen_urls:
                continue
            seen_urls.add(url)
            self._analyze_url(url, path, line_no, findings, content)

        api_findings = self._check_network_api(content, path)
        findings.extend(api_findings)

        return AnalyzerResult(findings)

    def _extract_urls(self, text: str) -> List[Tuple[str, int]]:
        results = []
        for match in URL_PATTERN.finditer(text):
            url = match.group(0).rstrip(".,:;!?)]}")
            line_no = text[:match.start()].count("\n") + 1
            results.append((url, line_no))
        return results

    def _analyze_url(self, url: str, path: str, line_no: int,
                     findings: List[Finding], context: str):
        try:
            parsed = urlparse(url)
        except Exception:
            return
        hostname = (parsed.hostname or "").lower()

        if hostname in SAFE_PACKAGE_REGISTRIES or \
           any(hostname.endswith("." + d) for d in SAFE_PACKAGE_REGISTRIES):
            return

        signals = []

        # Check for IP address targets
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private:
                signals.append(f"Private IP address ({hostname}) — possible SSRF or internal scan")
            elif ip.is_loopback:
                signals.append(f"Loopback address ({hostname})")
        except ValueError:
            pass

        # Check TLD
        tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
        if tld in SUSPICIOUS_TLDS:
            signals.append(f"Suspicious TLD: .{tld}")

        # Check keywords
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in url.lower():
                signals.append(f"URL contains '{kw}'")

        # Check known C2 indicators
        for c2 in KNOWN_C2_DOMAINS:
            if c2 in hostname:
                signals.append(f"Hostname matches known C2/paste pattern: {c2}")

        # Check URL length
        if len(url) > 500:
            signals.append(f"Unusually long URL ({len(url)} chars)")

        # Check for auth in URL
        if "@" in hostname:
            signals.append("URL contains embedded credentials (@ host)")

        if not signals:
            return

        severity = Severity.CRITICAL if any(
            "C2" in s or "private IP" in s or "credentials" in s
            for s in signals
        ) else Severity.HIGH

        findings.append(Finding(
            path, severity, Confidence.MEDIUM, Category.C2_CALLBACK,
            title="Suspicious external URL detected",
            description="; ".join(signals),
            attack_path=f"File references {url} -> network request to attacker-controlled server -> data exfiltration / payload download",
            remediation="Remove or replace the URL. Verify it is necessary and uses a trusted service.",
            line_number=line_no, raw_value=url,
        ))

    def _check_network_api(self, content: str, path: str) -> List[Finding]:
        findings = []
        for pat, api_name in NETWORK_API_CALLS:
            for match in re.finditer(pat, content, re.IGNORECASE):
                line_no = content[:match.start()].count("\n") + 1
                url_match = re.search(r'https?://[^"\')]+', match.group(0))
                url = url_match.group(0) if url_match else "UNKNOWN"

                try:
                    hostname = urlparse(url).hostname or ""
                    if hostname.lower() in SAFE_PACKAGE_REGISTRIES or \
                       any(hostname.lower().endswith("." + d) for d in SAFE_PACKAGE_REGISTRIES):
                        continue
                except Exception:
                    pass

                findings.append(Finding(
                    path, Severity.HIGH, Confidence.MEDIUM, Category.RUNTIME_NETWORK_CALL,
                    title=f"Runtime network call via {api_name}",
                    description=f"Code makes network request to: {url}",
                    attack_path=f"Code executes -> {api_name} -> contacts {url} -> potential C2 / data exfil",
                    remediation="Review network calls. Ensure they connect to trusted, necessary endpoints.",
                    line_number=line_no, raw_value=url,
                ))
        return findings
