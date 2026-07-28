# SPDX-License-Identifier: MIT
"""Threat intelligence feed integration — OSV, MalwareBazaar, and known C2 feeds.

Fetches and caches vulnerability data for dependency checking.
All network calls are opt-in (user must configure).
"""

import json
import logging
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("reporeaver.feeds")

FEED_DIR = Path.home() / ".reporeaver" / "feeds"
FEED_DB = FEED_DIR / "feeds.db"

# Hook for test injection — production uses urllib.request.urlopen
_urlopen = urllib.request.urlopen

# How long to cache feed data before re-fetching
CACHE_TTL = {
    "osv": 3600 * 24,          # 24h for OSV (vulnerability DB changes daily)
    "malwarebazaar": 3600 * 6,  # 6h for malware hashes
}

OSV_API = "https://api.osv.dev/v1/query"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
C2_FEED_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"


def _init_db():
    FEED_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(FEED_DB))
    db.execute("""
        CREATE TABLE IF NOT EXISTS feed_cache (
            feed_name TEXT PRIMARY KEY,
            fetched_at REAL NOT NULL,
            data TEXT NOT NULL
        )
    """)
    db.commit()
    return db


def _get_cached(feed_name: str, ttl: int) -> Optional[Any]:
    """Get cached feed data if still fresh."""
    db = _init_db()
    row = db.execute(
        "SELECT fetched_at, data FROM feed_cache WHERE feed_name = ?",
        (feed_name,)
    ).fetchone()
    db.close()
    if row:
        fetched_at, data = row
        if time.time() - fetched_at < ttl:
            return json.loads(data)
    return None


def _set_cache(feed_name: str, data: Any):
    db = _init_db()
    db.execute(
        "INSERT OR REPLACE INTO feed_cache (feed_name, fetched_at, data) VALUES (?, ?, ?)",
        (feed_name, time.time(), json.dumps(data)),
    )
    db.commit()
    db.close()


def query_osv(package_name: str, ecosystem: str = "npm") -> List[Dict]:
    """Query OSV for known vulnerabilities affecting a package.

    Args:
        package_name: e.g., 'lodash', '@angular/core'
        ecosystem: 'npm', 'PyPI', 'RubyGems', 'crates.io', etc.

    Returns list of vulnerability dicts, or empty list on error.
    """
    cache_key = f"osv_{ecosystem}_{package_name}"
    cached = _get_cached(cache_key, CACHE_TTL["osv"])
    if cached is not None:
        return cached

    try:
        req = urllib.request.Request(
            OSV_API,
            data=json.dumps({
                "package": {"name": package_name, "ecosystem": ecosystem},
                "per_page": 10,
            }).encode(),
            headers={"Content-Type": "application/json"},
        )
        with _urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        vulns = data.get("vulns", [])
        _set_cache(cache_key, vulns)
        return vulns
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        return []


def query_malwarebazaar(hash_sha256: str) -> Optional[Dict]:
    """Check if a file hash is known malware via MalwareBazaar.

    Returns file info dict if malicious, None if not found or error.
    """
    cache_key = f"mb_{hash_sha256}"
    cached = _get_cached(cache_key, CACHE_TTL["malwarebazaar"])
    if cached is not None:
        return cached if cached else None

    try:
        data = urllib.parse.urlencode({"query": "get_info", "hash": hash_sha256}).encode()
        req = urllib.request.Request(MALWAREBAZAAR_API, data=data)
        with _urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())
        if result.get("query_status") == "ok" and result.get("data"):
            info = result["data"][0]
            _set_cache(cache_key, info)
            return info
        # Not found — cache empty result
        _set_cache(cache_key, {})
        return None
    except (urllib.error.URLError, json.JSONDecodeError):
        return None


def get_known_c2_domains() -> List[str]:
    """Fetch known C2 domains from public feed."""
    cache_key = "c2_feed"
    cached = _get_cached(cache_key, 3600 * 12)
    if cached is not None:
        return cached

    try:
        req = urllib.request.Request(C2_FEED_URL)
        with _urlopen(req, timeout=15) as resp:
            text = resp.read().decode()
        domains = []
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ip = line.split()[0]
                domains.append(ip)
        _set_cache(cache_key, domains)
        return domains
    except (urllib.error.URLError, OSError):
        log.warning("Failed to fetch C2 feed from %s", C2_FEED_URL)
        return []


def check_known_vulnerable(
    package_name: str,
    version: str,
    ecosystem: str = "npm",
) -> List[Dict]:
    """Check if a specific package@version has known vulnerabilities.

    Returns list of advisories with id, severity, summary.
    """
    vulns = query_osv(package_name, ecosystem)
    results = []
    for v in vulns:
        aliases = v.get("aliases", [])
        summary = v.get("summary", v.get("details", ""))
        severity = "unknown"
        for ref in v.get("references", []):
            if "severity" in ref.get("url", "").lower() or "cve" in ref.get("url", "").lower():
                severity = "high"
                break
        results.append({
            "id": ", ".join(aliases) if aliases else v.get("id", "unknown"),
            "summary": summary,
            "severity": severity,
        })
    return results
