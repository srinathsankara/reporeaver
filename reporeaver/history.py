"""Scan history — persists results to SQLite for the dashboard."""

import copy
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

HISTORY_DIR = Path.home() / ".reporeaver"
HISTORY_DB = HISTORY_DIR / "history.db"

SENSITIVE_FIELDS = {"raw", "decoded", "value"}


def _redact_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Strip sensitive/secret payloads before persisting to history DB."""
    redacted = copy.deepcopy(findings)
    for f in redacted:
        for field in SENSITIVE_FIELDS:
            if field in f:
                f[field] = "<redacted>"
        for field in ("snippet", "description"):
            if field in f and isinstance(f[field], str) and len(f[field]) > 120:
                f[field] = f[field][:120] + "..."
        if "context" in f and isinstance(f.get("context"), str) and len(f["context"]) > 120:
            f["context"] = f["context"][:120] + "..."
    return redacted

# Schema migrations for when we inevitably break things
SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER);
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    scan_time   TEXT NOT NULL,
    duration_ms INTEGER DEFAULT 0,
    files_count INTEGER DEFAULT 0,
    risk_score  REAL DEFAULT 0.0,
    max_sev     TEXT DEFAULT 'info',
    critical    INTEGER DEFAULT 0,
    high        INTEGER DEFAULT 0,
    medium      INTEGER DEFAULT 0,
    low         INTEGER DEFAULT 0,
    findings    TEXT DEFAULT '[]',
    sarif_path  TEXT,
    html_path   TEXT,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS scan_tags (
    scan_id INTEGER,
    tag     TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_scan_time ON scans(scan_time);
CREATE INDEX IF NOT EXISTS idx_risk_score ON scans(risk_score);
"""


def _get_db() -> sqlite3.Connection:
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(HISTORY_DB))
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    row = db.execute("SELECT version FROM schema_version").fetchone()
    current_version = row["version"] if row else 0
    if current_version != SCHEMA_VERSION:
        db.executescript("DROP TABLE IF EXISTS scans; DROP TABLE IF EXISTS scan_tags; DROP TABLE IF EXISTS schema_version;")
        db.executescript(SCHEMA)
        db.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))
        db.commit()
    return db


def save_scan_history(result) -> int:
    """Save a ScanResult object to the history database."""
    from .models import RiskScore
    rs = result.risk_score or RiskScore(0.0, None)
    return save_scan(
        target=result.target,
        scan_time=result.scan_time,
        duration_ms=0,
        files_count=result.files_scanned,
        risk_score=rs.score,
        max_sev=(rs.max_severity.value if rs.max_severity else "info"),
        critical=rs.critical,
        high=rs.high,
        medium=rs.medium,
        low=rs.low,
        findings=result.to_dict().get("findings", []),
    )


def save_scan(
    target: str,
    scan_time: str,
    duration_ms: int,
    files_count: int,
    risk_score: float,
    max_sev: str,
    critical: int,
    high: int,
    medium: int,
    low: int,
    findings: List[Dict[str, Any]],
    sarif_path: Optional[str] = None,
    html_path: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> int:
    findings_clean = _redact_findings(findings)
    db = _get_db()
    try:
        cur = db.execute(
            """INSERT INTO scans
               (target, scan_time, duration_ms, files_count,
                risk_score, max_sev, critical, high, medium, low,
                findings, sarif_path, html_path)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                target, scan_time, duration_ms, files_count,
                risk_score, max_sev, critical, high, medium, low,
                json.dumps(findings_clean), sarif_path, html_path,
            ),
        )
        scan_id = cur.lastrowid
        if tags:
            db.executemany(
                "INSERT INTO scan_tags (scan_id, tag) VALUES (?, ?)",
                [(scan_id, t) for t in tags],
            )
        db.commit()
        return scan_id
    finally:
        db.close()


def get_scans(limit: int = 50, offset: int = 0, tag: Optional[str] = None) -> List[Dict[str, Any]]:
    db = _get_db()
    try:
        if tag:
            rows = db.execute(
                """SELECT s.* FROM scans s
                   JOIN scan_tags t ON s.id = t.scan_id
                   WHERE t.tag = ?
                   ORDER BY s.scan_time DESC LIMIT ? OFFSET ?""",
                (tag, limit, offset),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM scans ORDER BY scan_time DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    db = _get_db()
    try:
        row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None
    finally:
        db.close()


def delete_scan(scan_id: int) -> bool:
    db = _get_db()
    try:
        db.execute("DELETE FROM scan_tags WHERE scan_id = ?", (scan_id,))
        db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        db.commit()
        return db.total_changes > 0
    finally:
        db.close()


def get_stats() -> Dict[str, Any]:
    db = _get_db()
    try:
        total = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        avg_risk = db.execute("SELECT AVG(risk_score) FROM scans").fetchone()[0] or 0
        worst = db.execute(
            "SELECT target, risk_score, scan_time FROM scans ORDER BY risk_score DESC LIMIT 1"
        ).fetchone()
        recent = db.execute(
            "SELECT target, risk_score, scan_time FROM scans ORDER BY scan_time DESC LIMIT 5"
        ).fetchall()
        return {
            "total_scans": total,
            "avg_risk_score": round(avg_risk, 1),
            "worst": dict(worst) if worst else None,
            "recent": [dict(r) for r in recent],
        }
    finally:
        db.close()
