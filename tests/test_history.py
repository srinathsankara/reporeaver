"""Tests for scan history persistence."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from reporeaver import history


def test_save_and_get_scan():
    with patch.object(history, "HISTORY_DB", Path(tempfile.mktemp(suffix=".db"))):
        scan_id = history.save_scan(
            target="/tmp/test-repo",
            scan_time="2026-07-25T00:00:00Z",
            duration_ms=1000,
            files_count=42,
            risk_score=5.0,
            max_sev="high",
            critical=1,
            high=2,
            medium=3,
            low=0,
            findings=[{"file": "test.js", "severity": "high", "title": "test"}],
        )
        assert scan_id > 0

        scans = history.get_scans(limit=10)
        assert len(scans) >= 1
        assert scans[0]["target"] == "/tmp/test-repo"
        assert scans[0]["risk_score"] == 5.0

        stats = history.get_stats()
        assert stats["total_scans"] >= 1
        assert stats["avg_risk_score"] > 0

        history.delete_scan(scan_id)
        assert history.get_scan_by_id(scan_id) is None
