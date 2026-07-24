"""Dashboard server — local web UI for scan history."""

import json
import os
import sys
import webbrowser
from pathlib import Path
from typing import Optional

HERE = Path(__file__).parent


def serve(host: str = "127.0.0.1", port: int = 9520, open_browser: bool = True):
    """Spin up the dashboard. Dies cleanly on Ctrl+C."""
    try:
        from fastapi import FastAPI, Query
        from fastapi.responses import HTMLResponse
        import uvicorn
    except ImportError:
        print("Dashboard requires: pip install reporeaver[dashboard]", file=sys.stderr)
        print("  or: pip install fastapi uvicorn jinja2", file=sys.stderr)
        sys.exit(1)

    from ..history import get_scan_by_id, get_scans, get_stats, delete_scan
    from .. import __version__

    app = FastAPI(title="RepoReaver Dashboard", version=__version__)

    template = (HERE / "templates" / "dashboard.html").read_text(encoding="utf-8")

    @app.get("/", response_class=HTMLResponse)
    def index():
        return template.replace("{{VERSION}}", __version__)

    @app.get("/api/scans")
    def api_scans(
        limit: int = Query(50),
        offset: int = Query(0),
        tag: Optional[str] = Query(None),
    ):
        return {"scans": get_scans(limit, offset, tag)}

    @app.get("/api/scans/{scan_id}")
    def api_scan_detail(scan_id: int):
        scan = get_scan_by_id(scan_id)
        if not scan:
            return {"error": "not found"}, 404
        return scan

    @app.get("/api/stats")
    def api_stats():
        return get_stats()

    @app.delete("/api/scans/{scan_id}")
    def api_delete_scan(scan_id: int):
        ok = delete_scan(scan_id)
        return {"deleted": ok}

    url = f"http://{host}:{port}"
    print(f"  Dashboard: {url}")
    if open_browser:
        webbrowser.open(url)
    print("  Ctrl+C to stop")
    uvicorn.run(app, host=host, port=port, log_level="warning")
