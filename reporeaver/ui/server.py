"""Dashboard server — local web UI for scan history with optional token auth."""

import json
import os
import sys
import webbrowser
from pathlib import Path
from typing import Optional

HERE = Path(__file__).parent


def serve(host: str = "127.0.0.1", port: int = 9520,
          open_browser: bool = True, auth_token: Optional[str] = None):
    """Spin up the dashboard. Optional auth via ?token= or Authorization header."""
    try:
        from fastapi import FastAPI, HTTPException, Query, Request
        from fastapi.responses import HTMLResponse
        import uvicorn
    except ImportError:
        print("Dashboard requires: pip install reporeaver[dashboard]", file=sys.stderr)
        print("  or: pip install fastapi uvicorn jinja2", file=sys.stderr)
        sys.exit(1)

    from ..history import get_scan_by_id, get_scans, get_stats, delete_scan
    from .. import __version__

    if not auth_token:
        auth_token = os.environ.get("REPOREAVER_DASHBOARD_TOKEN")

    app = FastAPI(title="RepoReaver Dashboard", version=__version__)

    def _check_auth(request: Request):
        if not auth_token:
            return
        q_token = request.query_params.get("token")
        h_token = request.headers.get("Authorization", "").replace("Bearer ", "")
        token = q_token or h_token
        if not token:
            raise HTTPException(401, "Unauthorized — provide ?token= or Authorization: Bearer")
        if token != auth_token:
            raise HTTPException(403, "Forbidden — invalid token")

    template = (HERE / "templates" / "dashboard.html").read_text(encoding="utf-8")

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        _check_auth(request)
        return template.replace("{{VERSION}}", __version__)

    @app.get("/api/scans")
    def api_scans(request: Request, limit: int = Query(50),
                 offset: int = Query(0), tag: Optional[str] = Query(None)):
        _check_auth(request)
        return {"scans": get_scans(limit, offset, tag)}

    @app.get("/api/scans/{scan_id}")
    def api_scan_detail(request: Request, scan_id: int):
        _check_auth(request)
        scan = get_scan_by_id(scan_id)
        if not scan:
            return {"error": "not found"}, 404
        return scan

    @app.get("/api/stats")
    def api_stats(request: Request):
        _check_auth(request)
        return get_stats()

    @app.delete("/api/scans/{scan_id}")
    def api_delete_scan(request: Request, scan_id: int):
        _check_auth(request)
        ok = delete_scan(scan_id)
        return {"deleted": ok}

    url = f"http://{host}:{port}"
    if auth_token:
        url += f"?token={auth_token}"
    print(f"  Dashboard: http://{host}:{port}")
    if auth_token:
        print(f"  Auth token: {auth_token[:8]}..." if len(auth_token) > 8 else "  Auth enabled")
    if open_browser:
        webbrowser.open(url)
    print("  Ctrl+C to stop")
    uvicorn.run(app, host=host, port=port, log_level="warning")
