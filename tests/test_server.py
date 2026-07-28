"""Tests for the dashboard server."""

from unittest.mock import patch

from fastapi.testclient import TestClient

from reporeaver.ui.server import _build_app, serve


class TestDashboardApp:
    def test_build_app(self):
        app = _build_app(auth_token="test-token")
        assert app.title == "RepoReaver Dashboard"
        routes = [r.path for r in app.routes]
        assert "/" in routes
        assert "/api/scans" in routes
        assert "/api/scans/{scan_id}" in routes
        assert "/api/stats" in routes

    def test_build_app_from_env(self, monkeypatch):
        monkeypatch.setenv("REPOREAVER_DASHBOARD_TOKEN", "env_token")
        app = _build_app(auth_token=None)
        assert app.title == "RepoReaver Dashboard"

    @patch("uvicorn.run")
    @patch("webbrowser.open")
    def test_serve_starts_uvicorn(self, mock_web, mock_uvicorn):
        serve(host="127.0.0.1", port=9520, open_browser=False)
        mock_uvicorn.assert_called_once()

    @patch("uvicorn.run")
    @patch("webbrowser.open")
    def test_serve_opens_browser(self, mock_web, mock_uvicorn):
        serve(host="127.0.0.1", port=9520, open_browser=True)
        mock_web.assert_called_once()


class TestDashboardAPI:
    def test_index(self):
        with patch("reporeaver.history.get_scans", return_value=[]):
            app = _build_app()
        client = TestClient(app)
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_index_auth_required(self):
        app = _build_app(auth_token="secret")
        client = TestClient(app)
        resp = client.get("/")
        assert resp.status_code == 401

    def test_index_auth_valid(self):
        app = _build_app(auth_token="secret")
        client = TestClient(app)
        resp = client.get("/", headers={"Authorization": "Bearer secret"})
        assert resp.status_code == 200

    def test_index_auth_invalid(self):
        app = _build_app(auth_token="secret")
        client = TestClient(app)
        resp = client.get("/", headers={"Authorization": "Bearer wrong"})
        assert resp.status_code == 403

    def test_api_scans(self):
        with patch("reporeaver.history.get_scans", return_value=[{"id": 1}]):
            app = _build_app()
        client = TestClient(app)
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        assert resp.json() == {"scans": [{"id": 1}]}

    def test_api_scan_detail_found(self):
        with patch("reporeaver.history.get_scan_by_id", return_value={"id": 1, "path": "/test"}):
            app = _build_app()
        client = TestClient(app)
        resp = client.get("/api/scans/1")
        assert resp.status_code == 200
        assert resp.json()["id"] == 1

    def test_api_scan_detail_not_found(self):
        with patch("reporeaver.history.get_scan_by_id", return_value=None):
            app = _build_app()
        client = TestClient(app)
        resp = client.get("/api/scans/999")
        assert resp.status_code == 404
        assert resp.json() == {"error": "not found"}

    def test_api_stats(self):
        with patch("reporeaver.history.get_stats", return_value={"total": 42}):
            app = _build_app()
        client = TestClient(app)
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        assert resp.json() == {"total": 42}

    def test_api_delete_scan(self):
        with patch("reporeaver.history.delete_scan", return_value=True):
            app = _build_app()
        client = TestClient(app)
        resp = client.delete("/api/scans/1")
        assert resp.status_code == 200
        assert resp.json() == {"deleted": True}

    def test_api_delete_scan_fail(self):
        with patch("reporeaver.history.delete_scan", return_value=False):
            app = _build_app()
        client = TestClient(app)
        resp = client.delete("/api/scans/1")
        assert resp.status_code == 200
        assert resp.json() == {"deleted": False}
