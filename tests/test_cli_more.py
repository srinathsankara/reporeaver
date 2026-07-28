"""Additional CLI tests — main() function path coverage."""

import sys
from unittest.mock import patch, MagicMock
from reporeaver.cli import build_parser, main


class TestParser:
    def test_scan_verbose(self):
        args = build_parser().parse_args(["scan", "/x", "-v"])
        assert args.verbose is True

    def test_scan_json(self):
        args = build_parser().parse_args(["scan", "/x", "-j"])
        assert args.json_output is True

    def test_scan_output(self):
        args = build_parser().parse_args(["scan", "/x", "-o", "report.json"])
        assert args.output == "report.json"

    def test_scan_html(self):
        args = build_parser().parse_args(["scan", "/x", "--html", "report.html"])
        assert args.html_output == "report.html"

    def test_scan_sarif(self):
        args = build_parser().parse_args(["scan", "/x", "--sarif", "out.sarif"])
        assert args.sarif_output == "out.sarif"

    def test_scan_policy(self):
        args = build_parser().parse_args(["scan", "/x", "--policy", "strict"])
        assert args.policy == "strict"

    def test_scan_max_size(self):
        args = build_parser().parse_args(["scan", "/x", "--max-size", "5.0"])
        assert args.max_size == 5.0

    def test_scan_skip(self):
        args = build_parser().parse_args(["scan", "/x", "--skip", "secrets,entropy"])
        assert args.skip == "secrets,entropy"

    def test_scan_no_history(self):
        args = build_parser().parse_args(["scan", "/x", "--no-history"])
        assert args.no_history is True

    def test_scan_diff_only(self):
        args = build_parser().parse_args(["scan", "/x", "--diff-only"])
        assert args.diff_mode is True

    def test_scan_no_cache(self):
        args = build_parser().parse_args(["scan", "/x", "--no-cache"])
        assert args.no_cache is True

    def test_init_precommit_default(self):
        args = build_parser().parse_args(["init-precommit"])
        assert args.target_dir == "."

    def test_init_precommit_with_dir(self):
        args = build_parser().parse_args(["init-precommit", "--target-dir", "myrepo"])
        assert args.target_dir == "myrepo"

    def test_history_last(self):
        args = build_parser().parse_args(["history", "--last", "5"])
        assert args.last == 5

    def test_history_stats(self):
        args = build_parser().parse_args(["history", "--stats"])
        assert args.stats is True

    def test_dashboard_host_port(self):
        args = build_parser().parse_args(["dashboard", "--host", "0.0.0.0", "--port", "8080"])
        assert args.host == "0.0.0.0"
        assert args.port == 8080


class TestMain:
    def test_scan_main(self, tmp_path):
        test_dir = tmp_path / "scantarget"
        test_dir.mkdir()
        with (
            patch.object(sys, "argv", ["reporeaver", "scan", str(test_dir)]),
            patch("reporeaver.cli.setup_logging"),
            patch("reporeaver.cli.scan_target", return_value=0),
        ):
            with patch("reporeaver.cli.sys.exit", side_effect=SystemExit) as mock_exit:
                try:
                    main()
                except SystemExit:
                    pass
        mock_exit.assert_called_once_with(0)

    def test_scan_failure(self, tmp_path):
        test_dir = tmp_path / "scantarget"
        test_dir.mkdir()
        with (
            patch.object(sys, "argv", ["reporeaver", "scan", str(test_dir)]),
            patch("reporeaver.cli.setup_logging"),
            patch("reporeaver.cli.scan_target", return_value=1),
        ):
            with patch("reporeaver.cli.sys.exit", side_effect=SystemExit) as mock_exit:
                try:
                    main()
                except SystemExit:
                    pass
        mock_exit.assert_called_once_with(1)

    def test_scan_target_not_found(self):
        with (
            patch.object(sys, "argv", ["reporeaver", "scan", "/nonexistent/path"]),
            patch("reporeaver.cli.setup_logging"),
        ):
            with patch("reporeaver.cli.sys.exit", side_effect=SystemExit) as mock_exit:
                try:
                    main()
                except SystemExit:
                    pass
        mock_exit.assert_called_once_with(1)

    def test_init_precommit(self):
        with (
            patch.object(sys, "argv", ["reporeaver", "init-precommit"]),
            patch("reporeaver.cli.setup_logging"),
            patch("reporeaver.hooks.install_precommit") as mock_install,
        ):
            with patch("reporeaver.cli.sys.exit", side_effect=SystemExit):
                try:
                    main()
                except SystemExit:
                    pass
        mock_install.assert_called_once_with(".")

    def test_init_precommit_with_dir(self):
        with (
            patch.object(sys, "argv", ["reporeaver", "init-precommit", "--target-dir", "custom-dir"]),
            patch("reporeaver.cli.setup_logging"),
            patch("reporeaver.hooks.install_precommit") as mock_install,
        ):
            with patch("reporeaver.cli.sys.exit", side_effect=SystemExit):
                try:
                    main()
                except SystemExit:
                    pass
        mock_install.assert_called_once_with("custom-dir")

    def test_dashboard(self):
        with (
            patch.object(sys, "argv", ["reporeaver", "dashboard"]),
            patch("reporeaver.cli.setup_logging"),
            patch("reporeaver.ui.server.serve") as mock_serve,
        ):
            with patch("reporeaver.cli.sys.exit", side_effect=SystemExit):
                try:
                    main()
                except SystemExit:
                    pass
        mock_serve.assert_called_once_with(host="127.0.0.1", port=9520, open_browser=True)

    def test_dashboard_no_browser(self):
        with (
            patch.object(sys, "argv", ["reporeaver", "dashboard", "--no-browser"]),
            patch("reporeaver.cli.setup_logging"),
            patch("reporeaver.ui.server.serve") as mock_serve,
        ):
            with patch("reporeaver.cli.sys.exit", side_effect=SystemExit):
                try:
                    main()
                except SystemExit:
                    pass
        mock_serve.assert_called_once_with(host="127.0.0.1", port=9520, open_browser=False)

    def test_history_delete(self):
        with (
            patch.object(sys, "argv", ["reporeaver", "history", "--delete", "5"]),
            patch("reporeaver.cli.setup_logging"),
            patch("reporeaver.history.delete_scan", return_value=True) as mock_del,
        ):
            main()
        mock_del.assert_called_once_with(5)

    def test_history_delete_not_found(self):
        with (
            patch.object(sys, "argv", ["reporeaver", "history", "--delete", "99"]),
            patch("reporeaver.cli.setup_logging"),
            patch("reporeaver.history.delete_scan", return_value=False) as mock_del,
        ):
            main()
        mock_del.assert_called_once_with(99)

    def test_history_stats(self):
        mock_stats = {"total_scans": 10, "avg_risk_score": 3.5, "worst": {"target": "bad", "risk_score": 8.0}}
        with (
            patch.object(sys, "argv", ["reporeaver", "history", "--stats"]),
            patch("reporeaver.cli.setup_logging"),
            patch("reporeaver.history.get_stats", return_value=mock_stats),
        ):
            main()

    def test_history_stats_no_worst(self):
        mock_stats = {"total_scans": 0, "avg_risk_score": 0.0, "worst": None}
        with (
            patch.object(sys, "argv", ["reporeaver", "history", "--stats"]),
            patch("reporeaver.cli.setup_logging"),
            patch("reporeaver.history.get_stats", return_value=mock_stats),
        ):
            main()

    def test_history_list(self):
        mock_scans = [
            {"id": 1, "max_sev": "high", "risk_score": 7.5, "files_count": 10, "target": "/repo/foo"},
            {"id": 2, "max_sev": None, "risk_score": 2.0, "files_count": 0, "target": "/repo/bar"},
        ]
        with (
            patch.object(sys, "argv", ["reporeaver", "history", "--last", "2"]),
            patch("reporeaver.cli.setup_logging"),
            patch("reporeaver.history.get_scans", return_value=mock_scans),
        ):
            main()

    def test_history_empty(self):
        with (
            patch.object(sys, "argv", ["reporeaver", "history"]),
            patch("reporeaver.cli.setup_logging"),
            patch("reporeaver.history.get_scans", return_value=[]),
        ):
            main()
