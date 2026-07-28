"""Tests for the CLI module."""

from argparse import ArgumentParser
from pathlib import Path

from reporeaver.cli import build_parser


def test_build_parser_returns_parser():
    parser = build_parser()
    assert isinstance(parser, ArgumentParser)


def test_parse_scan_path():
    parser = build_parser()
    args = parser.parse_args(["scan", str(Path.cwd())])
    assert args.command == "scan"
    assert args.path == str(Path.cwd())


def test_parse_scan_with_options():
    parser = build_parser()
    args = parser.parse_args([
        "scan", "/tmp/test",
        "--output", "report.json",
        "--html", "report.html",
        "--sarif", "results.sarif",
        "--verbose",
        "--json",
        "--max-size", "10",
        "--workers", "4",
        "--no-history",
    ])
    assert args.command == "scan"
    assert args.output == "report.json"
    assert args.html_output == "report.html"
    assert args.sarif_output == "results.sarif"
    assert args.verbose is True
    assert args.json_output is True
    assert args.max_size == 10
    assert args.workers == 4
    assert args.no_history is True


def test_parse_dashboard():
    parser = build_parser()
    args = parser.parse_args(["dashboard", "--port", "9090"])
    assert args.command == "dashboard"
    assert args.port == 9090


def test_parse_init_precommit():
    parser = build_parser()
    args = parser.parse_args(["init-precommit"])
    assert args.command == "init-precommit"


def test_parse_history():
    parser = build_parser()
    args = parser.parse_args(["history", "--last", "5"])
    assert args.command == "history"
    assert args.last == 5


def test_scan_help_contains_scan():
    parser = build_parser()
    help_text = parser.format_help()
    assert "scan" in help_text
    assert "dashboard" in help_text
    assert "init-precommit" in help_text
    assert "history" in help_text
