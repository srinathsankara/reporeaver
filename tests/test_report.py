"""Tests for console report output."""

import json

from reporeaver.models import Category, Confidence, Finding, RiskScore, ScanResult, Severity
from reporeaver.output.report import print_report


def test_print_report_no_findings(capsys):
    result = ScanResult(target="/tmp/test", files_scanned=10, findings=[])
    print_report(result, verbose=False)
    captured = capsys.readouterr()
    assert "NO ISSUES DETECTED" in captured.out
    assert "Risk score" in captured.out


def test_print_report_with_findings(capsys):
    f = Finding("file.js", Severity.HIGH, Confidence.HIGH, Category.C2_CALLBACK,
                "C2 callback", "desc", attack_path="path", remediation="fix")
    result = ScanResult(target="/tmp/test", files_scanned=1,
                        findings=[f],
                        risk_score=RiskScore(5.0, Severity.HIGH, high=1, total=1))
    print_report(result, verbose=False)
    captured = capsys.readouterr()
    assert "file.js" in captured.out
    assert "C2 callback" in captured.out
    assert "HIGH" in captured.out or "RISK SCORE" in captured.out


def test_print_report_verbose_shows_medium(capsys):
    f = Finding("med.js", Severity.MEDIUM, Confidence.MEDIUM, Category.HIGH_ENTROPY,
                "Medium finding", "desc")
    result = ScanResult(target="/tmp/test", files_scanned=1, findings=[f],
                        risk_score=RiskScore(0.5, Severity.MEDIUM, medium=1, total=1))
    print_report(result, verbose=True)
    captured = capsys.readouterr()
    assert "Medium finding" in captured.out


def test_print_report_json_output(capsys):
    f = Finding("f.js", Severity.LOW, Confidence.LOW, Category.INFO, "info", "desc")
    result = ScanResult(target="/tmp/test", files_scanned=1, findings=[f])
    print_report(result, verbose=False, json_output=True)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["target"] == "/tmp/test"
    assert len(data["findings"]) == 1


def test_print_report_unicode(capsys):
    f = Finding("unicode.txt", Severity.LOW, Confidence.LOW, Category.INFO,
                "Unicode \u00e9\u00e0\u00fc test", "desc")
    result = ScanResult(target="/tmp/test", files_scanned=1, findings=[f])
    print_report(result, verbose=True)
    captured = capsys.readouterr()
    assert "\u00e9" in captured.out or "Unicode" in captured.out
