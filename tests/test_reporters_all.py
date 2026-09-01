"""Tests for SARIF, HTML, and ReportService."""

import json
from pathlib import Path

from inframetrix.models.finding import Finding
from inframetrix.reporters.html import render_html
from inframetrix.reporters.sarif import render_sarif
from inframetrix.services.report_service import ReportService


def _sample_report() -> dict:
    f = Finding(
        id="sarif-test-rule",
        title="Test Finding for SARIF",
        severity="high",
        category="sast",
        file_path="src/main.py",
        line=15,
        message="SQL injection vulnerability",
        recommendation="Use parameterized queries",
    )
    return {
        "project": "DemoApp",
        "path": "/path/to/demo",
        "risk_score": 50,
        "risk_level": "high",
        "findings": [f],
    }


def test_render_sarif_schema(tmp_path: Path):
    report = _sample_report()
    out = tmp_path / "report.sarif"
    sarif_str = render_sarif(report, output_path=out)

    assert out.is_file()
    data = json.loads(sarif_str)
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    assert len(data["runs"][0]["results"]) == 1
    assert data["runs"][0]["results"][0]["ruleId"] == "sarif-test-rule"


def test_render_html_offline(tmp_path: Path):
    report = _sample_report()
    out = tmp_path / "report.html"
    html_str = render_html(report, output_path=out)

    assert out.is_file()
    assert "InfraMetrix Security Report" in html_str
    assert "Test Finding for SARIF" in html_str


def test_report_service_dispatcher(tmp_path: Path):
    report = _sample_report()
    json_out = tmp_path / "report.json"
    ReportService.export_report(report, "json", output_path=json_out)
    assert json_out.is_file()

    html_out = tmp_path / "report.html"
    ReportService.export_report(report, "html", output_path=html_out)
    assert html_out.is_file()
