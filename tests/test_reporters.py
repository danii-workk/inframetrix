"""Tests for console, json, and markdown reporters."""

import json
from pathlib import Path

from inframetrix.finding import Finding
from inframetrix.reporters.console import render_console
from inframetrix.reporters.json_report import render_json
from inframetrix.reporters.markdown import render_markdown


def _sample_report() -> dict:
    finding = Finding(
        id="test-finding",
        title="Test Finding",
        severity="high",
        category="security",
        file_path="app.py",
        line=10,
        message="Test vulnerability found",
        recommendation="Fix it",
    )
    return {
        "project": "my-project",
        "path": "/path/to/project",
        "rules_path": "/path/to/rules",
        "rules_loaded": ["auth.yaml"],
        "risk_score": 15,
        "risk_level": "low",
        "findings": [finding],
    }


def test_render_json_to_file(tmp_path: Path):
    report = _sample_report()
    out_file = tmp_path / "nested" / "report.json"
    result = render_json(report, output_path=out_file)

    assert out_file.exists()
    data = json.loads(result)
    assert data["project"] == "my-project"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["id"] == "test-finding"


def test_render_markdown_to_file(tmp_path: Path):
    report = _sample_report()
    out_file = tmp_path / "nested" / "report.md"
    result = render_markdown(report, output_path=out_file)

    assert out_file.exists()
    assert "# InfraMetrix Report" in result
    assert "Test Finding" in result
    assert "`app.py`" in result


def test_render_console_runs_without_error():
    report = _sample_report()
    render_console(report, no_color=True)
