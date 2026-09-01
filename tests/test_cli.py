"""Tests for the CLI interface."""

from pathlib import Path

from typer.testing import CliRunner

from inframetrix.cli import app

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "inframetrix" in result.output


def test_cli_scan_clean_project(tmp_path: Path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "low"])
    assert result.exit_code == 0
    assert "No findings" in result.output


def test_cli_scan_json_output(tmp_path: Path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    out_file = tmp_path / "report.json"
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "-o", str(out_file)])
    assert result.exit_code == 0
    assert out_file.exists()


def test_cli_scan_markdown_output(tmp_path: Path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    out_file = tmp_path / "report.md"
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "markdown", "-o", str(out_file)])
    assert result.exit_code == 0
    assert out_file.exists()


def test_cli_scan_fail_on_threshold(tmp_path: Path):
    (tmp_path / ".env").write_text("SECRET=123\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "medium"])
    assert result.exit_code == 1
