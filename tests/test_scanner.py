"""Tests for the scanner integration with YAML rules engine."""

from pathlib import Path

from inframetrix.scanner import scan_project


def _write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_scan_empty_project(tmp_path: Path):
    report = scan_project(tmp_path)
    assert report["risk_score"] == 0
    assert report["risk_level"] == "low"
    assert report["findings"] == []
    assert isinstance(report["rules_loaded"], list)
    assert len(report["rules_loaded"]) > 0  # default rulesets loaded


def test_scan_detects_env_file(tmp_path: Path):
    _write_file(tmp_path / ".env", "SECRET=abc123\n")
    report = scan_project(tmp_path)
    ids = [f.id for f in report["findings"]]
    assert "committed-env-file" in ids


def test_scan_detects_security_todo(tmp_path: Path):
    _write_file(tmp_path / "app.py", "# TODO auth check\n")
    report = scan_project(tmp_path)
    ids = [f.id for f in report["findings"]]
    assert "security-todo" in ids


def test_scan_custom_rules_path(tmp_path: Path):
    # Create a custom ruleset
    rules_dir = tmp_path / "custom_rules"
    rules_dir.mkdir()
    yaml_content = """\
rules:
  - id: custom-rule
    title: Custom Rule
    severity: info
    category: custom
    patterns:
      - "CUSTOM_MARKER"
    message: "Custom marker found"
"""
    _write_file(rules_dir / "custom.yaml", yaml_content)

    # Create a project with the marker
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    _write_file(project_dir / "test.py", "# CUSTOM_MARKER\n")

    report = scan_project(project_dir, rules_path=rules_dir)
    assert report["rules_path"] == str(rules_dir.resolve())
    assert "custom.yaml" in report["rules_loaded"]
    ids = [f.id for f in report["findings"]]
    assert "custom-rule" in ids


def test_scan_report_structure(tmp_path: Path):
    _write_file(tmp_path / "app.py", "x = 1\n")
    report = scan_project(tmp_path)
    assert "project" in report
    assert "path" in report
    assert "rules_path" in report
    assert "rules_loaded" in report
    assert "risk_score" in report
    assert "risk_level" in report
    assert "findings" in report