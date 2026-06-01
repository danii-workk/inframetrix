"""Tests for YAML rule loading."""

from pathlib import Path

import pytest

from inframetrix.rules.loader import load_ruleset, load_rulesets
from inframetrix.rules.rule import Ruleset

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "rulesets"


def _write_yaml(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_load_empty_ruleset(tmp_path: Path):
    p = _write_yaml(tmp_path, "empty.yaml", "rules: []\n")
    rs = load_ruleset(p)
    assert isinstance(rs, Ruleset)
    assert rs.rules == []


def test_load_single_rule(tmp_path: Path):
    yaml_content = """\
rules:
  - id: test-rule
    title: Test Rule
    severity: high
    category: test
    patterns:
      - "danger"
    message: "Found danger"
    recommendation: "Fix it"
    confidence: high
"""
    p = _write_yaml(tmp_path, "test.yaml", yaml_content)
    rs = load_ruleset(p)
    assert len(rs.rules) == 1
    rule = rs.rules[0]
    assert rule.id == "test-rule"
    assert rule.severity == "high"
    assert rule.patterns == ["danger"]
    assert rule.match_mode == "contains"


def test_load_multiple_rulesets(tmp_path: Path):
    yaml1 = """\
rules:
  - id: rule-a
    title: Rule A
    severity: low
    category: test
"""
    yaml2 = """\
rules:
  - id: rule-b
    title: Rule B
    severity: critical
    category: test
"""
    p1 = _write_yaml(tmp_path, "a.yaml", yaml1)
    p2 = _write_yaml(tmp_path, "b.yaml", yaml2)

    merged, names = load_rulesets([p1, p2])
    assert len(merged.rules) == 2
    assert set(names) == {"a.yaml", "b.yaml"}


def test_load_ruleset_invalid_yaml(tmp_path: Path):
    import yaml

    p = _write_yaml(tmp_path, "bad.yaml", "rules:\n  - id: [invalid\n")
    with pytest.raises(yaml.YAMLError):
        load_ruleset(p)


def test_load_rulesets_invalid_yaml(tmp_path: Path):
    p = _write_yaml(tmp_path, "bad.yaml", "rules:\n  - id: [invalid\n")
    with pytest.raises(SystemExit):
        load_rulesets([p])


def test_load_rulesets_missing_file(tmp_path: Path):
    with pytest.raises(SystemExit):
        load_rulesets([tmp_path / "nonexistent.yaml"])