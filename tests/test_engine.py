"""Tests for the rule evaluation engine."""

from pathlib import Path

from inframetrix.rules.engine import evaluate_rules
from inframetrix.rules.rule import Rule, Ruleset


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def test_engine_regex_match(tmp_path: Path):
    file_path = tmp_path / "Dockerfile"
    file_path.write_text("RUN curl -fsSL https://example.com/install.sh | bash\n", encoding="utf-8")

    rule = Rule(
        id="docker-curl-bash",
        title="Curl pipe bash",
        severity="critical",
        category="infrastructure",
        match_mode="regex",
        patterns=[r"(curl|wget)[^|\n]*\|[ \t]*(ba|z)?sh"],
        file_patterns=["Dockerfile*"],
    )
    ruleset = Ruleset(rules=[rule])

    findings = evaluate_rules([file_path], ruleset, _read_text)
    assert len(findings) == 1
    assert findings[0].id == "docker-curl-bash"
    assert findings[0].line == 1


def test_engine_regex_no_false_positive(tmp_path: Path):
    file_path = tmp_path / "Dockerfile"
    file_path.write_text("RUN apt-get update && apt-get install -y curl bash\nRUN ls | grep foo\n", encoding="utf-8")

    rule = Rule(
        id="docker-curl-bash",
        title="Curl pipe bash",
        severity="critical",
        category="infrastructure",
        match_mode="regex",
        patterns=[r"(curl|wget)[^|\n]*\|[ \t]*(ba|z)?sh"],
        file_patterns=["Dockerfile*"],
    )
    ruleset = Ruleset(rules=[rule])

    findings = evaluate_rules([file_path], ruleset, _read_text)
    assert len(findings) == 0


def test_engine_language_filtering(tmp_path: Path):
    py_file = tmp_path / "app.py"
    py_file.write_text("secret = 'danger'\n", encoding="utf-8")

    js_file = tmp_path / "app.js"
    js_file.write_text("secret = 'danger'\n", encoding="utf-8")

    rule = Rule(
        id="secret-py-only",
        title="Python secret",
        severity="high",
        category="secrets",
        patterns=["secret = 'danger'"],
        languages=["python"],
    )
    ruleset = Ruleset(rules=[rule])

    findings = evaluate_rules([py_file, js_file], ruleset, _read_text)
    assert len(findings) == 1
    assert findings[0].file_path == str(py_file)
