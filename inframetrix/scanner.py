"""Core scanner that collects files, applies detection rules, and produces findings."""

from __future__ import annotations

from pathlib import Path

from inframetrix.file_walker import collect_files
from inframetrix.risk_score import calculate_risk_score
from inframetrix.rules.engine import evaluate_rules
from inframetrix.rules.loader import load_rulesets

# ---------------------------------------------------------------------------
# Default rulesets shipped with the package
# ---------------------------------------------------------------------------

_DEFAULT_RULESETS_DIR = Path(__file__).parent / "rulesets"


def _read_text(path: Path) -> str | None:
    """Read a file as UTF-8 text. Return None on failure."""
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def scan_project(project_path: Path, rules_path: Path | None = None) -> dict:
    """Scan a project directory and return a report dictionary.

    Args:
        project_path: Directory to scan.
        rules_path: Optional directory containing YAML ruleset files.
                     Falls back to built-in rulesets if not provided.
    """
    files = collect_files(project_path)

    # Load rulesets
    if rules_path is not None:
        yaml_files = sorted(rules_path.glob("*.yaml"))
        if not yaml_files:
            yaml_files = sorted(rules_path.glob("*.yml"))
        ruleset, loaded_names = load_rulesets(yaml_files)
        resolved_rules_path = str(rules_path.resolve())
    else:
        default_dir = _DEFAULT_RULESETS_DIR
        yaml_files = sorted(default_dir.glob("*.yaml"))
        if not yaml_files:
            yaml_files = sorted(default_dir.glob("*.yml"))
        ruleset, loaded_names = load_rulesets(yaml_files)
        resolved_rules_path = str(default_dir.resolve())

    # Evaluate rules
    findings = evaluate_rules(files, ruleset, _read_text)

    score, level = calculate_risk_score(findings)

    return {
        "project": project_path.resolve().name,
        "path": str(project_path.resolve()),
        "rules_path": resolved_rules_path,
        "rules_loaded": loaded_names,
        "risk_score": score,
        "risk_level": level,
        "findings": findings,
    }