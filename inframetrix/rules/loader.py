"""Load and validate YAML rulesets from disk."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from inframetrix.rules.rule import Ruleset


def load_ruleset(path: Path) -> Ruleset:
    """Load a single YAML ruleset file and return a validated Ruleset."""
    text = path.read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    if raw is None:
        return Ruleset()
    return Ruleset.model_validate(raw)


def load_rulesets(paths: list[Path]) -> tuple[Ruleset, list[str]]:
    """Load multiple ruleset files. Return merged ruleset and list of loaded names."""
    all_rules = []
    loaded: list[str] = []

    for p in paths:
        try:
            rs = load_ruleset(p)
            all_rules.extend(rs.rules)
            loaded.append(p.name)
        except (yaml.YAMLError, ValidationError, OSError) as exc:
            raise SystemExit(f"Error loading ruleset {p}: {exc}") from exc

    merged = Ruleset(rules=all_rules)
    return merged, loaded