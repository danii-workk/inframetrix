"""JSON report output."""

from __future__ import annotations

import json
from pathlib import Path


def render_json(report: dict, output_path: Path | None = None) -> str:
    """Serialize the report as JSON. Optionally write to a file."""
    data = {
        "project": report["project"],
        "path": report["path"],
        "rules_path": report.get("rules_path", ""),
        "rules_loaded": report.get("rules_loaded", []),
        "risk_score": report["risk_score"],
        "risk_level": report["risk_level"],
        "findings": [f.model_dump() for f in report["findings"]],
    }

    text = json.dumps(data, indent=2, ensure_ascii=False)

    if output_path is not None:
        output_path.write_text(text, encoding="utf-8")

    return text