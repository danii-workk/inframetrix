"""SARIF (Static Analysis Results Interchange Format) v2.1.0 exporter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from inframetrix import __version__
from inframetrix.models.finding import Finding

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}


def render_sarif(report: dict[str, Any], output_path: Path | None = None) -> str:
    """Export scan report to standard OASIS SARIF v2.1.0 format."""
    findings: list[Finding] = report.get("findings", [])

    rules_dict: dict[str, dict[str, Any]] = {}
    results = []

    for f in findings:
        rule_id = f.id
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.message},
                "defaultConfiguration": {"level": SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning")},
                "help": {"text": f.recommendation or "No recommendation provided."},
                "properties": {
                    "category": f.category,
                    "tags": f.tags,
                },
            }

        # Location
        locations = []
        if f.file_path:
            clean_uri = f.file_path.replace("\\", "/")
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": clean_uri,
                        },
                        "region": {
                            "startLine": f.line if f.line and f.line > 0 else 1,
                            "startColumn": f.column if f.column and f.column > 0 else 1,
                        },
                    }
                }
            )

        results.append(
            {
                "ruleId": rule_id,
                "level": SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f.message or f.description or f.title},
                "locations": locations,
                "properties": {
                    "fingerprint": f.fingerprint,
                    "confidence": f.confidence,
                    "cvss": f.cvss,
                    "cve": f.cve,
                    "cwe": f.cwe,
                    "source_engine": f.source_engine,
                },
            }
        )

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "InfraMetrix",
                        "version": __version__,
                        "informationUri": "https://github.com/danii-workk/inframetrix",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    text = json.dumps(sarif_data, indent=2, ensure_ascii=False)

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text, encoding="utf-8")

    return text
