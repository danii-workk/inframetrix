"""Core scanner facade preserving backward compatibility."""

from __future__ import annotations

import uuid
from pathlib import Path

from inframetrix.core.scan_context import ScanContext
from inframetrix.engines.native.adapter import _DEFAULT_RULESETS_DIR, NativeScannerAdapter
from inframetrix.scoring.legacy import calculate_risk_score


def scan_project(project_path: Path, rules_path: Path | None = None) -> dict:
    """Scan a project directory and return a report dictionary (backward-compatible API).

    Args:
        project_path: Directory to scan.
        rules_path: Optional directory containing YAML ruleset files.
                     Falls back to built-in rulesets if not provided.
    """
    adapter = NativeScannerAdapter()
    context = ScanContext(
        project_path=project_path,
        project_id=str(uuid.uuid4()),
        session_id=str(uuid.uuid4()),
        preset="quick",
        custom_rules_path=rules_path,
    )

    result = adapter.scan(context)
    findings = result.findings

    score, level = calculate_risk_score(findings)
    resolved_rules_path = result.metadata.get("rules_path", str((rules_path or _DEFAULT_RULESETS_DIR).resolve()))
    loaded_names = result.metadata.get("rules_loaded", [])

    return {
        "project": project_path.resolve().name,
        "path": str(project_path.resolve()),
        "rules_path": resolved_rules_path,
        "rules_loaded": loaded_names,
        "risk_score": score,
        "risk_level": level,
        "findings": findings,
    }
