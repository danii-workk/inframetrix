"""Legacy linear risk score calculation (v1)."""

from __future__ import annotations

from inframetrix.models.finding import Finding

SEVERITY_WEIGHTS: dict[str, int] = {
    "info": 1,
    "low": 3,
    "medium": 7,
    "high": 15,
    "critical": 25,
}

RISK_LEVELS: list[tuple[int, str]] = [
    (71, "critical"),
    (46, "high"),
    (21, "medium"),
    (0, "low"),
]


def calculate_risk_score(findings: list[Finding]) -> tuple[int, str]:
    """Calculate a risk score (0-100) and risk level from a list of findings."""
    total = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    score = min(total, 100)

    level = "low"
    for threshold, name in RISK_LEVELS:
        if score >= threshold:
            level = name
            break

    return score, level
