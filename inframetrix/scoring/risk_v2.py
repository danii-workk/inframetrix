"""Context-aware Risk Engine v2 with duplicate dampening and confidence weighting."""

from __future__ import annotations

import math

from inframetrix.models.finding import Finding

SEVERITY_BASE: dict[str, float] = {
    "critical": 30.0,
    "high": 18.0,
    "medium": 8.0,
    "low": 3.0,
    "info": 0.5,
}

CONFIDENCE_MULTIPLIER: dict[str, float] = {
    "high": 1.0,
    "medium": 0.8,
    "low": 0.5,
}

RISK_LEVELS_V2: list[tuple[float, str]] = [
    (75.0, "critical"),
    (50.0, "high"),
    (25.0, "medium"),
    (0.0, "low"),
]


def calculate_risk_score_v2(findings: list[Finding]) -> tuple[float, str]:
    """Calculate contextual risk score v2 (0.0 - 100.0) with duplicate dampening.

    Features:
    - Ignores closed, suppressed, and false-positive findings.
    - Applies confidence and CVSS multipliers.
    - Uses logarithmic dampening for repeated instances of identical finding fingerprints.
    """
    active_findings = [f for f in findings if f.status in ("open", "accepted_risk")]
    if not active_findings:
        return 0.0, "low"

    # Group by fingerprint for duplicate dampening
    fingerprint_groups: dict[str, list[Finding]] = {}
    for f in active_findings:
        fp = f.fingerprint or f.compute_fingerprint()
        fingerprint_groups.setdefault(fp, []).append(f)

    total_weighted_points = 0.0

    for group in fingerprint_groups.values():
        primary = group[0]
        base = SEVERITY_BASE.get(primary.severity, 3.0)
        conf = CONFIDENCE_MULTIPLIER.get(primary.confidence, 0.8)

        # CVSS factor
        cvss_mult = 1.0
        if primary.cvss is not None and primary.cvss > 0:
            cvss_mult = 0.5 + (primary.cvss / 20.0)  # e.g. CVSS 10.0 -> 1.0, CVSS 5.0 -> 0.75

        # Check multiple engines confirmation
        engines = {f.source_engine for f in group if f.source_engine}
        multi_engine_mult = 1.2 if len(engines) > 1 else 1.0

        # Primary finding impact
        primary_impact = base * conf * cvss_mult * multi_engine_mult

        # Repeated occurrences contribute logarithmically: 1 + ln(count)
        repeat_factor = 1.0 + math.log(len(group))

        group_score = primary_impact * repeat_factor
        total_weighted_points += group_score

    # Normalize into 0..100 scale using asymptotic curve
    # Score = 100 * (1 - e^(-total / 60))
    normalized_score = round(100.0 * (1.0 - math.exp(-total_weighted_points / 60.0)), 1)
    normalized_score = min(max(normalized_score, 0.0), 100.0)

    level = "low"
    for threshold, name in RISK_LEVELS_V2:
        if normalized_score >= threshold:
            level = name
            break

    return normalized_score, level
