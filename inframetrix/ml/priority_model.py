"""ML Priority Score ranking (0..100) for triage and remediation sequencing."""

from __future__ import annotations

from inframetrix.models.finding import Finding

SEVERITY_BASE = {
    "critical": 80.0,
    "high": 60.0,
    "medium": 35.0,
    "low": 15.0,
    "info": 5.0,
}


class PriorityModel:
    """Calculates actionable priority score without altering security severity."""

    @classmethod
    def calculate_priority_score(
        cls,
        finding: Finding,
        fp_probability: float = 0.1,
    ) -> float:
        """Calculate triage priority score (0.0 to 100.0).

        Factors:
        - Base severity (critical > high > medium > low)
        - CVSS boost
        - Confidence multiplier
        - Internet exposure boost (URL / endpoint presence)
        - FP dampening (high FP probability reduces priority)
        """
        base = SEVERITY_BASE.get(finding.severity, 35.0)

        # CVSS adjustment
        if finding.cvss is not None and finding.cvss > 0:
            cvss_factor = finding.cvss * 2.0  # 0..20
            base = min(base + cvss_factor, 95.0)

        # Confidence factor
        conf_mult = 1.0
        if finding.confidence == "high":
            conf_mult = 1.1
        elif finding.confidence == "low":
            conf_mult = 0.7

        # Internet exposure boost
        exposure_boost = 10.0 if (finding.url or finding.endpoint) else 0.0

        # Production vs Test location
        path = (finding.file_path or "").lower()
        test_penalty = 0.6 if ("test" in path or "mock" in path or "fixture" in path) else 1.0

        # FP discount: priority * (1 - 0.5 * fp_prob)
        fp_factor = 1.0 - (0.5 * fp_probability)

        raw_priority = (base + exposure_boost) * conf_mult * test_penalty * fp_factor
        return round(min(max(raw_priority, 0.0), 100.0), 1)
