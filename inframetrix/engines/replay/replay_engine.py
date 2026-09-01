"""Security Regression Correlator linking code changes to new findings."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from inframetrix.models.finding import Finding


@dataclass
class RegressionEvent:
    """Security regression identified between two scan checkpoints."""

    file_path: str
    change_timestamp: datetime
    diff_text: str | None
    risk_before: float
    risk_after: float
    new_findings: list[Finding]


class ReplayEngine:
    """Correlates code modification events with newly introduced security findings."""

    @classmethod
    def correlate_regressions(
        cls,
        findings_before: list[Finding],
        findings_after: list[Finding],
        recent_events: list[dict[str, Any]],
        risk_before: float,
        risk_after: float,
    ) -> list[RegressionEvent]:
        """Find which newly introduced findings correlate with recently modified files."""
        before_fps = {f.fingerprint for f in findings_before}
        newly_introduced = [f for f in findings_after if f.fingerprint not in before_fps]

        if not newly_introduced:
            return []

        # Group new findings by file
        findings_by_file: dict[str, list[Finding]] = {}
        for f in newly_introduced:
            if f.file_path:
                # Normalize file path
                clean_path = f.file_path.replace("\\", "/")
                findings_by_file.setdefault(clean_path, []).append(f)

        regressions: list[RegressionEvent] = []

        for event in recent_events:
            event_file = event.get("file_path", "").replace("\\", "/")
            matched_findings = []

            for path_key, f_list in findings_by_file.items():
                if event_file in path_key or path_key in event_file:
                    matched_findings.extend(f_list)

            if matched_findings:
                ts = datetime.fromisoformat(event["timestamp"]) if isinstance(event["timestamp"], str) else event["timestamp"]
                regressions.append(
                    RegressionEvent(
                        file_path=event_file,
                        change_timestamp=ts,
                        diff_text=event.get("diff_text"),
                        risk_before=risk_before,
                        risk_after=risk_after,
                        new_findings=matched_findings,
                    )
                )

        return regressions
