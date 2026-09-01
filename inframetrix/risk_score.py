"""Risk score calculation facade (backward-compatible)."""

from __future__ import annotations

from inframetrix.scoring.legacy import (
    RISK_LEVELS,
    SEVERITY_WEIGHTS,
    calculate_risk_score,
)
from inframetrix.scoring.risk_v2 import calculate_risk_score_v2

__all__ = [
    "RISK_LEVELS",
    "SEVERITY_WEIGHTS",
    "calculate_risk_score",
    "calculate_risk_score_v2",
]
