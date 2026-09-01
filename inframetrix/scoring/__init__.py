"""Risk calculation engines."""

from inframetrix.scoring.legacy import calculate_risk_score
from inframetrix.scoring.risk_v2 import calculate_risk_score_v2

__all__ = ["calculate_risk_score", "calculate_risk_score_v2"]
