"""ML triage review labels."""

from __future__ import annotations

from typing import Literal

ReviewLabel = Literal["true_positive", "false_positive", "accepted_risk", "wont_fix"]

LABEL_MAP: dict[str, int] = {
    "true_positive": 1,
    "accepted_risk": 1,
    "wont_fix": 1,
    "false_positive": 0,
}
