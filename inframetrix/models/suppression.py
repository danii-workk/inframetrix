"""Finding suppression and false positive tracking."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field


class SuppressionRule(BaseModel):
    """Rule to suppress specific findings by fingerprint, rule ID, or path pattern."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str
    target_type: Literal["fingerprint", "rule_id", "path_glob"]
    target_value: str
    reason: Literal["false_positive", "accepted_risk", "wont_fix", "mitigated"] = "false_positive"
    notes: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
