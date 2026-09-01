"""ScanSession model for tracking security execution history."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class ScanSession(BaseModel):
    """An execution instance of a security scan against a project."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str
    preset: str = "quick"
    status: Literal["queued", "running", "completed", "failed", "cancelled"] = "queued"
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None

    # Risk scores
    risk_score_v1: int = 0
    risk_score_v2: float = 0.0
    risk_level: Literal["low", "medium", "high", "critical"] = "low"
    findings_count: int = 0

    # Engine tracking
    enabled_engines: list[str] = Field(default_factory=list)
    tool_versions: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
