"""Normalized scan result returned by individual scanner adapters."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from inframetrix.models.finding import Finding


class ToolRun(BaseModel):
    """Execution telemetry for a single scanner adapter."""

    tool_name: str
    tool_version: str | None = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    error_message: str | None = None
    status: str = "completed"


class ScanResult(BaseModel):
    """Aggregate result from a scanner adapter execution."""

    engine_name: str
    findings: list[Finding] = Field(default_factory=list)
    tool_run: ToolRun | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
