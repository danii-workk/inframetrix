"""Artifact model for scan-generated files (SBOM, HTML, SARIF, screenshots)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field


class Artifact(BaseModel):
    """A file generated during scan execution."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    artifact_type: str  # sbom-cyclonedx, sbom-spdx, sarif, html, screenshot, raw-log
    file_path: str
    content_type: str = "application/octet-stream"
    size_bytes: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
