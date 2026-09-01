"""Unified Finding Model for InfraMetrix AppSec Workstation."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class Finding(BaseModel):
    """Unified security finding model representing vulnerabilities across all engines."""

    id: str
    fingerprint: str = ""
    title: str
    description: str | None = None
    message: str = ""
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    confidence: Literal["low", "medium", "high"] = "medium"
    category: str = "general"
    source_engine: str = "inframetrix-native"

    # Code location (SAST, Secrets)
    file_path: str | None = None
    line: int | None = None
    column: int | None = None

    # Web location (DAST, urlscan)
    url: str | None = None
    endpoint: str | None = None
    http_method: str | None = None

    # Dependency info (SCA, Supply Chain)
    package_name: str | None = None
    package_version: str | None = None

    # Security metadata
    cve: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    cvss: float | None = None
    epss: float | None = None

    evidence: str | None = None
    recommendation: str | None = None
    references: list[str] = Field(default_factory=list)

    # Lifecyle
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: Literal["open", "fixed", "suppressed", "false_positive", "accepted_risk"] = "open"
    suppression_reason: str | None = None

    # ML & Prioritization
    ml_fp_probability: float | None = None
    ml_priority_score: float | None = None
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _sync_message_and_description(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # If message is provided but not description, copy message to description
            if "message" in data and not data.get("description"):
                data["description"] = data["message"]
            elif "description" in data and not data.get("message"):
                data["message"] = data["description"]
        return data

    @model_validator(mode="after")
    def _compute_fingerprint_if_empty(self) -> Finding:
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()
        return self

    def compute_fingerprint(self) -> str:
        """Generate a deterministic SHA-256 fingerprint for finding deduplication & tracking."""
        components = [
            self.source_engine or "unknown",
            self.id or "",
            (self.file_path or "").replace("\\", "/"),
            str(self.line or ""),
            self.url or "",
            self.package_name or "",
            self.package_version or "",
            self.cve or "",
        ]
        raw_key = ":".join(components)
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]
