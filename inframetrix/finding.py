"""Pydantic model for scan findings."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class Finding(BaseModel):
    id: str
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    category: str
    file_path: str
    line: int | None = None
    message: str
    recommendation: str | None = None
    confidence: Literal["low", "medium", "high"] = "medium"