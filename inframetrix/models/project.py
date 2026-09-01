"""Project metadata model for InfraMetrix workspace."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field


class Project(BaseModel):
    """A target project registered in the InfraMetrix workspace."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    root_path: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
