"""Pydantic models for YAML-defined scan rules."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class Rule(BaseModel):
    """A single detection rule loaded from YAML."""

    id: str
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    category: str
    patterns: list[str] = []
    file_patterns: list[str] = []
    message: str = ""
    recommendation: str | None = None
    confidence: Literal["low", "medium", "high"] = "medium"
    match_mode: Literal["contains", "case_insensitive_contains"] = "contains"
    languages: list[str] = []


class Ruleset(BaseModel):
    """Top-level YAML structure for a ruleset file."""

    rules: list[Rule] = []