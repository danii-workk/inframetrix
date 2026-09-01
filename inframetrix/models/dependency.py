"""Dependency graph node models for SCA & SBOM analysis."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class DependencyNode(BaseModel):
    """A single software dependency in the project graph."""

    name: str
    version: str
    ecosystem: str  # npm, pypi, go, cargo, maven, etc.
    direct: bool = True
    development_only: bool = False
    license: str = "UNKNOWN"
    license_risk: Literal["permissive", "weak-copyleft", "strong-copyleft", "proprietary", "unknown"] = "unknown"
    purl: str | None = None
    manifest_path: str | None = None
    dependencies: list[str] = Field(default_factory=list)  # list of child package names
    vulnerability_ids: list[str] = Field(default_factory=list)  # CVE / GHSA list
