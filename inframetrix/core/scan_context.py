"""Scan execution context and configuration presets."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class PresetConfig:
    """Configuration for predefined scan profiles."""

    name: str
    description: str
    enabled_engines: list[str]
    max_concurrency: int = 4
    timeout_seconds: int = 300


PRESETS: dict[str, PresetConfig] = {
    "quick": PresetConfig(
        name="quick",
        description="Fast offline scan: Native SAST, Secrets, Manifests, Infrastructure",
        enabled_engines=["native-sast", "native-secrets", "supply-chain"],
        max_concurrency=4,
        timeout_seconds=60,
    ),
    "full": PresetConfig(
        name="full",
        description="Comprehensive scan: Native SAST, Semgrep, Secrets, SCA, Supply Chain, SBOM, ML Triage",
        enabled_engines=[
            "native-sast",
            "semgrep",
            "gitleaks",
            "osv-sca",
            "supply-chain",
            "sbom",
        ],
        max_concurrency=4,
        timeout_seconds=600,
    ),
    "web": PresetConfig(
        name="web",
        description="Full code scan + passive DAST & URL analysis for authorized targets",
        enabled_engines=[
            "native-sast",
            "semgrep",
            "gitleaks",
            "osv-sca",
            "supply-chain",
            "sbom",
            "zap-dast",
            "urlscan",
        ],
        max_concurrency=4,
        timeout_seconds=900,
    ),
}


@dataclass
class ScanContext:
    """Full execution context supplied to the ScanOrchestrator."""

    project_path: Path
    project_id: str
    session_id: str
    preset: str = "quick"
    enabled_engines: list[str] = field(default_factory=list)
    custom_rules_path: Path | None = None
    target_url: str | None = None
    options: dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 300

    def __post_init__(self) -> None:
        self.project_path = self.project_path.resolve()
        if not self.enabled_engines:
            preset_config = PRESETS.get(self.preset, PRESETS["quick"])
            self.enabled_engines = list(preset_config.enabled_engines)
