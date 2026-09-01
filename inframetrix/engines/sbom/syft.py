"""Syft SBOM generation adapter."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from inframetrix.core.cancellation import CancellationToken
from inframetrix.core.scan_context import ScanContext
from inframetrix.models.scan_result import ScanResult, ToolRun
from inframetrix.security.subprocess_policy import SecureProcessRunner


class SyftAdapter:
    """SBOM generation adapter wrapping Anchore Syft CLI."""

    name = "syft"
    category = "sbom"
    is_builtin = False
    install_hint = "Install with: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin or brew install syft."

    def __init__(self) -> None:
        self.runner = SecureProcessRunner(default_timeout=300)

    def available(self) -> bool:
        return shutil.which("syft") is not None

    def version(self) -> str | None:
        if not self.available():
            return None
        res = self.runner.run(["syft", "version"])
        return res.stdout.strip() if res.exit_code == 0 else None

    def scan(
        self,
        context: ScanContext,
        cancellation_token: CancellationToken | None = None,
    ) -> ScanResult:
        if not self.available():
            return ScanResult(
                engine_name=self.name,
                findings=[],
                tool_run=ToolRun(
                    tool_name=self.name,
                    status="unavailable",
                    error_message="syft executable not found in PATH",
                ),
            )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            res = self.runner.run(
                [
                    "syft",
                    f"dir:{context.project_path}",
                    "-o",
                    f"cyclonedx-json={tmp_path}",
                ],
                cancellation_token=cancellation_token,
            )

            metadata = {}
            if tmp_path.is_file() and tmp_path.stat().st_size > 0:
                try:
                    sbom_json = json.loads(tmp_path.read_text(encoding="utf-8"))
                    components = sbom_json.get("components", [])
                    metadata["components_count"] = len(components)
                except Exception:  # noqa: BLE001, S110
                    pass

            return ScanResult(
                engine_name=self.name,
                findings=[],
                tool_run=ToolRun(
                    tool_name=self.name,
                    tool_version=self.version(),
                    exit_code=res.exit_code,
                    stdout=res.stdout,
                    stderr=res.stderr,
                    status="completed",
                ),
                metadata=metadata,
            )
        finally:
            if tmp_path.exists():
                tmp_path.unlink()
