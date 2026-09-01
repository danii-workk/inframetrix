"""Gitleaks adapter for deep secret scanning."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from inframetrix.core.cancellation import CancellationToken
from inframetrix.core.scan_context import ScanContext
from inframetrix.models.finding import Finding
from inframetrix.models.scan_result import ScanResult, ToolRun
from inframetrix.security.redaction import RedactionService
from inframetrix.security.subprocess_policy import SecureProcessRunner


class GitleaksAdapter:
    """Specialized secret scanner adapter wrapping Gitleaks CLI."""

    name = "gitleaks"
    category = "secrets"
    is_builtin = False
    install_hint = "Install with: brew install gitleaks or download from github.com/gitleaks/gitleaks/releases."

    def __init__(self) -> None:
        self.runner = SecureProcessRunner(default_timeout=300)

    def available(self) -> bool:
        return shutil.which("gitleaks") is not None

    def version(self) -> str | None:
        if not self.available():
            return None
        res = self.runner.run(["gitleaks", "version"])
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
                    error_message="gitleaks executable not found in PATH",
                ),
            )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            res = self.runner.run(
                [
                    "gitleaks",
                    "detect",
                    "--no-git",
                    "--source",
                    str(context.project_path),
                    "--report-format",
                    "json",
                    "--report-path",
                    str(tmp_path),
                ],
                cancellation_token=cancellation_token,
            )

            findings: list[Finding] = []
            if tmp_path.is_file() and tmp_path.stat().st_size > 0:
                try:
                    data = json.loads(tmp_path.read_text(encoding="utf-8"))
                    for entry in data:
                        rule_id = entry.get("RuleID", "generic-secret")
                        desc = entry.get("Description", "Secret detected")
                        file_path = entry.get("File", "")
                        start_line = entry.get("StartLine")
                        secret_val = entry.get("Secret", "")
                        masked = RedactionService.mask_secret(secret_val)

                        findings.append(
                            Finding(
                                id=f"gitleaks-{rule_id.lower()}",
                                title=f"Gitleaks: {desc}",
                                description=f"Secret match ({rule_id}) found in {file_path}",
                                message=f"Secret: {masked}",
                                severity="critical",
                                confidence="high",
                                category="secrets",
                                source_engine=self.name,
                                file_path=file_path,
                                line=start_line,
                                recommendation="Revoke and rotate the exposed secret immediately.",
                                tags=["secrets", "gitleaks"],
                            )
                        )
                except Exception:  # noqa: BLE001, S110
                    pass

            return ScanResult(
                engine_name=self.name,
                findings=findings,
                tool_run=ToolRun(
                    tool_name=self.name,
                    tool_version=self.version(),
                    exit_code=res.exit_code,
                    stdout=res.stdout,
                    stderr=res.stderr,
                    status="completed",
                ),
            )
        finally:
            if tmp_path.exists():
                tmp_path.unlink()
