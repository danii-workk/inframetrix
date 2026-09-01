"""Semgrep SAST adapter for advanced AST and rule-based code scanning."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from inframetrix.core.cancellation import CancellationToken
from inframetrix.core.scan_context import ScanContext
from inframetrix.models.finding import Finding
from inframetrix.models.scan_result import ScanResult, ToolRun
from inframetrix.security.subprocess_policy import SecureProcessRunner


class SemgrepAdapter:
    """Advanced AST-aware SAST scanner wrapping Semgrep CLI."""

    name = "semgrep"
    category = "sast"
    is_builtin = False
    install_hint = "Install with: pip install semgrep or brew install semgrep."

    def __init__(self) -> None:
        self.runner = SecureProcessRunner(default_timeout=600)

    def available(self) -> bool:
        return shutil.which("semgrep") is not None

    def version(self) -> str | None:
        if not self.available():
            return None
        res = self.runner.run(["semgrep", "--version"])
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
                    error_message="semgrep executable not found in PATH",
                ),
            )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            res = self.runner.run(
                [
                    "semgrep",
                    "scan",
                    "--config",
                    "auto",
                    "--json",
                    "--output",
                    str(tmp_path),
                    str(context.project_path),
                ],
                cancellation_token=cancellation_token,
            )

            findings: list[Finding] = []
            if tmp_path.is_file() and tmp_path.stat().st_size > 0:
                try:
                    data = json.loads(tmp_path.read_text(encoding="utf-8"))
                    results = data.get("results", [])
                    for r in results:
                        check_id = r.get("check_id", "semgrep-rule")
                        path_str = r.get("path", "")
                        start = r.get("start", {})
                        line_num = start.get("line")
                        col_num = start.get("col")
                        extra = r.get("extra", {})
                        message = extra.get("message", "Semgrep security finding")
                        severity_raw = extra.get("severity", "WARNING").lower()

                        sev_map = {
                            "error": "high",
                            "warning": "medium",
                            "info": "low",
                            "critical": "critical",
                        }
                        severity = sev_map.get(severity_raw, "medium")

                        metadata = extra.get("metadata", {})
                        cwe = metadata.get("cwe")
                        if isinstance(cwe, list):
                            cwe = ", ".join(cwe)

                        owasp = metadata.get("owasp")
                        if isinstance(owasp, list):
                            owasp = ", ".join(owasp)

                        findings.append(
                            Finding(
                                id=f"semgrep-{check_id.lower().replace('.', '-')}",
                                title=f"Semgrep: {check_id.split('.')[-1]}",
                                description=message,
                                message=message,
                                severity=severity,  # type: ignore[arg-type]
                                confidence="high",
                                category="sast",
                                source_engine=self.name,
                                file_path=path_str,
                                line=line_num,
                                column=col_num,
                                cwe=str(cwe) if cwe else None,
                                owasp=str(owasp) if owasp else None,
                                recommendation=extra.get("fix") or "Review and patch the flagged code construct.",
                                tags=["sast", "semgrep"],
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
