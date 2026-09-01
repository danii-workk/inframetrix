"""Scan orchestrator coordinating parallel and sequential execution of security engines."""

from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime

from inframetrix.core.cancellation import CancellationToken
from inframetrix.core.events import EventBus, ScanEvent
from inframetrix.core.exceptions import ScanCancelledError
from inframetrix.core.scan_context import ScanContext
from inframetrix.core.tool_registry import ToolRegistry
from inframetrix.models.finding import Finding
from inframetrix.models.scan_result import ScanResult, ToolRun
from inframetrix.models.scan_session import ScanSession

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Orchestrates security engines, collects findings, and normalizes execution results."""

    def __init__(
        self,
        registry: ToolRegistry,
        event_bus: EventBus | None = None,
    ) -> None:
        self.registry = registry
        self.event_bus = event_bus or EventBus()

    def run_scan(
        self,
        context: ScanContext,
        cancellation_token: CancellationToken | None = None,
        on_finding_cb: Callable[[Finding], None] | None = None,
    ) -> tuple[ScanSession, list[Finding], list[ScanResult]]:
        """Run all enabled and available security adapters for the given scan context."""
        cancellation_token = cancellation_token or CancellationToken()

        session = ScanSession(
            id=context.session_id,
            project_id=context.project_id,
            preset=context.preset,
            status="running",
            started_at=datetime.now(UTC),
            enabled_engines=context.enabled_engines,
        )

        self.event_bus.publish(
            ScanEvent(
                event_type="scan_started",
                session_id=session.id,
                message=f"Starting scan with preset '{context.preset}' on '{context.project_path.name}'",
                data={"preset": context.preset, "path": str(context.project_path)},
            )
        )

        # Select matching adapters
        target_adapters = []
        for engine_name in context.enabled_engines:
            adapter = self.registry.get(engine_name)
            if adapter and adapter.available():
                target_adapters.append(adapter)
            else:
                self.event_bus.publish(
                    ScanEvent(
                        event_type="log_message",
                        session_id=session.id,
                        tool_name=engine_name,
                        message=f"Engine '{engine_name}' is not installed or unavailable. Skipping.",
                    )
                )

        all_findings: list[Finding] = []
        scan_results: list[ScanResult] = []
        tool_versions: dict[str, str] = {}

        if cancellation_token.is_cancelled:
            session.status = "cancelled"
            session.finished_at = datetime.now(UTC)
            self.event_bus.publish(
                ScanEvent(
                    event_type="scan_cancelled",
                    session_id=session.id,
                    message="Scan was cancelled by user request.",
                )
            )
            raise ScanCancelledError("Scan was aborted.")

        max_workers = min(len(target_adapters) or 1, 4)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_adapter = {
                executor.submit(
                    self._run_adapter_safely,
                    adapter,
                    context,
                    cancellation_token,
                ): adapter
                for adapter in target_adapters
            }

            for future in as_completed(future_to_adapter):
                adapter = future_to_adapter[future]
                if cancellation_token.is_cancelled:
                    continue

                try:
                    result = future.result()
                    scan_results.append(result)
                    if result.tool_run and result.tool_run.tool_version:
                        tool_versions[adapter.name] = result.tool_run.tool_version

                    for f in result.findings:
                        all_findings.append(f)
                        if on_finding_cb:
                            on_finding_cb(f)
                        self.event_bus.publish(
                            ScanEvent(
                                event_type="finding_discovered",
                                session_id=session.id,
                                tool_name=adapter.name,
                                message=f"Discovered: [{f.severity.upper()}] {f.title}",
                                data={"finding_id": f.id, "severity": f.severity, "file": f.file_path},
                            )
                        )
                except Exception:
                    logger.exception(f"Unexpected error executing adapter {adapter.name}")
                    scan_results.append(
                        ScanResult(
                            engine_name=adapter.name,
                            findings=[],
                            tool_run=ToolRun(
                                tool_name=adapter.name,
                                status="failed",
                                error_message="Adapter execution error",
                            ),
                        )
                    )

        if cancellation_token.is_cancelled:
            session.status = "cancelled"
            session.finished_at = datetime.now(UTC)
            self.event_bus.publish(
                ScanEvent(
                    event_type="scan_cancelled",
                    session_id=session.id,
                    message="Scan was cancelled by user request.",
                )
            )
            raise ScanCancelledError("Scan was aborted.")

        session.status = "completed"
        session.finished_at = datetime.now(UTC)
        session.findings_count = len(all_findings)
        session.tool_versions = tool_versions

        self.event_bus.publish(
            ScanEvent(
                event_type="scan_completed",
                session_id=session.id,
                message=f"Scan completed. Discovered {len(all_findings)} finding(s).",
                data={"findings_count": len(all_findings)},
            )
        )

        return session, all_findings, scan_results

    def _run_adapter_safely(
        self,
        adapter,
        context: ScanContext,
        cancellation_token: CancellationToken,
    ) -> ScanResult:
        """Safely execute an adapter with lifecycle events and exception handling."""
        self.event_bus.publish(
            ScanEvent(
                event_type="tool_started",
                session_id=context.session_id,
                tool_name=adapter.name,
                message=f"Running {adapter.name}...",
            )
        )

        started_at = datetime.now(UTC)
        try:
            result = adapter.scan(context, cancellation_token)
            if not result.tool_run:
                result.tool_run = ToolRun(
                    tool_name=adapter.name,
                    tool_version=adapter.version(),
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                    status="completed",
                )
            self.event_bus.publish(
                ScanEvent(
                    event_type="tool_completed",
                    session_id=context.session_id,
                    tool_name=adapter.name,
                    message=f"{adapter.name} completed successfully ({len(result.findings)} findings).",
                    data={"count": len(result.findings)},
                )
            )
            return result
        except Exception as exc:  # noqa: BLE001
            self.event_bus.publish(
                ScanEvent(
                    event_type="tool_failed",
                    session_id=context.session_id,
                    tool_name=adapter.name,
                    message=f"{adapter.name} failed: {exc}",
                    data={"error": str(exc)},
                )
            )
            return ScanResult(
                engine_name=adapter.name,
                findings=[],
                tool_run=ToolRun(
                    tool_name=adapter.name,
                    tool_version=adapter.version(),
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                    status="failed",
                    error_message=str(exc),
                ),
            )
