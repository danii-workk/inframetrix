"""Tests for ScanOrchestrator and CancellationToken."""

from pathlib import Path

import pytest

from inframetrix.core.cancellation import CancellationToken
from inframetrix.core.events import EventBus, ScanEvent
from inframetrix.core.exceptions import ScanCancelledError
from inframetrix.core.orchestrator import ScanOrchestrator
from inframetrix.core.scan_context import ScanContext
from inframetrix.core.tool_registry import ToolRegistry
from inframetrix.engines.native.adapter import NativeScannerAdapter
from inframetrix.models.finding import Finding
from inframetrix.models.scan_result import ScanResult


class DummyMockAdapter:
    name = "mock-scanner"
    category = "sast"
    is_builtin = False

    def available(self) -> bool:
        return True

    def version(self) -> str:
        return "1.0.0"

    def scan(self, context: ScanContext, cancellation_token: CancellationToken | None = None) -> ScanResult:
        finding = Finding(
            id="mock-vuln",
            title="Mock Vulnerability",
            severity="medium",
            file_path="mock.py",
            source_engine=self.name,
        )
        return ScanResult(engine_name=self.name, findings=[finding])


def test_orchestrator_execution(tmp_path: Path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    registry = ToolRegistry()
    registry.register(NativeScannerAdapter())
    registry.register(DummyMockAdapter())

    events: list[ScanEvent] = []
    event_bus = EventBus()
    event_bus.subscribe(events.append)

    orchestrator = ScanOrchestrator(registry=registry, event_bus=event_bus)

    context = ScanContext(
        project_path=tmp_path,
        project_id="test-proj",
        session_id="test-sess",
        enabled_engines=["native-sast", "mock-scanner"],
    )

    session, findings, results = orchestrator.run_scan(context)

    assert session.status == "completed"
    assert len(results) == 2
    assert any(f.id == "mock-vuln" for f in findings)
    assert any(e.event_type == "scan_completed" for e in events)


def test_orchestrator_cancellation(tmp_path: Path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    registry = ToolRegistry()
    registry.register(NativeScannerAdapter())

    token = CancellationToken()
    token.cancel()

    orchestrator = ScanOrchestrator(registry=registry)
    context = ScanContext(
        project_path=tmp_path,
        project_id="test-proj",
        session_id="test-sess",
        enabled_engines=["native-sast"],
    )

    with pytest.raises(ScanCancelledError):
        orchestrator.run_scan(context, cancellation_token=token)
