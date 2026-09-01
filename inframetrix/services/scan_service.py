"""ScanService coordinating project scans, database persistence, and scoring."""

from __future__ import annotations

import uuid
from pathlib import Path

from inframetrix.core.cancellation import CancellationToken
from inframetrix.core.events import EventBus
from inframetrix.core.orchestrator import ScanOrchestrator
from inframetrix.core.scan_context import ScanContext
from inframetrix.core.tool_registry import ToolRegistry
from inframetrix.engines.native.adapter import NativeScannerAdapter
from inframetrix.models.finding import Finding
from inframetrix.models.project import Project
from inframetrix.models.scan_session import ScanSession
from inframetrix.scoring.legacy import calculate_risk_score
from inframetrix.scoring.risk_v2 import calculate_risk_score_v2
from inframetrix.storage.database import DatabaseManager
from inframetrix.storage.repositories.finding_repo import FindingRepository
from inframetrix.storage.repositories.project_repo import ProjectRepository
from inframetrix.storage.repositories.session_repo import SessionRepository


class ScanService:
    """High-level application service for launching scans and managing findings."""

    def __init__(
        self,
        db: DatabaseManager | None = None,
        registry: ToolRegistry | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self.db = db or DatabaseManager()
        self.project_repo = ProjectRepository(self.db)
        self.session_repo = SessionRepository(self.db)
        self.finding_repo = FindingRepository(self.db)

        self.event_bus = event_bus or EventBus()
        self.registry = registry or self._build_default_registry()
        self.orchestrator = ScanOrchestrator(self.registry, self.event_bus)

    @staticmethod
    def _build_default_registry() -> ToolRegistry:
        registry = ToolRegistry()
        registry.register(NativeScannerAdapter())
        return registry

    def scan_project(
        self,
        project_path: Path,
        preset: str = "quick",
        custom_rules_path: Path | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> tuple[ScanSession, list[Finding]]:
        """Run a full orchestrated scan session and persist results in SQLite."""
        project_path = project_path.resolve()

        # 1. Ensure project is registered in DB
        project = self.project_repo.get_by_path(str(project_path))
        if not project:
            project = Project(
                id=str(uuid.uuid4()),
                name=project_path.name,
                root_path=str(project_path),
            )
            self.project_repo.save(project)

        # 2. Build scan context
        session_id = str(uuid.uuid4())
        context = ScanContext(
            project_path=project_path,
            project_id=project.id,
            session_id=session_id,
            preset=preset,
            custom_rules_path=custom_rules_path,
        )

        # 3. Execute scan via orchestrator
        session, findings, _results = self.orchestrator.run_scan(
            context=context,
            cancellation_token=cancellation_token,
        )

        # 4. Calculate Risk Scores
        score_v1, level_v1 = calculate_risk_score(findings)
        score_v2, _ = calculate_risk_score_v2(findings)

        session.risk_score_v1 = score_v1
        session.risk_score_v2 = score_v2
        session.risk_level = level_v1  # type: ignore[assignment]
        session.findings_count = len(findings)

        # 5. Persist to DB
        self.session_repo.save(session)
        self.finding_repo.save_many(findings, project_id=project.id, session_id=session.id)

        return session, findings
