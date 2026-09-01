"""Main Desktop Workstation Window for InfraMetrix."""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from PySide6.QtCore import QObject, QThread, Signal, Slot
    from PySide6.QtWidgets import (
        QFrame,
        QHBoxLayout,
        QLabel,
        QMainWindow,
        QPushButton,
        QStackedWidget,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    QMainWindow = object  # type: ignore[misc, assignment]
    QThread = object  # type: ignore[misc, assignment]
    QObject = object  # type: ignore[misc, assignment]
    Signal = lambda *args: None  # type: ignore[assignment]
    Slot = lambda *args: lambda f: f  # type: ignore[assignment]

from inframetrix.core.cancellation import CancellationToken
from inframetrix.core.events import EventBus, ScanEvent
from inframetrix.core.tool_registry import ToolRegistry
from inframetrix.engines.dast.zap import ZAPAdapter
from inframetrix.engines.native.adapter import NativeScannerAdapter
from inframetrix.engines.sast.semgrep import SemgrepAdapter
from inframetrix.engines.sbom.syft import SyftAdapter
from inframetrix.engines.sca.osv import OSVScannerAdapter
from inframetrix.engines.secrets.gitleaks import GitleaksAdapter
from inframetrix.engines.secrets.native_secrets import NativeSecretsAdapter
from inframetrix.engines.supply_chain.analyzer import SupplyChainAdapter
from inframetrix.models.finding import Finding
from inframetrix.models.project import Project
from inframetrix.models.scan_session import ScanSession
from inframetrix.services.project_service import ProjectService
from inframetrix.services.replay_service import ReplayService
from inframetrix.services.scan_service import ScanService
from inframetrix.storage.database import DatabaseManager
from inframetrix.ui.pages.dashboard import DashboardPage
from inframetrix.ui.pages.dast import DASTPage
from inframetrix.ui.pages.dependencies import DependenciesPage
from inframetrix.ui.pages.findings import FindingsPage
from inframetrix.ui.pages.hash_audit import HashAuditPage
from inframetrix.ui.pages.project import ProjectPage
from inframetrix.ui.pages.replay import ReplayPage
from inframetrix.ui.pages.reports import ReportsPage
from inframetrix.ui.pages.sast import SASTPage
from inframetrix.ui.pages.settings import SettingsPage
from inframetrix.ui.pages.supply_chain import SupplyChainPage
from inframetrix.ui.pages.urlscan import URLScanPage
from inframetrix.ui.theme import DARK_STYLE
from inframetrix.ui.widgets.tool_console import ToolConsoleWidget


class ScanWorker(QThread):
    """Background scanning thread executing scan orchestration without blocking UI."""

    scan_finished = Signal(object, list) if callable(Signal) else None  # (session, findings)
    scan_failed = Signal(str) if callable(Signal) else None

    def __init__(
        self,
        scan_service: ScanService,
        project_path: Path,
        preset: str,
        token: CancellationToken,
    ) -> None:
        super().__init__()
        self.scan_service = scan_service
        self.project_path = project_path
        self.preset = preset
        self.token = token

    def run(self) -> None:
        try:
            session, findings = self.scan_service.scan_project(
                project_path=self.project_path,
                preset=self.preset,
                cancellation_token=self.token,
            )
            if self.scan_finished:
                self.scan_finished.emit(session, findings)
        except Exception as exc:  # noqa: BLE001
            if self.scan_failed:
                self.scan_failed.emit(str(exc))


class MainWindow(QMainWindow):
    """InfraMetrix AppSec Workstation Main Window."""

    def __init__(self, initial_project: str | None = None) -> None:
        super().__init__()
        self.setWindowTitle("InfraMetrix — Local Application Security Workstation")
        self.resize(1300, 850)

        # 1. Initialize Core Services
        self.db = DatabaseManager()
        self.event_bus = EventBus()
        self.event_bus.subscribe(self._on_scan_event)

        self.registry = self._build_tool_registry()
        self.scan_service = ScanService(db=self.db, registry=self.registry, event_bus=self.event_bus)
        self.project_service = ProjectService(db=self.db)
        self.replay_service = ReplayService(db=self.db)

        self.active_project: Project | None = None
        self.current_session: ScanSession | None = None
        self.current_findings: list[Finding] = []
        self.scan_worker: ScanWorker | None = None
        self.cancellation_token = CancellationToken()

        # 2. Setup UI layout
        self.setStyleSheet(DARK_STYLE)
        self._init_ui()

        # 3. Load initial or default project
        if initial_project:
            self.load_project(initial_project)
        else:
            projects = self.project_service.list_projects()
            if projects:
                self.load_project(projects[0].root_path)

    def _build_tool_registry(self) -> ToolRegistry:
        reg = ToolRegistry()
        reg.register(NativeScannerAdapter())
        reg.register(NativeSecretsAdapter())
        reg.register(SupplyChainAdapter())
        reg.register(SemgrepAdapter())
        reg.register(GitleaksAdapter())
        reg.register(OSVScannerAdapter())
        reg.register(SyftAdapter())
        reg.register(ZAPAdapter())
        return reg

    def _init_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Sidebar
        sidebar = QFrame()
        sidebar.setStyleSheet("background-color: #0b1120; border-right: 1px solid #1e293b;")
        sidebar.setFixedWidth(200)
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(10, 20, 10, 20)
        sb_layout.setSpacing(6)

        logo = QLabel("🛡️ InfraMetrix")
        logo.setStyleSheet("font-size: 16px; font-weight: bold; color: #6366f1; margin-bottom: 15px;")
        sb_layout.addWidget(logo)

        self.nav_buttons = {}
        pages_nav = [
            ("Dashboard", 0),
            ("Projects", 1),
            ("Findings", 2),
            ("SAST", 3),
            ("Dependencies", 4),
            ("Supply Chain", 5),
            ("DAST", 6),
            ("urlscan.io", 7),
            ("Hash Audit", 8),
            ("Code Replay", 9),
            ("Reports", 10),
            ("Settings", 11),
        ]

        for title, idx in pages_nav:
            btn = QPushButton(title)
            btn.setObjectName("btn-secondary")
            btn.setStyleSheet("text-align: left; padding: 8px 12px;")
            btn.clicked.connect(lambda _, i=idx: self.stack.setCurrentIndex(i))
            sb_layout.addWidget(btn)
            self.nav_buttons[title] = btn

        sb_layout.addStretch()
        main_layout.addWidget(sidebar)

        # Right Content Area
        right_content = QWidget()
        right_layout = QVBoxLayout(right_content)
        right_layout.setContentsMargins(0, 0, 0, 0)

        # Stacked Pages
        self.stack: Any = QStackedWidget()

        # Instantiate Pages
        self.dashboard_page = DashboardPage()
        if self.dashboard_page.scan_requested:
            self.dashboard_page.scan_requested.connect(self.start_scan)
        if self.dashboard_page.stop_requested:
            self.dashboard_page.stop_requested.connect(self.stop_scan)

        self.project_page = ProjectPage()
        if self.project_page.project_selected:
            self.project_page.project_selected.connect(self.load_project)

        self.findings_page = FindingsPage()
        if self.findings_page.status_changed:
            self.findings_page.status_changed.connect(self._on_finding_status_changed)

        self.sast_page = SASTPage()
        self.deps_page = DependenciesPage()
        self.sc_page = SupplyChainPage()
        self.dast_page = DASTPage()
        self.urlscan_page = URLScanPage()
        self.hash_page = HashAuditPage()
        self.replay_page = ReplayPage()
        self.reports_page = ReportsPage()
        self.settings_page = SettingsPage(registry=self.registry)

        self.stack.addWidget(self.dashboard_page)  # 0
        self.stack.addWidget(self.project_page)    # 1
        self.stack.addWidget(self.findings_page)   # 2
        self.stack.addWidget(self.sast_page)       # 3
        self.stack.addWidget(self.deps_page)       # 4
        self.stack.addWidget(self.sc_page)         # 5
        self.stack.addWidget(self.dast_page)       # 6
        self.stack.addWidget(self.urlscan_page)    # 7
        self.stack.addWidget(self.hash_page)       # 8
        self.stack.addWidget(self.replay_page)     # 9
        self.stack.addWidget(self.reports_page)    # 10
        self.stack.addWidget(self.settings_page)   # 11

        right_layout.addWidget(self.stack, stretch=1)

        # Tool Console (Bottom Collapsible)
        self.tool_console = ToolConsoleWidget()
        right_layout.addWidget(self.tool_console)

        main_layout.addWidget(right_content)

    def load_project(self, root_path_str: str) -> None:
        p = Path(root_path_str).resolve()
        if not p.is_dir():
            return

        self.active_project = self.project_service.register_project(p)
        self.project_page.set_projects(self.project_service.list_projects())

        # Load recent session findings from DB
        sessions = self.scan_service.session_repo.list_by_project(self.active_project.id, limit=1)
        if sessions:
            self.current_session = sessions[0]
            self.current_findings = self.scan_service.finding_repo.list_by_session(self.current_session.id)
        else:
            self.current_session = None
            self.current_findings = []

        self._refresh_all_views()
        self.tool_console.append_log(f"[*] Loaded project: {self.active_project.name} ({p})")

    def start_scan(self, preset: str = "quick") -> None:
        if not self.active_project:
            return

        self.cancellation_token = CancellationToken()
        self.dashboard_page.quick_scan_btn.setEnabled(False)
        self.dashboard_page.full_scan_btn.setEnabled(False)
        self.dashboard_page.stop_btn.setEnabled(True)

        self.scan_worker = ScanWorker(
            scan_service=self.scan_service,
            project_path=Path(self.active_project.root_path),
            preset=preset,
            token=self.cancellation_token,
        )
        if self.scan_worker.scan_finished:
            self.scan_worker.scan_finished.connect(self._on_scan_finished)
        if self.scan_worker.scan_failed:
            self.scan_worker.scan_failed.connect(self._on_scan_failed)
        self.scan_worker.start()

    def stop_scan(self) -> None:
        if self.cancellation_token:
            self.cancellation_token.cancel()
            self.tool_console.append_log("[!] Scan cancellation requested.")

    def _on_scan_finished(self, session: ScanSession, findings: list[Finding]) -> None:
        self.current_session = session
        self.current_findings = findings
        self.dashboard_page.quick_scan_btn.setEnabled(True)
        self.dashboard_page.full_scan_btn.setEnabled(True)
        self.dashboard_page.stop_btn.setEnabled(False)

        self._refresh_all_views()

    def _on_scan_failed(self, err_msg: str) -> None:
        self.dashboard_page.quick_scan_btn.setEnabled(True)
        self.dashboard_page.full_scan_btn.setEnabled(True)
        self.dashboard_page.stop_btn.setEnabled(False)
        self.tool_console.append_log(f"[ERROR] Scan failed: {err_msg}")

    def _on_finding_status_changed(self, finding_id: str, new_status: str) -> None:
        if self.active_project:
            self.scan_service.finding_repo.update_status(finding_id, status=new_status)
            self._refresh_all_views()

    def _on_scan_event(self, event: ScanEvent) -> None:
        msg = f"[{event.event_type.upper()}] {event.message}"
        self.tool_console.append_log(msg)

    def _refresh_all_views(self) -> None:
        name = self.active_project.name if self.active_project else "None"
        counts: dict[str, int] = {}
        for f in self.current_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        self.dashboard_page.update_dashboard(name, self.current_session, counts)
        self.findings_page.set_findings(self.current_findings)
        self.sast_page.set_findings(self.current_findings)
        self.deps_page.set_findings(self.current_findings)
        self.sc_page.set_findings(self.current_findings)
        self.dast_page.set_findings(self.current_findings)
        self.urlscan_page.set_findings(self.current_findings)

        # Update Reports Data
        report_dict = {
            "project": name,
            "path": self.active_project.root_path if self.active_project else "",
            "risk_score": self.current_session.risk_score_v1 if self.current_session else 0,
            "risk_level": self.current_session.risk_level if self.current_session else "low",
            "findings": self.current_findings,
        }
        self.reports_page.set_report_data(report_dict)

        # Replay events
        if self.active_project:
            events = self.replay_service.get_timeline(self.active_project.id)
            self.replay_page.set_events(events)

        self.settings_page.refresh_tools()
