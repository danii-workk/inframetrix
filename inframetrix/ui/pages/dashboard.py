"""Dashboard Page showing project overview, risk gauge, and quick actions."""

from __future__ import annotations

try:
    from PySide6.QtCore import Qt, Signal
    from PySide6.QtWidgets import (
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QLabel,
        QPushButton,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    QWidget = object  # type: ignore[misc, assignment]
    Signal = lambda *args: None  # type: ignore[assignment]

from inframetrix.models.scan_session import ScanSession
from inframetrix.ui.widgets.risk_gauge import RiskGaugeWidget


class DashboardPage(QWidget):
    """Main dashboard overview for the active project."""

    scan_requested = Signal(str) if callable(Signal) else None  # "quick" or "full"
    stop_requested = Signal() if callable(Signal) else None

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        if hasattr(self, "setLayout"):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(20, 20, 20, 20)
            layout.setSpacing(20)

            # Top Header Bar
            header = QHBoxLayout()
            self.proj_title = QLabel("<h2>Project: None selected</h2>")
            header.addWidget(self.proj_title)
            header.addStretch()

            self.quick_scan_btn = QPushButton("⚡ Quick Scan")
            self.quick_scan_btn.clicked.connect(lambda: self.scan_requested.emit("quick") if self.scan_requested else None)

            self.full_scan_btn = QPushButton("🔍 Full Code Scan")
            self.full_scan_btn.setObjectName("btn-secondary")
            self.full_scan_btn.clicked.connect(lambda: self.scan_requested.emit("full") if self.scan_requested else None)

            self.stop_btn = QPushButton("⏹ Stop")
            self.stop_btn.setObjectName("btn-danger")
            self.stop_btn.setEnabled(False)
            self.stop_btn.clicked.connect(lambda: self.stop_requested.emit() if self.stop_requested else None)

            header.addWidget(self.quick_scan_btn)
            header.addWidget(self.full_scan_btn)
            header.addWidget(self.stop_btn)
            layout.addLayout(header)

            # Main Grid
            grid = QGridLayout()

            # Gauge Card
            gauge_card = QFrame()
            gauge_card.setStyleSheet("background: #1e293b; border-radius: 8px; padding: 15px;")
            g_layout = QVBoxLayout(gauge_card)
            g_title = QLabel("<h3>AppSec Risk Score</h3>")
            self.gauge = RiskGaugeWidget()
            g_layout.addWidget(g_title, alignment=Qt.AlignmentFlag.AlignCenter)
            g_layout.addWidget(self.gauge, alignment=Qt.AlignmentFlag.AlignCenter)
            grid.addWidget(gauge_card, 0, 0, 2, 1)

            # Metrics Cards
            self.crit_lbl = QLabel("0")
            self.high_lbl = QLabel("0")
            self.med_lbl = QLabel("0")
            self.low_lbl = QLabel("0")

            grid.addWidget(self._create_metric_card("Critical Findings", self.crit_lbl, "#ef4444"), 0, 1)
            grid.addWidget(self._create_metric_card("High Findings", self.high_lbl, "#f97316"), 0, 2)
            grid.addWidget(self._create_metric_card("Medium Findings", self.med_lbl, "#eab308"), 1, 1)
            grid.addWidget(self._create_metric_card("Low Findings", self.low_lbl, "#3b82f6"), 1, 2)

            layout.addLayout(grid)
            layout.addStretch()

    def _create_metric_card(self, title: str, val_lbl: QLabel, border_color: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet(f"background: #1e293b; border-left: 4px solid {border_color}; border-radius: 6px; padding: 15px;")
        l = QVBoxLayout(card)
        t_lbl = QLabel(title)
        t_lbl.setStyleSheet("color: #94a3b8; font-weight: bold;")
        val_lbl.setStyleSheet(f"color: {border_color}; font-size: 24px; font-weight: bold;")
        l.addWidget(t_lbl)
        l.addWidget(val_lbl)
        return card

    def update_dashboard(self, project_name: str, session: ScanSession | None, counts: dict[str, int]) -> None:
        if not hasattr(self, "proj_title"):
            return
        self.proj_title.setText(f"<h2>Project: {project_name}</h2>")
        if session:
            self.gauge.set_score(session.risk_score_v2 or session.risk_score_v1, session.risk_level)
        self.crit_lbl.setText(str(counts.get("critical", 0)))
        self.high_lbl.setText(str(counts.get("high", 0)))
        self.med_lbl.setText(str(counts.get("medium", 0)))
        self.low_lbl.setText(str(counts.get("low", 0)))
