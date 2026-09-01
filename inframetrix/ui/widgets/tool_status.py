"""Tool status and scan progress indicators."""

from __future__ import annotations

try:
    from PySide6.QtWidgets import (
        QHBoxLayout,
        QLabel,
        QProgressBar,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    QWidget = object  # type: ignore[misc, assignment]

from inframetrix.core.tool_registry import ToolStatus


class ToolStatusListWidget(QWidget):
    """Grid list of installed security engines and readiness statuses."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        if hasattr(self, "setLayout"):
            self.layout = QVBoxLayout(self)
            self.layout.setContentsMargins(0, 0, 0, 0)

    def set_statuses(self, statuses: list[ToolStatus]) -> None:
        if not hasattr(self, "layout"):
            return

        # Clear existing
        while self.layout.count():
            item = self.layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for s in statuses:
            row = QHBoxLayout()
            name_lbl = QLabel(f"<strong>{s.name}</strong> ({s.category})")
            status_text = f"✓ {s.version or 'Ready'}" if s.is_available else "✗ Not Installed"
            color = "#10b981" if s.is_available else "#94a3b8"

            status_lbl = QLabel(status_text)
            status_lbl.setStyleSheet(f"color: {color}; font-weight: bold;")

            row.addWidget(name_lbl)
            row.addStretch()
            row.addWidget(status_lbl)
            self.layout.addLayout(row)


class ScanProgressWidget(QWidget):
    """Scan progress bar with active task description."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        if hasattr(self, "setLayout"):
            layout = QVBoxLayout(self)
            self.status_lbl = QLabel("Ready")
            self.pbar = QProgressBar()
            self.pbar.setRange(0, 100)
            self.pbar.setValue(0)
            layout.addWidget(self.status_lbl)
            layout.addWidget(self.pbar)

    def update_progress(self, message: str, percent: int) -> None:
        if hasattr(self, "status_lbl") and hasattr(self, "pbar"):
            self.status_lbl.setText(message)
            self.pbar.setValue(percent)
