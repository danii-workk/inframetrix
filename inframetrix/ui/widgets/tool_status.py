"""Tool status and scan progress indicators with install action triggers."""

from __future__ import annotations

try:
    from PySide6.QtCore import Signal
    from PySide6.QtWidgets import (
        QHBoxLayout,
        QLabel,
        QProgressBar,
        QPushButton,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    QWidget = object  # type: ignore[misc, assignment]
    Signal = lambda *args: None  # type: ignore[assignment]

from inframetrix.core.tool_registry import ToolStatus

INSTALLABLE_TOOLS = {"semgrep", "gitleaks", "osv-sca", "syft"}


class ToolStatusListWidget(QWidget):
    """Grid list of installed security engines with inline install actions."""

    install_tool_requested = Signal(str) if callable(Signal) else None  # tool_name

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        if hasattr(self, "setLayout"):
            self.layout = QVBoxLayout(self)
            self.layout.setContentsMargins(0, 0, 0, 0)
            self.layout.setSpacing(10)

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

            if not s.is_available and s.name in INSTALLABLE_TOOLS:
                btn = QPushButton("⬇️ Install")
                btn.setObjectName("btn-secondary")
                btn.setStyleSheet("padding: 4px 8px; font-size: 11px;")
                btn.clicked.connect(
                    lambda _, name=s.name: self.install_tool_requested.emit(name)
                    if self.install_tool_requested
                    else None
                )
                row.addWidget(btn)

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
