"""Tool Console widget streaming execution logs."""

from __future__ import annotations

try:
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import (
        QHBoxLayout,
        QLabel,
        QPlainTextEdit,
        QPushButton,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    QWidget = object  # type: ignore[misc, assignment]


class ToolConsoleWidget(QWidget):
    """Collapsible developer console showing real-time tool logs."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        if hasattr(self, "setLayout"):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)

            # Header bar
            header = QHBoxLayout()
            self.title_lbl = QLabel("💻 Tool Console")
            self.title_lbl.setStyleSheet("font-weight: bold; color: #94a3b8;")
            self.clear_btn = QPushButton("Clear")
            self.clear_btn.setObjectName("btn-secondary")
            self.clear_btn.setMaximumWidth(80)
            self.clear_btn.clicked.connect(self.clear)

            header.addWidget(self.title_lbl)
            header.addStretch()
            header.addWidget(self.clear_btn)
            layout.addLayout(header)

            # Log Area
            self.log_area = QPlainTextEdit()
            self.log_area.setReadOnly(True)
            self.log_area.setMaximumHeight(150)
            font = QFont("Consolas, Courier New, monospace", 10)
            self.log_area.setFont(font)
            layout.addWidget(self.log_area)

    def append_log(self, text: str) -> None:
        if hasattr(self, "log_area"):
            self.log_area.appendPlainText(text)

    def clear(self) -> None:
        if hasattr(self, "log_area"):
            self.log_area.clear()
