"""Settings and Tool Manager Page."""

from __future__ import annotations

try:
    from PySide6.QtCore import Signal
    from PySide6.QtWidgets import (
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMessageBox,
        QPushButton,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    QWidget = object  # type: ignore[misc, assignment]
    Signal = lambda *args: None  # type: ignore[assignment]

from inframetrix.core.tool_registry import ToolRegistry
from inframetrix.security.secrets_store import SecretsStore
from inframetrix.ui.widgets.tool_status import ToolStatusListWidget


class SettingsPage(QWidget):
    """Settings page for configuring API keys and viewing security tool readiness."""

    tools_refreshed = Signal() if callable(Signal) else None

    def __init__(self, registry: ToolRegistry | None = None, parent=None) -> None:
        super().__init__(parent)
        self.registry = registry

        if hasattr(self, "setLayout"):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(20, 20, 20, 20)

            title = QLabel("<h2>Workstation Settings & Tools</h2>")
            layout.addWidget(title)

            # API Keys Group
            api_group = QGroupBox("API Keys & Credentials (Stored in OS Keyring)")
            api_layout = QVBoxLayout(api_group)

            # urlscan
            u_layout = QHBoxLayout()
            self.urlscan_input = QLineEdit()
            self.urlscan_input.setEchoMode(QLineEdit.EchoMode.Password)
            existing_urlscan = SecretsStore.get_secret("URLSCAN_API_KEY")
            if existing_urlscan:
                self.urlscan_input.setText(existing_urlscan)
            u_layout.addWidget(QLabel("urlscan.io API Key:"))
            u_layout.addWidget(self.urlscan_input)
            api_layout.addLayout(u_layout)

            # Gemini
            g_layout = QHBoxLayout()
            self.gemini_input = QLineEdit()
            self.gemini_input.setEchoMode(QLineEdit.EchoMode.Password)
            existing_gemini = SecretsStore.get_secret("GEMINI_API_KEY")
            if existing_gemini:
                self.gemini_input.setText(existing_gemini)
            g_layout.addWidget(QLabel("Gemini API Key (Optional AI Analyst):"))
            g_layout.addWidget(self.gemini_input)
            api_layout.addLayout(g_layout)

            save_btn = QPushButton("Save Credentials")
            save_btn.clicked.connect(self._save_credentials)
            api_layout.addWidget(save_btn)

            layout.addWidget(api_group)

            # Tools Status Group
            tools_group = QGroupBox("Security Scanning Engines")
            t_layout = QVBoxLayout(tools_group)

            self.status_list = ToolStatusListWidget()
            t_layout.addWidget(self.status_list)

            refresh_btn = QPushButton("🔄 Refresh Tool Status")
            refresh_btn.setObjectName("btn-secondary")
            refresh_btn.clicked.connect(self.refresh_tools)
            t_layout.addWidget(refresh_btn)

            layout.addWidget(tools_group)
            layout.addStretch()

    def refresh_tools(self) -> None:
        if self.registry and hasattr(self, "status_list"):
            statuses = self.registry.list_status()
            self.status_list.set_statuses(statuses)

    def _save_credentials(self) -> None:
        u_key = self.urlscan_input.text().strip()
        g_key = self.gemini_input.text().strip()

        if u_key:
            SecretsStore.set_secret("URLSCAN_API_KEY", u_key)
        if g_key:
            SecretsStore.set_secret("GEMINI_API_KEY", g_key)

        QMessageBox.information(self, "Settings Saved", "API credentials safely stored in OS Keyring.")
