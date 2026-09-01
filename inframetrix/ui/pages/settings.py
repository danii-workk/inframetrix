"""Settings, API keys, and Automated Tool Downloader Page."""

from __future__ import annotations

try:
    from PySide6.QtCore import QThread, Signal
    from PySide6.QtWidgets import (
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMessageBox,
        QProgressBar,
        QPushButton,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    QWidget = object  # type: ignore[misc, assignment]
    QThread = object  # type: ignore[misc, assignment]
    Signal = lambda *args: None  # type: ignore[assignment]

from inframetrix.core.tool_registry import ToolRegistry
from inframetrix.security.secrets_store import SecretsStore
from inframetrix.services.tool_installer import ToolInstallerService, ensure_bin_in_path
from inframetrix.ui.widgets.tool_status import ToolStatusListWidget


class ToolInstallWorker(QThread):
    """Background worker thread downloading and installing tools without freezing GUI."""

    progress_updated = Signal(int, str) if callable(Signal) else None  # percent, message
    install_finished = Signal(bool, str) if callable(Signal) else None  # success, summary

    def __init__(self, tools: list[str]) -> None:
        super().__init__()
        self.tools = tools

    def run(self) -> None:
        total = len(self.tools)
        if total == 0:
            if self.install_finished:
                self.install_finished.emit(True, "All tools are already installed.")
            return

        success_count = 0
        for idx, tool in enumerate(self.tools, start=1):
            if self.progress_updated:
                self.progress_updated.emit(
                    int(((idx - 1) / total) * 100),
                    f"Installing {tool} ({idx}/{total})...",
                )

            def _on_sub_progress(sub_pct: int, msg: str, curr_idx=idx, curr_tool=tool) -> None:
                if self.progress_updated:
                    overall = int((((curr_idx - 1) + (sub_pct / 100.0)) / total) * 100)
                    self.progress_updated.emit(overall, f"[{curr_tool}] {msg}")

            ok = ToolInstallerService.install_tool(tool, progress_cb=_on_sub_progress)
            if ok:
                success_count += 1

        ensure_bin_in_path()
        if self.install_finished:
            self.install_finished.emit(
                success_count == total,
                f"Successfully installed {success_count} of {total} tools.",
            )


class SettingsPage(QWidget):
    """Settings page for configuring API keys and automated tool installation."""

    tools_refreshed = Signal() if callable(Signal) else None

    def __init__(self, registry: ToolRegistry | None = None, parent=None) -> None:
        super().__init__(parent)
        self.registry = registry
        self.worker: ToolInstallWorker | None = None

        if hasattr(self, "setLayout"):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(20, 20, 20, 20)
            layout.setSpacing(15)

            title = QLabel("<h2>Workstation Settings & Automated Tool Downloader</h2>")
            layout.addWidget(title)

            # 1. Automated Tool Installer Group
            tools_group = QGroupBox("Security Scanning Engines & Automatic Downloader")
            t_layout = QVBoxLayout(tools_group)
            t_layout.setSpacing(12)

            self.status_list = ToolStatusListWidget()
            if self.status_list.install_tool_requested:
                self.status_list.install_tool_requested.connect(self._install_single_tool)
            t_layout.addWidget(self.status_list)

            # Progress metric bar
            self.progress_bar = QProgressBar()
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
            self.progress_bar.setVisible(False)
            t_layout.addWidget(self.progress_bar)

            self.progress_lbl = QLabel("")
            self.progress_lbl.setStyleSheet("color: #6366f1; font-weight: bold;")
            self.progress_lbl.setVisible(False)
            t_layout.addWidget(self.progress_lbl)

            # Actions Bar
            btn_bar = QHBoxLayout()
            self.install_all_btn = QPushButton("⬇️ Download & Install All Missing Tools")
            self.install_all_btn.clicked.connect(self._install_all_missing)

            self.refresh_btn = QPushButton("🔄 Refresh Tool Status")
            self.refresh_btn.setObjectName("btn-secondary")
            self.refresh_btn.clicked.connect(self.refresh_tools)

            btn_bar.addWidget(self.install_all_btn)
            btn_bar.addWidget(self.refresh_btn)
            btn_bar.addStretch()
            t_layout.addLayout(btn_bar)

            layout.addWidget(tools_group)

            # 2. API Keys Group
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
            layout.addStretch()

    def refresh_tools(self) -> None:
        ensure_bin_in_path()
        if self.registry and hasattr(self, "status_list"):
            statuses = self.registry.list_status()
            self.status_list.set_statuses(statuses)

    def _install_single_tool(self, tool_name: str) -> None:
        self._start_download_worker([tool_name])

    def _install_all_missing(self) -> None:
        if not self.registry:
            return

        missing = []
        statuses = self.registry.list_status()
        installable = ToolInstallerService.get_installable_tools()

        for s in statuses:
            if not s.is_available and s.name in installable:
                missing.append(s.name)

        if not missing:
            QMessageBox.information(
                self,
                "All Tools Ready",
                "All automated security engines (Semgrep, Gitleaks, OSV-Scanner, Syft) are already installed!",
            )
            return

        self._start_download_worker(missing)

    def _start_download_worker(self, tools: list[str]) -> None:
        self.install_all_btn.setEnabled(False)
        self.refresh_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_lbl.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_lbl.setText("Starting download...")

        self.worker = ToolInstallWorker(tools)
        if self.worker.progress_updated:
            self.worker.progress_updated.connect(self._on_install_progress)
        if self.worker.install_finished:
            self.worker.install_finished.connect(self._on_install_complete)
        self.worker.start()

    def _on_install_progress(self, pct: int, msg: str) -> None:
        self.progress_bar.setValue(pct)
        self.progress_lbl.setText(msg)

    def _on_install_complete(self, success: bool, summary: str) -> None:
        self.install_all_btn.setEnabled(True)
        self.refresh_btn.setEnabled(True)
        self.progress_bar.setValue(100 if success else 0)
        self.progress_lbl.setText(summary)

        self.refresh_tools()
        if success:
            QMessageBox.information(self, "Installation Complete", summary)
        else:
            QMessageBox.warning(self, "Installation Finished", summary)

    def _save_credentials(self) -> None:
        u_key = self.urlscan_input.text().strip()
        g_key = self.gemini_input.text().strip()

        if u_key:
            SecretsStore.set_secret("URLSCAN_API_KEY", u_key)
        if g_key:
            SecretsStore.set_secret("GEMINI_API_KEY", g_key)

        QMessageBox.information(self, "Settings Saved", "API credentials safely stored in OS Keyring.")
