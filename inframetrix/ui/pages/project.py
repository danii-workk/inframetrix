"""Project selection and workspace manager page."""

from __future__ import annotations

try:
    from PySide6.QtCore import Signal
    from PySide6.QtWidgets import (
        QFileDialog,
        QHBoxLayout,
        QLabel,
        QListWidget,
        QPushButton,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    QWidget = object  # type: ignore[misc, assignment]
    Signal = lambda *args: None  # type: ignore[assignment]

from inframetrix.models.project import Project


class ProjectPage(QWidget):
    """Project manager and local directory selection."""

    project_selected = Signal(str) if callable(Signal) else None  # project_path

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        if hasattr(self, "setLayout"):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(20, 20, 20, 20)

            title = QLabel("<h2>Workspace & Projects</h2>")
            layout.addWidget(title)

            # Action bar
            btn_layout = QHBoxLayout()
            self.browse_btn = QPushButton("📁 Open Local Project Directory")
            self.browse_btn.clicked.connect(self._on_browse)
            btn_layout.addWidget(self.browse_btn)
            btn_layout.addStretch()
            layout.addLayout(btn_layout)

            # Recent projects list
            recents_title = QLabel("<h3>Recent Projects</h3>")
            layout.addWidget(recents_title)

            self.project_list = QListWidget()
            self.project_list.itemDoubleClicked.connect(self._on_project_double_click)
            layout.addWidget(self.project_list)

    def set_projects(self, projects: list[Project]) -> None:
        if not hasattr(self, "project_list"):
            return
        self.project_list.clear()
        for p in projects:
            self.project_list.addItem(f"{p.name} — {p.root_path}")

    def _on_browse(self) -> None:
        dir_path = QFileDialog.getExistingDirectory(self, "Select Project Root Directory")
        if dir_path and self.project_selected:
            self.project_selected.emit(dir_path)

    def _on_project_double_click(self, item) -> None:
        text = item.text()
        if " — " in text and self.project_selected:
            path_str = text.split(" — ")[1].strip()
            self.project_selected.emit(path_str)
