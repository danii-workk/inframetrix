"""Code Replay & Security Time Machine Page."""

from __future__ import annotations

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (
        QFrame,
        QLabel,
        QListWidget,
        QSplitter,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    QWidget = object  # type: ignore[misc, assignment]


class ReplayPage(QWidget):
    """Source Code Replay timeline with diff preview and regression tracking."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.events: list[dict] = []

        if hasattr(self, "setLayout"):
            layout = QVBoxLayout(self)
            layout.setContentsMargins(15, 15, 15, 15)

            title = QLabel("<h2>Code Replay — Security Time Machine</h2>")
            layout.addWidget(title)

            splitter = QSplitter(Qt.Orientation.Horizontal)

            # Left Timeline List
            left_frame = QFrame()
            l_layout = QVBoxLayout(left_frame)
            l_layout.addWidget(QLabel("<h3>Modification Timeline</h3>"))
            self.event_list = QListWidget()
            self.event_list.itemClicked.connect(self._on_item_clicked)
            l_layout.addWidget(self.event_list)
            splitter.addWidget(left_frame)

            # Right Diff Viewer
            right_frame = QFrame()
            r_layout = QVBoxLayout(right_frame)
            r_layout.addWidget(QLabel("<h3>Unified Diff Preview</h3>"))
            self.diff_viewer = QTextEdit()
            self.diff_viewer.setReadOnly(True)
            r_layout.addWidget(self.diff_viewer)
            splitter.addWidget(right_frame)

            splitter.setSizes([350, 650])
            layout.addWidget(splitter)

    def set_events(self, events: list[dict]) -> None:
        self.events = events
        if not hasattr(self, "event_list"):
            return
        self.event_list.clear()
        for e in events:
            ts = str(e.get("timestamp", ""))[:19]
            f = e.get("file_path", "")
            self.event_list.addItem(f"{ts} — {f}")

    def _on_item_clicked(self, item) -> None:
        row = self.event_list.row(item)
        if 0 <= row < len(self.events):
            diff = self.events[row].get("diff_text") or "No textual diff available for this snapshot."
            self.diff_viewer.setPlainText(diff)
