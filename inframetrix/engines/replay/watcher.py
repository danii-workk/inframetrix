"""Filesystem watcher tracking file modifications for Code Replay."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

REPLAY_BLACKLIST_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    "coverage",
    "venv",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".inframetrix",
    "inframetrix-data",
}


class FileWatcher:
    """Watches project directory for file modifications, ignoring noisy build directories."""

    def __init__(
        self,
        project_path: Path,
        on_modified_cb: Callable[[Path], None],
    ) -> None:
        self.project_path = project_path.resolve()
        self.on_modified_cb = on_modified_cb
        self._observer: Any = None
        self._is_watching = False
        self._lock = threading.Lock()

    @property
    def is_watching(self) -> bool:
        return self._is_watching

    def start(self) -> bool:
        """Start filesystem observation."""
        with self._lock:
            if self._is_watching:
                return True

            try:
                from watchdog.events import FileSystemEventHandler
                from watchdog.observers import Observer

                outer = self

                class ChangeHandler(FileSystemEventHandler):
                    def on_modified(self, event):
                        if event.is_directory:
                            return
                        p = Path(event.src_path)
                        rel = p.relative_to(outer.project_path)
                        if any(part in REPLAY_BLACKLIST_DIRS for part in rel.parts):
                            return
                        outer.on_modified_cb(p)

                self._observer = Observer()
                self._observer.schedule(ChangeHandler(), str(self.project_path), recursive=True)
                self._observer.start()
                self._is_watching = True
                return True
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"Watchdog unavailable or error starting observer: {exc}")
                return False

    def stop(self) -> None:
        """Stop filesystem observation."""
        with self._lock:
            if self._observer and self._is_watching:
                try:
                    self._observer.stop()
                    self._observer.join(timeout=2.0)
                except Exception:  # noqa: BLE001, S110
                    pass
                self._observer = None
            self._is_watching = False
