"""Cooperative cancellation token for graceful scan termination."""

from __future__ import annotations

import threading
from collections.abc import Callable


class CancellationToken:
    """Thread-safe token for signalling cancellation across async tasks and processes."""

    def __init__(self) -> None:
        self._is_cancelled = threading.Event()
        self._callbacks: list[Callable[[], None]] = []
        self._lock = threading.Lock()

    @property
    def is_cancelled(self) -> bool:
        return self._is_cancelled.is_set()

    def cancel(self) -> None:
        """Signal cancellation to all registered listeners and child processes."""
        with self._lock:
            if not self._is_cancelled.is_set():
                self._is_cancelled.set()
                for cb in self._callbacks:
                    try:
                        cb()
                    except Exception:  # noqa: BLE001, S110
                        pass

    def register_callback(self, callback: Callable[[], None]) -> None:
        """Register a callback to be triggered immediately when cancellation occurs."""
        with self._lock:
            if self._is_cancelled.is_set():
                callback()
            else:
                self._callbacks.append(callback)
