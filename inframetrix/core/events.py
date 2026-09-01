"""Event bus and progress streaming for scan orchestration."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal


@dataclass
class ScanEvent:
    """Event emitted during scan execution."""

    event_type: Literal[
        "scan_started",
        "tool_started",
        "tool_progress",
        "tool_completed",
        "tool_failed",
        "finding_discovered",
        "scan_completed",
        "scan_failed",
        "scan_cancelled",
        "log_message",
    ]
    session_id: str
    tool_name: str | None = None
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class EventBus:
    """Thread-safe publish-subscribe event bus."""

    def __init__(self) -> None:
        self._subscribers: list[Callable[[ScanEvent], None]] = []
        self._lock = threading.Lock()

    def subscribe(self, callback: Callable[[ScanEvent], None]) -> None:
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[ScanEvent], None]) -> None:
        with self._lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def publish(self, event: ScanEvent) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for sub in subscribers:
            try:
                sub(event)
            except Exception:  # noqa: BLE001, S110
                pass
