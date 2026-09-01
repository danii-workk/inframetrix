"""Registry for discovering, tracking and querying scanner adapters."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from dataclasses import dataclass

from inframetrix.engines.protocol import ScannerAdapter


@dataclass
class ToolStatus:
    """Readiness status and metadata for a security engine."""

    name: str
    category: str
    is_available: bool
    version: str | None
    description: str = ""
    is_builtin: bool = False
    install_hint: str = ""


class ToolRegistry:
    """Central registry of all security scanner adapters available in InfraMetrix."""

    def __init__(self) -> None:
        self._adapters: dict[str, ScannerAdapter] = {}
        self._lock = threading.Lock()

    def register(self, adapter: ScannerAdapter) -> None:
        """Register a scanner adapter instance."""
        with self._lock:
            self._adapters[adapter.name] = adapter

    def unregister(self, name: str) -> None:
        """Unregister an adapter by name."""
        with self._lock:
            self._adapters.pop(name, None)

    def get(self, name: str) -> ScannerAdapter | None:
        """Retrieve an adapter by name."""
        with self._lock:
            return self._adapters.get(name)

    def list_all(self) -> list[ScannerAdapter]:
        """List all registered adapters."""
        with self._lock:
            return list(self._adapters.values())

    def list_status(self) -> list[ToolStatus]:
        """Get status metadata for all registered adapters."""
        with self._lock:
            adapters = list(self._adapters.values())

        statuses: list[ToolStatus] = []
        for adapter in adapters:
            avail = False
            ver = None
            try:
                avail = adapter.available()
                if avail:
                    ver = adapter.version()
            except Exception:  # noqa: BLE001
                avail = False

            statuses.append(
                ToolStatus(
                    name=adapter.name,
                    category=getattr(adapter, "category", "general"),
                    is_available=avail,
                    version=ver,
                    is_builtin=getattr(adapter, "is_builtin", False),
                    install_hint=getattr(adapter, "install_hint", ""),
                )
            )
        return statuses

    def __iter__(self) -> Iterator[ScannerAdapter]:
        with self._lock:
            return iter(list(self._adapters.values()))
