"""Scanner adapter protocol defining standard interface for all security engines."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from inframetrix.core.cancellation import CancellationToken
from inframetrix.core.scan_context import ScanContext
from inframetrix.models.scan_result import ScanResult


@runtime_checkable
class ScannerAdapter(Protocol):
    """Unified interface required for all security scanning engines."""

    name: str
    category: str  # sast, dast, sca, secrets, sbom, supply_chain, urlscan, hash_audit

    def available(self) -> bool:
        """Check whether the underlying tool/engine is installed and operational."""
        ...

    def version(self) -> str | None:
        """Return the detected version string of the engine, or None if unavailable."""
        ...

    def scan(
        self,
        context: ScanContext,
        cancellation_token: CancellationToken | None = None,
    ) -> ScanResult:
        """Execute scan against the target project and return normalized findings."""
        ...
