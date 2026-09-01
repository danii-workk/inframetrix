"""InfraMetrix core exceptions."""

from __future__ import annotations


class InfraMetrixError(Exception):
    """Base exception for all InfraMetrix errors."""


class ScanCancelledError(InfraMetrixError):
    """Raised when a scan operation is aborted by user cancellation."""


class AdapterExecutionError(InfraMetrixError):
    """Raised when a scanner adapter fails to execute properly."""


class TargetPolicyViolationError(InfraMetrixError):
    """Raised when a scan target violates security policy (e.g. unauthorized DAST)."""


class DatabaseError(InfraMetrixError):
    """Raised on storage/database operations failure."""
