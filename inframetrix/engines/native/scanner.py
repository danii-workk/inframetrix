"""Native scanner module."""

from inframetrix.engines.native.adapter import (
    _DEFAULT_RULESETS_DIR,
    NativeScannerAdapter,
    _read_text,
)

__all__ = ["_DEFAULT_RULESETS_DIR", "NativeScannerAdapter", "_read_text"]
