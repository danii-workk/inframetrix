"""OS Keyring credentials store for API keys."""

from __future__ import annotations

import logging
from typing import ClassVar

logger = logging.getLogger(__name__)

SERVICE_NAME = "inframetrix"


class SecretsStore:
    """Secure store using operating system keychain with in-memory fallback."""

    _memory_store: ClassVar[dict[str, str]] = {}

    @classmethod
    def get_secret(cls, key: str) -> str | None:
        """Retrieve a secret by key name."""
        try:
            import keyring  # type: ignore[import-not-found]

            val = keyring.get_password(SERVICE_NAME, key)
            if val is not None:
                return val
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"Keyring unavailable, using memory store: {exc}")

        return cls._memory_store.get(key)

    @classmethod
    def set_secret(cls, key: str, value: str) -> None:
        """Store a secret securely."""
        try:
            import keyring  # type: ignore[import-not-found]

            keyring.set_password(SERVICE_NAME, key, value)
            return
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"Keyring set failed, using memory store: {exc}")

        cls._memory_store[key] = value

    @classmethod
    def delete_secret(cls, key: str) -> None:
        """Remove a secret from store."""
        try:
            import keyring  # type: ignore[import-not-found]

            keyring.delete_password(SERVICE_NAME, key)
        except Exception:  # noqa: BLE001, S110
            pass

        cls._memory_store.pop(key, None)
