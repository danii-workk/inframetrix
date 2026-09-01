"""Content-addressed snapshot storage manager."""

from __future__ import annotations

import hashlib

from inframetrix.storage.repositories.replay_repo import ReplayRepository


class SnapshotStore:
    """Stores and retrieves deduplicated content blobs by SHA-256 hash."""

    def __init__(self, replay_repo: ReplayRepository) -> None:
        self.repo = replay_repo

    def store_content(self, content: bytes) -> str:
        """Store content bytes and return hex SHA-256 hash."""
        content_hash = hashlib.sha256(content).hexdigest()
        self.repo.save_snapshot(content_hash, content)
        return content_hash

    def get_content(self, content_hash: str) -> bytes | None:
        """Retrieve stored content bytes."""
        return self.repo.get_snapshot(content_hash)
