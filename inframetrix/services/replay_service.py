"""Replay service managing file watching, snapshot persistence, and timeline history."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from inframetrix.engines.replay.diff_engine import DiffEngine
from inframetrix.engines.replay.replay_engine import RegressionEvent, ReplayEngine
from inframetrix.engines.replay.snapshots import SnapshotStore
from inframetrix.engines.replay.watcher import FileWatcher
from inframetrix.models.finding import Finding
from inframetrix.storage.database import DatabaseManager
from inframetrix.storage.repositories.replay_repo import ReplayRepository


class ReplayService:
    """High-level service managing Code Replay & Security Time Machine."""

    def __init__(self, db: DatabaseManager | None = None) -> None:
        self.db = db or DatabaseManager()
        self.replay_repo = ReplayRepository(self.db)
        self.snapshot_store = SnapshotStore(self.replay_repo)
        self._watchers: dict[str, FileWatcher] = {}
        self._last_hashes: dict[str, str] = {}  # file_path -> sha256

    def record_file_change(
        self,
        project_id: str,
        file_path: Path,
        old_text: str | None = None,
    ) -> int | None:
        """Capture a file snapshot and save diff to SQLite."""
        if not file_path.is_file():
            return None

        try:
            content_bytes = file_path.read_bytes()
            new_text = content_bytes.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return None

        new_hash = hashlib.sha256(content_bytes).hexdigest()
        path_key = str(file_path)

        old_hash = self._last_hashes.get(path_key)
        if old_hash == new_hash:
            return None  # No actual content change

        diff_text = None
        if old_text is not None:
            diff_text = DiffEngine.compute_diff(old_text, new_text, filename=file_path.name)
        elif old_hash:
            old_bytes = self.snapshot_store.get_content(old_hash)
            if old_bytes:
                diff_text = DiffEngine.compute_diff(
                    old_bytes.decode("utf-8", errors="replace"),
                    new_text,
                    filename=file_path.name,
                )

        self.snapshot_store.store_content(content_bytes)
        self._last_hashes[path_key] = new_hash

        return self.replay_repo.save_event(
            project_id=project_id,
            timestamp=datetime.now(UTC),
            file_path=str(file_path),
            old_hash=old_hash,
            new_hash=new_hash,
            diff_text=diff_text,
            snapshot_hash=new_hash,
        )

    def get_timeline(self, project_id: str, limit: int = 100) -> list[dict]:
        """Fetch chronological change history."""
        return self.replay_repo.list_events_by_project(project_id, limit=limit)

    def correlate_security_regression(
        self,
        project_id: str,
        findings_before: list[Finding],
        findings_after: list[Finding],
        risk_before: float,
        risk_after: float,
    ) -> list[RegressionEvent]:
        """Correlate recently changed files with newly introduced vulnerabilities."""
        events = self.get_timeline(project_id, limit=20)
        return ReplayEngine.correlate_regressions(
            findings_before=findings_before,
            findings_after=findings_after,
            recent_events=events,
            risk_before=risk_before,
            risk_after=risk_after,
        )

    def create_restore_copy(self, file_path: Path, target_snapshot_hash: str) -> Path:
        """Safely restore a snapshot into `.inframetrix/replay/<timestamp>/` without destructive overwrites."""
        content_bytes = self.snapshot_store.get_content(target_snapshot_hash)
        if not content_bytes:
            raise ValueError(f"Snapshot hash '{target_snapshot_hash}' not found in store.")

        timestamp_str = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        backup_dir = file_path.parent / ".inframetrix" / "replay" / timestamp_str
        backup_dir.mkdir(parents=True, exist_ok=True)

        dest_file = backup_dir / file_path.name
        dest_file.write_bytes(content_bytes)
        return dest_file
