"""Secure subprocess execution runner with timeout and cancellation support."""

from __future__ import annotations

import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from inframetrix.core.cancellation import CancellationToken


@dataclass
class ProcessResult:
    """Execution output from a subprocess execution."""

    args: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    cancelled: bool = False


class SecureProcessRunner:
    """Executes system CLI tools safely without shell injection risks."""

    def __init__(self, default_timeout: int = 300) -> None:
        self.default_timeout = default_timeout

    def run(
        self,
        args: list[str],
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout: int | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> ProcessResult:
        """Run a process strictly using argument arrays (never shell=True)."""
        if not args or not isinstance(args, list):
            raise ValueError("Arguments must be a non-empty list of strings.")

        effective_timeout = timeout or self.default_timeout
        start_time = time.monotonic()

        proc = subprocess.Popen(
            args,
            cwd=str(cwd) if cwd else None,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )

        timed_out = False
        cancelled = False

        def _handle_cancel() -> None:
            nonlocal cancelled
            cancelled = True
            try:
                proc.terminate()
                # Give process a moment to exit gracefully, else kill
                threading.Timer(2.0, lambda: proc.kill() if proc.poll() is None else None).start()
            except Exception:  # noqa: BLE001, S110
                pass

        if cancellation_token:
            if cancellation_token.is_cancelled:
                _handle_cancel()
            else:
                cancellation_token.register_callback(_handle_cancel)

        try:
            stdout, stderr = proc.communicate(timeout=effective_timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            stdout, stderr = proc.communicate()

        duration = time.monotonic() - start_time

        return ProcessResult(
            args=args,
            exit_code=proc.returncode if proc.returncode is not None else -1,
            stdout=stdout or "",
            stderr=stderr or "",
            duration_seconds=duration,
            timed_out=timed_out,
            cancelled=cancelled,
        )
