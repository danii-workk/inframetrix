"""Automated tool installer and downloader with progress streaming."""

from __future__ import annotations

import io
import logging
import os
import platform
import subprocess
import sys
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger(__name__)

BIN_DIR = Path.home() / ".inframetrix" / "bin"


def ensure_bin_in_path() -> None:
    """Ensure ~/.inframetrix/bin is present in PATH environment variable."""
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    bin_str = str(BIN_DIR.resolve())
    current_path = os.environ.get("PATH", "")
    if bin_str not in current_path:
        os.environ["PATH"] = f"{bin_str}{os.pathsep}{current_path}"


# Call immediately on module load
ensure_bin_in_path()


class ToolInstallerService:
    """Downloads and installs external security CLI tools with progress metrics."""

    @classmethod
    def get_installable_tools(cls) -> list[str]:
        if platform.system().lower() == "windows":
            return ["gitleaks", "osv-sca", "syft"]
        return ["semgrep", "gitleaks", "osv-sca", "syft"]

    @classmethod
    def install_tool(
        cls,
        tool_name: str,
        progress_cb: Callable[[int, str], None] | None = None,
    ) -> bool:
        """Download and install a tool by name."""
        ensure_bin_in_path()
        name = tool_name.lower()

        if name == "semgrep":
            return cls._install_semgrep(progress_cb)
        if name == "gitleaks":
            return cls._install_gitleaks(progress_cb)
        if name in ("osv-sca", "osv-scanner"):
            return cls._install_osv_scanner(progress_cb)
        if name == "syft":
            return cls._install_syft(progress_cb)

        if progress_cb:
            progress_cb(0, f"No automated installer available for {tool_name}.")
        return False

    @classmethod
    def _install_semgrep(cls, progress_cb: Callable[[int, str], None] | None) -> bool:
        system = platform.system().lower()
        if system == "windows":
            if progress_cb:
                progress_cb(
                    0,
                    "Semgrep officially requires WSL / Linux on Windows. Built-in Native SAST is used instead.",
                )
            return False

        if progress_cb:
            progress_cb(10, "Installing semgrep via pip...")
        try:
            cmd = [sys.executable, "-m", "pip", "install", "semgrep"]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode == 0:
                if progress_cb:
                    progress_cb(100, "Semgrep successfully installed!")
                return True
            if progress_cb:
                progress_cb(0, f"Pip install failed: {proc.stderr[:100]}")
            return False
        except Exception as exc:  # noqa: BLE001
            if progress_cb:
                progress_cb(0, f"Error installing semgrep: {exc}")
            return False

    @classmethod
    def _install_gitleaks(cls, progress_cb: Callable[[int, str], None] | None) -> bool:
        version = "8.24.0"
        system = platform.system().lower()
        arch = platform.machine().lower()

        is_win = system == "windows"
        os_tag = "windows" if is_win else ("darwin" if system == "darwin" else "linux")
        arch_tag = "x64" if arch in ("x86_64", "amd64") else ("arm64" if "arm" in arch else "x64")

        url = f"https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_{os_tag}_{arch_tag}.zip"

        if progress_cb:
            progress_cb(10, f"Downloading Gitleaks v{version} for {os_tag}_{arch_tag}...")

        try:
            zip_bytes = cls._download_with_progress(url, progress_cb, start_pct=15, end_pct=85)
            if progress_cb:
                progress_cb(88, "Extracting gitleaks binary...")

            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
                exe_name = "gitleaks.exe" if is_win else "gitleaks"
                for member in z.namelist():
                    if member.endswith(exe_name):
                        data = z.read(member)
                        dest = BIN_DIR / exe_name
                        dest.write_bytes(data)
                        if not is_win:
                            dest.chmod(0o755)
                        break

            ensure_bin_in_path()
            if progress_cb:
                progress_cb(100, "Gitleaks successfully installed!")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"Gitleaks install error: {exc}")
            if progress_cb:
                progress_cb(0, f"Failed to install Gitleaks: {exc}")
            return False

    @classmethod
    def _install_osv_scanner(cls, progress_cb: Callable[[int, str], None] | None) -> bool:
        version = "1.9.2"
        system = platform.system().lower()
        arch = platform.machine().lower()

        is_win = system == "windows"
        os_tag = "windows" if is_win else ("darwin" if system == "darwin" else "linux")
        arch_tag = "amd64" if arch in ("x86_64", "amd64") else ("arm64" if "arm" in arch else "amd64")

        exe_name = "osv-scanner.exe" if is_win else "osv-scanner"
        filename = f"osv-scanner_{os_tag}_{arch_tag}.exe" if is_win else f"osv-scanner_{os_tag}_{arch_tag}"
        url = f"https://github.com/google/osv-scanner/releases/download/v{version}/{filename}"

        if progress_cb:
            progress_cb(10, f"Downloading OSV-Scanner v{version} for {os_tag}_{arch_tag}...")

        try:
            binary_bytes = cls._download_with_progress(url, progress_cb, start_pct=15, end_pct=90)
            dest = BIN_DIR / exe_name
            dest.write_bytes(binary_bytes)
            if not is_win:
                dest.chmod(0o755)

            ensure_bin_in_path()
            if progress_cb:
                progress_cb(100, "OSV-Scanner successfully installed!")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"OSV-Scanner install error: {exc}")
            if progress_cb:
                progress_cb(0, f"Failed to install OSV-Scanner: {exc}")
            return False

    @classmethod
    def _install_syft(cls, progress_cb: Callable[[int, str], None] | None) -> bool:
        version = "1.20.0"
        system = platform.system().lower()
        arch = platform.machine().lower()

        is_win = system == "windows"
        os_tag = "windows" if is_win else ("darwin" if system == "darwin" else "linux")
        arch_tag = "amd64" if arch in ("x86_64", "amd64") else ("arm64" if "arm" in arch else "amd64")

        url = f"https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_{os_tag}_{arch_tag}.zip"

        if progress_cb:
            progress_cb(10, f"Downloading Syft v{version} for {os_tag}_{arch_tag}...")

        try:
            zip_bytes = cls._download_with_progress(url, progress_cb, start_pct=15, end_pct=85)
            if progress_cb:
                progress_cb(88, "Extracting syft binary...")

            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
                exe_name = "syft.exe" if is_win else "syft"
                for member in z.namelist():
                    if member.endswith(exe_name):
                        data = z.read(member)
                        dest = BIN_DIR / exe_name
                        dest.write_bytes(data)
                        if not is_win:
                            dest.chmod(0o755)
                        break

            ensure_bin_in_path()
            if progress_cb:
                progress_cb(100, "Syft successfully installed!")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"Syft install error: {exc}")
            if progress_cb:
                progress_cb(0, f"Failed to install Syft: {exc}")
            return False

    @classmethod
    def _download_with_progress(
        cls,
        url: str,
        progress_cb: Callable[[int, str], None] | None,
        start_pct: int = 10,
        end_pct: int = 90,
    ) -> bytes:
        """Download URL with streaming progress tracking."""
        req = urllib.request.Request(url, headers={"User-Agent": "InfraMetrix-Installer/0.1.0"})
        with urllib.request.urlopen(req, timeout=60.0) as resp:
            total_len = resp.headers.get("Content-Length")
            total_bytes = int(total_len) if total_len else 0

            downloaded = 0
            chunks = []
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
                downloaded += len(chunk)

                if total_bytes > 0 and progress_cb:
                    ratio = downloaded / total_bytes
                    pct = int(start_pct + ratio * (end_pct - start_pct))
                    mb_cur = downloaded / (1024 * 1024)
                    mb_tot = total_bytes / (1024 * 1024)
                    progress_cb(pct, f"Downloading: {pct}% ({mb_cur:.1f} MB / {mb_tot:.1f} MB)...")

        return b"".join(chunks)
