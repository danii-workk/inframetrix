"""Safe recursive file collector for project scanning."""

from __future__ import annotations

from pathlib import Path

IGNORED_DIRS: set[str] = {
    ".git",
    "node_modules",
    ".next",
    "dist",
    "build",
    "venv",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "coverage",
    ".idea",
    ".vscode",
    "rulesets",
}

SCANNED_EXTENSIONS: set[str] = {
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".py",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".env",
    ".example",
    ".txt",
    ".md",
    ".conf",
    ".cfg",
    ".ini",
    ".sh",
    ".bash",
    ".zsh",
    ".dockerfile",
}

EXPLICIT_FILES: set[str] = {
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "nginx.conf",
    ".env",
    ".dockerignore",
}

EXCLUDED_FILES: set[str] = {
    "inframetrix-report.json",
    "inframetrix-report.md",
}


def collect_files(project_path: Path) -> list[Path]:
    """Collect scannable files from a project directory."""
    files: list[Path] = []

    for item in sorted(project_path.rglob("*")):
        if item.is_dir():
            continue

        # Check if any parent directory should be ignored
        rel = item.relative_to(project_path)
        if any(part in IGNORED_DIRS for part in rel.parts):
            continue

        name = item.name

        # Skip report output files
        if name in EXCLUDED_FILES:
            continue

        # Include by explicit filename
        if name in EXPLICIT_FILES:
            files.append(item)
            continue

        # Include any .env files (.env, .env.local, .env.staging, .env.production, etc.)
        if name == ".env" or name.startswith(".env."):
            files.append(item)
            continue

        # Include Dockerfiles (Dockerfile.dev, Dockerfile.prod, etc.)
        if name.startswith("Dockerfile"):
            files.append(item)
            continue

        # Include by extension (case-insensitive)
        if item.suffix.lower() in SCANNED_EXTENSIONS:
            files.append(item)

    return files