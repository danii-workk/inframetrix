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
    ".ts",
    ".tsx",
    ".py",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".env",
    ".example",
    ".txt",
    ".md",
}

EXPLICIT_FILES: set[str] = {
    "Dockerfile",
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.example",
    "docker-compose.yml",
    "package.json",
    "requirements.txt",
    "pyproject.toml",
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

        # Include by extension
        if item.suffix in SCANNED_EXTENSIONS:
            files.append(item)

    return files
