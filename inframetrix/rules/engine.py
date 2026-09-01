"""Evaluate YAML rules against project files to produce findings."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from inframetrix.finding import Finding
from inframetrix.rules.rule import Rule, Ruleset

# File extension to language mapping for language filtering
_EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".env": "dotenv",
    ".example": "dotenv",
    ".txt": "text",
    ".md": "markdown",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
}


def _file_matches_patterns(filepath: Path, patterns: list[str]) -> bool:
    """Check if a filename matches any of the given glob patterns."""
    name = filepath.name.lower()
    return any(fnmatch.fnmatch(name, p.lower()) for p in patterns)


def _compile_pattern(pattern: str, match_mode: str) -> re.Pattern[str]:
    """Compile a pattern string based on match mode."""
    if match_mode == "regex":
        return re.compile(pattern)
    flags = re.IGNORECASE if match_mode == "case_insensitive_contains" else 0
    return re.compile(re.escape(pattern), flags)


def _detect_language(filepath: Path) -> str:
    """Detect the language of a file based on its extension."""
    return _EXT_TO_LANG.get(filepath.suffix.lower(), "")


def evaluate_rules(
    files: list[Path],
    ruleset: Ruleset,
    read_text_fn,
) -> list[Finding]:
    """Evaluate all rules against a list of files and return findings."""
    findings: list[Finding] = []

    for rule in ruleset.rules:
        findings.extend(_evaluate_rule(files, rule, read_text_fn))

    return findings


def _evaluate_rule(
    files: list[Path],
    rule: Rule,
    read_text_fn,
) -> list[Finding]:
    """Evaluate a single rule against files."""
    findings: list[Finding] = []

    has_file_patterns = bool(rule.file_patterns)
    has_patterns = bool(rule.patterns)

    for fp in files:
        name = fp.name

        # Check if file matches the file_patterns filter (if any)
        file_filter_match = has_file_patterns and _file_matches_patterns(fp, rule.file_patterns)

        # Case 1: File-level rule (file_patterns only, no content patterns)
        # Fires when the filename matches, regardless of content
        if has_file_patterns and not has_patterns:
            if file_filter_match:
                findings.append(
                    Finding(
                        id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        category=rule.category,
                        file_path=str(fp),
                        message=rule.message or f"File `{name}` matches pattern.",
                        recommendation=rule.recommendation,
                        confidence=rule.confidence,
                    )
                )
            continue

        # Case 2: Content rule with optional file filter (has patterns)
        # If file_patterns exist, file must match the filter first
        if has_file_patterns and not file_filter_match:
            continue

        # Language filter
        if rule.languages:
            lang = _detect_language(fp)
            if lang not in rule.languages:
                continue

        content = read_text_fn(fp)
        if content is None:
            continue

        compiled = [_compile_pattern(p, rule.match_mode) for p in rule.patterns]
        lines = content.splitlines()

        for lineno, line in enumerate(lines, start=1):
            for pat in compiled:
                if pat.search(line):
                    findings.append(
                        Finding(
                            id=rule.id,
                            title=rule.title,
                            severity=rule.severity,
                            category=rule.category,
                            file_path=str(fp),
                            line=lineno,
                            message=rule.message or f"Pattern matched on line {lineno}",
                            recommendation=rule.recommendation,
                            confidence=rule.confidence,
                        )
                    )
                    break  # one match per line per rule

    return findings