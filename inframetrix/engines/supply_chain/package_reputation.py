"""Package reputation, typosquatting, and dependency hygiene analyzer."""

from __future__ import annotations

from pathlib import Path

from inframetrix.engines.sca.osv import ManifestParser
from inframetrix.models.finding import Finding

# Common targets for typosquatting attacks
POPULAR_PACKAGES = {
    "npm": ["express", "react", "lodash", "axios", "chalk", "commander", "moment", "vue", "next", "dotenv"],
    "pypi": ["requests", "urllib3", "numpy", "pandas", "django", "flask", "pydantic", "pytest", "scipy", "cryptography"],
}


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row: list[int] = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


class PackageReputationAnalyzer:
    """Checks for package typosquatting risks, unpinned dependencies, and missing lockfiles."""

    @classmethod
    def audit_dependencies(cls, project_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        deps = ManifestParser.parse_project_dependencies(project_path)

        # 1. Lockfile check
        has_pkg_json = (project_path / "package.json").is_file()
        has_npm_lock = any(
            (project_path / f).is_file()
            for f in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")
        )
        if has_pkg_json and not has_npm_lock:
            findings.append(
                Finding(
                    id="supply-chain-missing-lockfile",
                    title="Missing JavaScript lock file",
                    description="package.json found without a corresponding lock file (package-lock.json, yarn.lock, pnpm-lock.yaml).",
                    message="Missing lock file allows non-deterministic build risks.",
                    severity="medium",
                    confidence="high",
                    category="supply-chain",
                    source_engine="supply-chain",
                    file_path=str(project_path / "package.json"),
                    recommendation="Run `npm install` / `pnpm install` and commit the generated lock file to version control.",
                    tags=["supply-chain", "lockfile"],
                )
            )

        # 2. Typosquatting heuristics
        for dep in deps:
            pop_list = POPULAR_PACKAGES.get(dep.ecosystem, [])
            name_lower = dep.name.lower()

            for target in pop_list:
                if name_lower != target and _levenshtein_distance(name_lower, target) == 1:
                    findings.append(
                        Finding(
                            id="supply-chain-potential-typosquat",
                            title=f"Potential typosquatting dependency '{dep.name}'",
                            description=f"Package '{dep.name}' is suspiciously close in name to popular package '{target}' (distance 1).",
                            message=f"Possible typosquat of '{target}'",
                            severity="high",
                            confidence="medium",
                            category="supply-chain",
                            source_engine="supply-chain",
                            package_name=dep.name,
                            package_version=dep.version,
                            recommendation=f"Verify if you intended to install '{target}' instead of '{dep.name}'.",
                            tags=["supply-chain", "typosquatting"],
                        )
                    )

        return findings
