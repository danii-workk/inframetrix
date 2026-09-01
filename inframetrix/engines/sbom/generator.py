"""CycloneDX v1.5 and SPDX v2.3 SBOM generator."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from inframetrix.engines.sca.osv import ManifestParser
from inframetrix.models.dependency import DependencyNode


class SBOMGenerator:
    """Generates Software Bill of Materials (SBOM) artifacts for projects."""

    @classmethod
    def generate_cyclonedx_json(
        cls,
        project_name: str,
        dependencies: list[DependencyNode],
    ) -> dict:
        """Produce standard CycloneDX v1.5 JSON structure."""
        components = []
        for dep in dependencies:
            purl = dep.purl or f"pkg:{dep.ecosystem}/{dep.name}@{dep.version}"
            components.append(
                {
                    "type": "library",
                    "bom-ref": purl,
                    "name": dep.name,
                    "version": dep.version,
                    "purl": purl,
                    "scope": "optional" if dep.development_only else "required",
                    "licenses": [{"license": {"id": dep.license}}] if dep.license != "UNKNOWN" else [],
                }
            )

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(UTC).isoformat(),
                "tools": [{"vendor": "InfraMetrix", "name": "InfraMetrix AppSec Workstation", "version": "0.1.0"}],
                "component": {
                    "type": "application",
                    "name": project_name,
                    "version": "latest",
                },
            },
            "components": components,
        }

    @classmethod
    def generate_for_project(cls, project_path: Path, project_name: str | None = None) -> dict:
        """Parse project manifests and generate CycloneDX JSON."""
        deps = ManifestParser.parse_project_dependencies(project_path)
        name = project_name or project_path.name
        return cls.generate_cyclonedx_json(name, deps)

    @classmethod
    def write_cyclonedx_file(cls, project_path: Path, output_file: Path) -> Path:
        """Generate and save CycloneDX JSON to disk."""
        data = cls.generate_for_project(project_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return output_file
