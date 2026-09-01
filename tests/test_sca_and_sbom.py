"""Tests for SCA manifest parsing and SBOM generation."""

from pathlib import Path

from inframetrix.engines.sbom.generator import SBOMGenerator
from inframetrix.engines.sca.osv import ManifestParser


def test_manifest_parser_package_json(tmp_path: Path):
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(
        '{"name": "my-app", "dependencies": {"express": "^4.18.2"}, "devDependencies": {"jest": "^29.0.0"}}',
        encoding="utf-8",
    )

    deps = ManifestParser.parse_project_dependencies(tmp_path)
    names = {d.name: d for d in deps}

    assert "express" in names
    assert names["express"].direct
    assert not names["express"].development_only
    assert "jest" in names
    assert names["jest"].development_only


def test_manifest_parser_requirements_txt(tmp_path: Path):
    req_txt = tmp_path / "requirements.txt"
    req_txt.write_text(
        "requests==2.31.0\nflask>=2.0.0\n# comment\n",
        encoding="utf-8",
    )

    deps = ManifestParser.parse_project_dependencies(tmp_path)
    names = {d.name: d for d in deps}

    assert "requests" in names
    assert names["requests"].version == "2.31.0"
    assert "flask" in names


def test_cyclonedx_sbom_generation(tmp_path: Path):
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text('{"dependencies": {"lodash": "4.17.21"}}', encoding="utf-8")

    sbom = SBOMGenerator.generate_for_project(tmp_path, project_name="test-proj")
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert len(sbom["components"]) == 1
    assert sbom["components"][0]["name"] == "lodash"
    assert sbom["components"][0]["purl"] == "pkg:npm/lodash@4.17.21"


def test_sbom_write_to_file(tmp_path: Path):
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text('{"dependencies": {"axios": "1.0.0"}}', encoding="utf-8")

    out_file = tmp_path / "sbom.cdx.json"
    SBOMGenerator.write_cyclonedx_file(tmp_path, out_file)

    assert out_file.is_file()
    assert "CycloneDX" in out_file.read_text(encoding="utf-8")
