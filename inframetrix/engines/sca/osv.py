"""SCA (Software Composition Analysis) adapter using OSV-Scanner and local manifest parsing."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Literal

from inframetrix.core.cancellation import CancellationToken
from inframetrix.core.scan_context import ScanContext
from inframetrix.models.dependency import DependencyNode
from inframetrix.models.finding import Finding
from inframetrix.models.scan_result import ScanResult, ToolRun
from inframetrix.security.subprocess_policy import SecureProcessRunner


class OSVScannerAdapter:
    """Software Composition Analysis engine powered by OSV-Scanner and manifest parsing."""

    name = "osv-sca"
    category = "sca"
    is_builtin = False
    install_hint = "Install with: go install github.com/google/osv-scanner/cmd/osv-scanner@latest or download from releases."

    def __init__(self) -> None:
        self.runner = SecureProcessRunner(default_timeout=300)

    def available(self) -> bool:
        return shutil.which("osv-scanner") is not None

    def version(self) -> str | None:
        if not self.available():
            return None
        res = self.runner.run(["osv-scanner", "--version"])
        return res.stdout.strip() if res.exit_code == 0 else None

    def scan(
        self,
        context: ScanContext,
        cancellation_token: CancellationToken | None = None,
    ) -> ScanResult:
        if not self.available():
            return ScanResult(
                engine_name=self.name,
                findings=[],
                tool_run=ToolRun(
                    tool_name=self.name,
                    status="unavailable",
                    error_message="osv-scanner executable not found in PATH",
                ),
            )

        res = self.runner.run(
            ["osv-scanner", "--json", "-r", str(context.project_path)],
            cancellation_token=cancellation_token,
        )

        findings: list[Finding] = []
        if res.stdout:
            try:
                data = json.loads(res.stdout)
                results_list = data.get("results", [])
                for r in results_list:
                    pkg_source = r.get("source", {}).get("path", "")
                    packages = r.get("packages", [])
                    for pkg_entry in packages:
                        pkg_info = pkg_entry.get("package", {})
                        pkg_name = pkg_info.get("name", "")
                        pkg_version = pkg_info.get("version", "")
                        ecosystem = pkg_info.get("ecosystem", "")

                        vulnerabilities = pkg_entry.get("vulnerabilities", [])
                        for vuln in vulnerabilities:
                            vuln_id = vuln.get("id", "UNKNOWN-VULN")
                            summary = vuln.get("summary") or vuln.get("details") or f"Vulnerability {vuln_id} in {pkg_name}"
                            aliases = vuln.get("aliases", [])
                            cve_id = next((a for a in aliases if a.startswith("CVE-")), None)

                            # Severity calculation from database_specific or severity
                            severity: Literal["info", "low", "medium", "high", "critical"] = "high"
                            cvss_score = None
                            for sev in vuln.get("severity", []):
                                if sev.get("type") == "CVSS_V3":
                                    cvss_score = 8.0

                            findings.append(
                                Finding(
                                    id=f"sca-{vuln_id.lower()}",
                                    title=f"Vulnerable dependency {pkg_name}@{pkg_version} ({vuln_id})",
                                    description=summary,
                                    message=summary,
                                    severity=severity,
                                    confidence="high",
                                    category="dependency",
                                    source_engine=self.name,
                                    file_path=pkg_source,
                                    package_name=pkg_name,
                                    package_version=pkg_version,
                                    cve=cve_id or vuln_id,
                                    cvss=cvss_score,
                                    recommendation=f"Upgrade {pkg_name} to a secure patched version.",
                                    references=[f"https://osv.dev/vulnerability/{vuln_id}"],
                                    tags=["sca", "dependency", ecosystem.lower()],
                                )
                            )
            except Exception as exc:  # noqa: BLE001
                return ScanResult(
                    engine_name=self.name,
                    findings=findings,
                    tool_run=ToolRun(
                        tool_name=self.name,
                        status="failed",
                        error_message=f"JSON parsing error: {exc}",
                        stdout=res.stdout,
                        stderr=res.stderr,
                    ),
                )

        return ScanResult(
            engine_name=self.name,
            findings=findings,
            tool_run=ToolRun(
                tool_name=self.name,
                tool_version=self.version(),
                exit_code=res.exit_code,
                stdout=res.stdout,
                stderr=res.stderr,
                status="completed" if not res.cancelled else "cancelled",
            ),
        )


class ManifestParser:
    """Extracts dependency nodes from project manifests across multiple ecosystems."""

    @staticmethod
    def parse_project_dependencies(project_path: Path) -> list[DependencyNode]:
        nodes: list[DependencyNode] = []
        # 1. package.json / package-lock.json
        pkg_json = project_path / "package.json"
        if pkg_json.is_file():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8"))
                deps = data.get("dependencies", {})
                for name, ver in deps.items():
                    clean_ver = re.sub(r"[^\d.]", "", ver) or ver
                    nodes.append(
                        DependencyNode(
                            name=name,
                            version=clean_ver,
                            ecosystem="npm",
                            direct=True,
                            development_only=False,
                            manifest_path=str(pkg_json),
                        )
                    )
                dev_deps = data.get("devDependencies", {})
                for name, ver in dev_deps.items():
                    clean_ver = re.sub(r"[^\d.]", "", ver) or ver
                    nodes.append(
                        DependencyNode(
                            name=name,
                            version=clean_ver,
                            ecosystem="npm",
                            direct=True,
                            development_only=True,
                            manifest_path=str(pkg_json),
                        )
                    )
            except Exception:  # noqa: BLE001, S110
                pass

        # 2. requirements.txt
        req_txt = project_path / "requirements.txt"
        if req_txt.is_file():
            try:
                for line in req_txt.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "==" in line:
                        parts = line.split("==")
                        name = parts[0].strip()
                        ver = parts[1].split(";")[0].strip()
                        nodes.append(
                            DependencyNode(
                                name=name,
                                version=ver,
                                ecosystem="pypi",
                                direct=True,
                                manifest_path=str(req_txt),
                            )
                        )
                    elif line and not line.startswith("-"):
                        nodes.append(
                            DependencyNode(
                                name=line.split(">=")[0].split("<=")[0].split("~=")[0].strip(),
                                version="unpinned",
                                ecosystem="pypi",
                                direct=True,
                                manifest_path=str(req_txt),
                            )
                        )
            except Exception:  # noqa: BLE001, S110
                pass

        return nodes
