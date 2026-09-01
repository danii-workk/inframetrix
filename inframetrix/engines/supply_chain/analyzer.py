"""Supply Chain & CI/CD Security Adapter."""

from __future__ import annotations

from datetime import UTC, datetime

from inframetrix import __version__
from inframetrix.core.cancellation import CancellationToken
from inframetrix.core.scan_context import ScanContext
from inframetrix.engines.supply_chain.ci_security import CISecurityAnalyzer
from inframetrix.engines.supply_chain.package_reputation import PackageReputationAnalyzer
from inframetrix.models.finding import Finding
from inframetrix.models.scan_result import ScanResult, ToolRun


class SupplyChainAdapter:
    """Built-in Supply Chain and CI/CD Pipeline security analyzer."""

    name = "supply-chain"
    category = "supply_chain"
    is_builtin = True
    install_hint = "Built into InfraMetrix."

    def available(self) -> bool:
        return True

    def version(self) -> str:
        return __version__

    def scan(
        self,
        context: ScanContext,
        cancellation_token: CancellationToken | None = None,
    ) -> ScanResult:
        started_at = datetime.now(UTC)
        findings: list[Finding] = []

        # 1. CI/CD security audit
        ci_findings = CISecurityAnalyzer.audit_project_workflows(context.project_path)
        findings.extend(ci_findings)

        if cancellation_token and cancellation_token.is_cancelled:
            return ScanResult(
                engine_name=self.name,
                findings=[],
                tool_run=ToolRun(
                    tool_name=self.name,
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                    status="cancelled",
                ),
            )

        # 2. Package reputation & lockfile audit
        pkg_findings = PackageReputationAnalyzer.audit_dependencies(context.project_path)
        findings.extend(pkg_findings)

        return ScanResult(
            engine_name=self.name,
            findings=findings,
            tool_run=ToolRun(
                tool_name=self.name,
                tool_version=self.version(),
                started_at=started_at,
                finished_at=datetime.now(UTC),
                status="completed",
            ),
        )
