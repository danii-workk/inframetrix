"""OWASP ZAP DAST adapter with strict TargetPolicy enforcement."""

from __future__ import annotations

import json
from urllib.parse import urlparse

from inframetrix.core.cancellation import CancellationToken
from inframetrix.core.exceptions import TargetPolicyViolationError
from inframetrix.core.scan_context import ScanContext
from inframetrix.models.finding import Finding
from inframetrix.models.scan_result import ScanResult, ToolRun
from inframetrix.security.target_policy import TargetPolicy


class ZAPAdapter:
    """Dynamic Application Security Testing adapter integrating OWASP ZAP."""

    name = "zap-dast"
    category = "dast"
    is_builtin = False
    install_hint = "Run OWASP ZAP locally with `-daemon -port 8080` or use Docker: `docker run -u zap -p 8080:8080 -d ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true`"

    def __init__(self, zap_base_url: str = "http://localhost:8080") -> None:
        self.zap_base_url = zap_base_url

    def available(self) -> bool:
        """Check if ZAP daemon API is reachable."""
        try:
            import urllib.request

            req = urllib.request.Request(f"{self.zap_base_url}/JSON/core/view/version/")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                return resp.status == 200
        except Exception:  # noqa: BLE001
            return False

    def version(self) -> str | None:
        try:
            import urllib.request

            req = urllib.request.Request(f"{self.zap_base_url}/JSON/core/view/version/")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("version")
        except Exception:  # noqa: BLE001
            return None

    def scan(
        self,
        context: ScanContext,
        cancellation_token: CancellationToken | None = None,
    ) -> ScanResult:
        target_url = context.target_url or context.options.get("target_url")
        if not target_url:
            return ScanResult(
                engine_name=self.name,
                findings=[],
                tool_run=ToolRun(
                    tool_name=self.name,
                    status="skipped",
                    error_message="No target_url specified for DAST scan.",
                ),
            )

        # 1. Target policy authorization check
        allowed_hosts = context.options.get("allowed_hosts", [])
        policy = TargetPolicy(
            allowed_hosts=allowed_hosts,
            allow_private_ips=context.options.get("allow_private_ips", False),
            allow_active_scan=context.options.get("allow_active_scan", False),
        )

        try:
            policy.validate_target(target_url)
        except TargetPolicyViolationError as exc:
            return ScanResult(
                engine_name=self.name,
                findings=[],
                tool_run=ToolRun(
                    tool_name=self.name,
                    status="failed",
                    error_message=f"TargetPolicy violation: {exc}",
                ),
            )

        if not self.available():
            return ScanResult(
                engine_name=self.name,
                findings=[],
                tool_run=ToolRun(
                    tool_name=self.name,
                    status="unavailable",
                    error_message="OWASP ZAP daemon is not running on localhost:8080.",
                ),
            )

        # 2. Fetch ZAP Alerts for target
        findings: list[Finding] = []
        try:
            import urllib.parse
            import urllib.request

            encoded_url = urllib.parse.quote(target_url, safe="")
            req = urllib.request.Request(
                f"{self.zap_base_url}/JSON/alert/view/alerts/?baseurl={encoded_url}"
            )
            with urllib.request.urlopen(req, timeout=15.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                alerts = data.get("alerts", [])

                sev_map = {
                    "high": "high",
                    "medium": "medium",
                    "low": "low",
                    "informational": "info",
                }

                for alert in alerts:
                    plugin_id = alert.get("pluginId", "zap-alert")
                    alert_name = alert.get("alert", "ZAP Alert")
                    risk_str = alert.get("risk", "Medium").lower()
                    url_val = alert.get("url", target_url)
                    parsed_u = urlparse(url_val)
                    cwe_id = alert.get("cweid")

                    findings.append(
                        Finding(
                            id=f"zap-{plugin_id}",
                            title=f"DAST: {alert_name}",
                            description=alert.get("description", ""),
                            message=f"{alert_name} detected at {parsed_u.path or '/'}",
                            severity=sev_map.get(risk_str, "medium"),  # type: ignore[arg-type]
                            confidence="high",
                            category="dast",
                            source_engine=self.name,
                            url=url_val,
                            endpoint=parsed_u.path,
                            http_method=alert.get("method"),
                            cwe=f"CWE-{cwe_id}" if cwe_id and int(cwe_id) > 0 else None,
                            evidence=alert.get("evidence"),
                            recommendation=alert.get("solution"),
                            references=[alert.get("reference")] if alert.get("reference") else [],
                            tags=["dast", "zap", "web"],
                        )
                    )
        except Exception as exc:  # noqa: BLE001
            return ScanResult(
                engine_name=self.name,
                findings=[],
                tool_run=ToolRun(
                    tool_name=self.name,
                    status="failed",
                    error_message=f"ZAP communication error: {exc}",
                ),
            )

        return ScanResult(
            engine_name=self.name,
            findings=findings,
            tool_run=ToolRun(
                tool_name=self.name,
                tool_version=self.version(),
                status="completed",
            ),
        )
