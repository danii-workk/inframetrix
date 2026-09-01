"""Normalizer transforming urlscan.io JSON responses into Unified Findings."""

from __future__ import annotations

from typing import Any

from inframetrix.models.finding import Finding
from inframetrix.models.scan_result import ScanResult, ToolRun


class UrlscanNormalizer:
    """Extracts security indicators and vulnerabilities from urlscan.io data."""

    @classmethod
    def normalize(cls, data: dict[str, Any], url: str) -> ScanResult:
        findings: list[Finding] = []
        page = data.get("page", {})
        verdicts = data.get("verdicts", {})
        overall_verdict = verdicts.get("overall", {})
        malicious = overall_verdict.get("malicious", False)
        score = overall_verdict.get("score", 0)

        # 1. Malicious verdict
        if malicious or score > 0:
            findings.append(
                Finding(
                    id="urlscan-malicious-verdict",
                    title=f"urlscan.io verdict: Malicious (Score {score})",
                    description=f"urlscan.io classified {url} with a malicious verdict (score {score}).",
                    message="Malicious activity detected by threat intelligence engines.",
                    severity="critical" if score >= 50 else "high",
                    confidence="high",
                    category="urlscan",
                    source_engine="urlscan",
                    url=url,
                    recommendation="Investigate flagged domain indicators and associated network requests.",
                    tags=["urlscan", "threat-intel", "malicious"],
                )
            )

        # 2. TLS/Certificate checks
        tls_issuer = page.get("tlsIssuer", "")
        tls_valid_days = page.get("tlsValidDays", 0)
        if tls_valid_days and tls_valid_days < 0:
            findings.append(
                Finding(
                    id="urlscan-expired-tls-cert",
                    title="Expired TLS Certificate",
                    description=f"TLS certificate issued by '{tls_issuer}' is expired.",
                    message="Expired SSL/TLS certificate on target.",
                    severity="high",
                    confidence="high",
                    category="urlscan",
                    source_engine="urlscan",
                    url=url,
                    recommendation="Renew the SSL/TLS certificate immediately.",
                    tags=["urlscan", "tls", "crypto"],
                )
            )

        # 3. Open directory / status checks
        status_code = page.get("status")
        if status_code and status_code >= 500:
            findings.append(
                Finding(
                    id="urlscan-server-error",
                    title=f"Target returned HTTP {status_code} server error",
                    description=f"Initial response returned HTTP status {status_code}.",
                    message=f"HTTP {status_code} internal error",
                    severity="low",
                    confidence="high",
                    category="urlscan",
                    source_engine="urlscan",
                    url=url,
                    tags=["urlscan", "availability"],
                )
            )

        screenshot_url = data.get("task", {}).get("screenshotURL") or data.get("screenshotURL")

        return ScanResult(
            engine_name="urlscan",
            findings=findings,
            tool_run=ToolRun(
                tool_name="urlscan",
                tool_version="v1",
                status="completed",
            ),
            metadata={
                "screenshot_url": screenshot_url,
                "ip": page.get("ip"),
                "country": page.get("country"),
                "asn": page.get("asn"),
                "asn_name": page.get("asnname"),
                "server": page.get("server"),
            },
        )
