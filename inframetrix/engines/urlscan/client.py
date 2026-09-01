"""urlscan.io API client with policy enforcement and secret redaction."""

from __future__ import annotations

import json
import time
import urllib.request
from typing import Any

from inframetrix.core.cancellation import CancellationToken
from inframetrix.security.secrets_store import SecretsStore
from inframetrix.security.target_policy import TargetPolicy


class UrlscanClient:
    """Official API client for urlscan.io automated submissions and report retrieval."""

    BASE_URL = "https://urlscan.io/api/v1"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or SecretsStore.get_secret("URLSCAN_API_KEY")

    def submit_url(
        self,
        url: str,
        visibility: str = "unlisted",
        target_policy: TargetPolicy | None = None,
    ) -> str:
        """Submit URL for scanning. Returns scan uuid."""
        # 1. Enforce policy check (prevents leaking internal tokens, localhost, private IP)
        policy = target_policy or TargetPolicy()
        policy.validate_target(url)

        # 2. Never submit with public by default
        effective_visibility = visibility if visibility in ("unlisted", "private", "public") else "unlisted"

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "InfraMetrix-AppSec-Workstation/0.1.0",
        }
        if self.api_key:
            headers["API-Key"] = self.api_key

        payload = json.dumps({"url": url, "visibility": effective_visibility}).encode("utf-8")
        req = urllib.request.Request(f"{self.BASE_URL}/scan/", data=payload, headers=headers, method="POST")

        with urllib.request.urlopen(req, timeout=15.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["uuid"]

    def poll_result(
        self,
        scan_id: str,
        max_wait_seconds: int = 45,
        cancellation_token: CancellationToken | None = None,
    ) -> dict[str, Any]:
        """Poll urlscan.io for scan completion."""
        start_time = time.monotonic()
        req = urllib.request.Request(
            f"{self.BASE_URL}/result/{scan_id}/",
            headers={"User-Agent": "InfraMetrix-AppSec-Workstation/0.1.0"},
        )

        while time.monotonic() - start_time < max_wait_seconds:
            if cancellation_token and cancellation_token.is_cancelled:
                raise TimeoutError("URL scan polling was cancelled.")

            try:
                with urllib.request.urlopen(req, timeout=10.0) as resp:
                    if resp.status == 200:
                        return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    # Still scanning
                    time.sleep(3.0)
                    continue
                raise
            except Exception:  # noqa: BLE001
                time.sleep(3.0)
                continue

        raise TimeoutError(f"urlscan.io result timed out after {max_wait_seconds}s for {scan_id}")
