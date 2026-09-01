"""DAST & URL analysis target scope validation policy."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from inframetrix.core.exceptions import TargetPolicyViolationError


class TargetPolicy:
    """Enforces authorization boundaries for web scanning and URL submissions."""

    def __init__(
        self,
        allowed_hosts: list[str] | None = None,
        allow_private_ips: bool = False,
        allow_active_scan: bool = False,
    ) -> None:
        self.allowed_hosts = [h.lower() for h in (allowed_hosts or [])]
        self.allow_private_ips = allow_private_ips
        self.allow_active_scan = allow_active_scan

    def validate_target(self, url: str) -> None:
        """Validate if target URL is within allowed authorization scope."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise TargetPolicyViolationError(
                f"Invalid URL scheme '{parsed.scheme}'. Only http:// and https:// are supported."
            )

        hostname = parsed.hostname
        if not hostname:
            raise TargetPolicyViolationError(f"Target URL '{url}' lacks a valid hostname.")

        hostname = hostname.lower()

        # Check for sensitive query parameters that shouldn't be submitted externally
        query = parsed.query.lower()
        for sensitive_token in ("token=", "api_key=", "password=", "secret=", "auth=", "session="):
            if sensitive_token in query:
                raise TargetPolicyViolationError(
                    f"URL contains sensitive credential query parameter '{sensitive_token}'. Redact before scanning."
                )

        # Check private IPs / localhost
        if not self.allow_private_ips:
            if hostname in ("localhost", "127.0.0.1", "::1"):
                raise TargetPolicyViolationError(
                    "Localhost scanning is restricted under default policy. Explicitly authorize private addresses."
                )
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_private or ip.is_loopback:
                    raise TargetPolicyViolationError(
                        f"Target IP '{hostname}' is a private RFC1918/loopback address. Explicit authorization required."
                    )
            except ValueError:
                # Not a literal IP address
                pass

        if self.allowed_hosts and hostname not in self.allowed_hosts:
            raise TargetPolicyViolationError(
                f"Hostname '{hostname}' is not in the allowed targets list: {self.allowed_hosts}"
            )
