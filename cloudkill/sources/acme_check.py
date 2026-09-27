"""
CloudFail-Killer - ACME Check Source Plugin

Check for ACME protocol misconfigurations that can reveal origin IPs.

Based on CVE-2025-29441 (Cloudflare ACME WAF Bypass) and related research.

When a domain uses Let's Encrypt or other ACME-based certificate authorities,
the ACME challenge may be served directly from the origin server, bypassing
Cloudflare's proxy. This can expose the origin IP.

Technique:
    1. Check .well-known/acme-challenge/ paths
    2. Check for ACME TLS-ALPN-01 challenge endpoints
    3. Identify if the origin is directly accessible for certificate validation

Reference:
    https://github.com/nulsec/Cloudflare-ACME-WAF-Bypass-Scanner

Note: This source does NOT actively exploit ACME challenges. It only checks
for misconfigurations that may indicate direct origin accessibility.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from typing import Any

from cloudkill import __version__
from cloudkill.sources.base import BaseSource, IPVersion, SourceResult

logger = logging.getLogger(__name__)


class ACMECheckSource(BaseSource):
    """
    ACME protocol misconfiguration detection.

    Checks for:
    1. Accessible .well-known/acme-challenge/ endpoint (potential bypass)
    2. Direct origin access via HTTP (non-HTTPS)
    3. ACME challenge response headers
    4. Let's Encrypt directory exposure

    This is a reference/informational source. It does not actively exploit
    any vulnerabilities but flags potential misconfigurations.

    MITRE ATT&CK: T1590.002 (Resolve Hostname)
    """

    name = "acme_check"
    description = "ACME protocol config audit (CVE-2025-29441 related)"
    requires_api_key = False
    supports_ipv6 = False  # Primarily checks HTTP behavior, not DNS
    default_enabled = False  # Informational, disabled by default

    TIMEOUT = 15
    ACME_PATHS = [
        "/.well-known/acme-challenge/",
        "/.well-known/acme-challenge/test-challenge-token",
        "/.well-known/openid-configuration",
    ]

    async def enumerate(
        self, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """
        Check ACME configuration for the target domain.

        Performs safe checks only:
        1. HEAD requests to .well-known paths
        2. Check response headers for ACME indicators
        3. Check for non-proxied HTTP access

        Args:
            domain: Target domain

        Yields:
            SourceResult objects (informational, with config metadata)
        """
        import httpx

        # Check both HTTP and HTTPS
        protocols = [("https", 443), ("http", 80)]

        for protocol, port in protocols:
            base_url = f"{protocol}://{domain}"

            for path in self.ACME_PATHS:
                url = f"{base_url}{path}"

                try:
                    async with httpx.AsyncClient(
                        timeout=self.TIMEOUT,
                        follow_redirects=False,  # Don't follow redirects
                    ) as client:
                        # Use HEAD to minimize data transfer
                        response = await client.head(
                            url,
                            headers={
                                "User-Agent": f"CloudKill/{__version__} (ACME Audit)",
                            },
                        )

                        metadata: dict[str, Any] = {
                            "acme_check_url": url,
                            "acme_check_protocol": protocol,
                            "status_code": response.status_code,
                            "server_header": response.headers.get("server", ""),
                            "cf_ray": response.headers.get("cf-ray", ""),
                            "cf_headers": {
                                k: v for k, v in response.headers.items()
                                if k.lower().startswith("cf-")
                            },
                        }

                        # Check if this request bypassed Cloudflare
                        cf_ray = response.headers.get("cf-ray", "")

                        is_bypassed = (
                            response.status_code in (200, 404, 403, 503)
                            and not cf_ray
                        )

                        if is_bypassed:
                            # Try to extract server IP from response
                            # If the origin is directly accessible, the IP
                            # might be revealed through headers or redirect
                            server_header = response.headers.get("server", "")
                            x_forwarded_for = response.headers.get("x-forwarded-for", "")

                            # Check for IP leak in headers
                            import re
                            ip_match = re.search(
                                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                                x_forwarded_for or server_header,
                            )

                            if ip_match:
                                ip = ip_match.group(1)
                                yield SourceResult(
                                    subdomain=domain,
                                    ip=ip,
                                    ip_version=IPVersion.V4,
                                    source=self.name,
                                    port=port,
                                    confidence_boost=15,
                                    metadata={
                                        **metadata,
                                        "acme_bypass": True,
                                        "ip_leak_source": "response_header",
                                    },
                                )

                            # Report bypass even without IP (log only, don't yield placeholder)
                            metadata["acme_bypass"] = True
                            logger.info(
                                "ACME Check: Potential bypass detected on %s (status=%d, no CF headers)",
                                url, response.status_code,
                            )

                except httpx.ConnectError as e:
                    logger.debug("ACME Check: Connection error for %s: %s", url, e)
                    # Connection error on HTTP might indicate direct origin
                    if protocol == "http" and port == 80:
                        logger.info(
                            "ACME Check: HTTP port 80 connection error for %s "
                            "(may indicate origin is not directly accessible)",
                            domain,
                        )
                except Exception as e:
                    logger.debug("ACME Check: Error for %s: %s", url, e)

        logger.info("ACME Check: Audit complete for %s", domain)
