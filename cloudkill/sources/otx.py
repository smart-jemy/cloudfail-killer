"""
CloudFail-Killer - AlienVault OTX Source Plugin

Open Threat Exchange (OTX) by AlienVault provides community-driven
threat intelligence including passive DNS data, IP reputation,
and associated indicators for domains.

API: https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from typing import Any

from cloudkill import __version__
from cloudkill.sources.base import BaseSource, IPVersion, SourceResult

logger = logging.getLogger(__name__)


class OTXSource(BaseSource):
    """
    Passive DNS and threat intelligence from AlienVault OTX.

    Free to use with optional API key for higher rate limits.
    Provides historical DNS data that can reveal previous origin IPs.
    """

    name = "otx"
    description = "AlienVault OTX threat intelligence"
    requires_api_key = False
    supports_ipv6 = True
    default_enabled = True

    OTX_API_BASE = "https://otx.alienvault.com/api/v1/indicators/domain"
    TIMEOUT = 30

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        import os
        self._api_key = os.environ.get("OTX_API_KEY", "")

    async def enumerate(
        self, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """
        Query AlienVault OTX for passive DNS data of the target domain.

        Args:
            domain: Target domain

        Yields:
            SourceResult objects with discovered IPs
        """
        import httpx

        headers = {"User-Agent": f"CloudKill/{__version__}"}
        if self._api_key:
            headers["X-OTX-API-KEY"] = self._api_key

        endpoints = [
            f"{self.OTX_API_BASE}/{domain}/passive_dns",
            f"{self.OTX_API_BASE}/{domain}/general",
        ]

        seen_ips: set[str] = set()

        for endpoint_url in endpoints:
            try:
                async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
                    response = await client.get(endpoint_url, headers=headers)

                    if response.status_code == 429:
                        logger.warning("OTX: Rate limited")
                        break

                    if response.status_code == 404:
                        logger.debug("OTX: No data for domain %s", domain)
                        continue

                    response.raise_for_status()
                    data = response.json()

                # Process passive DNS data
                if "passive_dns" in endpoint_url:
                    async for result in self._process_passive_dns(data, domain, seen_ips):
                        yield result

                # Process general data (may contain subdomains/URLs)
                elif "general" in endpoint_url:
                    async for result in self._process_general(data, domain, seen_ips):
                        yield result

            except Exception as e:
                logger.warning("OTX query failed for %s: %s", endpoint_url, e)

        logger.info("OTX discovered %d unique IPs", len(seen_ips))

    async def _process_passive_dns(
        self,
        data: dict[str, Any],
        domain: str,
        seen_ips: set[str],
    ) -> AsyncGenerator[SourceResult, None]:
        """Process OTX passive DNS response."""
        passive_dns = data.get("passive_dns", [])
        if not isinstance(passive_dns, list):
            return

        for record in passive_dns:
            hostname = record.get("hostname", "")
            ip = record.get("ip", "")
            record_type = record.get("record_type", "")

            if not ip or ip in seen_ips:
                continue

            # Filter for A and AAAA records
            if record_type not in ("A", "AAAA"):
                continue

            seen_ips.add(ip)

            ip_version = IPVersion.V6 if ":" in ip else IPVersion.V4

            result = SourceResult(
                subdomain=hostname or domain,
                ip=ip,
                ip_version=ip_version,
                source=self.name,
                is_historical=True,
                confidence_boost=10,
                metadata={
                    "otx_record_type": record_type,
                    "otx_last_seen": record.get("last_seen", ""),
                    "otx_first_seen": record.get("first_seen", ""),
                },
            )
            yield result

    async def _process_general(
        self,
        data: dict[str, Any],
        domain: str,
        seen_ips: set[str],
    ) -> AsyncGenerator[SourceResult, None]:
        """Process OTX general data (extract subdomains from URL list)."""
        # Extract unique hostnames from URL data
        url_list = data.get("url_list", [])
        if not isinstance(url_list, list):
            return

        seen_hostnames: set[str] = set()
        for url_entry in url_list:
            url = url_entry.get("url", "")
            if not url:
                continue

            # Simple hostname extraction from URL
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                hostname = parsed.hostname or ""
            except Exception:
                continue

            if not hostname or hostname in seen_hostnames:
                continue
            if not (hostname == domain or hostname.endswith(f".{domain}")):
                continue

            seen_hostnames.add(hostname)

            # Resolve the discovered hostname
            resolved = await self.resolve_with_fallback(hostname)
            for r in resolved:
                if r.ip not in seen_ips:
                    seen_ips.add(r.ip)
                    r.source = self.name
                    r.is_historical = True
                    r.confidence_boost = 8
                    yield r
