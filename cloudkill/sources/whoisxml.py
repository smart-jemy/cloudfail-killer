"""
CloudFail-Killer - WhoisXML Source Plugin

WHOIS and DNS data from WhoisXML API (whoisxmlapi.com).

Provides comprehensive WHOIS data, DNS records, and domain registration
information that can reveal infrastructure details.

Free tier: 500 queries (one-time).

API: https://www.whoisxmlapi.com/whoisserver/WhoisService
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncGenerator
from typing import Any

from cloudkill import __version__
from cloudkill.sources.base import BaseSource, IPVersion, SourceResult

logger = logging.getLogger(__name__)


class WhoisXMLSource(BaseSource):
    """
    WHOIS and DNS data from WhoisXML API.

    Provides domain registration details and DNS records.
    Free tier: 500 one-time queries. Requires API key.

    Key intelligence:
    - Registrar information
    - Name servers (with IPs)
    - DNS records
    - Historical WHOIS data
    """

    name = "whoisxml"
    description = "WHOIS/DNS data (WhoisXML API)"
    requires_api_key = True
    supports_ipv6 = True
    default_enabled = False  # Requires API key

    WHOISXML_API = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    DNS_API = "https://www.whoisxmlapi.com/whoisserver/DnsService"
    TIMEOUT = 30

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._api_key = os.environ.get("WHOISXML_API_KEY", "")

    def is_configured(self) -> bool:
        """Check if WhoisXML API key is available."""
        return bool(self._api_key)

    async def enumerate(
        self, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """
        Query WhoisXML for WHOIS and DNS data.

        Performs:
        1. WHOIS lookup for registration details
        2. DNS record query for A/AAAA records

        Args:
            domain: Target domain

        Yields:
            SourceResult objects with discovered IPs
        """
        if not self.is_configured():
            logger.info("WhoisXML: No API key configured (set WHOISXML_API_KEY)")
            return

        import httpx

        seen_ips: set[str] = set()

        # Query WHOIS data
        whois_params = {
            "apiKey": self._api_key,
            "domainName": domain,
            "outputFormat": "JSON",
        }

        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
                response = await client.get(
                    self.WHOISXML_API,
                    params=whois_params,
                    headers={"User-Agent": f"CloudKill/{__version__}"},
                )

                if response.status_code == 401:
                    logger.warning("WhoisXML: Invalid API key")
                    return

                if response.status_code == 429:
                    logger.warning("WhoisXML: Rate limited or quota exceeded")
                    return

                response.raise_for_status()
                data = response.json()

            # Extract nameserver IPs from WHOIS
            whois_data = data.get("WhoisRecord", {})
            name_servers = whois_data.get("nameServers", {}).get("hostNames", [])

            for ns in name_servers:
                if isinstance(ns, str) and ns.strip():
                    resolved = await self.resolve_with_fallback(ns.strip())
                    for r in resolved:
                        if r.ip not in seen_ips:
                            seen_ips.add(r.ip)
                            r.source = self.name
                            r.confidence_boost = 3
                            r.metadata["whoisxml_source"] = "nameserver"
                            yield r

            # Extract registrant data for metadata (no IP yield)
            registrant = whois_data.get("registrant", {})
            if registrant:
                logger.debug(
                    "WhoisXML: Registrar=%s, Org=%s",
                    registrant.get("registrarName", "N/A"),
                    registrant.get("organization", "N/A"),
                )

        except Exception as e:
            logger.error("WhoisXML WHOIS query failed: %s", e)

        # Query DNS records
        dns_params = {
            "apiKey": self._api_key,
            "domainName": domain,
            "type": "A",
            "outputFormat": "JSON",
        }

        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
                # Query A records
                dns_params["type"] = "A"
                response = await client.get(
                    self.DNS_API,
                    params=dns_params,
                    headers={"User-Agent": f"CloudKill/{__version__}"},
                )

                if response.status_code == 200:
                    data = response.json()
                    a_records = data.get("DnsRecords", {}).get("A", [])

                    for record in a_records:
                        ip = record.get("address", "")
                        if ip and ip not in seen_ips:
                            seen_ips.add(ip)
                            yield SourceResult(
                                subdomain=domain,
                                ip=ip,
                                ip_version=IPVersion.V4,
                                source=self.name,
                                confidence_boost=3,
                                metadata={"whoisxml_source": "dns_a"},
                            )

                # Query AAAA records
                dns_params["type"] = "AAAA"
                response = await client.get(
                    self.DNS_API,
                    params=dns_params,
                    headers={"User-Agent": f"CloudKill/{__version__}"},
                )

                if response.status_code == 200:
                    data = response.json()
                    aaaa_records = data.get("DnsRecords", {}).get("AAAA", [])

                    for record in aaaa_records:
                        ip = record.get("address", "")
                        if ip and ip not in seen_ips:
                            seen_ips.add(ip)
                            yield SourceResult(
                                subdomain=domain,
                                ip=ip,
                                ip_version=IPVersion.V6,
                                source=self.name,
                                confidence_boost=3,
                                metadata={"whoisxml_source": "dns_aaaa"},
                            )

        except Exception as e:
            logger.error("WhoisXML DNS query failed: %s", e)

        logger.info("WhoisXML: %d unique IPs discovered", len(seen_ips))
