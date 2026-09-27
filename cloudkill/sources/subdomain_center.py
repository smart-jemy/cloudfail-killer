"""
CloudFail-Killer - SubdomainCenter Source Plugin

Aggregated subdomain intelligence from Subdomain.Center.

The service aggregates subdomain data from dozens of public sources
(passive DNS, CT logs, crawls). Free to query, no API key required.

Endpoint: https://api.subdomain.center/?domain={domain}
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator

from cloudkill import __version__
from cloudkill.sources.base import BaseSource, SourceResult

logger = logging.getLogger(__name__)


class SubdomainCenterSource(BaseSource):
    """
    Aggregated subdomain enumeration via Subdomain.Center.

    Returns a JSON array of subdomains which are then resolved
    (A + AAAA) to candidate origin IPs. Results are capped to keep
    DNS resolution time bounded.
    """

    name = "subdomain_center"
    description = "Aggregated subdomain intelligence (Subdomain.Center)"
    requires_api_key = False
    supports_ipv6 = True
    default_enabled = True

    API_URL = "https://api.subdomain.center/"
    TIMEOUT = 45
    MAX_SUBDOMAINS = 200

    async def enumerate(
        self, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """
        Query Subdomain.Center and resolve discovered subdomains.

        Args:
            domain: Target domain

        Yields:
            SourceResult objects with resolved IPs
        """
        import httpx

        url = f"{self.API_URL}?domain={domain}"

        try:
            async with httpx.AsyncClient(
                timeout=self.TIMEOUT, follow_redirects=True
            ) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": f"CloudKill/{__version__}"},
                )

                if response.status_code == 429:
                    logger.warning("SubdomainCenter: Rate limited")
                    return

                response.raise_for_status()
                data = response.json()

        except Exception as e:
            logger.error("SubdomainCenter query failed: %s", e)
            return

        if not isinstance(data, list):
            logger.warning("SubdomainCenter: Unexpected response format")
            return

        seen: set[str] = set()
        resolved_count = 0

        for entry in data[: self.MAX_SUBDOMAINS]:
            if not isinstance(entry, str):
                continue

            subdomain = entry.strip().lower().rstrip(".")
            if not subdomain or subdomain in seen:
                continue

            if subdomain.startswith("*"):
                continue

            # Only accept entries under the target domain
            if not (subdomain == domain or subdomain.endswith(f".{domain}")):
                continue

            seen.add(subdomain)

            resolved = await self.resolve_with_fallback(subdomain)
            for r in resolved:
                r.source = self.name
                resolved_count += 1
                yield r

        logger.info(
            "SubdomainCenter: %d subdomains processed, %d IPs resolved",
            len(seen),
            resolved_count,
        )
