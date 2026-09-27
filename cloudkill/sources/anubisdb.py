"""
CloudFail-Killer - AnubisDB Source Plugin

Passive DNS data from AnubisDB (jonlu.ca/anubis).

AnubisDB aggregates subdomain data from multiple passive DNS sources.
Free to use, no API key required.

API: https://jldc.me/anubis/subdomains/{domain}
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator

from cloudkill import __version__
from cloudkill.sources.base import BaseSource, SourceResult

logger = logging.getLogger(__name__)


class AnubisDBSource(BaseSource):
    """
    Passive DNS subdomain enumeration via AnubisDB.

    Free service that aggregates passive DNS data.
    Returns list of subdomains which we then resolve to IPs.
    """

    name = "anubisdb"
    description = "Passive DNS database (AnubisDB)"
    requires_api_key = False
    supports_ipv6 = True
    default_enabled = True

    ANUBISDB_API = "https://jldc.me/anubis/subdomains/"
    ANUBISDB_API_NEW = "https://jonlu.ca/anubis/subdomains/"
    TIMEOUT = 30

    async def enumerate(
        self, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """
        Query AnubisDB for subdomains of the target domain.

        Args:
            domain: Target domain

        Yields:
            SourceResult objects with resolved IPs
        """
        import httpx

        url = f"{self.ANUBISDB_API}{domain}"

        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT, follow_redirects=True) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": f"CloudKill/{__version__}"},
                )

                if response.status_code == 429:
                    logger.warning("AnubisDB: Rate limited")
                    return

                response.raise_for_status()
                data = response.json()

        except Exception as e:
            logger.error("AnubisDB query failed: %s", e)
            return

        if not isinstance(data, list):
            logger.warning("AnubisDB: Unexpected response format")
            return

        seen: set[str] = set()
        count = 0

        for subdomain in data:
            if not isinstance(subdomain, str):
                continue

            subdomain = subdomain.strip().lower()
            if not subdomain or subdomain in seen:
                continue

            # Filter wildcards
            if subdomain.startswith("*"):
                continue

            # Must be under the target domain
            if not (subdomain == domain or subdomain.endswith(f".{domain}")):
                continue

            seen.add(subdomain)

            resolved = await self.resolve_with_fallback(subdomain)
            for r in resolved:
                r.source = self.name
                count += 1
                yield r

        logger.info("AnubisDB found %d subdomains, resolved to %d IPs", len(seen), count)
