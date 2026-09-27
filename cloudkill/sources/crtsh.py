"""
CloudFail-Killer - crt.sh Source Plugin

Certificate Transparency log search via crt.sh API.
crt.sh provides free access to certificate transparency logs operated by Comodo.

Note: crt.sh can be slow/degraded at times. This plugin uses:
- Extended timeout (60s)
- Retry logic
- Identity-based deduplication for cert results

API: https://crt.sh/?q=%.domain.com&output=json
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator
from typing import Any

from cloudkill import __version__
from cloudkill.sources.base import BaseSource, SourceResult

logger = logging.getLogger(__name__)


class CRTShSource(BaseSource):
    """
    Certificate Transparency log search via crt.sh.

    Free, no API key required. Can return thousands of subdomains
    for popular domains. Known to be slow at times - uses extended
    timeout and retry logic.
    """

    name = "crtsh"
    description = "Certificate Transparency logs (crt.sh)"
    requires_api_key = False
    supports_ipv6 = True
    default_enabled = True

    CRTSH_API = "https://crt.sh/"
    TIMEOUT = 60  # crt.sh can be slow
    MAX_RETRIES = 3
    RETRY_DELAYS = [5, 15, 30]  # Exponential backoff for retries

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._session = None

    async def enumerate(
        self, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """
        Search crt.sh for certificates issued to the target domain.

        Queries certificate transparency logs for any certificate containing
        the domain name, extracts subdomains, and resolves them to IPs.

        Args:
            domain: Target domain (e.g., "example.com")

        Yields:
            SourceResult objects with discovered subdomains and IPs
        """
        query_domain = f"%.{domain}"

        for attempt in range(self.MAX_RETRIES):
            try:
                results = await self._query_crsh(domain, query_domain)
                if results:
                    for result in results:
                        yield result
                    return

                # Empty result, retry if we have retries left
                if attempt < self.MAX_RETRIES - 1:
                    delay = self.RETRY_DELAYS[attempt]
                    logger.info(
                        "crt.sh returned empty results, retrying in %ds (attempt %d/%d)",
                        delay, attempt + 1, self.MAX_RETRIES,
                    )
                    await asyncio.sleep(delay)

            except Exception as e:
                if attempt < self.MAX_RETRIES - 1:
                    delay = self.RETRY_DELAYS[attempt]
                    logger.warning(
                        "crt.sh query failed (attempt %d/%d): %s, retrying in %ds",
                        attempt + 1, self.MAX_RETRIES, e, delay,
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error("crt.sh all retries exhausted: %s", e)

    async def _query_crsh(
        self, domain: str, query_domain: str
    ) -> list[SourceResult]:
        """Query crt.sh API and process results."""
        import httpx

        params = {
            "q": query_domain,
            "output": "json",
        }

        async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
            response = await client.get(
                self.CRTSH_API,
                params=params,
                headers={"User-Agent": f"CloudKill/{__version__}"},
            )

            if response.status_code == 429:
                logger.warning("crt.sh rate limited, waiting 30s")
                await asyncio.sleep(30)
                return []

            if response.status_code == 503:
                logger.warning("crt.sh service unavailable")
                return []

            response.raise_for_status()
            data = response.json()

        # Parse and deduplicate subdomains
        seen_names: set[str] = set()
        results: list[SourceResult] = []

        for entry in data:
            # entry has 'name_value' which can contain multiple names separated by newlines
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if not name or name in seen_names:
                    continue

                # Filter: must end with domain
                if not name.endswith(domain) and name != domain:
                    continue

                # Filter out wildcard entries
                if name.startswith("*"):
                    continue

                seen_names.add(name)

                # Resolve the subdomain
                resolved = await self.resolve_with_fallback(name)
                for r in resolved:
                    r.source = self.name
                    r.metadata["crtsh_entry"] = {
                        "issuer_ca_id": entry.get("issuer_ca_id"),
                        "not_before": entry.get("not_before"),
                        "not_after": entry.get("not_after"),
                    }
                    results.append(r)

        logger.info(
            "crt.sh found %d unique subdomains, resolved to %d IPs",
            len(seen_names), len(results),
        )
        return results
