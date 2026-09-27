"""
CloudFail-Killer - Wayback CDX Source Plugin

Historical web archive data from the Wayback Machine CDX API.

The Wayback Machine (archive.org) stores historical snapshots of websites.
The CDX API allows searching for archived URLs which can reveal:
- Historical subdomains
- Previous IP addresses (via archived responses)
- Technology fingerprints

CDX API: http://web.archive.org/cdx/search/cdx?url=*.example.com&output=json&fl=original
"""

from __future__ import annotations

import logging
import urllib.parse
from collections.abc import AsyncGenerator

from cloudkill import __version__
from cloudkill.sources.base import BaseSource, SourceResult

logger = logging.getLogger(__name__)


class WaybackSource(BaseSource):
    """
    Historical subdomain discovery via Wayback Machine CDX API.

    Free service. Can reveal subdomains that existed historically
    but may no longer be active. These historical subdomains may
    still resolve to the origin IP.
    """

    name = "wayback"
    description = "Historical web archive (Wayback Machine CDX)"
    requires_api_key = False
    supports_ipv6 = True
    default_enabled = True

    CDX_API = "http://web.archive.org/cdx/search/cdx"
    TIMEOUT = 30
    MAX_PAGES = 5  # Limit API calls to prevent abuse

    async def enumerate(
        self, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """
        Search Wayback Machine for historical URLs under the target domain.

        Uses the CDX API to find archived URLs, extracts unique subdomains,
        and resolves them to current IP addresses.

        Args:
            domain: Target domain

        Yields:
            SourceResult objects with discovered IPs
        """
        import httpx

        seen: set[str] = set()
        total_results = 0

        # Start from position 0 and paginate
        for page in range(self.MAX_PAGES):
            params = {
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": 1000,
                "offset": page * 1000,
            }

            try:
                async with httpx.AsyncClient(timeout=self.TIMEOUT, follow_redirects=True) as client:
                    response = await client.get(
                        self.CDX_API,
                        params=params,
                        headers={"User-Agent": f"CloudKill/{__version__}"},
                    )

                    if response.status_code == 429:
                        logger.warning("Wayback: Rate limited")
                        break

                    response.raise_for_status()
                    lines = response.text.strip().split("\n")

            except Exception as e:
                logger.error("Wayback CDX query failed: %s", e)
                break

            if not lines:
                break

            # Skip header row (first line is ["original"])
            new_count = 0
            for line in lines[1:]:
                line = line.strip().strip('"').strip("[]")
                if not line or line == "original":
                    continue

                # Extract hostname from URL
                try:
                    if line.startswith("http"):
                        parsed = urllib.parse.urlparse(line)
                        hostname = parsed.hostname or ""
                    else:
                        hostname = line.split("/")[0]
                except Exception:
                    continue

                hostname = hostname.strip().lower()
                if not hostname or hostname in seen:
                    continue

                # Remove port number if present
                if ":" in hostname and not hostname.startswith("["):
                    hostname = hostname.split(":")[0]

                # Must be under target domain
                if not (hostname == domain or hostname.endswith(f".{domain}")):
                    continue

                seen.add(hostname)

                # Resolve to IPs
                resolved = await self.resolve_with_fallback(hostname)
                for r in resolved:
                    r.source = self.name
                    r.is_historical = True
                    r.confidence_boost = 5
                    r.metadata["wayback_url"] = line[:200]  # Truncate long URLs
                    new_count += 1
                    yield r

            total_results += new_count

            # If we got fewer than the page limit, we've reached the end
            if new_count < 500:
                break

            logger.info(
                "Wayback: Page %d, found %d new subdomains (total unique: %d)",
                page + 1, new_count, len(seen),
            )

        logger.info("Wayback: Total %d unique subdomains, %d IPs resolved", len(seen), total_results)
