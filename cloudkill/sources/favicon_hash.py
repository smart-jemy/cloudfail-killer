"""
CloudFail-Killer - Favicon Hash Source Plugin

Favicon fingerprinting via MurmurHash3 (mmh3) for Shodan/Censys search.

This is the #1 rated technique for origin IP discovery in 2026:
1. Fetch the favicon from the target domain
2. Compute its MurmurHash3 hash
3. Search Shodan/Censys for servers with the same hash
4. Non-Cloudflare matches are potential origin IPs

This technique works because the favicon is often identical between
the Cloudflare proxy and the origin server.

References:
    - https://github.com/devanshbatham/FavFreak
    - https://shodan.io/blog/exploring-shodans-favicon-hashing/
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncGenerator
from typing import Any

from cloudkill import __version__
from cloudkill.sources.base import BaseSource, IPVersion, SourceResult
from cloudkill.utils.cloudflare_ips import CloudflareIPChecker

logger = logging.getLogger(__name__)


class FaviconHashSource(BaseSource):
    """
    Favicon fingerprinting for origin IP discovery via Shodan/Censys.

    Process:
    1. Download favicon from target domain (try multiple common paths)
    2. Compute MurmurHash3 hash
    3. Search Shodan API for matching servers
    4. Filter out Cloudflare IPs
    5. Return non-CF matches as potential origin IPs

    Requires either SHODAN_API_KEY or CENSYS_API_ID + CENSYS_API_SECRET.
    """

    name = "favicon_hash"
    description = "Favicon fingerprinting via Shodan/Censys (CRITICAL)"
    requires_api_key = True
    supports_ipv6 = True
    default_enabled = True  # Enabled but needs API key

    TIMEOUT = 15
    MAX_SHODAN_RESULTS = 100

    # Common favicon paths to try
    FAVICON_PATHS = [
        "/favicon.ico",
        "/favicon.png",
        "/favicon-32x32.png",
        "/apple-touch-icon.png",
        "/assets/favicon.ico",
        "/static/favicon.ico",
        "/img/favicon.ico",
        "/images/favicon.ico",
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._shodan_key = os.environ.get("SHODAN_API_KEY", "")
        self._censys_id = os.environ.get("CENSYS_API_ID", "")
        self._censys_secret = os.environ.get("CENSYS_API_SECRET", "")
        self._cf_checker = CloudflareIPChecker()

    def is_configured(self) -> bool:
        """Check if at least one search API is available."""
        return bool(self._shodan_key) or (bool(self._censys_id) and bool(self._censys_secret))

    async def enumerate(
        self, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """
        Perform favicon hash attack against the target domain.

        Steps:
        1. Download favicon from common paths
        2. Compute mmh3 hash
        3. Query Shodan/Censys for matching servers
        4. Return non-Cloudflare IPs

        Args:
            domain: Target domain

        Yields:
            SourceResult objects with discovered IPs
        """
        if not self.is_configured():
            logger.info(
                "Favicon Hash: No API key configured "
                "(set SHODAN_API_KEY or CENSYS_API_ID+CENSYS_API_SECRET)"
            )
            return

        # Load Cloudflare ranges for filtering
        try:
            await self._cf_checker.load_ranges_async()
        except Exception as e:
            logger.warning("Favicon Hash: Failed to load CF ranges: %s", e)

        # Step 1: Download favicon
        favicon_data = await self._download_favicon(domain)
        if not favicon_data:
            logger.info("Favicon Hash: Could not download favicon from %s", domain)
            return

        # Step 2: Compute hash
        from cloudkill.utils.favicon import compute_favicon_hash

        favicon_hash = compute_favicon_hash(favicon_data)
        if not favicon_hash:
            logger.warning("Favicon Hash: Failed to compute hash")
            return

        logger.info("Favicon Hash: Computed hash=%s for %s", favicon_hash, domain)

        # Step 3: Search Shodan
        if self._shodan_key:
            async for result in self._search_shodan(favicon_hash, domain):
                yield result

        # Step 4: Search Censys
        if self._censys_id and self._censys_secret:
            async for result in self._search_censys(favicon_hash, domain):
                yield result

    async def _download_favicon(self, domain: str) -> bytes | None:
        """
        Download favicon from the target domain.

        Tries multiple common favicon paths and returns the first
        successful download.

        Args:
            domain: Target domain

        Returns:
            Raw favicon bytes or None
        """
        import httpx

        for path in self.FAVICON_PATHS:
            url = f"https://{domain}{path}"

            try:
                async with httpx.AsyncClient(timeout=self.TIMEOUT, follow_redirects=True) as client:
                    response = await client.get(url, headers={
                        "User-Agent": (
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/131.0.0.0 Safari/537.36"
                        ),
                    })

                    if response.status_code == 200:
                        content = response.content
                        if content and len(content) >= 100:  # Valid favicon minimum size
                            logger.debug(
                                "Favicon downloaded from %s (%d bytes)",
                                path, len(content),
                            )
                            return content

            except Exception as e:
                logger.debug("Failed to download favicon from %s: %s", path, e)
                continue

        # Try fetching from HTML <link> tags
        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT, follow_redirects=True) as client:
                response = await client.get(f"https://{domain}/", headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0",
                })
                if response.status_code == 200:
                    import re
                    link_match = re.search(
                        r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']',
                        response.text,
                        re.IGNORECASE,
                    )
                    if link_match:
                        href = link_match.group(1)
                        if not href.startswith("http"):
                            href = f"https://{domain}{href}"
                        async with httpx.AsyncClient(timeout=self.TIMEOUT, follow_redirects=True) as c2:
                            r = await c2.get(href)
                            if r.status_code == 200 and len(r.content) >= 100:
                                return r.content
        except Exception as e:
            logger.debug("Failed to extract favicon from HTML: %s", e)

        return None

    async def _search_shodan(
        self, favicon_hash: str, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """Search Shodan for servers with matching favicon hash."""
        import httpx

        from cloudkill.utils.favicon import shodan_search_query

        query = shodan_search_query(favicon_hash)
        url = f"https://api.shodan.io/shodan/host/search?key={self._shodan_key}&query={query}"

        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
                response = await client.get(url)

                if response.status_code == 401:
                    logger.warning("Shodan: Invalid API key")
                    return
                if response.status_code == 429:
                    logger.warning("Shodan: Rate limited")
                    return

                response.raise_for_status()
                data = response.json()

        except Exception as e:
            logger.error("Shodan query failed: %s", e)
            return

        matches = data.get("matches", [])
        total = data.get("total", 0)
        logger.info("Shodan: %d total matches for favicon hash %s", total, favicon_hash)

        seen_ips: set[str] = set()

        for match in matches[:self.MAX_SHODAN_RESULTS]:
            ip_str = match.get("ip_str", "")
            if not ip_str or ip_str in seen_ips:
                continue

            # Filter Cloudflare IPs
            if self._cf_checker.is_cloudflare_ip(ip_str):
                continue

            seen_ips.add(ip_str)

            # Check if this IP's hostname matches our domain
            hostnames = match.get("hostnames", [])
            port = match.get("port", 443)
            org = match.get("org", "")
            asn = match.get("asn", "")
            location = match.get("location", {})

            result = SourceResult(
                subdomain=hostnames[0] if hostnames else domain,
                ip=ip_str,
                ip_version=IPVersion.V6 if ":" in ip_str else IPVersion.V4,
                source=self.name,
                port=port,
                confidence_boost=20,  # High confidence - favicon match
                metadata={
                    "favicon_hash": favicon_hash,
                    "search_engine": "shodan",
                    "shodan_port": port,
                    "shodan_org": org,
                    "shodan_asn": asn,
                    "shodan_location": location.get("country_name", ""),
                    "shodan_hostnames": hostnames[:5],
                },
            )
            yield result

        logger.info("Shodan: %d non-CF IPs found via favicon hash", len(seen_ips))

    async def _search_censys(
        self, favicon_hash: str, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """Search Censys for servers with matching favicon hash."""
        import httpx

        from cloudkill.utils.favicon import censys_search_query

        query = censys_search_query(favicon_hash)

        # Censys API uses basic auth
        import base64
        auth_str = base64.b64encode(
            f"{self._censys_id}:{self._censys_secret}".encode()
        ).decode()

        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
                response = await client.post(
                    "https://search.censys.io/api/v2/hosts/search",
                    json={
                        "q": query,
                        "per_page": 100,
                    },
                    headers={
                        "Authorization": f"Basic {auth_str}",
                        "Content-Type": "application/json",
                        "User-Agent": f"CloudKill/{__version__}",
                    },
                )

                if response.status_code == 401:
                    logger.warning("Censys: Invalid API credentials")
                    return
                if response.status_code == 429:
                    logger.warning("Censys: Rate limited")
                    return

                response.raise_for_status()
                data = response.json()

        except Exception as e:
            logger.error("Censys query failed: %s", e)
            return

        result_list = data.get("result", {}).get("hits", [])
        seen_ips: set[str] = set()

        for hit in result_list:
            ip_str = hit.get("ip", "")
            if not ip_str or ip_str in seen_ips:
                continue

            if self._cf_checker.is_cloudflare_ip(ip_str):
                continue

            seen_ips.add(ip_str)

            services = hit.get("services", [])
            port = 443
            if services:
                # Use the first service port
                service = services[0]
                port = service.get("port", 443)

            yield SourceResult(
                subdomain=domain,
                ip=ip_str,
                ip_version=IPVersion.V6 if ":" in ip_str else IPVersion.V4,
                source=self.name,
                port=port,
                confidence_boost=20,
                metadata={
                    "favicon_hash": favicon_hash,
                    "search_engine": "censys",
                    "censys_port": port,
                },
            )

        logger.info("Censys: %d non-CF IPs found via favicon hash", len(seen_ips))
