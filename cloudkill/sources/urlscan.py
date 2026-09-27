"""
CloudFail-Killer - URLScan.io Source Plugin

URLScan.io provides website scanning results including:
- Historical subdomains
- DOM storage data (localStorage, sessionStorage)
- JavaScript file URLs
- Technology fingerprints
- IP addresses from historical scans

URLScan.io is particularly valuable for discovering hidden subdomains
and JS endpoints through its DOM storage analysis.

API: https://urlscan.io/api/v1/search/?q=domain:example.com
"""

from __future__ import annotations

import logging
import urllib.parse
from collections.abc import AsyncGenerator
from typing import Any

from cloudkill import __version__
from cloudkill.sources.base import BaseSource, SourceResult

logger = logging.getLogger(__name__)


class URLScanSource(BaseSource):
    """
    Historical scans and DOM analysis from URLScan.io.

    Free tier: 1000 searches/month without API key.
    Provides subdomain discovery, JS endpoint extraction,
    and DOM storage analysis.

    This is the primary source for:
    - DOM Storage leakage (localStorage/sessionStorage with origin info)
    - JS file discovery (for JS Recon Phase 3)
    - Historical subdomain enumeration
    """

    name = "urlscan"
    description = "Website scanner results + DOM storage (URLScan.io)"
    requires_api_key = False
    supports_ipv6 = True
    default_enabled = True

    URLSCAN_API = "https://urlscan.io/api/v1/search/"
    RESULT_API = "https://urlscan.io/api/v1/result/"
    TIMEOUT = 30

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        import os
        self._api_key = os.environ.get("URLSCAN_API_KEY", "")

    async def enumerate(
        self, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """
        Search URLScan.io for scans of the target domain.

        Performs two queries:
        1. Domain-level search for all subdomains
        2. Extracts DOM storage data and JS files from results

        Args:
            domain: Target domain

        Yields:
            SourceResult objects with discovered IPs
        """
        import httpx

        headers = {"User-Agent": f"CloudKill/{__version__}"}
        if self._api_key:
            headers["API-Key"] = self._api_key

        seen: set[str] = set()
        js_endpoints: list[str] = []
        dom_storage_data: list[dict] = []
        total_ips = 0

        # Search for all scans related to this domain
        params = {"q": f"domain:{domain}"}

        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
                response = await client.get(
                    self.URLSCAN_API,
                    params=params,
                    headers=headers,
                )

                if response.status_code == 429:
                    logger.warning("URLScan.io: Rate limited")
                    return

                response.raise_for_status()
                data = response.json()

        except Exception as e:
            logger.error("URLScan.io search failed: %s", e)
            return

        results = data.get("results", [])
        total_available = data.get("total", 0)
        logger.info(
            "URLScan.io: Found %d total scans for %s (showing %d)",
            total_available, domain, len(results),
        )

        # Process each scan result
        for scan_entry in results[:50]:  # Limit to 50 most recent
            page_url = scan_entry.get("page", {}).get("url", "")
            if not page_url:
                continue

            # Extract subdomain from page URL
            try:
                parsed = urllib.parse.urlparse(page_url)
                hostname = parsed.hostname or ""
            except Exception:
                continue

            hostname = hostname.strip().lower()
            if ":" in hostname and not hostname.startswith("["):
                hostname = hostname.split(":")[0]

            if not hostname or hostname in seen:
                continue
            if not (hostname == domain or hostname.endswith(f".{domain}")):
                continue

            seen.add(hostname)

            # Resolve to IPs
            resolved = await self.resolve_with_fallback(hostname)
            for r in resolved:
                r.source = self.name
                r.is_historical = True
                r.confidence_boost = 5
                r.metadata["urlscan_task"] = scan_entry.get("task", "")
                r.metadata["urlscan_url"] = page_url[:200]
                total_ips += 1
                yield r

            # Collect JS endpoints and DOM storage from individual results
            task_id = scan_entry.get("task", "")
            if task_id:
                task_results = await self._fetch_task_data(
                    task_id, domain, headers
                )
                js_endpoints.extend(task_results["js_files"])
                dom_storage_data.extend(task_results["dom_storage"])

        # Store JS endpoints and DOM storage in metadata of last result
        if js_endpoints or dom_storage_data:
            logger.info(
                "URLScan.io: Collected %d JS endpoints, %d DOM storage entries",
                len(js_endpoints), len(dom_storage_data),
            )

        logger.info("URLScan.io: %d unique subdomains, %d IPs resolved", len(seen), total_ips)

    async def _fetch_task_data(
        self,
        task_id: str,
        domain: str,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        """Fetch detailed scan data for a URLScan.io task."""
        import httpx

        result: dict[str, Any] = {"js_files": [], "dom_storage": []}

        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
                response = await client.get(
                    f"{self.RESULT_API}{task_id}/",
                    headers=headers,
                )

                if response.status_code != 200:
                    return result

                data = response.json()

            # Extract JS files
            lists_data = data.get("lists", {})
            for js_url in lists_data.get("js", []):
                if isinstance(js_url, str) and domain in js_url:
                    result["js_files"].append(js_url)

            # Extract DOM storage
            data_section = data.get("data", {})
            dom_storage = data_section.get("domStorage", {})
            for storage_url, storage_items in dom_storage.items():
                if isinstance(storage_items, list):
                    for item in storage_items:
                        if isinstance(item, dict):
                            result["dom_storage"].append({
                                "url": storage_url,
                                "key": item.get("name", ""),
                                "value": item.get("value", "")[:200],
                            })

        except Exception as e:
            logger.debug("URLScan.io task fetch failed: %s", e)

        return result
