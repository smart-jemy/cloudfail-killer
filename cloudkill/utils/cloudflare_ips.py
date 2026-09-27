"""
CloudFail-Killer - Cloudflare IP Ranges

Manages Cloudflare IPv4 and IPv6 IP ranges with local file caching.
Automatically downloads and caches ranges from Cloudflare's official endpoints.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

CF_IPS_V4_URL = "https://www.cloudflare.com/ips-v4"
CF_IPS_V6_URL = "https://www.cloudflare.com/ips-v6"
CACHE_FILE = Path.home() / ".cache" / "cloudkill" / "cf_ranges.json"
CACHE_TTL_SECONDS = 86400  # 24 hours


class CloudflareIPChecker:
    """
    Check if an IP address belongs to Cloudflare.

    Supports both IPv4 and IPv6 ranges. Downloads ranges from
    Cloudflare's official endpoints and caches them locally.
    """

    def __init__(self, cache_dir: Path | None = None) -> None:
        self._v4_networks: list[ipaddress.IPv4Network] = []
        self._v6_networks: list[ipaddress.IPv6Network] = []
        self._loaded = False
        self._cache_file = self._resolve_cache_file(cache_dir)

    @staticmethod
    def _resolve_cache_file(cache_dir: Path | None) -> Path:
        """Resolve the cache file path, rejecting traversal components."""
        if cache_dir is None:
            return CACHE_FILE
        if ".." in Path(cache_dir).parts:
            logger.warning(
                "Ignoring cache_dir with path traversal components: %s", cache_dir
            )
            return CACHE_FILE
        return Path(cache_dir).expanduser().resolve() / "cf_ranges.json"

    @property
    def v4_networks(self) -> list[ipaddress.IPv4Network]:
        if not self._loaded:
            raise RuntimeError("Call load_ranges() first")
        return self._v4_networks

    @property
    def v6_networks(self) -> list[ipaddress.IPv6Network]:
        if not self._loaded:
            raise RuntimeError("Call load_ranges() first")
        return self._v6_networks

    def is_cloudflare_ip(self, ip: str) -> bool:
        """
        Check if an IP address belongs to Cloudflare.

        Works with both IPv4 and IPv6 addresses.

        Args:
            ip: IP address string (e.g., "1.1.1.1" or "2606:4700::")

        Returns:
            True if the IP is in Cloudflare ranges
        """
        if not self._loaded:
            logger.warning("Cloudflare ranges not loaded, loading now...")
            # Best effort sync load
            try:
                self.load_ranges()
            except Exception:
                return False

        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                return any(ip_obj in net for net in self._v4_networks)
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                return any(ip_obj in net for net in self._v6_networks)
        except ValueError:
            logger.debug("Invalid IP address: %s", ip)
        return False

    def is_cloudflare_cidr(self, cidr: str) -> bool:
        """Check if a CIDR range overlaps with Cloudflare ranges."""
        if not self._loaded:
            return False
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                return any(net.overlaps(cf_net) for cf_net in self._v4_networks)
            elif isinstance(net, ipaddress.IPv6Network):
                return any(net.overlaps(cf_net) for cf_net in self._v6_networks)
        except ValueError:
            return False
        return False

    async def load_ranges_async(self) -> None:
        """Asynchronously load Cloudflare IP ranges."""
        # Try loading from cache first
        if self._try_load_cache():
            self._loaded = True
            return

        # Download fresh ranges
        v4_ranges = await self._fetch_ranges(CF_IPS_V4_URL)
        v6_ranges = await self._fetch_ranges(CF_IPS_V6_URL)

        # Parse into network objects
        self._v4_networks = []
        for line in v4_ranges:
            line = line.strip()
            if line and '/' in line:
                try:
                    self._v4_networks.append(ipaddress.ip_network(line.strip()))
                except ValueError:
                    continue

        self._v6_networks = []
        for line in v6_ranges:
            line = line.strip()
            if line and '/' in line:
                try:
                    self._v6_networks.append(ipaddress.ip_network(line.strip()))
                except ValueError:
                    continue

        # Save to cache
        self._save_cache()
        self._loaded = True

        logger.info(
            "Loaded Cloudflare IP ranges: %d IPv4 + %d IPv6",
            len(self._v4_networks),
            len(self._v6_networks),
        )

    def load_ranges(self) -> None:
        """Synchronously load Cloudflare IP ranges (uses httpx sync)."""
        try:
            asyncio.get_running_loop()
            # Already inside a running event loop — create a new thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, self.load_ranges_async())
                future.result()
        except RuntimeError:
            # No running event loop — safe to use asyncio.run()
            asyncio.run(self.load_ranges_async())

    async def _fetch_ranges(self, url: str) -> list[str]:
        """Fetch IP ranges from a Cloudflare URL."""
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(url)
                response.raise_for_status()
                return response.text.strip().split("\n")
        except httpx.HTTPError as e:
            logger.error("Failed to fetch Cloudflare ranges from %s: %s", url, e)
            return []

    def _try_load_cache(self) -> bool:
        """Try to load ranges from local cache file."""
        if not self._cache_file.exists():
            return False

        try:
            data = json.loads(self._cache_file.read_text(encoding="utf-8"))

            # Check cache TTL
            cached_at = data.get("cached_at", 0)
            if time.time() - cached_at > CACHE_TTL_SECONDS:
                logger.debug("Cloudflare cache expired (age=%ds)", time.time() - cached_at)
                return False

            self._v4_networks = [
                ipaddress.ip_network(n) for n in data.get("v4", [])
            ]
            self._v6_networks = [
                ipaddress.ip_network(n) for n in data.get("v6", [])
            ]

            logger.debug(
                "Loaded Cloudflare ranges from cache: %d IPv4 + %d IPv6",
                len(self._v4_networks),
                len(self._v6_networks),
            )
            return True

        except (json.JSONDecodeError, ValueError, OSError) as e:
            logger.debug("Failed to load Cloudflare cache: %s", e)
            return False

    def _save_cache(self) -> None:
        """Save current ranges to local cache file."""
        try:
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "cached_at": time.time(),
                "v4": [str(n) for n in self._v4_networks],
                "v6": [str(n) for n in self._v6_networks],
            }
            self._cache_file.write_text(
                json.dumps(payload, indent=2), encoding="utf-8"
            )
            logger.debug("Saved Cloudflare ranges to cache")
        except OSError as e:
            logger.debug("Failed to save Cloudflare cache: %s", e)

    @property
    def total_ranges(self) -> int:
        return len(self._v4_networks) + len(self._v6_networks)

    def get_stats(self) -> dict:
        return {
            "v4_ranges": len(self._v4_networks),
            "v6_ranges": len(self._v6_networks),
            "total": self.total_ranges,
            "cached": self._cache_file.exists(),
        }
