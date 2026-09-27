"""
CloudFail-Killer - HackerTarget Source Plugin

DNS lookup and reconnaissance via HackerTarget.com API.

HackerTarget provides multiple DNS intelligence tools:
- DNS lookup (A, AAAA, MX, NS, TXT)
- Reverse DNS lookup
- Zone transfer check
- Host search (find hosts on same network)

Free tier: 50 queries/day without API key.

API: https://api.hackertarget.com/dnslookup/?q=example.com
API: https://api.hackertarget.com/hostsearch/?q=example.com
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator

from cloudkill import __version__
from cloudkill.sources.base import BaseSource, IPVersion, SourceResult

logger = logging.getLogger(__name__)


class HackerTargetSource(BaseSource):
    """
    DNS intelligence from HackerTarget.com.

    Free: 50 queries/day. Provides DNS lookup, host search,
    and reverse DNS capabilities.

    The 'hostsearch' endpoint is particularly useful as it returns
    IP-subdomain pairs directly.
    """

    name = "hackertarget"
    description = "DNS lookup and host search (HackerTarget)"
    requires_api_key = False
    supports_ipv6 = True
    default_enabled = True

    DNSLOOKUP_API = "https://api.hackertarget.com/dnslookup/?q="
    HOSTSEARCH_API = "https://api.hackertarget.com/hostsearch/?q="
    REVERSEDNS_API = "https://api.hackertarget.com/reversedns/?q="
    TIMEOUT = 30

    async def enumerate(
        self, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """
        Query HackerTarget for DNS and host data.

        Uses three endpoints:
        1. hostsearch: Find hosts (IP-subdomain pairs)
        2. dnslookup: Get DNS records
        3. reversedns: Reverse DNS (if IP found)

        Args:
            domain: Target domain

        Yields:
            SourceResult objects with discovered IPs
        """
        seen_ips: set[str] = set()
        total = 0

        # 1. Host search - most useful, returns IP+hostname pairs directly
        async for result in self._host_search(domain, seen_ips):
            total += 1
            yield result

        # 2. DNS lookup - extract records
        async for result in self._dns_lookup(domain, seen_ips):
            total += 1
            yield result

        logger.info("HackerTarget: %d unique IPs discovered", total)

    async def _host_search(
        self,
        domain: str,
        seen_ips: set[str],
    ) -> AsyncGenerator[SourceResult, None]:
        """Query host search API."""
        import httpx

        url = f"{self.HOSTSEARCH_API}{domain}"

        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": f"CloudKill/{__version__}"},
                )

                if response.status_code == 429:
                    logger.warning("HackerTarget: Daily limit reached")
                    return

                response.raise_for_status()
                text = response.text.strip()

        except Exception as e:
            logger.error("HackerTarget host search failed: %s", e)
            return

        if not text or "error" in text.lower():
            return

        for line in text.split("\n"):
            line = line.strip()
            if not line or "," not in line:
                continue

            try:
                ip, hostname = line.split(",", 1)
                ip = ip.strip()
                hostname = hostname.strip().lower()
            except ValueError:
                continue

            if not ip or ip in seen_ips:
                continue

            seen_ips.add(ip)

            yield SourceResult(
                subdomain=hostname or domain,
                ip=ip,
                ip_version=IPVersion.V6 if ":" in ip else IPVersion.V4,
                source=self.name,
                confidence_boost=5,
                metadata={"hackertarget_method": "hostsearch"},
            )

    async def _dns_lookup(
        self,
        domain: str,
        seen_ips: set[str],
    ) -> AsyncGenerator[SourceResult, None]:
        """Query DNS lookup API and extract IPs from text response."""
        import httpx

        url = f"{self.DNSLOOKUP_API}{domain}"

        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": f"CloudKill/{__version__}"},
                )

                if response.status_code == 429:
                    return

                response.raise_for_status()
                text = response.text.strip()

        except Exception as e:
            logger.error("HackerTarget DNS lookup failed: %s", e)
            return

        if not text or "error" in text.lower():
            return

        import re

        # Extract IP addresses from DNS lookup response
        # Look for lines that contain IP addresses after record type labels
        ip_pattern = re.compile(
            r"(?:A|AAAA|MX|NS)\s+(?:record|Address|mail)\s*[:;]?\s*([^\s,]+)"
        )

        for line in text.split("\n"):
            line = line.strip()
            if not line:
                continue

            matches = ip_pattern.findall(line)
            for ip in matches:
                ip = ip.strip()
                if not ip or ip in seen_ips:
                    continue
                if not self._is_valid_ip(ip):
                    continue

                seen_ips.add(ip)

                yield SourceResult(
                    subdomain=domain,
                    ip=ip,
                    ip_version=IPVersion.V6 if ":" in ip else IPVersion.V4,
                    source=self.name,
                    confidence_boost=3,
                    metadata={"hackertarget_method": "dnslookup"},
                )

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Quick IP validation."""
        if ":" in ip:
            parts = ip.split(":")
            if len(parts) < 2:
                return False
        else:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            for p in parts:
                try:
                    num = int(p)
                    if num < 0 or num > 255:
                        return False
                except ValueError:
                    return False
        return True
