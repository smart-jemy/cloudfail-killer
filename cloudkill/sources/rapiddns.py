"""
CloudFail-Killer - RapidDNS Source Plugin

Passive DNS subdomain data from RapidDNS.io.

RapidDNS maintains a large historical DNS database searchable by domain.
Free to query, no API key required.

Endpoint: https://rapiddns.io/subdomain/{domain}?full=1
"""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncGenerator
from typing import Any

from cloudkill import __version__
from cloudkill.sources.base import BaseSource, IPVersion, SourceResult

logger = logging.getLogger(__name__)

# Matches IPv4 and IPv6 (compressed forms included) candidates in table cells
_IP_CANDIDATE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    r"|\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b"
)

# Table row cells: <td>...</td>
_TD = re.compile(r"<td[^>]*>(.*?)</td>", re.IGNORECASE | re.DOTALL)
_TR = re.compile(r"<tr[^>]*>(.*?)</tr>", re.IGNORECASE | re.DOTALL)
_TAG = re.compile(r"<[^>]+>")


def _strip_tags(cell: str) -> str:
    """Remove HTML tags and decode minimal entities from a cell."""
    text = _TAG.sub("", cell)
    return (
        text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
        .strip()
    )


def _is_valid_ip(ip: str) -> bool:
    """Validate IPv4/IPv6 candidate strings."""
    try:
        import ipaddress

        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


class RapidDNSSource(BaseSource):
    """
    Historical DNS subdomain data from RapidDNS.io.

    Single HTML-table query per domain. Rows contain subdomain and
    DNS answer (A/AAAA) pairs which are resolved candidates for the
    origin IP.

    Free: no API key. Keep query rate low (one request per domain).
    """

    name = "rapiddns"
    description = "Historical DNS subdomain database (RapidDNS)"
    requires_api_key = False
    supports_ipv6 = True
    default_enabled = True

    BASE_URL = "https://rapiddns.io/subdomain/"
    TIMEOUT = 30
    MAX_RESULTS = 500

    async def enumerate(
        self, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """
        Query RapidDNS for subdomains and DNS answers of the target.

        Args:
            domain: Target domain

        Yields:
            SourceResult objects with discovered IPs
        """
        import httpx

        url = f"{self.BASE_URL}{domain}?full=1"

        try:
            async with httpx.AsyncClient(
                timeout=self.TIMEOUT, follow_redirects=True
            ) as client:
                response = await client.get(
                    url,
                    headers={
                        "User-Agent": f"CloudKill/{__version__}",
                        "Accept": "text/html",
                    },
                )

                if response.status_code == 429:
                    logger.warning("RapidDNS: Rate limited")
                    return

                response.raise_for_status()
                html = response.text

        except Exception as e:
            logger.error("RapidDNS query failed: %s", e)
            return

        if not html or "error" in html[:500].lower():
            return

        yielded = 0
        seen_pairs: set[tuple[str, str]] = set()

        for row in _TR.finditer(html):
            cells: list[str] = [
                _strip_tags(c) for c in _TD.findall(row.group(1))
            ]
            if len(cells) < 2:
                continue

            hostname = ""
            for cell in cells:
                cell_lower = cell.strip().lower()
                if cell_lower == domain or cell_lower.endswith(f".{domain}"):
                    hostname = cell_lower
                    break

            if not hostname:
                continue

            for match in _IP_CANDIDATE.finditer(" ".join(cells[1:])):
                ip = match.group()
                if not _is_valid_ip(ip):
                    continue

                pair = (hostname, ip)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)

                yield SourceResult(
                    subdomain=hostname,
                    ip=ip,
                    ip_version=IPVersion.V6 if ":" in ip else IPVersion.V4,
                    source=self.name,
                    is_historical=True,
                    confidence_boost=6,
                    metadata={"rapiddns": "subdomain_table"},
                )
                yielded += 1

                if yielded >= self.MAX_RESULTS:
                    logger.info("RapidDNS: hit result cap (%d)", self.MAX_RESULTS)
                    return

        logger.info("RapidDNS: %d candidate IPs discovered", yielded)

    def parse_rows(self, html: str) -> list[dict[str, Any]]:
        """Expose row parsing for tests: returns hostname/ip dicts."""
        out: list[dict[str, Any]] = []
        for row in _TR.finditer(html):
            cells = [_strip_tags(c) for c in _TD.findall(row.group(1))]
            if len(cells) < 2:
                continue
            out.append({"cells": cells})
        return out
