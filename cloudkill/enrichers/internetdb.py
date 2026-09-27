"""
CloudFail-Killer - Shodan InternetDB Origin Verifier

Keyless origin verification using the Shodan InternetDB
(https://internetdb.shodan.io). For each candidate origin IP the
InternetDB returns open ports, hostnames, CPEs, and known
vulnerabilities collected from internet-wide scanning.

Verification signals:
    - If any hostname observed on the IP falls under the target
      domain, the IP very likely serves that domain directly
      (i.e., it is the origin, not the Cloudflare proxy).
    - Open web ports (80/443) support the "serves HTTP" hypothesis.

Free: no API key required. Be polite: small concurrency + dedup.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class InternetDBInfo:
    """Parsed InternetDB response for a single IP."""
    ip: str
    ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    lookup_error: str | None = None
    found: bool = False  # False when InternetDB has no data (404)

    def domain_hostname_match(self, domain: str) -> str | None:
        """Return the first observed hostname under the target domain."""
        domain = domain.lower()
        for hostname in self.hostnames:
            h = hostname.lower().rstrip(".")
            if h == domain or h.endswith(f".{domain}"):
                return h
        return None

    def web_ports_open(self) -> list[int]:
        """Return open web ports (80/443/8080/8443)."""
        web = {80, 443, 8080, 8443}
        return [p for p in self.ports if p in web]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "ports": self.ports,
            "hostnames": self.hostnames,
            "cpes": self.cpes,
            "vulns": self.vulns[:10],
            "found": self.found,
        }


class InternetDBLookup:
    """
    Batch lookup of Shodan InternetDB records for candidate IPs.

    Usage:
        idb = InternetDBLookup()
        infos = await idb.lookup_batch(["1.2.3.4", "5.6.7.8"])
    """

    API_BASE = "https://internetdb.shodan.io/"

    def __init__(
        self,
        timeout: float = 10.0,
        max_concurrent: int = 10,
    ) -> None:
        self.timeout = timeout
        self.max_concurrent = max_concurrent

    async def lookup_batch(
        self, ips: list[str]
    ) -> dict[str, InternetDBInfo]:
        """
        Look up InternetDB data for a list of unique IPs.

        Args:
            ips: List of IP address strings

        Returns:
            Mapping of IP -> InternetDBInfo (with lookup_error set
            and found=False on failures)
        """
        results: dict[str, InternetDBInfo] = {}
        if not ips:
            return results

        semaphore = asyncio.Semaphore(self.max_concurrent)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            tasks = [
                self._lookup_one(client, ip, semaphore) for ip in dict.fromkeys(ips)
            ]
            infos = await asyncio.gather(*tasks)

        for info in infos:
            results[info.ip] = info
        return results

    async def _lookup_one(
        self,
        client: httpx.AsyncClient,
        ip: str,
        semaphore: asyncio.Semaphore,
    ) -> InternetDBInfo:
        """Fetch and parse a single InternetDB record."""
        info = InternetDBInfo(ip=ip)

        async with semaphore:
            try:
                response = await client.get(f"{self.API_BASE}{ip}")

                if response.status_code == 404:
                    # InternetDB has no data for this IP
                    info.found = False
                    return info

                if response.status_code == 429:
                    info.lookup_error = "rate_limited"
                    return info

                response.raise_for_status()
                data = response.json()

            except Exception as e:
                info.lookup_error = str(e)[:120]
                return info

        if not isinstance(data, dict):
            info.lookup_error = "unexpected response"
            return info

        info.found = True
        info.ports = [int(p) for p in data.get("ports", []) if isinstance(p, int)]
        info.hostnames = [
            h for h in data.get("hostnames", []) if isinstance(h, str)
        ]
        info.cpes = [c for c in data.get("cpes", []) if isinstance(c, str)]
        info.vulns = [v for v in data.get("vulns", []) if isinstance(v, str)]
        return info
