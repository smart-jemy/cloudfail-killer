"""
CloudFail-Killer - Enhanced DNS Resolver

Dual-stack DNS resolver with support for A, AAAA, CNAME, MX, TXT, NS, SOA records.
Provides DNS-based techniques for origin IP discovery.

Techniques supported:
    - A/AAAA record resolution (dual-stack)
    - CNAME chain following
    - TXT record extraction (SPF, DKIM, verification)
    - MX record extraction (mail server IPs)
    - NS record extraction (nameserver IPs)
    - SOA record extraction
    - DNS subdomain enumeration via wildcard detection
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import aiodns

logger = logging.getLogger(__name__)


@dataclass
class DNSRecord:
    """A single DNS record."""
    record_type: str
    name: str
    value: str
    ttl: int = 0
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.record_type,
            "name": self.name,
            "value": self.value,
            "ttl": self.ttl,
        }


@dataclass
class DNSResult:
    """Complete DNS resolution result for a domain."""
    domain: str
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    cname_records: list[str] = field(default_factory=list)
    mx_records: list[dict[str, str]] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    soa_records: list[dict[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def all_ips(self) -> list[str]:
        """Get all resolved IP addresses (IPv4 + IPv6)."""
        return self.a_records + self.aaaa_records

    @property
    def ipv4_count(self) -> int:
        return len(self.a_records)

    @property
    def ipv6_count(self) -> int:
        return len(self.aaaa_records)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "a_records": self.a_records,
            "aaaa_records": self.aaaa_records,
            "cname_records": self.cname_records,
            "mx_records": self.mx_records,
            "txt_records": self.txt_records,
            "ns_records": self.ns_records,
            "soa_records": self.soa_records,
            "errors": self.errors,
        }


class DualStackResolver:
    """
    Enhanced dual-stack DNS resolver with async support.

    Features:
    - Concurrent A + AAAA resolution
    - CNAME chain following
    - Multiple record type queries
    - Wildcard detection
    - Custom nameserver support

    Usage:
        resolver = DualStackResolver()
        result = await resolver.resolve_all("example.com")
    """

    def __init__(
        self,
        nameservers: list[str] | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.timeout = timeout
        self._resolver_kwargs: dict[str, Any] = {"timeout": timeout}
        if nameservers:
            self._resolver_kwargs["nameservers"] = nameservers

    def _get_resolver(self) -> aiodns.DNSResolver:
        """Create a new DNS resolver instance."""
        return aiodns.DNSResolver(**self._resolver_kwargs)

    async def resolve_a(self, hostname: str) -> list[str]:
        """Resolve A records (IPv4) for a hostname."""
        resolver = self._get_resolver()
        ips: list[str] = []
        try:
            result = await resolver.query(hostname, "A")
            ips = [r.host for r in result]
        except aiodns.error.DNSError as e:
            logger.debug("A record query failed for %s: %s", hostname, e)
        return ips

    async def resolve_aaaa(self, hostname: str) -> list[str]:
        """Resolve AAAA records (IPv6) for a hostname."""
        resolver = self._get_resolver()
        ips: list[str] = []
        try:
            result = await resolver.query(hostname, "AAAA")
            ips = [r.host for r in result]
        except aiodns.error.DNSError as e:
            logger.debug("AAAA record query failed for %s: %s", hostname, e)
        return ips

    async def resolve_dual(self, hostname: str, prefer_ipv6: bool = False) -> list[str]:
        """
        Resolve both A and AAAA records concurrently.

        Args:
            hostname: Domain to resolve
            prefer_ipv6: If True, return IPv6 first

        Returns:
            List of IP addresses (IPv6 first if prefer_ipv6)
        """
        v4_task = asyncio.create_task(self.resolve_a(hostname))
        v6_task = asyncio.create_task(self.resolve_aaaa(hostname))

        v4_results, v6_results = await asyncio.gather(v4_task, v6_task)

        if prefer_ipv6:
            return v6_results + v4_results
        return v4_results + v6_results

    async def resolve_cname(self, hostname: str) -> list[str]:
        """Resolve CNAME records for a hostname."""
        resolver = self._get_resolver()
        cnames: list[str] = []
        try:
            result = await resolver.query(hostname, "CNAME")
            cnames = [r.cname for r in result]
        except aiodns.error.DNSError as e:
            logger.debug("CNAME query failed for %s: %s", hostname, e)
        return cnames

    async def resolve_mx(self, hostname: str) -> list[dict[str, str]]:
        """Resolve MX records (mail servers) for a domain."""
        resolver = self._get_resolver()
        mx_records: list[dict[str, str]] = []
        try:
            result = await resolver.query(hostname, "MX")
            for r in result:
                mx_records.append({
                    "exchange": r.exchange,
                    "priority": str(r.priority),
                })
        except aiodns.error.DNSError as e:
            logger.debug("MX query failed for %s: %s", hostname, e)
        return mx_records

    async def resolve_txt(self, hostname: str) -> list[str]:
        """Resolve TXT records for a domain."""
        resolver = self._get_resolver()
        records: list[str] = []
        try:
            result = await resolver.query(hostname, "TXT")
            records = [r.text for r in result]
        except aiodns.error.DNSError as e:
            logger.debug("TXT query failed for %s: %s", hostname, e)
        return records

    async def resolve_ns(self, hostname: str) -> list[str]:
        """Resolve NS records (nameservers) for a domain."""
        resolver = self._get_resolver()
        records: list[str] = []
        try:
            result = await resolver.query(hostname, "NS")
            records = [r.host for r in result]
        except aiodns.error.DNSError as e:
            logger.debug("NS query failed for %s: %s", hostname, e)
        return records

    async def resolve_soa(self, hostname: str) -> list[dict[str, str]]:
        """Resolve SOA records for a domain."""
        resolver = self._get_resolver()
        records: list[dict[str, str]] = []
        try:
            result = await resolver.query(hostname, "SOA")
            for r in result:
                records.append({
                    "nsname": r.nsname,
                    "hostmaster": r.hostmaster,
                    "serial": str(r.serial),
                    "refresh": str(r.refresh),
                    "retry": str(r.retry),
                    "expires": str(r.expires),
                    "minttl": str(r.minttl),
                })
        except aiodns.error.DNSError as e:
            logger.debug("SOA query failed for %s: %s", hostname, e)
        return records

    async def resolve_all(self, domain: str) -> DNSResult:
        """
        Resolve all record types for a domain concurrently.

        Args:
            domain: Domain to query

        Returns:
            DNSResult with all discovered records
        """
        result = DNSResult(domain=domain)

        # Run all queries concurrently
        tasks = {
            "a": self.resolve_a(domain),
            "aaaa": self.resolve_aaaa(domain),
            "cname": self.resolve_cname(domain),
            "mx": self.resolve_mx(domain),
            "txt": self.resolve_txt(domain),
            "ns": self.resolve_ns(domain),
            "soa": self.resolve_soa(domain),
        }

        task_names = list(tasks.keys())
        task_coros = list(tasks.values())

        try:
            results_list = await asyncio.gather(*task_coros, return_exceptions=True)

            for name, res in zip(task_names, results_list, strict=False):
                if isinstance(res, Exception):
                    result.errors.append(f"{name.upper()} query failed: {res}")
                    continue

                if name == "a":
                    result.a_records = res
                elif name == "aaaa":
                    result.aaaa_records = res
                elif name == "cname":
                    result.cname_records = res
                elif name == "mx":
                    result.mx_records = res
                elif name == "txt":
                    result.txt_records = res
                elif name == "ns":
                    result.ns_records = res
                elif name == "soa":
                    result.soa_records = res

        except Exception as e:
            result.errors.append(f"DNS resolution error: {e}")

        return result

    async def check_wildcard(self, domain: str, test_subdomain: str = "cktestwildcard") -> bool:
        """
        Check if a domain has DNS wildcard resolution.

        Resolves a random subdomain. If it returns an IP, the domain likely has
        wildcard DNS configured.

        Args:
            domain: Base domain to test
            test_subdomain: Random subdomain prefix to use

        Returns:
            True if wildcard DNS is detected
        """
        test_host = f"{test_subdomain}.{domain}"
        ips = await self.resolve_a(test_host)
        return len(ips) > 0

    async def reverse_dns(self, ip: str) -> list[str]:
        """Perform reverse DNS lookup for an IP address."""
        resolver = self._get_resolver()
        hostnames: list[str] = []
        try:
            if ":" in ip:
                # IPv6 PTR format
                result = await resolver.query(ip, "PTR")
            else:
                result = await resolver.query(ip, "PTR")
            hostnames = [r.name for r in result]
        except aiodns.error.DNSError as e:
            logger.debug("PTR query failed for %s: %s", ip, e)
        return hostnames

    async def resolve_mx_ips(self, domain: str) -> list[str]:
        """
        Resolve MX records and then resolve IPs for each mail server.

        Mail server IPs can sometimes reveal the origin infrastructure
        since they're often hosted on the same network as the web server.

        Args:
            domain: Domain to query

        Returns:
            List of IP addresses of mail servers
        """
        mx_records = await self.resolve_mx(domain)
        ips: list[str] = []

        for mx in mx_records:
            exchange = mx.get("exchange", "")
            if exchange:
                mx_ips = await self.resolve_dual(exchange)
                ips.extend(mx_ips)

        return ips

    async def resolve_ns_ips(self, domain: str) -> list[str]:
        """
        Resolve NS records and then resolve IPs for each nameserver.

        Args:
            domain: Domain to query

        Returns:
            List of IP addresses of nameservers
        """
        ns_records = await self.resolve_ns(domain)
        ips: list[str] = []

        for ns in ns_records:
            ns_ips = await self.resolve_dual(ns)
            ips.extend(ns_ips)

        return ips
