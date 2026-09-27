"""
CloudFail-Killer - SPF/DKIM Source Plugin

Analyze email-related DNS records (SPF, DKIM, DMARC) to discover
origin IP addresses and mail server infrastructure.

Mail server infrastructure often shares the same network as the
web server, making email records a valuable source for origin IP discovery.

Technique discovered via Intigriti research (2025):
    - SPF records reveal authorized mail servers
    - DKIM selectors can be enumerated
    - MX records point to mail servers on the same infrastructure
    - DMARC reports may reveal additional infrastructure

References:
    - https://blog.intigriti.com/2025/brute-forcing-dkim-selectors/
"""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncGenerator

from cloudkill.sources.base import BaseSource, IPVersion, SourceResult

logger = logging.getLogger(__name__)


class SPFDKIMSource(BaseSource):
    """
    Email DNS record analysis for origin IP discovery.

    Analyzes SPF, DKIM, DMARC, and MX records to discover:
    - Mail server IP addresses
    - IP ranges authorized to send email
    - Infrastructure providers shared between mail and web
    - Additional subdomains via DKIM selectors

    This technique is highly effective because mail infrastructure
    is often colocated with or connected to web infrastructure.
    """

    name = "spf_dkim"
    description = "Email record analysis (SPF/DKIM/DMARC/MX)"
    requires_api_key = False
    supports_ipv6 = True
    default_enabled = True

    # Common DKIM selector prefixes for brute-force enumeration
    COMMON_SELECTORS = [
        "default", "selector1", "selector2", "google", "k1", "s1",
        "mail", "email", "smtp", "send", "dkim", "mandrill",
        "sendgrid", "postmark", "mailgun", "ses", "amazonses",
        "cloudmailin", "selector", "e", "k", "s", "dkim1024",
        "dkim2048", "paypal", "ebay", "stripe", "shopify",
        "microsoft", "office365", "exchange", "zoho",
    ]

    # Regex to extract IP addresses from SPF include mechanisms
    SPF_IP_PATTERN = re.compile(
        r'ip[46]:(\S+)|include:(\S+)|a:(\S+)|mx(?:[:/]?)(\S+)|exists:(\S+)|redirect=(\S+)'
    )

    async def enumerate(
        self, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """
        Analyze email DNS records for the target domain.

        Process:
        1. Query MX records and resolve mail server IPs
        2. Query SPF record and extract authorized IPs/includes
        3. Query DMARC record for reporting addresses
        4. Brute-force common DKIM selectors
        5. Resolve all discovered hostnames to IPs

        Args:
            domain: Target domain

        Yields:
            SourceResult objects with discovered IPs
        """
        seen_ips: set[str] = set()
        seen_hostnames: set[str] = set()
        total = 0

        # Step 1: MX Records
        async for result in self._analyze_mx(domain, seen_ips, seen_hostnames):
            total += 1
            yield result

        # Step 2: SPF Record
        async for result in self._analyze_spf(domain, seen_ips, seen_hostnames):
            total += 1
            yield result

        # Step 3: DMARC Record
        await self._analyze_dmarc(domain)

        # Step 4: DKIM Selector Enumeration
        async for result in self._enumerate_dkim(domain, seen_ips, seen_hostnames):
            total += 1
            yield result

        logger.info("SPF/DKIM: %d IPs discovered across %d hostnames", total, len(seen_hostnames))

    async def _analyze_mx(
        self,
        domain: str,
        seen_ips: set[str],
        seen_hostnames: set[str],
    ) -> AsyncGenerator[SourceResult, None]:
        """Analyze MX records and resolve mail server IPs."""
        mx_records = await self.resolve_mx_records(domain)

        for record in mx_records:
            exchange = record.get("exchange", "")
            if not exchange or exchange in seen_hostnames:
                continue

            seen_hostnames.add(exchange)

            # Resolve the mail server
            resolved = await self.resolve_with_fallback(exchange)
            for r in resolved:
                if r.ip not in seen_ips:
                    seen_ips.add(r.ip)
                    r.source = self.name
                    r.confidence_boost = 12
                    r.metadata["spf_dkim_source"] = "mx_record"
                    r.metadata["mx_priority"] = record.get("priority", "0")
                    yield r

    async def resolve_mx_records(self, domain: str) -> list[dict[str, str]]:
        """Resolve MX records for a domain."""
        resolver = self.resolver
        records: list[dict[str, str]] = []

        try:
            result = await resolver.query(domain, "MX")
            for r in result:
                records.append({
                    "exchange": r.exchange,
                    "priority": str(r.priority),
                })
        except Exception as e:
            logger.debug("MX query failed for %s: %s", domain, e)

        return records

    async def _analyze_spf(
        self,
        domain: str,
        seen_ips: set[str],
        seen_hostnames: set[str],
    ) -> AsyncGenerator[SourceResult, None]:
        """Analyze SPF record and extract authorized IPs and includes."""
        resolver = self.resolver
        spf_record = ""

        try:
            result = await resolver.query(domain, "TXT")
            for r in result:
                text = r.text
                if text.startswith("v=spf1"):
                    spf_record = text
                    break
        except Exception as e:
            logger.debug("SPF query failed for %s: %s", domain, e)
            return

        if not spf_record:
            return

        logger.debug("SPF record for %s: %s", domain, spf_record[:200])

        # Extract mechanisms
        for match in self.SPF_IP_PATTERN.finditer(spf_record):
            ip_addr = match.group(1)  # ip4: or ip6:
            include_domain = match.group(2)  # include:
            a_domain = match.group(3)  # a:
            mx_domain = match.group(4)  # mx:
            redirect = match.group(6)  # redirect=

            # Direct IP in SPF (handle CIDR notation like ip4:192.168.1.0/24)
            if ip_addr and ip_addr not in seen_ips:
                # Handle CIDR notation — extract just the IP
                ip_clean = ip_addr.split("/")[0] if "/" in ip_addr else ip_addr

                # Validate IP
                is_valid = True
                try:
                    import ipaddress
                    ipaddress.ip_address(ip_clean)
                except ValueError:
                    is_valid = False

                if is_valid and ip_clean not in seen_ips:
                    seen_ips.add(ip_clean)
                    yield SourceResult(
                        subdomain=domain,
                        ip=ip_clean,
                        ip_version=IPVersion.V6 if ":" in ip_clean else IPVersion.V4,
                        source=self.name,
                        confidence_boost=15,
                        metadata={
                            "spf_dkim_source": "spf_record",
                            "spf_mechanism": "ip" + ("4" if ":" not in ip_addr else "6"),
                        },
                    )

            # Include mechanism - resolve the included domain
            for included in [include_domain, a_domain, mx_domain, redirect]:
                if not included or included in seen_hostnames:
                    continue

                # Clean up the domain
                included = included.rstrip(")").strip("?~")
                if not included or included.startswith("_"):
                    continue

                seen_hostnames.add(included)

                # Resolve the included domain's A/AAAA records
                resolved = await self.resolve_with_fallback(included)
                for r in resolved:
                    if r.ip not in seen_ips:
                        seen_ips.add(r.ip)
                        r.source = self.name
                        r.confidence_boost = 10
                        r.metadata["spf_dkim_source"] = "spf_include"
                        r.metadata["spf_included_domain"] = included
                        yield r

    async def _analyze_dmarc(self, domain: str) -> None:
        """Analyze DMARC record for reporting addresses."""
        resolver = self.resolver
        dmarc_domain = f"_dmarc.{domain}"

        try:
            result = await resolver.query(dmarc_domain, "TXT")
            for r in result:
                text = r.text
                if text.startswith("v=DMARC1"):
                    logger.debug("DMARC record: %s", text[:200])
                    # Extract rua (aggregate report) addresses for subdomain discovery
                    rua_match = re.search(r'rua=([^;]+)', text)
                    if rua_match:
                        rua = rua_match.group(1)
                        logger.debug("DMARC RUA: %s", rua)
        except Exception as e:
            logger.debug("DMARC query failed for %s: %s", domain, e)

    async def _enumerate_dkim(
        self,
        domain: str,
        seen_ips: set[str],
        seen_hostnames: set[str],
    ) -> AsyncGenerator[SourceResult, None]:
        """Brute-force common DKIM selectors and resolve associated infrastructure."""
        resolver = self.resolver
        found_selectors: list[str] = []

        for selector in self.COMMON_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{domain}"

            try:
                result = await resolver.query(dkim_domain, "TXT")
                for r in result:
                    text = r.text
                    if text.startswith("v=DKIM1"):
                        found_selectors.append(selector)
                        logger.debug("DKIM selector found: %s", selector)
                        break
            except Exception:
                continue

            # Rate limit: small delay between queries
            import asyncio
            await asyncio.sleep(0.05)

        if found_selectors:
            logger.info("SPF/DKIM: Found %d DKIM selectors: %s", len(found_selectors), ", ".join(found_selectors[:5]))

        # Resolve IPs for DKIM-related hostnames to discover infrastructure
        dkim_hosts = [f"{selector}.{domain}" for selector in found_selectors if selector not in seen_hostnames]
        for hostname in dkim_hosts:
            seen_hostnames.add(hostname)
            resolved = await self.resolve_with_fallback(hostname)
            for r in resolved:
                r.source = self.name
                yield r
