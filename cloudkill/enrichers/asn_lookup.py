"""
CloudFail-Killer - ASN & Hosting Provider Lookup

Identifies the hosting provider and network infrastructure of discovered IPs
using ASN (Autonomous System Number) lookups.

Uses free APIs to determine:
    - ASN number and organization
    - Country and city geolocation
    - Hosting provider detection (AWS, GCP, Azure, OVH, DigitalOcean, etc.)
    - Whether the IP belongs to a known CDN/hosting provider

Multiple fallback APIs ensure reliability:
    1. ip-api.com (free, 45 req/min, no key)
    2. ipinfo.io (free 50k/month, optional key)
    3. ipwhois.app (free, backup)

MITRE ATT&CK: T1595.002 (SSL/TLS Inspection)
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Known hosting providers mapped to their ASN patterns or org names
HOSTING_PROVIDERS: dict[str, dict[str, Any]] = {
    "amazon": {
        "names": ["amazon", "amazon.com", "aws", "amazon web services", "amazone"],
        "asn_prefixes": ["16509", "14618", "57626", "7224"],
        "short": "AWS",
        "color": "#FF9900",
    },
    "google": {
        "names": ["google", "google cloud", "gcp", "google llc"],
        "asn_prefixes": ["15169", "36040", "396982", "43515"],
        "short": "GCP",
        "color": "#4285F4",
    },
    "digitalocean": {
        "names": ["digitalocean", "digital ocean"],
        "asn_prefixes": ["14061", "63949", "26496"],
        "short": "DO",
        "color": "#0080FF",
    },
    "ovh": {
        "names": ["ovh", "ovh sas", "ovh cloud"],
        "asn_prefixes": ["16276", "213258", "35908", "29169"],
        "short": "OVH",
        "color": "#123F6D",
    },
    "hetzner": {
        "names": ["hetzner", "hetzner online"],
        "asn_prefixes": ["24940", "61157", "43366"],
        "short": "Hetzner",
        "color": "#D50C2D",
    },
    "linode": {
        "names": ["linode", "akamai connected cloud"],
        "asn_prefixes": ["63949", "26496", "62597"],
        "short": "Linode",
        "color": "#00A95C",
    },
    "cloudflare": {
        "names": ["cloudflare", "cloudflare inc"],
        "asn_prefixes": ["13335", "395982"],
        "short": "CF",
        "color": "#F38020",
    },
    "vultr": {
        "names": ["vultr holdings", "choopa"],
        "asn_prefixes": ["20473"],
        "short": "Vultr",
        "color": "#007BFC",
    },
    "oracle": {
        "names": ["oracle", "oracle cloud"],
        "asn_prefixes": ["31898"],
        "short": "Oracle",
        "color": "#F80000",
    },
    "alibaba": {
        "names": ["alibaba", "alibaba cloud", "alicloud"],
        "asn_prefixes": ["45102", "37963", "4766"],
        "short": "Alibaba",
        "color": "#FF6A00",
    },
    "cloudlinux": {
        "names": ["cloudlinux", "tucows"],
        "asn_prefixes": ["16968", "19994"],
        "short": "Tucows",
        "color": "#1E88E5",
    },
    "leaseweb": {
        "names": ["leaseweb", "ovh sas"],
        "asn_prefixes": ["16276", "57626"],
        "short": "LeaseWeb",
        "color": "#B71C1C",
    },
    "godaddy": {
        "names": ["godaddy.com", "godaddy"],
        "asn_prefixes": ["16509", "26496"],
        "short": "GoDaddy",
        "color": "#1BDB87",
    },
    "fastly": {
        "names": ["fastly", "fastly inc"],
        "asn_prefixes": ["54113"],
        "short": "Fastly",
        "color": "red",
    },
    "akamai": {
        "names": ["akamai", "akamai technologies"],
        "asn_prefixes": ["16625", "20940", "35994"],
        "short": "Akamai",
        "color": "#009BDE",
    },
    "microsoft": {
        "names": ["microsoft", "microsoft corporation", "azure"],
        "asn_prefixes": ["8075", "12076", "8068"],
        "short": "Azure",
        "color": "#0078D4",
    },
}


@dataclass
class ASNInfo:
    """ASN and hosting provider information for an IP."""
    ip: str
    asn: int | None = None
    asn_org: str | None = None
    as_name: str | None = None
    country: str | None = None
    country_name: str | None = None
    city: str | None = None
    region: str | None = None
    isp: str | None = None
    hosting_provider: str | None = None
    hosting_color: str | None = None
    is_hosting: bool = False
    is_datacenter: bool = False
    is_residential: bool = False
    lookup_error: str | None = None
    raw_response: dict = field(default_factory=dict)

    @property
    def is_confidence_signal(self) -> bool:
        """Whether this ASN info provides a useful confidence signal."""
        return self.asn is not None and not self.lookup_error

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "asn": self.asn,
            "asn_org": self.asn_org,
            "as_name": self.as_name,
            "country": self.country,
            "country_name": self.country_name,
            "city": self.city,
            "region": self.region,
            "isp": self.isp,
            "hosting_provider": self.hosting_provider,
            "is_hosting": self.is_hosting,
            "is_datacenter": self.is_datacenter,
            "is_residential": self.is_residential,
            "lookup_error": self.lookup_error,
        }


class ASNLookup:
    """
    ASN and hosting provider lookup service.

    Uses free APIs with automatic fallback:
    1. ip-api.com (primary, 45 req/min)
    2. ipinfo.io (fallback)

    Detects hosting providers from ASN/org names.

    Usage:
        asn_lookup = ASNLookup()
        info = await asn_lookup.lookup("1.2.3.4")
        print(f"Provider: {info.hosting_provider}")
    """

    def __init__(
        self,
        timeout: float = 10.0,
        max_concurrent: int = 30,
        rate_limit_delay: float = 1.5,
    ) -> None:
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.rate_limit_delay = rate_limit_delay
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._last_request: float = 0.0

    async def lookup(self, ip: str) -> ASNInfo:
        """
        Look up ASN and hosting provider for an IP.

        Args:
            ip: IP address to look up

        Returns:
            ASNInfo with ASN, geolocation, and hosting provider data
        """
        info = ASNInfo(ip=ip)

        # Rate limiting
        await self._rate_limit()

        # Try primary API first
        result = await self._query_ip_api(ip)
        if result:
            self._parse_result(info, result)
            return info

        # Fallback to ipinfo.io
        result = await self._query_ipinfo(ip)
        if result:
            self._parse_result(info, result)
            return info

        info.lookup_error = "All ASN lookup APIs failed"
        return info

    async def lookup_batch(self, ips: list[str]) -> list[ASNInfo]:
        """
        Look up ASN info for multiple IPs concurrently with rate limiting.

        Args:
            ips: List of IP addresses

        Returns:
            List of ASNInfo results in same order as input
        """
        tasks = [self.lookup(ip) for ip in ips]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def _rate_limit(self) -> None:
        """Apply rate limiting between requests."""
        import time
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - elapsed)
        self._last_request = time.monotonic()

    async def _query_ip_api(self, ip: str) -> dict | None:
        """Query ip-api.com for ASN data (free, 45 req/min)."""
        import httpx

        url = f"http://ip-api.com/json/{ip}?fields=status,message,as,asname,org,isp,country,countryCode,regionName,city,hosting,query"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url)
                data = response.json()

            if data.get("status") == "success":
                return data
            return None

        except Exception as e:
            logger.debug("ip-api.com lookup failed for %s: %s", ip, e)
            return None

    async def _query_ipinfo(self, ip: str) -> dict | None:
        """Query ipinfo.io for ASN data (free 50k/month)."""
        import httpx

        url = f"https://ipinfo.io/{ip}/json"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url)
                data = response.json()

            if "org" in data or "asn" in data:
                return {
                    "as": data.get("asn"),
                    "asname": data.get("asname", ""),
                    "org": data.get("org", ""),
                    "isp": data.get("org", ""),
                    "country": data.get("country"),
                    "countryCode": data.get("country"),
                    "regionName": data.get("region", ""),
                    "city": data.get("city", ""),
                    "hosting": False,  # ipinfo doesn't provide this
                }
            return None

        except Exception as e:
            logger.debug("ipinfo.io lookup failed for %s: %s", ip, e)
            return None

    def _parse_result(self, info: ASNInfo, data: dict) -> None:
        """Parse API response into ASNInfo."""
        info.raw_response = data

        # ASN
        asn_str = data.get("as", "")
        if asn_str:
            # ip-api returns "AS12345", ipinfo returns "AS12345 Amazon"
            asn_match = re.match(r"AS(\d+)", str(asn_str))
            if asn_match:
                info.asn = int(asn_match.group(1))
                info.as_name = asn_str

        info.asn_org = data.get("org", "") or data.get("asname", "")
        info.isp = data.get("isp", "")
        info.country = data.get("country") or data.get("countryCode", "")
        info.country_name = self._country_code_to_name(info.country)
        info.city = data.get("city", "")
        info.region = data.get("regionName", "")

        # Determine if hosting/datacenter/residential
        info.is_hosting = bool(data.get("hosting", False))

        # Detect if datacenter IP (common for origin servers)
        dc_indicators = ["ovh", "server", "cloud", "dedicated", "hosting"]
        org_lower = info.asn_org.lower() if info.asn_org else ""
        isp_lower = info.isp.lower() if info.isp else ""
        info.is_datacenter = any(kw in org_lower or kw in isp_lower for kw in dc_indicators)

        # Detect residential
        res_indicators = ["telecom", "mobile", "broadband", "dsl", "cable", "wireless", "cellular", "vodafone", "at&t", "verizon", "comcast"]
        info.is_residential = any(kw in org_lower or kw in isp_lower for kw in res_indicators)

        # Detect hosting provider
        provider = self._detect_hosting_provider(info.asn, info.asn_org, info.isp)
        if provider:
            info.hosting_provider = provider["short"]
            info.hosting_color = provider["color"]

    def _detect_hosting_provider(
        self, asn: int | None, org: str, isp: str
    ) -> dict[str, Any] | None:
        """Detect known hosting provider from ASN/org/ISP."""
        if asn is None and not org:
            return None

        asn_str = str(asn) if asn else ""
        org_lower = org.lower() if org else ""
        isp_lower = isp.lower() if isp else ""

        for provider_data in HOSTING_PROVIDERS.values():
            # Check ASN prefix match
            if asn_str and any(
                asn_str.startswith(prefix)
                for prefix in provider_data["asn_prefixes"]
            ):
                return provider_data

            # Check org name match
            for name in provider_data["names"]:
                if name in org_lower or name in isp_lower:
                    return provider_data

        return None

    @staticmethod
    def _country_code_to_name(code: str) -> str:
        """Convert 2-letter country code to full name."""
        if not code or len(code) != 2:
            return ""
        countries = {
            "US": "United States", "DE": "Germany", "FR": "France",
            "GB": "United Kingdom", "NL": "Netherlands", "JP": "Japan",
            "SG": "Singapore", "CA": "Canada", "AU": "Australia",
            "BR": "Brazil", "IN": "India", "KR": "South Korea",
            "FI": "Finland", "SE": "Sweden", "NO": "Norway",
            "IE": "Ireland", "CH": "Switzerland", "AT": "Austria",
            "PL": "Poland", "CZ": "Czech Republic", "RO": "Romania",
            "UA": "Ukraine", "RU": "Russia", "CN": "China",
            "HK": "Hong Kong", "TW": "Taiwan", "NZ": "New Zealand",
            "ES": "Spain", "IT": "Italy", "PT": "Portugal",
            "IL": "Israel", "AE": "UAE", "SA": "Saudi Arabia",
            "ZA": "South Africa", "NG": "Nigeria", "KE": "Kenya",
            "MX": "Mexico", "AR": "Argentina", "CO": "Colombia",
            "CL": "Chile", "PE": "Peru", "ID": "Indonesia",
            "MY": "Malaysia", "TH": "Thailand", "PH": "Philippines",
            "VN": "Vietnam", "TR": "Turkey", "EG": "Egypt",
        }
        return countries.get(code.upper(), "")
