"""
CloudFail-Killer - False Positive Filter

Filters out false positive IPs that are not actual origin servers.
Common false positive patterns include:
    - CDN/WAF providers other than Cloudflare
    - Shared hosting platforms
    - Content Delivery Networks (Akamai, Fastly, Incapsula)
    - Public DNS resolvers
    - Cloud security scanners
    - Honey pots and canary tokens
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass

from cloudkill.core.models import EnrichedResult

logger = logging.getLogger(__name__)

# Known non-origin IP ranges (CDNs, security scanners, etc.)
# These are IP ranges that commonly appear in results but are NOT origin IPs
FALSE_POSITIVE_RANGES: list[tuple[str, int]] = [
    # Akamai CDN
    ("23.32.0.0/10", 256),
    ("23.0.0.0/8", 256),
    ("72.246.0.0/14", 256),
    ("184.24.27.0/16", 256),
    ("72.247.176.0/20", 256),
    # Fastly
    ("151.101.0.0/16", 256),
    ("199.232.0.0/14", 256),
    # Incapsula
    ("45.64.0.0/18", 256),
    # Sucuri (CloudProxy)
    ("192.88.134.0/24", 256),
    ("192.88.135.0/24", 256),
    # StackPath
    ("198.41.128.0/17", 256),
    # Imperva
    ("35.186.0.0/15", 256),
    # BunnyCDN
    ("185.31.120.0/22", 256),
    # QUIC.cloud / Cloudflare edge
    ("162.159.0.0/16", 256),
    # Public DNS resolvers
    ("8.8.8.0/24", 256),
    ("8.8.4.0/24", 256),
    ("1.1.1.1/24", 256),
    ("1.0.0.1/24", 256),
    ("9.9.9.9/24", 256),
    ("208.67.222.222/32", 256),
    # Project Honey Pot
    ("64.225.16.0/24", 256),
    ("216.218.254.0/22", 256),
]

# Known false positive org/ISP patterns
FALSE_POSITIVE_ORGS = [
    "cloudflare", "akamai", "fastly", "incapsula", "sucuri",
    "imperva", "stackpath", "bunnycdn", "section io",
    "quic.cloud", "project honeypot", "cisco umbrella",
    "zscaler", "radware", "cloudflare, inc.",
]

# Patterns for identifying false positives
FP_SUBDOMAIN_PATTERNS = [
    r"^(cdn|static|assets|cache|edge|proxy|waf|firewall)\.",
    r"^(cloudflare|akamai|fastly|imperva|incapsula|sucuri)\.",
    r"^([\w-]+\.)?(cloudfront|cloudflare|akamai|fastly|edgecast|edge)\.",
]


@dataclass
class FilterResult:
    """Result of false positive analysis."""
    ip: str
    is_false_positive: bool = False
    reason: str = ""
    fp_type: str = ""  # "cdn", "waf", "dns_resolver", "honeypot"
    confidence_penalty: int = 0


class FalsePositiveFilter:
    """
    False positive detection and removal system.

    Analyzes enriched results and identifies IPs that are likely
    false positives (not actual origin servers).

    The filter uses multiple heuristics:
    1. Known CDN/WAF IP range matching
    2. Cloudflare org/ASN detection (already done, but double-check)
    3. Subdomain-based CDN detection
    4. Public DNS resolver detection
    5. Honeypot detection
    """

    def __init__(self) -> None:
        # Pre-compile FP IP range networks
        self._fp_networks: list[ipaddress.IPv4Network] = []
        self._fp_networks_v6: list[ipaddress.IPv6Network] = []

        for cidr, _prefix_len in FALSE_POSITIVE_RANGES:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    self._fp_networks.append(net)
                else:
                    self._fp_networks_v6.append(net)
            except ValueError:
                continue

        # Pre-compile subdomain patterns
        self._fp_subdomain_patterns = [
            re.compile(p, re.IGNORECASE) for p in FP_SUBDOMAIN_PATTERNS
        ]

        logger.info(
            "FalsePositiveFilter loaded: %d IPv4 + %d IPv6 known FP ranges, "
            "%d org patterns, %d subdomain patterns",
            len(self._fp_networks),
            len(self._fp_networks_v6),
            len(FALSE_POSITIVE_ORGS),
            len(self._fp_subdomain_patterns),
        )

    def check(self, result: EnrichedResult) -> FilterResult:
        """
        Check if a result is a false positive.

        Args:
            result: EnrichedResult to analyze

        Returns:
            FilterResult with analysis details
        """
        filter_result = FilterResult(ip=result.ip)

        # 1. Check known FP IP ranges
        if self._is_in_fp_range(result.ip):
            filter_result.is_false_positive = True
            filter_result.reason = "IP in known CDN/WAF range"
            filter_result.fp_type = "cdn"
            filter_result.confidence_penalty = 50
            return filter_result

        # 2. Check ASN org for WAF/CDN providers
        if result.asn_org:
            org_lower = result.asn_org.lower()
            if any(fp_org in org_lower for fp_org in FALSE_POSITIVE_ORGS):
                filter_result.is_false_positive = True
                filter_result.reason = f"ASN org matches WAF/CDN provider: {result.asn_org}"
                filter_result.fp_type = "waf"
                filter_result.confidence_penalty = 40
                return filter_result

        # 3. Check ISP for CDN patterns
        if result.isp:
            isp_lower = result.isp.lower()
            if any(fp_org in isp_lower for fp_org in FALSE_POSITIVE_ORGS):
                filter_result.is_false_positive = True
                filter_result.reason = f"ISP matches WAF/CDN provider: {result.isp}"
                filter_result.fp_type = "cdn"
                filter_result.confidence_penalty = 40
                return filter_result

        # 4. Check subdomain for CDN indicators
        subdomain = result.subdomain.lower()
        for pattern in self._fp_subdomain_patterns:
            if pattern.match(subdomain):
                filter_result.is_false_positive = True
                filter_result.reason = f"Subdomain matches CDN pattern: {subdomain}"
                filter_result.fp_type = "cdn"
                filter_result.confidence_penalty = 30
                return filter_result

        # 5. Check SSL certificate for Cloudflare signatures
        if result.ssl_is_cloudflare:
            filter_result.is_false_positive = True
            filter_result.reason = "SSL certificate issued by Cloudflare"
            filter_result.fp_type = "waf"
            filter_result.confidence_penalty = 60
            return filter_result

        # Not a false positive
        return filter_result

    def check_batch(
        self, results: list[EnrichedResult]
    ) -> tuple[list[EnrichedResult], list[EnrichedResult]]:
        """
        Filter a batch of results, separating true from false positives.

        Args:
            results: List of enriched results

        Returns:
            Tuple of (true_positives, false_positives)
        """
        true_positives: list[EnrichedResult] = []
        false_positives: list[EnrichedResult] = []

        for result in results:
            fp_result = self.check(result)
            if fp_result.is_false_positive:
                logger.debug(
                    "False positive filtered: %s (%s) - %s",
                    result.ip, result.subdomain, fp_result.reason,
                )
                # Still include with reduced confidence
                result.confidence = max(0, result.confidence - fp_result.confidence_penalty)
                result.confidence_reasons.append(
                    f"False positive risk: {fp_result.reason} (-{fp_result.confidence_penalty})"
                )
                false_positives.append(result)
            else:
                true_positives.append(result)

        logger.info(
            "False positive filter: %d true positives, %d false positives removed/penalized",
            len(true_positives), len(false_positives),
        )
        return true_positives, false_positives

    def _is_in_fp_range(self, ip: str) -> bool:
        """Check if an IP falls in known false positive ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                return any(ip_obj in net for net in self._fp_networks)
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                return any(ip_obj in net for net in self._fp_networks_v6)
        except ValueError:
            pass
        return False
