"""
CloudFail-Killer - Host Header Injection Probe

Verifies discovered IPs by sending HTTP requests with the target domain
in the Host header. This technique exploits the fact that many origin
servers respond to the original domain name even when accessed directly
via IP.

MITRE ATT&CK: T1595.002 (Active Scanning - Vulnerability Scanning)
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from cloudkill.core.active_scanner import ActiveScanner
from cloudkill.core.models import EnrichedResult
from cloudkill.utils.cloudflare_ips import CloudflareIPChecker

logger = logging.getLogger(__name__)


@dataclass
class HostHeaderResult:
    """Result of host header injection probe."""
    ip: str
    port: int
    matched: bool = False
    match_type: str = ""  # "exact", "partial", "redirect", "none"
    status_code: int | None = None
    title: str | None = None
    server_header: str | None = None
    x_powered_by: str | None = None
    body_length: int = 0
    response_time_ms: float = 0.0
    redirect_location: str | None = None
    ssl_fingerprint: str | None = None
    confidence_boost: int = 0
    reasons: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "port": self.port,
            "matched": self.matched,
            "match_type": self.match_type,
            "status_code": self.status_code,
            "title": self.title,
            "server_header": self.server_header,
            "x_powered_by": self.x_powered_by,
            "body_length": self.body_length,
            "response_time_ms": self.response_time_ms,
            "redirect_location": self.redirect_location,
            "ssl_fingerprint": self.ssl_fingerprint,
            "confidence_boost": self.confidence_boost,
            "reasons": self.reasons,
            "error": self.error,
        }


class HostHeaderProbe:
    """
    Host header injection probe for verifying origin IPs.

    Sends HTTP requests to discovered IPs with the target domain
    in the Host header. Compares responses to determine if the
    IP serves the same content as the Cloudflare proxy.

    Usage:
        probe = HostHeaderProbe(timeout=10)
        results = await probe.probe(domain, ips, baseline)
    """

    # Patterns indicating Cloudflare/proxy (not origin)
    PROXY_INDICATORS = [
        "cloudflare",
        "cf-ray",
        "cf-cache-status",
        "sucuri",
        "incapsula",
        "akamai",
        "x-cdn",
        "x-fastly",
        "x-proxy-id",
    ]

    # Patterns indicating origin server
    ORIGIN_INDICATORS = [
        "x-powered-by",
        "x-aspnet-version",
        "x-rack-cache",
        "x-nginx",
        "server: apache",
        "server: nginx",
        "server: microsoft-iis",
        "x-litespeed",
    ]

    TITLE_PATTERN = re.compile(
        r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL
    )

    def __init__(
        self,
        timeout: int = 10,
        max_concurrent: int = 20,
        cf_checker: CloudflareIPChecker | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.cf_checker = cf_checker or CloudflareIPChecker()
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def probe(
        self,
        domain: str,
        results: list[EnrichedResult],
        baseline: dict[str, Any] | None = None,
    ) -> list[HostHeaderResult]:
        """
        Probe discovered IPs with Host header injection.

        Args:
            domain: Target domain to use in Host header
            results: List of enriched results with IPs to probe
            baseline: Optional baseline from normal domain access
                      (title, server, content_hash, status_code)

        Returns:
            List of HostHeaderResult
        """
        if not results:
            return []

        unique_ips = list({r.ip for r in results})
        tasks = []

        for ip in unique_ips:
            # Get ports from results
            ports = {r.port for r in results if r.ip == ip and r.port}
            if not ports:
                ports = {443, 80}

            for port in ports:
                tasks.append(self._probe_single(ip, port, domain, baseline))

        completed = await asyncio.gather(*tasks, return_exceptions=True)
        probe_results: list[HostHeaderResult] = []

        for item in completed:
            if isinstance(item, HostHeaderResult):
                probe_results.append(item)
            elif isinstance(item, Exception):
                logger.debug("Host header probe error: %s", item)

        matched = sum(1 for r in probe_results if r.matched)
        logger.info(
            "Host header probe complete: %d/%d matched for %d IPs",
            matched, len(probe_results), len(unique_ips),
        )
        return probe_results

    async def fetch_baseline(
        self, domain: str, verify_ssl: bool = True
    ) -> dict[str, Any]:
        """
        Fetch a baseline response from the Cloudflare-protected domain.

        This is used for comparison when probing origin IPs.

        Args:
            domain: Domain to fetch baseline from
            verify_ssl: Whether to verify SSL certificates

        Returns:
            Dictionary with baseline response data
        """
        baseline: dict[str, Any] = {}

        for scheme in ["https", "http"]:
            url = f"{scheme}://{domain}/"
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(self.timeout, connect=5.0),
                    verify=verify_ssl,
                    follow_redirects=False,
                ) as client:
                    response = await client.get(url)

                baseline["url"] = url
                baseline["status_code"] = response.status_code
                baseline["server_header"] = response.headers.get("server", "")
                baseline["x_powered_by"] = response.headers.get("x-powered-by", "")
                baseline["content_length"] = len(response.text)
                baseline["content_hash"] = hashlib.md5(
                    response.text.encode(errors="ignore")
                ).hexdigest()

                title = self._extract_title(response.text)
                if title:
                    baseline["title"] = title

                # Collect all proxy headers
                proxy_headers = {}
                for h, v in response.headers.items():
                    for indicator in self.PROXY_INDICATORS:
                        if indicator in h.lower() or indicator in v.lower():
                            proxy_headers[h] = v
                baseline["proxy_headers"] = proxy_headers

                logger.info(
                    "Baseline fetched from %s: status=%d, title=%s",
                    url, response.status_code, title or "N/A",
                )
                return baseline

            except Exception as e:
                logger.debug("Baseline fetch from %s failed: %s", url, e)
                continue

        return baseline

    async def _probe_single(
        self,
        ip: str,
        port: int,
        domain: str,
        baseline: dict[str, Any] | None,
    ) -> HostHeaderResult:
        """Probe a single IP with host header injection."""
        async with self._semaphore:
            result = HostHeaderResult(ip=ip, port=port)

            # Skip Cloudflare IPs
            if self.cf_checker.is_cloudflare_ip(ip):
                result.error = "Cloudflare IP"
                return result

            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{ip}:{port}/"

            headers = {
                "Host": domain,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close",
            }

            start_time = asyncio.get_running_loop().time()

            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(self.timeout, connect=5.0),
                    verify=False,
                    follow_redirects=False,
                ) as client:
                    response = await client.get(url, headers=headers)

                elapsed = (asyncio.get_running_loop().time() - start_time) * 1000
                result.response_time_ms = elapsed
                result.status_code = response.status_code
                result.server_header = response.headers.get("server", "")
                result.x_powered_by = response.headers.get("x-powered-by", "")
                result.body_length = len(response.text)
                result.title = self._extract_title(response.text)

                if response.status_code in (301, 302, 303, 307, 308):
                    result.redirect_location = response.headers.get("location", "")

                # Analyze and score
                self._analyze_result(result, baseline, domain)

            except httpx.ConnectError:
                result.error = "Connection refused"
            except httpx.TimeoutException:
                result.error = "Timeout"
            except httpx.RemoteProtocolError:
                result.error = "Protocol error (possible SSL mismatch)"
            except Exception as e:
                result.error = str(e)[:200]

            return result

    def _analyze_result(
        self,
        result: HostHeaderResult,
        baseline: dict[str, Any] | None,
        domain: str = "",
    ) -> None:
        """Analyze probe result and determine match level."""
        score = 0
        reasons: list[str] = []

        # Strong negative: Cloudflare/proxy indicators in response
        is_proxy = False
        if result.server_header:
            for indicator in self.PROXY_INDICATORS:
                if indicator in result.server_header.lower():
                    is_proxy = True
                    reasons.append(f"Proxy server header: {result.server_header}")
                    break

        if is_proxy:
            result.matched = False
            result.match_type = "none"
            return

        # Positive signal: origin server indicators
        origin_signals = 0
        if result.server_header and not is_proxy:
            for indicator in self.ORIGIN_INDICATORS:
                if indicator in f"server: {result.server_header}".lower():
                    origin_signals += 1
                    reasons.append(f"Origin signal in headers: {result.server_header}")

        if result.x_powered_by:
            origin_signals += 1
            reasons.append(f"X-Powered-By: {result.x_powered_by}")

        score += origin_signals * 10

        # Compare with baseline if available
        if baseline:
            # Title comparison
            baseline_title = baseline.get("title", "")
            if result.title and baseline_title:
                similarity = ActiveScanner._similarity(
                    result.title, baseline_title
                )
                if similarity > 0.8:
                    score += 25
                    reasons.append(f"Title match ({similarity:.0%}): {result.title}")
                    result.match_type = "exact"
                elif similarity > 0.5:
                    score += 10
                    reasons.append(f"Partial title match ({similarity:.0%})")
                    result.match_type = "partial"

            # Status code comparison
            baseline_status = baseline.get("status_code")
            if baseline_status and result.status_code == baseline_status:
                score += 5
                reasons.append(f"Same status code: {result.status_code}")

            # Server header comparison
            baseline_server = baseline.get("server_header", "")
            if (result.server_header and baseline_server
                    and result.server_header != baseline_server):
                # Different server = likely origin
                score += 10
                reasons.append(
                    f"Different server: {result.server_header} vs {baseline_server}"
                )

        # Redirect to HTTPS or same domain
        if result.redirect_location:
            loc = result.redirect_location.lower()
            # Redirect to https version of domain = likely origin
            if f"https://{result.ip}" in loc or (domain and domain in loc):
                score += 5
                result.match_type = result.match_type or "redirect"
                reasons.append(f"Redirect to: {result.redirect_location}")

        # Successful response
        if result.status_code and 200 <= result.status_code < 400:
            score += 5
            reasons.append(f"HTTP {result.status_code}")

        # Non-empty response body
        if result.body_length > 500:
            score += 3
            reasons.append(f"Response body: {result.body_length} bytes")

        # Determine final match
        if score >= 25:
            result.matched = True
            if not result.match_type:
                result.match_type = "exact"
            result.confidence_boost = min(15, score // 2)
        elif score >= 10:
            result.matched = True
            if not result.match_type:
                result.match_type = "partial"
            result.confidence_boost = min(10, score // 3)
        else:
            result.matched = False
            result.match_type = "none"
            result.confidence_boost = 0

        result.reasons = reasons

    @staticmethod
    def _extract_title(html: str) -> str | None:
        """Extract page title from HTML."""
        match = HostHeaderProbe.TITLE_PATTERN.search(html)
        if match:
            return match.group(1).strip()[:200]
        return None
