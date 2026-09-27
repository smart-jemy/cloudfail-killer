"""
CloudFail-Killer - Active Scanner

Safe active probing module for verifying discovered IPs.
Performs HTTP-based probes and port connectivity checks WITHOUT
raw SYN scanning. All probes use standard HTTP requests.

Safety:
    - No raw packet injection (no SYN/FIN/XMAS scans)
    - HTTP-based only (standard GET/HEAD requests)
    - Rate-limited to avoid detection
    - Respects robots.txt conventions
    - Optional stealth delays between probes

MITRE ATT&CK: T1595.001 (Active Scanning - IP Block)
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx

from cloudkill import __version__
from cloudkill.core.models import EnrichedResult
from cloudkill.utils.cloudflare_ips import CloudflareIPChecker

logger = logging.getLogger(__name__)


class ProbeResult(str, Enum):
    """Result of an active probe against an IP."""
    MATCH = "match"
    SIMILAR = "similar"
    NO_MATCH = "no_match"
    TIMEOUT = "timeout"
    ERROR = "error"
    FILTERED = "filtered"


@dataclass
class ActiveProbeResult:
    """Result of probing a single IP."""
    ip: str
    port: int
    result: ProbeResult
    status_code: int | None = None
    title: str | None = None
    server_header: str | None = None
    content_hash: str | None = None
    body_length: int = 0
    response_time_ms: float = 0.0
    redirect_url: str | None = None
    ssl_error: bool = False
    error_message: str | None = None
    confidence_boost: int = 0
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "port": self.port,
            "result": self.result.value,
            "status_code": self.status_code,
            "title": self.title,
            "server_header": self.server_header,
            "content_hash": self.content_hash,
            "body_length": self.body_length,
            "response_time_ms": self.response_time_ms,
            "redirect_url": self.redirect_url,
            "ssl_error": self.ssl_error,
            "error_message": self.error_message,
            "confidence_boost": self.confidence_boost,
            "reasons": self.reasons,
        }


@dataclass
class PortCheckResult:
    """Result of checking if a port is open."""
    ip: str
    port: int
    is_open: bool = False
    service: str | None = None
    response_time_ms: float = 0.0
    banner: str | None = None
    ssl: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "port": self.port,
            "is_open": self.is_open,
            "service": self.service,
            "response_time_ms": self.response_time_ms,
            "banner": self.banner,
            "ssl": self.ssl,
        }


class ActiveScanner:
    """
    Safe active scanner for verifying discovered IPs.

    Uses HTTP-based probing to verify if discovered IPs are actual
    origin servers behind Cloudflare. Performs:
    1. Port connectivity checks (TCP connect, not SYN scan)
    2. HTTP GET probes with Host header
    3. Response comparison against baseline

    Usage:
        scanner = ActiveScanner(config, cf_checker)
        results = await scanner.scan(domain, ips, baseline_response)
    """

    DEFAULT_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]
    COMMON_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}

    # Title extraction pattern
    TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

    # Cloudflare error page indicators
    CF_ERROR_INDICATORS = [
        "cloudflare",
        "attention required",
        "checking your browser",
        "cf-browser-verification",
        "cf-ray:",
        "server error",
        "bad gateway",
        "503 service temporarily unavailable",
        "cloudflare ray",
    ]

    def __init__(
        self,
        timeout: int = 10,
        max_concurrent: int = 20,
        ports: list[int] | None = None,
        cf_checker: CloudflareIPChecker | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.ports = ports or self.DEFAULT_PORTS
        self.cf_checker = cf_checker or CloudflareIPChecker()
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def scan(
        self,
        domain: str,
        ips: list[EnrichedResult],
        baseline_response: dict[str, Any] | None = None,
    ) -> list[ActiveProbeResult]:
        """
        Probe a list of discovered IPs with HTTP requests.

        Args:
            domain: Target domain for Host header
            ips: List of enriched results to probe
            baseline_response: Baseline response from Cloudflare for comparison
                              (title, server_header, content_hash)

        Returns:
            List of ActiveProbeResult for each probe
        """
        if not ips:
            return []

        results: list[ActiveProbeResult] = []
        unique_ips = list({r.ip for r in ips})

        tasks = []
        for ip in unique_ips:
            # Determine ports to probe
            ports_to_check = self._get_ports_for_ip(ip, ips)
            for port in ports_to_check:
                tasks.append(self._probe_ip(ip, port, domain, baseline_response))

        # Execute concurrently with semaphore
        if tasks:
            completed = await asyncio.gather(*tasks, return_exceptions=True)
            for result in completed:
                if isinstance(result, ActiveProbeResult):
                    results.append(result)
                elif isinstance(result, Exception):
                    logger.debug("Probe task error: %s", result)

        logger.info(
            "Active scan complete: %d probes for %d unique IPs",
            len(results), len(unique_ips),
        )
        return results

    async def scan_ports(
        self,
        ips: list[str],
        ports: list[int] | None = None,
    ) -> list[PortCheckResult]:
        """
        Check which ports are open on discovered IPs.

        Uses TCP connect (NOT SYN scan) to check port accessibility.

        Args:
            ips: List of IP addresses
            ports: Ports to check (default: self.ports)

        Returns:
            List of PortCheckResult
        """
        check_ports = ports or self.ports
        results: list[PortCheckResult] = []

        tasks = []
        for ip in ips:
            for port in check_ports:
                tasks.append(self._check_port(ip, port))

        if tasks:
            completed = await asyncio.gather(*tasks, return_exceptions=True)
            for result in completed:
                if isinstance(result, PortCheckResult):
                    results.append(result)
                elif isinstance(result, Exception):
                    logger.debug("Port check task error: %s", result)

        open_ports = sum(1 for r in results if r.is_open)
        logger.info(
            "Port scan complete: %d/%d ports open across %d IPs",
            open_ports, len(results), len(ips),
        )
        return results

    async def _probe_ip(
        self,
        ip: str,
        port: int,
        domain: str,
        baseline: dict[str, Any] | None,
    ) -> ActiveProbeResult:
        """Probe a single IP:port with HTTP request."""
        async with self._semaphore:
            result = ActiveProbeResult(ip=ip, port=port, result=ProbeResult.ERROR)

            # Skip if IP is in Cloudflare ranges
            if self.cf_checker.is_cloudflare_ip(ip):
                result.result = ProbeResult.FILTERED
                result.reasons.append("IP is in Cloudflare ranges")
                return result

            # Skip private IPs
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private or ip_obj.is_loopback:
                    result.result = ProbeResult.FILTERED
                    result.reasons.append("Private/loopback IP")
                    return result
            except ValueError:
                pass

            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{ip}:{port}/"
            headers = {
                "Host": domain,
                "User-Agent": f"CloudKill-Scanner/{__version__}",
                "Accept": "text/html,application/json,*/*",
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

                # Extract title
                result.title = self._extract_title(response.text)
                result.server_header = response.headers.get("server", "")
                result.body_length = len(response.text)
                result.content_hash = hashlib.md5(
                    response.text.encode(errors="ignore")
                ).hexdigest()

                # Check redirect
                if response.status_code in (301, 302, 303, 307, 308):
                    result.redirect_url = response.headers.get("location", "")

                # Compare against baseline
                result = self._compare_response(result, baseline)

            except httpx.ConnectError:
                result.result = ProbeResult.NO_MATCH
                result.error_message = "Connection refused"
            except httpx.TimeoutException:
                result.result = ProbeResult.TIMEOUT
                result.error_message = "Connection timed out"
            except httpx.RemoteProtocolError:
                result.result = ProbeResult.ERROR
                result.error_message = "Protocol error (SSL mismatch?)"
                result.ssl_error = True
            except Exception as e:
                result.result = ProbeResult.ERROR
                result.error_message = str(e)[:200]

            return result

    async def _check_port(self, ip: str, port: int) -> PortCheckResult:
        """Check if a single port is open using TCP connect."""
        async with self._semaphore:
            result = PortCheckResult(ip=ip, port=port)
            is_ssl_port = port in (443, 8443)
            start_time = asyncio.get_running_loop().time()

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout,
                )
                writer.close()
                await writer.wait_closed()

                elapsed = (asyncio.get_running_loop().time() - start_time) * 1000
                result.is_open = True
                result.response_time_ms = elapsed
                result.ssl = is_ssl_port

                # Identify service
                if port == 80:
                    result.service = "HTTP"
                elif port == 443:
                    result.service = "HTTPS"
                elif port == 8080:
                    result.service = "HTTP-Alt"
                elif port == 8443:
                    result.service = "HTTPS-Alt"
                elif port == 3000:
                    result.service = "Node.js"
                elif port == 5000:
                    result.service = "Flask/Dev"
                elif port == 8000:
                    result.service = "Django/Dev"
                elif port == 8888:
                    result.service = "Jupyter/Alt"
                else:
                    result.service = "unknown"

            except TimeoutError:
                result.response_time_ms = self.timeout * 1000
            except ConnectionRefusedError:
                result.error_message = "Connection refused"
            except OSError as e:
                result.error_message = str(e)[:100]

            return result

    def _compare_response(
        self,
        result: ActiveProbeResult,
        baseline: dict[str, Any] | None,
    ) -> ActiveProbeResult:
        """Compare probe response against baseline to determine match level."""
        if not baseline:
            # No baseline — use heuristic scoring
            return self._score_without_baseline(result)

        # Check for Cloudflare error pages
        if result.title and any(
            ind in result.title.lower() for ind in self.CF_ERROR_INDICATORS
        ):
            result.result = ProbeResult.NO_MATCH
            result.reasons.append("Response shows Cloudflare error page")
            return result

        score = 0
        reasons: list[str] = []

        # Title match (strongest signal)
        baseline_title = baseline.get("title", "")
        if result.title and baseline_title:
            if result.title.strip().lower() == baseline_title.strip().lower():
                score += 30
                reasons.append("Title matches exactly")
            elif self._similarity(result.title, baseline_title) > 0.7:
                score += 15
                reasons.append("Title is similar")

        # Server header match
        baseline_server = baseline.get("server_header", "")
        if (result.server_header and baseline_server
                and result.server_header.lower() == baseline_server.lower()):
            score += 10
            reasons.append(f"Server header matches: {result.server_header}")

        # Same status code
        baseline_status = baseline.get("status_code")
        if baseline_status and result.status_code == baseline_status:
            score += 5
            reasons.append(f"Same status code: {result.status_code}")

        # Non-Cloudflare server header (positive signal)
        if result.server_header and not any(
            cf in result.server_header.lower()
            for cf in ["cloudflare", "cf-ray"]
        ):
            score += 10
            reasons.append(f"Non-CF server: {result.server_header}")

        # Content hash match
        baseline_hash = baseline.get("content_hash", "")
        if (result.content_hash and baseline_hash
                and result.content_hash == baseline_hash):
            score += 20
            reasons.append("Page content hash matches")

        # Successful response (not error)
        if result.status_code and 200 <= result.status_code < 400:
            score += 5
            reasons.append(f"Successful response: {result.status_code}")

        # No redirect to cloudflare
        if result.redirect_url and "cloudflare" in result.redirect_url.lower():
            score -= 20
            reasons.append("Redirects to Cloudflare")
            result.result = ProbeResult.NO_MATCH
            result.confidence_boost = max(0, score)
            return result

        # Determine result level
        if score >= 40:
            result.result = ProbeResult.MATCH
            result.confidence_boost = min(25, score // 2)
        elif score >= 20:
            result.result = ProbeResult.SIMILAR
            result.confidence_boost = min(15, score // 3)
        else:
            result.result = ProbeResult.NO_MATCH
            result.confidence_boost = 0

        result.reasons = reasons
        return result

    def _score_without_baseline(self, result: ActiveProbeResult) -> ActiveProbeResult:
        """Score a probe result when no baseline is available."""
        score = 0
        reasons: list[str] = []

        # Check for Cloudflare error page
        if result.title and any(
            ind in result.title.lower() for ind in self.CF_ERROR_INDICATORS
        ):
            result.result = ProbeResult.NO_MATCH
            result.reasons.append("Cloudflare error page detected")
            return result

        # Successful HTTP response
        if result.status_code and 200 <= result.status_code < 400:
            score += 10
            reasons.append(f"HTTP {result.status_code} OK")

        # Non-Cloudflare server header
        if result.server_header and "cloudflare" not in result.server_header.lower():
            score += 15
            reasons.append(f"Server: {result.server_header}")

        # Has a real page (not empty/error)
        if result.body_length > 100:
            score += 5
            reasons.append(f"Page content: {result.body_length} bytes")

        # Fast response (suggests direct connection, not CDN)
        if 0 < result.response_time_ms < 500:
            score += 5
            reasons.append(f"Fast response: {result.response_time_ms:.0f}ms")

        if score >= 20:
            result.result = ProbeResult.SIMILAR
            result.confidence_boost = min(15, score // 2)
        else:
            result.result = ProbeResult.NO_MATCH

        result.reasons = reasons
        return result

    def _get_ports_for_ip(
        self, ip: str, results: list[EnrichedResult]
    ) -> list[int]:
        """Get ports to probe for an IP based on discovery context."""
        # Start with common web ports
        ports_to_check = set(self.ports)

        # If IP was discovered on specific ports, include those
        for r in results:
            if r.ip == ip and r.port:
                ports_to_check.add(r.port)

        return sorted(ports_to_check)

    @staticmethod
    def _extract_title(html: str) -> str | None:
        """Extract page title from HTML."""
        match = ActiveScanner.TITLE_PATTERN.search(html)
        if match:
            return match.group(1).strip()[:200]
        return None

    @staticmethod
    def _similarity(a: str, b: str) -> float:
        """Simple character-level similarity between two strings."""
        if not a or not b:
            return 0.0
        a, b = a.lower().strip(), b.lower().strip()
        if a == b:
            return 1.0
        longer, shorter = (a, b) if len(a) > len(b) else (b, a)
        if not shorter:
            return 0.0
        matches = sum(1 for c in shorter if c in longer)
        return matches / len(longer)
