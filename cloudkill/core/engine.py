"""
CloudFail-Killer - Async HTTP Engine

High-performance async HTTP client with:
- Automatic retry with exponential backoff + jitter
- IPv4/IPv6 dual-stack support
- Per-source rate limiting
- User-Agent rotation
- Connection pooling
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from cloudkill.config import Config
from cloudkill.utils.useragents import USER_AGENTS

# Non-crypto use (jitter/UA rotation) but seeded from OS entropy anyway
_system_random = random.SystemRandom()

logger = logging.getLogger(__name__)

# Status codes that should trigger a retry
RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}

# Status codes that indicate we should not retry
STOP_STATUS_CODES = {400, 401, 403, 404, 405, 410, 422}


@dataclass
class RequestStats:
    """Track HTTP request statistics."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    retries: int = 0
    total_bytes_received: int = 0
    source_stats: dict[str, dict[str, int]] = field(default_factory=dict)

    def record(self, source: str, success: bool, bytes_received: int = 0) -> None:
        """Record a request outcome."""
        self.total_requests += 1
        if success:
            self.successful_requests += 1
            self.total_bytes_received += bytes_received
        else:
            self.failed_requests += 1

        if source not in self.source_stats:
            self.source_stats[source] = {"success": 0, "failed": 0}
        key = "success" if success else "failed"
        self.source_stats[source][key] += 1


class AsyncEngine:
    """
    Async HTTP engine with retry, rate-limiting, and IPv6 support.

    Usage:
        async with AsyncEngine(config) as engine:
            resp = await engine.get("https://api.example.com/data")
    """

    def __init__(
        self,
        config: Config | None = None,
        threads: int = 20,
        timeout: int = 30,
        proxy: str | None = None,
        ipv6_preference: bool = False,
    ) -> None:
        self.config = config or Config()
        self.threads = threads
        self.timeout = timeout
        self.proxy = proxy or self.config.proxy
        self.ipv6_preference = ipv6_preference or self.config.ipv6_preference
        self._client: httpx.AsyncClient | None = None
        self.stats = RequestStats()
        self._rate_limiters: dict[str, asyncio.Semaphore] = {}
        self._last_request_time: dict[str, float] = {}

    @property
    def _effective_threads(self) -> int:
        """Get effective thread count based on stealth mode."""
        return self.config.effective_threads if self.config else self.threads

    def _get_headers(self) -> dict[str, str]:
        """Generate headers with random User-Agent."""
        ua = _system_random.choice(USER_AGENTS)
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }
        return headers

    def _build_client_kwargs(self) -> dict[str, Any]:
        """Build kwargs for httpx.AsyncClient."""
        kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(self.timeout, connect=15.0),
            "limits": httpx.Limits(
                max_connections=self._effective_threads,
                max_keepalive_connections=self._effective_threads,
                keepalive_expiry=30,
            ),
            "headers": self._get_headers(),
            "follow_redirects": True,
            "http2": True,
        }

        if self.proxy:
            kwargs["proxy"] = self.proxy

        # IPv6 preference is handled at the DNS resolution level,
        # not at the HTTP client level. The httpx.AsyncClient does not
        # accept a `local_address` parameter — binding to a specific
        # local interface must be done via a custom transport if needed.
        return kwargs

    async def start(self) -> None:
        """Initialize the HTTP client (call before first request)."""
        if self._client is None:
            self._client = httpx.AsyncClient(**self._build_client_kwargs())
            logger.debug(
                "HTTP engine started (threads=%d, ipv6=%s, proxy=%s)",
                self._effective_threads,
                self.ipv6_preference,
                bool(self.proxy),
            )

    async def stop(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.debug("HTTP engine stopped. Stats: %s", self.stats)

    async def __aenter__(self) -> AsyncEngine:
        await self.start()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.stop()

    def _get_rate_limiter(self, source: str, rate_limit: float = 1.0) -> asyncio.Semaphore:
        """Get or create a rate limiter for a source."""
        if source not in self._rate_limiters:
            # Convert requests/second to min interval between requests
            tokens = max(1, int(rate_limit * 2))
            self._rate_limiters[source] = asyncio.Semaphore(tokens)
        return self._rate_limiters[source]

    async def _wait_for_rate_limit(self, source: str, rate_limit: float = 1.0) -> None:
        """Wait if necessary to respect rate limits."""
        now = time.monotonic()
        min_interval = 1.0 / max(rate_limit, 0.1)

        if source in self._last_request_time:
            elapsed = now - self._last_request_time[source]
            if elapsed < min_interval:
                wait_time = min_interval - elapsed
                # Add small random jitter (0-20%)
                jitter = _system_random.uniform(0, wait_time * 0.2)
                await asyncio.sleep(wait_time + jitter)

        self._last_request_time[source] = time.monotonic()

    async def get(
        self,
        url: str,
        source: str = "default",
        retries: int = 3,
        rate_limit: float = 1.0,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """
        Perform an HTTP GET request with retry and rate-limiting.

        Args:
            url: The URL to request
            source: Source name for rate limiting and stats
            retries: Number of retry attempts
            rate_limit: Max requests per second
            headers: Additional headers to merge
            **kwargs: Additional httpx.request kwargs

        Returns:
            httpx.Response object

        Raises:
            httpx.HTTPError: After all retries exhausted
        """
        await self._ensure_client()

        last_exception: Exception | None = None

        for attempt in range(1, retries + 1):
            try:
                # Rate limiting
                await self._wait_for_rate_limit(source, rate_limit)

                # Merge headers
                req_headers = {**self._get_headers(), **(headers or {})}
                kwargs["headers"] = req_headers

                response = await self._client.get(url, **kwargs)

                self.stats.record(source, True, len(response.content))

                # Check if response is retryable
                if response.status_code in RETRYABLE_STATUS_CODES and attempt < retries:
                    self.stats.retries += 1
                    backoff = min(2 ** attempt + _system_random.uniform(0, 1), 30)
                    logger.debug(
                        "Retry %d/%d for %s (status=%d, backoff=%.1fs)",
                        attempt, retries, url, response.status_code, backoff,
                    )
                    await asyncio.sleep(backoff)
                    continue

                return response

            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout) as e:
                last_exception = e
                self.stats.record(source, False)
                if attempt < retries:
                    backoff = min(2 ** attempt + _system_random.uniform(0, 1), 30)
                    logger.debug(
                        "Retry %d/%d for %s (%s, backoff=%.1fs)",
                        attempt, retries, url, e, backoff,
                    )
                    await asyncio.sleep(backoff)
                    continue
                break

            except httpx.HTTPStatusError:
                raise

        # All retries failed
        error_msg = f"All {retries} retries exhausted for {url}"
        if last_exception:
            raise httpx.ConnectError(f"{error_msg}: {last_exception}") from last_exception
        raise httpx.ConnectError(error_msg)

    async def post(
        self,
        url: str,
        source: str = "default",
        retries: int = 3,
        rate_limit: float = 1.0,
        **kwargs: Any,
    ) -> httpx.Response:
        """Perform an HTTP POST request with retry and rate-limiting."""
        await self._ensure_client()

        last_exception: Exception | None = None

        for attempt in range(1, retries + 1):
            try:
                await self._wait_for_rate_limit(source, rate_limit)

                kwargs["headers"] = kwargs.get("headers", self._get_headers())
                response = await self._client.post(url, **kwargs)

                self.stats.record(source, True, len(response.content))

                if response.status_code in RETRYABLE_STATUS_CODES and attempt < retries:
                    self.stats.retries += 1
                    backoff = min(2 ** attempt + _system_random.uniform(0, 1), 30)
                    await asyncio.sleep(backoff)
                    continue

                return response

            except (httpx.ConnectError, httpx.ReadTimeout) as e:
                last_exception = e
                self.stats.record(source, False)
                if attempt < retries:
                    backoff = min(2 ** attempt + _system_random.uniform(0, 1), 30)
                    await asyncio.sleep(backoff)
                    continue
                break

        error_msg = f"All {retries} retries exhausted for {url}"
        if last_exception:
            raise httpx.ConnectError(f"{error_msg}: {last_exception}") from last_exception
        raise httpx.ConnectError(error_msg)

    async def get_json(
        self,
        url: str,
        source: str = "default",
        retries: int = 3,
        rate_limit: float = 1.0,
        **kwargs: Any,
    ) -> Any:
        """GET request that returns parsed JSON."""
        response = await self.get(url, source=source, retries=retries, rate_limit=rate_limit, **kwargs)
        response.raise_for_status()
        return response.json()

    async def _ensure_client(self) -> None:
        """Ensure HTTP client is initialized."""
        if self._client is None:
            await self.start()

    def is_ipv6_address(self, ip: str) -> bool:
        """Check if an IP string is IPv6."""
        try:
            return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
        except ValueError:
            return False
