"""
CloudFail-Killer - Rate Limiter

Token bucket rate limiter for controlling request rates per source.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Process-wide shared buckets: concurrent batch scans all draw from ONE
# budget per source instead of multiplying the allowed rate by the
# concurrency factor. This is what keeps batch mode "fair" to every
# data source regardless of --batch-concurrency.
_SHARED_BUCKETS: dict[str, "TokenBucket"] = {}
_SHARED_LOCK = threading.Lock()


def get_shared_bucket(source: str, rate: float, burst: int) -> "TokenBucket":
    """Return the process-wide token bucket for ``source`` (create on first use)."""
    with _SHARED_LOCK:
        b = _SHARED_BUCKETS.get(source)
        if b is None:
            b = TokenBucket(rate=rate, burst=burst)
            _SHARED_BUCKETS[source] = b
        return b


@dataclass
class TokenBucket:
    """Token bucket rate limiter."""

    rate: float = 1.0  # requests per second
    burst: int = 3  # max burst size
    _tokens: float = 0.0
    _last_refill: float = 0.0
    _lock: asyncio.Lock | None = None
    _lock_loop: object = None

    def __post_init__(self) -> None:
        self._tokens = float(self.burst)
        self._last_refill = time.monotonic()
        self._lock = None
        self._lock_loop = None

    @property
    def lock(self) -> asyncio.Lock:
        """Loop-safe lazy lock: a shared bucket can outlive the event loop
        it was first used in, so the lock is rebound when the loop changes."""
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is not loop:
            self._lock = asyncio.Lock()
            self._lock_loop = loop
        return self._lock

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        self._last_refill = now

    async def acquire(self) -> None:
        """Acquire a token, waiting (and re-checking) until one is available.

        The lock is held while sleeping so competing workers queue behind us
        and re-evaluate the refill — a single sleep must not grant a token
        that was never refilled.
        """
        async with self.lock:
            while True:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                deficit = 1.0 - self._tokens
                await asyncio.sleep(deficit / self.rate)


class RateLimiter:
    """
    Multi-source rate limiter.

    Usage:
        limiter = RateLimiter(default_rate=1.0)
        limiter.register("crtsh", rate=0.5)  # 0.5 req/s for crt.sh
        await limiter.wait("crtsh")  # Wait before request
    """

    def __init__(
        self,
        default_rate: float = 1.0,
        default_burst: int = 3,
        shared: bool = False,
    ) -> None:
        self._buckets: dict[str, TokenBucket] = {}
        self._default_rate = default_rate
        self._default_burst = default_burst
        # shared=True: all limiters with the same flag draw from one
        # process-wide budget per source — required for fair batch
        # concurrency (N concurrent scans must not become N× the rate).
        self._shared = shared

    def register(self, source: str, rate: float | None = None, burst: int | None = None) -> None:
        """Register a rate limiter for a source."""
        rate = rate if rate is not None else self._default_rate
        burst = burst if burst is not None else self._default_burst
        if self._shared:
            self._buckets[source] = get_shared_bucket(source, rate, burst)
        else:
            self._buckets[source] = TokenBucket(rate=rate, burst=burst)

    async def wait(self, source: str) -> None:
        """Wait for rate limit on a source. Auto-registers if needed."""
        if source not in self._buckets:
            self.register(source)
        await self._buckets[source].acquire()

    def get_stats(self) -> dict[str, dict]:
        """Get stats for all registered sources."""
        return {
            name: {"rate": b.rate, "burst": b.burst, "tokens": round(b._tokens, 2)}
            for name, b in self._buckets.items()
        }
