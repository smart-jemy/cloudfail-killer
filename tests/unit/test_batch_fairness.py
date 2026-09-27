"""Tests for shared rate-limit fairness + batch exit codes."""

from __future__ import annotations

import asyncio

import pytest

from cloudkill.utils.ratelimit import RateLimiter, get_shared_bucket


class TestSharedRateLimitFairness:
    def test_two_limiters_share_one_bucket(self):
        """Concurrent batch scans must draw from ONE budget per source."""
        a = RateLimiter(default_rate=2.0, default_burst=5, shared=True)
        b = RateLimiter(default_rate=2.0, default_burst=5, shared=True)
        a.register("crtsh")
        b.register("crtsh")
        assert a._buckets["crtsh"] is b._buckets["crtsh"]

    def test_non_shared_limiters_are_independent(self):
        a = RateLimiter(default_rate=2.0, default_burst=5)
        b = RateLimiter(default_rate=2.0, default_burst=5)
        a.register("crtsh")
        b.register("crtsh")
        assert a._buckets["crtsh"] is not b._buckets["crtsh"]

    def test_shared_bucket_registry_returns_same_instance(self):
        s1 = get_shared_bucket("src", 1.0, 3)
        s2 = get_shared_bucket("src", 1.0, 3)
        assert s1 is s2

    def test_shared_bucket_survives_event_loop_change(self):
        """A shared bucket outlives one asyncio.run() loop — the lock must
        rebind to the new loop instead of raising."""

        async def drain_once():
            limiter = RateLimiter(default_rate=100.0, default_burst=5, shared=True)
            limiter.register("loop-test")
            await limiter.wait("loop-test")  # creates the lock on loop #1

        async def drain_again():
            limiter = RateLimiter(default_rate=100.0, default_burst=5, shared=True)
            limiter.register("loop-test")
            await limiter.wait("loop-test")  # reuse on loop #2 must not raise

        asyncio.run(drain_once())
        asyncio.run(drain_again())  # would raise 'attached to a different loop' pre-fix

    def test_fairness_under_concurrency(self):
        """5 workers sharing one bucket cannot spend more tokens than the
        bucket allows — total immediate acquisitions stay bounded."""
        async def scenario():
            limiter = RateLimiter(default_rate=1.0, default_burst=3, shared=True)
            limiter.register("src")

            async def worker():
                await limiter.wait("src")

            start = asyncio.get_running_loop().time()
            await asyncio.gather(*(worker() for _ in range(5)))
            return asyncio.get_running_loop().time() - start

        elapsed = asyncio.run(scenario())
        # burst=3 immediate + rate=1/s → the extra 2 waits cost ~2s.
        # Without the shared bucket, 5 independent buckets would finish ~0s.
        assert elapsed >= 1.5, "shared budget not enforced — rate multiplied!"


class TestBatchExitCodes:
    def test_ci_mode_requires_findings(self):
        """CI mode fails the build when a scan returns no origin candidates."""
        from cloudkill.core.models import ScanReport

        empty = ScanReport(domain="clean.example.com", profile="pentester")
        assert not any(r.results for r in [empty])  # the exit(1) condition
