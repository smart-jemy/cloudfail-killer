"""Phase 1 unit tests - Engine, Models, Cloudflare IPs, Rate Limiter, Stealth."""

import time

import pytest

from cloudkill.config import Config
from cloudkill.core.engine import AsyncEngine, RequestStats
from cloudkill.core.models import EnrichedResult, ResultStatus, ScanReport
from cloudkill.sources.base import IPVersion, SourceResult
from cloudkill.utils.cloudflare_ips import CloudflareIPChecker
from cloudkill.utils.ratelimit import RateLimiter, TokenBucket
from cloudkill.utils.stealth import StealthManager

# ============================================================
# SourceResult Tests
# ============================================================


class TestSourceResult:
    def test_auto_detect_ipv4(self):
        r = SourceResult(subdomain="test.com", ip="1.2.3.4", source="test")
        assert r.ip_version == IPVersion.V4

    def test_auto_detect_ipv6(self):
        r = SourceResult(subdomain="test.com", ip="2001:db8::1", source="test")
        assert r.ip_version == IPVersion.V6

    def test_auto_detect_ipv6_mixed_notation(self):
        r = SourceResult(subdomain="test.com", ip="::ffff:1.2.3.4", source="test")
        assert r.ip_version == IPVersion.V6

    def test_to_dict_keys(self):
        r = SourceResult(subdomain="test.com", ip="1.2.3.4", source="test", port=8080)
        d = r.to_dict()
        assert set(d.keys()) == {
            "subdomain", "ip", "ip_version", "source", "port",
            "is_historical", "confidence_boost", "metadata",
        }

    def test_to_dict_values(self):
        r = SourceResult(
            subdomain="sub.example.com", ip="10.0.0.1",
            source="crtsh", port=443, is_historical=True,
            confidence_boost=10, metadata={"extra": "data"},
        )
        d = r.to_dict()
        assert d["subdomain"] == "sub.example.com"
        assert d["ip"] == "10.0.0.1"
        assert d["ip_version"] == 4
        assert d["source"] == "crtsh"
        assert d["port"] == 443
        assert d["is_historical"] is True
        assert d["confidence_boost"] == 10
        assert d["metadata"] == {"extra": "data"}


# ============================================================
# RequestStats Tests
# ============================================================


class TestRequestStats:
    def test_initial_state(self):
        stats = RequestStats()
        assert stats.total_requests == 0
        assert stats.successful_requests == 0
        assert stats.failed_requests == 0
        assert stats.retries == 0

    def test_record_success(self):
        stats = RequestStats()
        stats.record("test", success=True, bytes_received=1024)
        assert stats.total_requests == 1
        assert stats.successful_requests == 1
        assert stats.total_bytes_received == 1024

    def test_record_failure(self):
        stats = RequestStats()
        stats.record("test", success=False)
        assert stats.total_requests == 1
        assert stats.failed_requests == 1

    def test_source_stats(self):
        stats = RequestStats()
        stats.record("crtsh", success=True)
        stats.record("crtsh", success=False)
        stats.record("otx", success=True)
        assert stats.source_stats["crtsh"]["success"] == 1
        assert stats.source_stats["crtsh"]["failed"] == 1
        assert stats.source_stats["otx"]["success"] == 1


# ============================================================
# AsyncEngine Tests
# ============================================================


class TestAsyncEngine:
    def test_is_ipv6_address_v4(self):
        engine = AsyncEngine()
        assert engine.is_ipv6_address("1.2.3.4") is False

    def test_is_ipv6_address_v6(self):
        engine = AsyncEngine()
        assert engine.is_ipv6_address("2001:db8::1") is True

    def test_is_ipv6_address_invalid(self):
        engine = AsyncEngine()
        assert engine.is_ipv6_address("not-an-ip") is False

    def test_effective_threads_normal(self):
        config = Config(stealth_mode="normal", threads=20)
        engine = AsyncEngine(config=config)
        assert engine._effective_threads == 20

    def test_effective_threads_stealth(self):
        config = Config(stealth_mode="stealth", threads=30)
        engine = AsyncEngine(config=config)
        assert engine._effective_threads == 10  # 30 // 3

    def test_effective_threads_clamped(self):
        config = Config(stealth_mode="stealth", threads=3)
        engine = AsyncEngine(config=config)
        assert engine._effective_threads == 5  # max(5, 3//3)

    def test_get_headers_structure(self):
        engine = AsyncEngine()
        headers = engine._get_headers()
        assert "User-Agent" in headers
        assert "Accept" in headers
        assert "Connection" in headers

    def test_get_headers_ua_varies(self):
        engine = AsyncEngine()
        uas = set()
        for _ in range(50):
            h = engine._get_headers()
            uas.add(h["User-Agent"])
        assert len(uas) > 1  # Should rotate through agents


# ============================================================
# EnrichedResult Tests
# ============================================================


class TestEnrichedResult:
    def test_from_source_result_v4(self):
        sr = SourceResult(subdomain="a.com", ip="1.2.3.4", source="test")
        er = EnrichedResult.from_source_result(sr)
        assert er.subdomain == "a.com"
        assert er.ip == "1.2.3.4"
        assert er.ip_version == IPVersion.V4
        assert er.source == "test"

    def test_from_source_result_v6(self):
        sr = SourceResult(subdomain="a.com", ip="2001:db8::1", source="test")
        er = EnrichedResult.from_source_result(sr)
        assert er.ip_version == IPVersion.V6

    def test_from_source_result_with_boost(self):
        sr = SourceResult(
            subdomain="a.com", ip="1.2.3.4", source="test",
            confidence_boost=15,
        )
        er = EnrichedResult.from_source_result(sr)
        assert er.confidence == 15
        assert len(er.confidence_reasons) == 1
        assert "+15" in er.confidence_reasons[0]

    def test_to_dict(self):
        er = EnrichedResult(
            subdomain="a.com", ip="1.2.3.4", source="test",
            confidence=85, confidence_reasons=["test reason"],
            asn_org="AWS", hosting_provider="Amazon",
        )
        d = er.to_dict()
        assert d["confidence"] == 85
        assert d["asn_org"] == "AWS"
        assert d["hosting_provider"] == "Amazon"
        assert d["ip_version"] == 4

    def test_defaults(self):
        er = EnrichedResult(subdomain="a.com", ip="1.2.3.4")
        assert er.is_cloudflare is True
        assert er.ssl_matches is False
        assert er.confidence == 0
        assert er.status == ResultStatus.POTENTIAL


# ============================================================
# ScanReport Tests
# ============================================================


class TestScanReport:
    def test_add_result_updates_counts(self):
        report = ScanReport(domain="test.com")
        r = EnrichedResult(
            subdomain="a.com", ip="1.2.3.4", source="test",
            confidence=80, status=ResultStatus.CONFIRMED,
        )
        report.add_result(r)
        assert report.total_results == 1
        assert report.ipv4_count == 1
        assert report.high_confidence_count == 1
        assert report.confirmed_count == 1
        assert "test" in report.sources_used

    def test_add_result_ipv6(self):
        report = ScanReport(domain="test.com")
        r = EnrichedResult(
            subdomain="a.com", ip="2001:db8::1", source="test",
            ip_version=IPVersion.V6, confidence=50,
        )
        report.add_result(r)
        assert report.ipv6_count == 1
        assert report.ipv4_count == 0
        assert report.high_confidence_count == 0  # 50 < 70

    def test_unique_ips_deduplication(self):
        report = ScanReport(domain="test.com")
        report.add_result(EnrichedResult(subdomain="a.com", ip="1.1.1.1", source="s1"))
        report.add_result(EnrichedResult(subdomain="b.com", ip="1.1.1.1", source="s2"))
        report.add_result(EnrichedResult(subdomain="c.com", ip="2.2.2.2", source="s3"))
        report.finalize()
        assert report.unique_ips == 2

    def test_finalize_duration(self):
        report = ScanReport(domain="test.com")
        report.add_result(EnrichedResult(subdomain="a.com", ip="1.1.1.1", source="s1"))
        report.finalize()
        assert report.completed_at is not None
        assert report.scan_duration_seconds >= 0

    def test_to_dict(self):
        report = ScanReport(domain="test.com", profile="pentester")
        report.add_result(EnrichedResult(subdomain="a.com", ip="1.1.1.1", source="s1"))
        report.finalize()
        d = report.to_dict()
        assert d["domain"] == "test.com"
        assert d["profile"] == "pentester"
        assert d["summary"]["total_results"] == 1
        assert len(d["results"]) == 1


# ============================================================
# CloudflareIPChecker Tests
# ============================================================


class TestCloudflareIPChecker:
    def test_is_cf_ip_v4(self):
        checker = CloudflareIPChecker()
        checker._v4_networks = [
            __import__("ipaddress").ip_network("1.1.1.0/24"),
        ]
        checker._loaded = True
        assert checker.is_cloudflare_ip("1.1.1.1") is True

    def test_is_cf_ip_v6(self):
        checker = CloudflareIPChecker()
        checker._v6_networks = [
            __import__("ipaddress").ip_network("2606:4700::/32"),
        ]
        checker._loaded = True
        assert checker.is_cloudflare_ip("2606:4700::1") is True

    def test_is_not_cf_ip(self):
        checker = CloudflareIPChecker()
        checker._v4_networks = [
            __import__("ipaddress").ip_network("1.1.1.0/24"),
        ]
        checker._loaded = True
        assert checker.is_cloudflare_ip("8.8.8.8") is False

    def test_is_cf_ip_invalid(self):
        checker = CloudflareIPChecker()
        checker._loaded = True
        assert checker.is_cloudflare_ip("not-an-ip") is False

    def test_is_cf_ip_not_loaded(self):
        checker = CloudflareIPChecker()
        # Should return False gracefully
        assert checker.is_cloudflare_ip("1.1.1.1") is False

    def test_get_stats_not_loaded(self):
        checker = CloudflareIPChecker()
        stats = checker.get_stats()
        assert stats["v4_ranges"] == 0
        assert stats["v6_ranges"] == 0

    def test_get_stats_loaded(self):
        import ipaddress
        checker = CloudflareIPChecker()
        checker._v4_networks = [ipaddress.ip_network("1.1.1.0/24")]
        checker._v6_networks = [ipaddress.ip_network("2606:4700::/32")]
        checker._loaded = True
        stats = checker.get_stats()
        assert stats["v4_ranges"] == 1
        assert stats["v6_ranges"] == 1
        assert stats["total"] == 2


# ============================================================
# TokenBucket Tests
# ============================================================


class TestTokenBucket:
    @pytest.mark.asyncio
    async def test_acquire_immediate(self):
        bucket = TokenBucket(rate=1000.0, burst=5)
        start = time.monotonic()
        await bucket.acquire()
        elapsed = time.monotonic() - start
        assert elapsed < 0.1  # Should be near-instant with high rate

    @pytest.mark.asyncio
    async def test_acquire_rate_limit(self):
        bucket = TokenBucket(rate=1000.0, burst=1)
        # Exhaust the bucket
        await bucket.acquire()
        # Second acquire should wait
        start = time.monotonic()
        await bucket.acquire()
        elapsed = time.monotonic() - start
        assert elapsed >= 0.0005  # Should have waited


# ============================================================
# RateLimiter Tests
# ============================================================


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_auto_register(self):
        limiter = RateLimiter(default_rate=100)
        await limiter.wait("new-source")  # Should auto-register
        assert "new-source" in limiter.get_stats()

    @pytest.mark.asyncio
    async def test_custom_rate(self):
        limiter = RateLimiter(default_rate=100)
        limiter.register("slow", rate=1.0)
        stats = limiter.get_stats()
        assert stats["slow"]["rate"] == 1.0


# ============================================================
# StealthManager Tests
# ============================================================


class TestStealthManager:
    def test_random_ua_rotation(self):
        stealth = StealthManager(enabled=False)
        uas = set()
        for _ in range(20):
            uas.add(stealth.random_ua())
        assert len(uas) > 1  # Should rotate through agents

    @pytest.mark.asyncio
    async def test_delay_disabled(self):
        stealth = StealthManager(enabled=False)
        start = time.monotonic()
        await stealth.delay()
        elapsed = time.monotonic() - start
        assert elapsed < 0.1  # No delay when disabled

    @pytest.mark.asyncio
    async def test_delay_enabled(self):
        stealth = StealthManager(enabled=True, min_delay=0.1, max_delay=0.15)
        start = time.monotonic()
        await stealth.delay()
        elapsed = time.monotonic() - start
        assert elapsed >= 0.1  # Should have delayed

    def test_get_tor_proxy(self):
        assert StealthManager.get_tor_proxy() == "socks5://127.0.0.1:9050"
        assert StealthManager.get_tor_proxy(9051) == "socks5://127.0.0.1:9051"

    def test_get_proxy_disabled(self):
        stealth = StealthManager(enabled=False)
        assert stealth.get_proxy() is None

    def test_get_proxy_enabled(self):
        stealth = StealthManager(enabled=True)
        assert stealth.get_proxy() == "socks5://127.0.0.1:9050"
