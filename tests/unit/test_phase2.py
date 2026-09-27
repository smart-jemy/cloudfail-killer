"""Phase 2 unit tests - All 13 source plugins, source registry, favicon, DNS utils."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cloudkill.sources.acme_check import ACMECheckSource
from cloudkill.sources.anubisdb import AnubisDBSource
from cloudkill.sources.base import SourceResult
from cloudkill.sources.certspotter import CertSpotterSource
from cloudkill.sources.crtsh import CRTShSource
from cloudkill.sources.dnsdumpster import DNSDumpsterSource
from cloudkill.sources.favicon_hash import FaviconHashSource
from cloudkill.sources.github_dork import GitHubDorkSource
from cloudkill.sources.hackertarget import HackerTargetSource
from cloudkill.sources.otx import OTXSource
from cloudkill.sources.spf_dkim import SPFDKIMSource
from cloudkill.sources.urlscan import URLScanSource
from cloudkill.sources.wayback import WaybackSource
from cloudkill.sources.whoisxml import WhoisXMLSource
from cloudkill.utils.dns import DNSResult, DualStackResolver
from cloudkill.utils.favicon import (
    _mmh3_fallback,
    censys_search_query,
    compute_favicon_hash,
    shodan_search_query,
)

# ============================================================
# Source Registry Tests
# ============================================================


class TestSourceRegistry:
    def test_get_all_sources_count(self):
        from cloudkill.sources import get_all_sources
        sources = get_all_sources()
        assert len(sources) == 15, f"Expected 15 sources, got {len(sources)}"

    def test_get_all_sources_types(self):
        from cloudkill.sources import get_all_sources
        sources = get_all_sources()
        names = {s.name for s in sources}
        expected = {
            "crtsh", "certspotter", "anubisdb", "otx", "wayback",
            "urlscan", "hackertarget", "dnsdumpster", "whoisxml",
            "github_dork", "favicon_hash", "spf_dkim", "acme_check",
            "rapiddns", "subdomain_center",
        }
        assert names == expected, f"Missing sources: {expected - names}"

    def test_get_source_info(self):
        from cloudkill.sources import get_source_info
        info = get_source_info()
        assert len(info) == 15
        for item in info:
            assert "name" in item
            assert "description" in item

    def test_get_enabled_sources_default(self):
        """Default config should enable free sources (no API key)."""
        from cloudkill.config import Config
        from cloudkill.sources import get_enabled_sources

        config = Config(profile="researcher")
        sources = get_enabled_sources(config=config)
        names = {s.name for s in sources}

        # Free sources should be enabled by default
        assert "crtsh" in names
        assert "anubisdb" in names
        assert "otx" in names
        assert "wayback" in names
        assert "urlscan" in names
        assert "hackertarget" in names
        assert "spf_dkim" in names

        # API-key sources should NOT be enabled without keys
        assert "certspotter" not in names
        assert "whoisxml" not in names

        # Disabled by default sources
        assert "dnsdumpster" not in names
        assert "acme_check" not in names


# ============================================================
# Individual Source Tests
# ============================================================


class TestCRTShSource:
    def test_source_metadata(self):
        src = CRTShSource()
        assert src.name == "crtsh"
        assert src.requires_api_key is False
        assert src.supports_ipv6 is True
        assert src.default_enabled is True

    @pytest.mark.asyncio
    async def test_enumerate_empty_response(self):
        src = CRTShSource()
        with patch("httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = []
            mock_resp.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value.get = AsyncMock(return_value=mock_resp)

            results = []
            async for r in src.enumerate("example.com"):
                results.append(r)
            assert len(results) == 0

    @pytest.mark.asyncio
    async def test_enumerate_with_results(self):
        src = CRTShSource()
        mock_response_data = [
            {"name_value": "www.example.com\napi.example.com", "issuer_ca_id": 1, "not_before": "2024-01-01", "not_after": "2025-01-01"},
        ]

        with patch.object(src, "resolve_with_fallback", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = [
                SourceResult(subdomain="www.example.com", ip="1.2.3.4", source="crtsh"),
            ]

            with patch("httpx.AsyncClient") as mock_client:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = mock_response_data
                mock_resp.raise_for_status = MagicMock()
                mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
                mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
                mock_client.return_value.get = AsyncMock(return_value=mock_resp)

                results = []
                async for r in src.enumerate("example.com"):
                    results.append(r)
                # crt.sh data has 2 subdomains (www + api), both resolve
                assert len(results) == 2
                assert results[0].source == "crtsh"


class TestCertSpotterSource:
    def test_source_metadata(self):
        src = CertSpotterSource()
        assert src.name == "certspotter"
        assert src.requires_api_key is True
        assert src.default_enabled is False

    def test_not_configured_without_key(self):
        with patch.dict(os.environ, {}, clear=True):
            src2 = CertSpotterSource()
            assert src2.is_configured() is False


class TestAnubisDBSource:
    def test_source_metadata(self):
        src = AnubisDBSource()
        assert src.name == "anubisdb"
        assert src.requires_api_key is False
        assert src.default_enabled is True

    @pytest.mark.asyncio
    async def test_enumerate_with_results(self):
        src = AnubisDBSource()
        mock_data = ["www.example.com", "api.example.com", "blog.example.com"]

        with patch.object(src, "resolve_with_fallback", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = [
                SourceResult(subdomain="www.example.com", ip="5.6.7.8", source="anubisdb"),
            ]

            with patch("httpx.AsyncClient") as mock_client:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = mock_data
                mock_resp.raise_for_status = MagicMock()
                mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
                mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
                mock_client.return_value.get = AsyncMock(return_value=mock_resp)

                results = []
                async for r in src.enumerate("example.com"):
                    results.append(r)
                assert len(results) >= 1


class TestOTXSource:
    def test_source_metadata(self):
        src = OTXSource()
        assert src.name == "otx"
        assert src.requires_api_key is False

    @pytest.mark.asyncio
    async def test_enumerate_passive_dns(self):
        src = OTXSource()
        mock_data = {
            "passive_dns": [
                {
                    "hostname": "www.example.com",
                    "ip": "10.20.30.40",
                    "record_type": "A",
                    "last_seen": "2024-01-01",
                    "first_seen": "2023-01-01",
                }
            ]
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_data
            mock_resp.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value.get = AsyncMock(return_value=mock_resp)

            results = []
            async for r in src.enumerate("example.com"):
                results.append(r)

            # Should find the A record IP
            assert len(results) >= 1
            assert any(r.ip == "10.20.30.40" for r in results)


class TestWaybackSource:
    def test_source_metadata(self):
        src = WaybackSource()
        assert src.name == "wayback"
        assert src.requires_api_key is False

    @pytest.mark.asyncio
    async def test_enumerate_with_results(self):
        src = WaybackSource()
        mock_response_text = '[\"original\"]\n"http://www.example.com/page"\n"http://api.example.com/endpoint"'

        with patch.object(src, "resolve_with_fallback", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = [
                SourceResult(subdomain="www.example.com", ip="11.22.33.44", source="wayback"),
            ]

            with patch("httpx.AsyncClient") as mock_client:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.text = mock_response_text
                mock_resp.raise_for_status = MagicMock()
                mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
                mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
                mock_client.return_value.get = AsyncMock(return_value=mock_resp)

                results = []
                async for r in src.enumerate("example.com"):
                    results.append(r)
                assert len(results) >= 1
                assert results[0].is_historical is True


class TestURLScanSource:
    def test_source_metadata(self):
        src = URLScanSource()
        assert src.name == "urlscan"
        assert src.default_enabled is True

    @pytest.mark.asyncio
    async def test_enumerate_empty(self):
        src = URLScanSource()
        mock_data = {"results": [], "total": 0}

        with patch("httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_data
            mock_resp.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value.get = AsyncMock(return_value=mock_resp)

            results = []
            async for r in src.enumerate("example.com"):
                results.append(r)
            assert len(results) == 0


class TestHackerTargetSource:
    def test_source_metadata(self):
        src = HackerTargetSource()
        assert src.name == "hackertarget"

    @pytest.mark.asyncio
    async def test_host_search_with_results(self):
        src = HackerTargetSource()
        mock_text = "1.2.3.4,www.example.com\n5.6.7.8,api.example.com"

        with patch("httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = mock_text
            mock_resp.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value.get = AsyncMock(return_value=mock_resp)

            results = []
            async for r in src.enumerate("example.com"):
                results.append(r)
            assert len(results) == 2
            assert results[0].ip == "1.2.3.4"
            assert results[1].ip == "5.6.7.8"

    def test_is_valid_ip(self):
        assert HackerTargetSource._is_valid_ip("1.2.3.4") is True
        assert HackerTargetSource._is_valid_ip("999.999.999.999") is False
        assert HackerTargetSource._is_valid_ip("not-an-ip") is False


class TestDNSDumpsterSource:
    def test_source_metadata(self):
        src = DNSDumpsterSource()
        assert src.name == "dnsdumpster"
        assert src.default_enabled is False  # Disabled by default


class TestWhoisXMLSource:
    def test_source_metadata(self):
        src = WhoisXMLSource()
        assert src.name == "whoisxml"
        assert src.requires_api_key is True
        assert src.default_enabled is False

    def test_not_configured_without_key(self):
        with patch.dict(os.environ, {}, clear=True):
            src = WhoisXMLSource()
            assert src.is_configured() is False


class TestGitHubDorkSource:
    def test_source_metadata(self):
        src = GitHubDorkSource()
        assert src.name == "github_dork"
        # GitHub code search requires authentication (401 otherwise)
        assert src.requires_api_key is True
        assert src.is_configured() is False

    def test_is_private_ip(self):
        assert GitHubDorkSource._is_private_ip("10.0.0.1") is True
        assert GitHubDorkSource._is_private_ip("192.168.1.1") is True
        assert GitHubDorkSource._is_private_ip("172.16.0.1") is True
        assert GitHubDorkSource._is_private_ip("127.0.0.1") is True
        assert GitHubDorkSource._is_private_ip("8.8.8.8") is False
        assert GitHubDorkSource._is_private_ip("1.1.1.1") is False

    def test_dork_queries_count(self):
        """Should have at least 6 dork queries."""
        assert len(GitHubDorkSource.DORK_QUERIES) >= 6


class TestFaviconHashSource:
    def test_source_metadata(self):
        src = FaviconHashSource()
        assert src.name == "favicon_hash"
        assert src.requires_api_key is True
        assert src.default_enabled is True

    def test_not_configured_without_keys(self):
        with patch.dict(os.environ, {}, clear=True):
            src = FaviconHashSource()
            assert src.is_configured() is False


class TestSPFDKIMSource:
    def test_source_metadata(self):
        src = SPFDKIMSource()
        assert src.name == "spf_dkim"
        assert src.requires_api_key is False
        assert src.default_enabled is True

    def test_common_selectors(self):
        """Should have a substantial list of selectors."""
        assert len(SPFDKIMSource.COMMON_SELECTORS) >= 20
        assert "default" in SPFDKIMSource.COMMON_SELECTORS
        assert "google" in SPFDKIMSource.COMMON_SELECTORS


class TestACMECheckSource:
    def test_source_metadata(self):
        src = ACMECheckSource()
        assert src.name == "acme_check"
        assert src.default_enabled is False  # Informational only
        assert src.supports_ipv6 is False


# ============================================================
# Favicon Hash Utility Tests
# ============================================================


class TestFaviconHash:
    def test_compute_hash_with_data(self):
        """Test hash computation with sample data."""
        # ICO file magic bytes (minimal)
        data = b'\x00\x00\x01\x00' + b'\x00' * 100
        hash_val = compute_favicon_hash(data)
        assert hash_val is not None
        # Should be a string that looks like a number (possibly negative)
        assert isinstance(hash_val, str)
        int(hash_val)  # Should be parseable as int

    def test_compute_hash_empty_data(self):
        assert compute_favicon_hash(b"") is None
        assert compute_favicon_hash(b"\x00\x01") is None

    def test_shodan_query(self):
        query = shodan_search_query("-1234567890")
        assert query == "http.favicon.hash:-1234567890"

    def test_censys_query(self):
        query = censys_search_query("-1234567890")
        assert "shodan_hash:-1234567890" in query

    def test_fallback_hash_deterministic(self):
        """Same input should always produce the same hash."""
        data = b"test favicon data" * 10
        h1 = _mmh3_fallback(data)
        h2 = _mmh3_fallback(data)
        assert h1 == h2

    def test_fallback_hash_different_inputs(self):
        """Different inputs should produce different hashes."""
        h1 = _mmh3_fallback(b"input one")
        h2 = _mmh3_fallback(b"input two")
        assert h1 != h2


# ============================================================
# DNS Utility Tests
# ============================================================


class TestDualStackResolver:
    def test_init_defaults(self):
        resolver = DualStackResolver()
        assert resolver.timeout == 5.0

    def test_init_custom_timeout(self):
        resolver = DualStackResolver(timeout=10.0)
        assert resolver.timeout == 10.0

    @pytest.mark.asyncio
    async def test_resolve_a_empty(self):
        resolver = DualStackResolver()
        with patch.object(resolver, "_get_resolver") as mock_get:
            mock_dns = AsyncMock()
            import aiodns
            mock_dns.query.side_effect = aiodns.error.DNSError("DNS error")
            mock_get.return_value = mock_dns
            result = await resolver.resolve_a("nonexistent.example.com")
            assert result == []

    @pytest.mark.asyncio
    async def test_resolve_aaaa_empty(self):
        resolver = DualStackResolver()
        with patch.object(resolver, "_get_resolver") as mock_get:
            mock_dns = AsyncMock()
            import aiodns
            mock_dns.query.side_effect = aiodns.error.DNSError("DNS error")
            mock_get.return_value = mock_dns
            result = await resolver.resolve_aaaa("nonexistent.example.com")
            assert result == []

    @pytest.mark.asyncio
    async def test_resolve_dual(self):
        resolver = DualStackResolver()
        with patch.object(resolver, "resolve_a", new_callable=AsyncMock) as mock_a, \
             patch.object(resolver, "resolve_aaaa", new_callable=AsyncMock) as mock_aaaa:
            mock_a.return_value = ["1.2.3.4"]
            mock_aaaa.return_value = ["2001:db8::1"]

            # Default: IPv4 first
            result = await resolver.resolve_dual("example.com")
            assert result == ["1.2.3.4", "2001:db8::1"]

            # IPv6 preferred
            result = await resolver.resolve_dual("example.com", prefer_ipv6=True)
            assert result == ["2001:db8::1", "1.2.3.4"]

    @pytest.mark.asyncio
    async def test_resolve_all(self):
        resolver = DualStackResolver()
        with patch.object(resolver, "resolve_a", new_callable=AsyncMock, return_value=["1.1.1.1"]), \
             patch.object(resolver, "resolve_aaaa", new_callable=AsyncMock, return_value=[]), \
             patch.object(resolver, "resolve_cname", new_callable=AsyncMock, return_value=[]), \
             patch.object(resolver, "resolve_mx", new_callable=AsyncMock, return_value=[]), \
             patch.object(resolver, "resolve_txt", new_callable=AsyncMock, return_value=[]), \
             patch.object(resolver, "resolve_ns", new_callable=AsyncMock, return_value=[]), \
             patch.object(resolver, "resolve_soa", new_callable=AsyncMock, return_value=[]):
            result = await resolver.resolve_all("example.com")
            assert isinstance(result, DNSResult)
            assert result.a_records == ["1.1.1.1"]
            assert result.all_ips == ["1.1.1.1"]


class TestDNSResult:
    def test_all_ips(self):
        result = DNSResult(domain="example.com", a_records=["1.1.1.1"], aaaa_records=["::1"])
        assert result.all_ips == ["1.1.1.1", "::1"]
        assert result.ipv4_count == 1
        assert result.ipv6_count == 1

    def test_to_dict(self):
        result = DNSResult(domain="example.com")
        d = result.to_dict()
        assert d["domain"] == "example.com"
        assert d["a_records"] == []
