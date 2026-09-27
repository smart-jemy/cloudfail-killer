"""Phase 5 unit tests - v0.7.0 features.

Covers: RapidDNS source, SubdomainCenter source, Shodan InternetDB
verification enricher, InternetDB scoring signal, extension-priority
output formatting, and updated source configuration behavior.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cloudkill.config import Config, ScoringWeights
from cloudkill.core.models import EnrichedResult
from cloudkill.enrichers.internetdb import InternetDBInfo, InternetDBLookup
from cloudkill.enrichers.scoring import ScoringEngine
from cloudkill.sources.base import IPVersion, SourceResult
from cloudkill.sources.rapiddns import RapidDNSSource
from cloudkill.sources.subdomain_center import SubdomainCenterSource

# ============================================================
# Helpers
# ============================================================

def _mock_httpx_get(payload, status_code: int = 200):
    """Build a patched httpx.AsyncClient returning a canned response."""
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.raise_for_status = MagicMock()
    if isinstance(payload, str):
        mock_resp.text = payload
    else:
        mock_resp.json.return_value = payload
    mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_client.return_value)
    mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
    mock_client.return_value.get = AsyncMock(return_value=mock_resp)
    return mock_client


# ============================================================
# RapidDNS Source
# ============================================================

RAPIDDNS_HTML = """
<html><body><table>
<tr><td>Subdomain</td><td>Type</td><td>Answer</td></tr>
<tr><td>www.example.com</td><td>A</td><td>93.184.216.34</td></tr>
<tr><td>api.example.com</td><td>A</td><td>93.184.216.35</td></tr>
<tr><td>v6.example.com</td><td>AAAA</td><td>2606:2800:220:1:248:1893:25c8:1946</td></tr>
<tr><td>unrelated.example.org</td><td>A</td><td>1.2.3.4</td></tr>
</table></body></html>
"""


class TestRapidDNSSource:
    def test_source_metadata(self):
        src = RapidDNSSource()
        assert src.name == "rapiddns"
        assert src.requires_api_key is False
        assert src.default_enabled is True
        assert src.supports_ipv6 is True

    @pytest.mark.asyncio
    async def test_enumerate_parses_table_rows(self):
        src = RapidDNSSource()
        with patch("httpx.AsyncClient", _mock_httpx_get(RAPIDDNS_HTML)):
            results = [r async for r in src.enumerate("example.com")]

        ips = {r.ip for r in results}
        assert "93.184.216.34" in ips
        assert "93.184.216.35" in ips
        # IPv6 answer is captured too
        assert any(r.ip_version == IPVersion.V6 for r in results)
        # Only entries under the target domain are kept
        assert "1.2.3.4" not in ips
        # Historical passive DNS data
        assert all(r.is_historical for r in results)

    @pytest.mark.asyncio
    async def test_enumerate_rate_limited(self):
        src = RapidDNSSource()
        with patch("httpx.AsyncClient", _mock_httpx_get("", status_code=429)):
            results = [r async for r in src.enumerate("example.com")]
        assert results == []


# ============================================================
# SubdomainCenter Source
# ============================================================


class TestSubdomainCenterSource:
    def test_source_metadata(self):
        src = SubdomainCenterSource()
        assert src.name == "subdomain_center"
        assert src.requires_api_key is False
        assert src.default_enabled is True

    @pytest.mark.asyncio
    async def test_enumerate_resolves_subdomains(self):
        src = SubdomainCenterSource()
        mock_data = [
            "www.example.com",
            "api.example.com",
            "*.wildcard.example.com",
            "notunder.example.org",
            "example.com",
        ]

        with patch.object(
            src, "resolve_with_fallback", new_callable=AsyncMock
        ) as mock_resolve:
            mock_resolve.return_value = [
                SourceResult(subdomain="www.example.com", ip="5.6.7.8", source="subdomain_center"),
            ]
            with patch("httpx.AsyncClient", _mock_httpx_get(mock_data)):
                results = [r async for r in src.enumerate("example.com")]

        # All kept entries resolved through resolve_with_fallback
        assert mock_resolve.await_count == 3  # www, api, apex (wildcard/foreign skipped)
        # Each resolved entry yields one mocked result
        assert len(results) == 3
        assert all(r.source == "subdomain_center" for r in results)

    @pytest.mark.asyncio
    async def test_enumerate_rate_limited(self):
        src = SubdomainCenterSource()
        with patch("httpx.AsyncClient", _mock_httpx_get([], status_code=429)):
            results = [r async for r in src.enumerate("example.com")]
        assert results == []


# ============================================================
# Shodan InternetDB Verification
# ============================================================


class TestInternetDBInfo:
    def test_domain_hostname_match(self):
        info = InternetDBInfo(
            ip="1.2.3.4",
            hostnames=["mail.example.com", "other.org"],
            ports=[80, 443, 22],
        )
        assert info.domain_hostname_match("example.com") == "mail.example.com"
        assert info.domain_hostname_match("notexample.com") is None

    def test_web_ports_open(self):
        info = InternetDBInfo(ip="1.2.3.4", ports=[22, 443, 8080])
        assert info.web_ports_open() == [443, 8080]

    def test_to_dict(self):
        info = InternetDBInfo(ip="1.2.3.4", ports=[443], hostnames=["a.example.com"])
        d = info.to_dict()
        assert d["ip"] == "1.2.3.4"
        assert d["found"] is False  # not marked found until lookup fills it


class TestInternetDBLookup:
    @pytest.mark.asyncio
    async def test_lookup_found(self):
        idb = InternetDBLookup()
        payload = {
            "ip": "1.2.3.4",
            "ports": [80, 443],
            "hostnames": ["www.example.com"],
            "cpes": [],
            "vulns": [],
        }
        with patch("httpx.AsyncClient", _mock_httpx_get(payload)):
            infos = await idb.lookup_batch(["1.2.3.4"])

        info = infos["1.2.3.4"]
        assert info.found is True
        assert info.domain_hostname_match("example.com") == "www.example.com"

    @pytest.mark.asyncio
    async def test_lookup_404_means_no_data(self):
        idb = InternetDBLookup()
        payload = {"detail": "Not found"}
        with patch("httpx.AsyncClient", _mock_httpx_get(payload, status_code=404)):
            infos = await idb.lookup_batch(["1.2.3.4"])

        assert infos["1.2.3.4"].found is False

    @pytest.mark.asyncio
    async def test_lookup_rate_limited(self):
        idb = InternetDBLookup()
        with patch("httpx.AsyncClient", _mock_httpx_get({}, status_code=429)):
            infos = await idb.lookup_batch(["1.2.3.4"])

        assert infos["1.2.3.4"].lookup_error == "rate_limited"

    @pytest.mark.asyncio
    async def test_lookup_empty_batch(self):
        idb = InternetDBLookup()
        infos = await idb.lookup_batch([])
        assert infos == {}


class TestInternetDBScoringSignal:
    def test_internetdb_match_adds_weight(self):
        config = Config(profile="researcher")
        engine = ScoringEngine(config)
        engine.set_target_domain("example.com")

        result = EnrichedResult(subdomain="www.example.com", ip="1.2.3.4")
        before = result.confidence
        result.internetdb_match = True
        engine.score(result)

        weight = config.scoring_weights.internetdb_match
        assert result.confidence == min(100, before + weight)
        assert any("InternetDB hostname match" in r for r in result.confidence_reasons)

    def test_internetdb_no_match_no_weight(self):
        config = Config(profile="researcher")
        engine = ScoringEngine(config)
        engine.set_target_domain("example.com")

        result = EnrichedResult(subdomain="www.example.com", ip="1.2.3.4")
        engine.score(result)
        assert not any("InternetDB" in r for r in result.confidence_reasons)

    def test_to_dict_includes_internetdb_fields(self):
        result = EnrichedResult(
            subdomain="www.example.com",
            ip="1.2.3.4",
            internetdb_match=True,
            internetdb_hostnames=["www.example.com"],
            internetdb_open_ports=[443],
        )
        d = result.to_dict()
        assert d["internetdb_match"] is True
        assert d["internetdb_hostnames"] == ["www.example.com"]
        assert d["internetdb_open_ports"] == [443]


# ============================================================
# CLI output-format resolution
# ============================================================


class TestReportFormatResolution:
    def test_extension_overrides_default_format(self):
        from cloudkill.cli import _report_format

        # Default --format is json; the extension must win
        assert _report_format("report.md", "json") == "md"
        assert _report_format("report.csv", "json") == "csv"
        assert _report_format("report.pdf", "json") == "pdf"
        assert _report_format("template.yml", "json") == "nuclei"
        assert _report_format("report.yaml", "nuclei") == "nuclei"

    def test_unknown_extension_keeps_format(self):
        from cloudkill.cli import _report_format

        assert _report_format("report.bin", "json") == "json"
        assert _report_format("report", "csv") == "csv"


# ============================================================
# Source configuration behavior
# ============================================================


class TestSourceConfigurationV07:
    def test_key_requiring_source_unconfigured_by_default(self):
        """Base is_configured must report False when a key is required."""
        from cloudkill.sources.base import BaseSource

        class _KeyedSource(BaseSource):
            name = "_keyed"
            requires_api_key = True

            async def enumerate(self, domain):
                yield  # pragma: no cover

        assert _KeyedSource().is_configured() is False

    def test_free_source_configured_by_default(self):
        from cloudkill.sources.base import BaseSource

        class _FreeSource(BaseSource):
            name = "_free"

            async def enumerate(self, domain):
                yield  # pragma: no cover

        assert _FreeSource().is_configured() is True

    def test_github_dork_requires_token(self):
        from cloudkill.sources.github_dork import GitHubDorkSource

        src = GitHubDorkSource()
        assert src.requires_api_key is True
        assert src.is_configured() is False

    def test_config_new_fields(self):
        config = Config(
            profile="researcher",
            dns_servers=["1.1.1.1", "9.9.9.9"],
            internetdb_enabled=False,
            min_confidence=50,
        )
        assert config.dns_servers == ["1.1.1.1", "9.9.9.9"]
        assert config.internetdb_enabled is False
        assert config.min_confidence == 50

    def test_scoring_weights_have_internetdb(self):
        weights = ScoringWeights()
        assert 0 < weights.internetdb_match <= 100

    def test_enabled_sources_respect_github_token(self):
        """github_dork is excluded without GITHUB_TOKEN, included with it."""
        import os

        from cloudkill.config import Config
        from cloudkill.sources import get_enabled_sources

        config = Config(profile="researcher")
        names = {s.name for s in get_enabled_sources(config=config)}
        assert "github_dork" not in names

        with patch.dict(os.environ, {"GITHUB_TOKEN": "test-token"}):
            config2 = Config(profile="researcher")
            names2 = {s.name for s in get_enabled_sources(config=config2)}
            assert "github_dork" in names2


# ============================================================
# Enrichment pipeline stage wiring
# ============================================================


class TestEnrichmentPipelineV07:
    def test_pipeline_accepts_internetdb_toggle(self):
        from cloudkill.core.enrichment import EnrichmentPipeline

        config = Config(profile="researcher")
        pipeline_on = EnrichmentPipeline(config, enable_internetdb=True)
        pipeline_off = EnrichmentPipeline(config)

        assert pipeline_on.internetdb is not None
        assert pipeline_off.internetdb is None

    def test_stats_include_internetdb_fields(self):
        from cloudkill.core.enrichment import EnrichmentStats

        stats = EnrichmentStats()
        d = stats.to_dict()
        assert "internetdb_lookups" in d
        assert "internetdb_matches" in d


# ============================================================
# Non-routable IP filtering (found during live testing)
# ============================================================


class TestNonRoutableIPFilter:
    def test_private_and_loopback_rejected(self):
        from cloudkill.core.runner import is_non_routable_ip

        assert is_non_routable_ip("127.0.0.1") is True
        assert is_non_routable_ip("10.0.0.5") is True
        assert is_non_routable_ip("172.16.0.9") is True
        assert is_non_routable_ip("192.168.1.1") is True
        assert is_non_routable_ip("169.254.1.1") is True
        assert is_non_routable_ip("0.0.0.0") is True
        assert is_non_routable_ip("::1") is True
        assert is_non_routable_ip("fe80::1") is True
        assert is_non_routable_ip("fc00::1") is True

    def test_nat64_well_known_prefix_rejected(self):
        from cloudkill.core.runner import is_non_routable_ip

        # RFC 6052 synthetic addresses observed in real scans
        assert is_non_routable_ip("64:ff9b::6814:179a") is True
        assert is_non_routable_ip("64:ff9b::ac42:93f3") is True

    def test_public_ips_accepted(self):
        from cloudkill.core.runner import is_non_routable_ip

        assert is_non_routable_ip("93.184.216.34") is False
        assert is_non_routable_ip("1.1.1.1") is False
        assert is_non_routable_ip("2606:2800:220:1:248:1893:25c8:1946") is False

    def test_unparseable_ip_rejected(self):
        from cloudkill.core.runner import is_non_routable_ip

        assert is_non_routable_ip("not-an-ip") is True

    def test_report_counts_non_routable(self):
        from cloudkill.core.models import ScanReport

        report = ScanReport(domain="example.com")
        report.non_routable_filtered = 3
        d = report.to_dict()
        assert d["summary"]["non_routable_filtered"] == 3
