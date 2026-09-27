"""Phase 3 unit tests - Enrichment Pipeline, SSL Checker, ASN Lookup, JS Recon, Scoring, FP Filter."""

from unittest.mock import AsyncMock, patch

import pytest

from cloudkill.config import Config, ScoringWeights
from cloudkill.core.enrichment import EnrichmentPipeline, EnrichmentStats
from cloudkill.core.filters import FalsePositiveFilter
from cloudkill.core.models import EnrichedResult, ResultStatus
from cloudkill.enrichers.asn_lookup import ASNInfo, ASNLookup
from cloudkill.enrichers.js_recon import JSReconEngine
from cloudkill.enrichers.scoring import ResultDeduplicator, ScoringEngine
from cloudkill.enrichers.ssl_checker import SSLChecker, SSLInfo
from cloudkill.sources.base import SourceResult

# ============================================================
# Helper Functions
# ============================================================


def _make_enriched_result(
    ip: str = "1.2.3.4",
    subdomain: str = "www.example.com",
    confidence: int = 40,
    **kwargs,
) -> EnrichedResult:
    """Create a test EnrichedResult."""
    return EnrichedResult(
        subdomain=subdomain,
        ip=ip,
        confidence=confidence,
        confidence_reasons=["Non-CF IP (+40)"],
        **kwargs,
    )


def _make_source_result(ip: str = "1.2.3.4", **kwargs) -> SourceResult:
    """Create a test SourceResult."""
    return SourceResult(
        subdomain="www.example.com",
        ip=ip,
        source="test",
        **kwargs,
    )


# ============================================================
# SSL Checker Tests
# ============================================================


class TestSSLChecker:
    def test_init_defaults(self):
        checker = SSLChecker()
        assert checker.timeout == 10.0
        assert checker.max_concurrent == 50
        assert checker.include_expired is True

    def test_init_custom(self):
        checker = SSLChecker(timeout=5.0, max_concurrent=10)
        assert checker.timeout == 5.0
        assert checker.max_concurrent == 10

    @pytest.mark.asyncio
    async def test_check_ssl_connection_refused(self):
        """Connection refused should return error info."""
        checker = SSLChecker(timeout=2.0)
        info = await checker.check_ssl("127.0.0.1", 1)
        assert info.ip == "127.0.0.1"
        assert info.port == 1
        assert info.ssl_error is not None
        assert info.is_valid is False

    @pytest.mark.asyncio
    async def test_check_ssl_invalid_ip(self):
        """Invalid IP should return error."""
        checker = SSLChecker(timeout=2.0)
        info = await checker.check_ssl("999.999.999.999", 443)
        assert info.ssl_error is not None

    @pytest.mark.asyncio
    async def test_check_ssl_batch(self):
        """Batch check should return list of SSLInfo."""
        checker = SSLChecker(timeout=2.0)
        results = await checker.check_ssl_batch([
            ("127.0.0.1", 1),
            ("127.0.0.1", 2),
        ])
        assert len(results) == 2
        assert all(isinstance(r, SSLInfo) for r in results)


class TestSSLInfo:
    def test_default_values(self):
        info = SSLInfo(ip="1.2.3.4", port=443)
        assert info.is_valid is False  # No CN
        assert info.is_cloudflare_cert is False

    def test_matches_domain_exact_cn(self):
        info = SSLInfo(ip="1.2.3.4", port=443, cn="www.example.com")
        assert info.matches_domain("example.com") is True

    def test_matches_domain_cn_suffix(self):
        info = SSLInfo(ip="1.2.3.4", port=443, cn="api.example.com")
        assert info.matches_domain("example.com") is True

    def test_matches_domain_san(self):
        info = SSLInfo(
            ip="1.2.3.4", port=443,
            cn="other.com",
            san=["api.example.com", "mail.example.com"],
        )
        assert info.matches_domain("example.com") is True

    def test_matches_domain_wildcard_san(self):
        info = SSLInfo(
            ip="1.2.3.4", port=443,
            cn="other.com",
            san=["*.example.com"],
        )
        assert info.matches_domain("example.com") is True
        assert info.matches_domain("api.example.com") is True

    def test_matches_domain_no_match(self):
        info = SSLInfo(ip="1.2.3.4", port=443, cn="completely.different.org")
        assert info.matches_domain("example.com") is False

    def test_to_dict(self):
        info = SSLInfo(ip="1.2.3.4", port=443, cn="example.com")
        d = info.to_dict()
        assert d["ip"] == "1.2.3.4"
        assert d["port"] == 443
        assert d["cn"] == "example.com"
        assert "is_valid" in d


# ============================================================
# ASN Lookup Tests
# ============================================================


class TestASNInfo:
    def test_default_values(self):
        info = ASNInfo(ip="1.2.3.4")
        assert info.is_confidence_signal is False
        assert info.is_hosting is False

    def test_confidence_signal(self):
        info = ASNInfo(ip="1.2.3.4", asn=16509, asn_org="Amazon")
        assert info.is_confidence_signal is True

    def test_confidence_signal_with_error(self):
        info = ASNInfo(ip="1.2.3.4", asn=16509, lookup_error="timeout")
        assert info.is_confidence_signal is False

    def test_to_dict(self):
        info = ASNInfo(ip="1.2.3.4", asn=16509, asn_org="Amazon")
        d = info.to_dict()
        assert d["ip"] == "1.2.3.4"
        assert d["asn"] == 16509


class TestASNLookup:
    def test_init_defaults(self):
        lookup = ASNLookup()
        assert lookup.timeout == 10.0
        assert lookup.max_concurrent == 30

    def test_detect_hosting_provider_aws(self):
        lookup = ASNLookup()
        result = lookup._detect_hosting_provider(
            asn=16509, org="Amazon.com, Inc.", isp="Amazon"
        )
        assert result is not None
        assert result["short"] == "AWS"

    def test_detect_hosting_provider_gcp(self):
        lookup = ASNLookup()
        result = lookup._detect_hosting_provider(
            asn=15169, org="Google LLC", isp="Google Cloud"
        )
        assert result is not None
        assert result["short"] == "GCP"

    def test_detect_hosting_provider_azure(self):
        lookup = ASNLookup()
        result = lookup._detect_hosting_provider(
            asn=8075, org="Microsoft Corporation", isp="Azure"
        )
        assert result is not None
        assert result["short"] == "Azure"

    def test_detect_hosting_provider_ovh(self):
        lookup = ASNLookup()
        result = lookup._detect_hosting_provider(
            asn=16276, org="OVH SAS", isp="OVH"
        )
        assert result is not None
        assert result["short"] == "OVH"

    def test_detect_hosting_provider_digitalocean(self):
        lookup = ASNLookup()
        result = lookup._detect_hosting_provider(
            asn=14061, org="DigitalOcean", isp="DigitalOcean"
        )
        assert result is not None
        assert result["short"] == "DO"

    def test_detect_hosting_provider_unknown(self):
        lookup = ASNLookup()
        result = lookup._detect_hosting_provider(
            asn=99999, org="Some ISP", isp="Some ISP"
        )
        assert result is None

    def test_detect_hosting_provider_cloudflare(self):
        lookup = ASNLookup()
        result = lookup._detect_hosting_provider(
            asn=13335, org="Cloudflare, Inc.", isp="Cloudflare"
        )
        assert result is not None
        assert result["short"] == "CF"

    @pytest.mark.asyncio
    async def test_lookup_api_failure(self):
        """Both APIs fail should return error."""
        lookup = ASNLookup()
        with patch.object(lookup, "_query_ip_api", new_callable=AsyncMock, return_value=None), \
             patch.object(lookup, "_query_ipinfo", new_callable=AsyncMock, return_value=None):
            info = await lookup.lookup("1.2.3.4")
            assert info.lookup_error is not None

    @pytest.mark.asyncio
    async def test_lookup_ip_api_success(self):
        """ip-api.com returns valid data."""
        lookup = ASNLookup()
        mock_data = {
            "status": "success",
            "as": "AS16509 Amazon",
            "asname": "Amazon",
            "org": "Amazon.com",
            "isp": "Amazon",
            "country": "US",
            "countryCode": "US",
            "regionName": "Virginia",
            "city": "Ashburn",
            "hosting": True,
        }
        with patch.object(lookup, "_query_ip_api", new_callable=AsyncMock, return_value=mock_data):
            info = await lookup.lookup("1.2.3.4")
            assert info.asn == 16509
            assert info.hosting_provider == "AWS"
            assert info.is_hosting is True


# ============================================================
# JS Recon Engine Tests
# ============================================================


class TestJSReconEngine:
    def test_init_defaults(self):
        engine = JSReconEngine()
        assert engine.timeout == 15.0
        assert engine.max_concurrent == 20

    def test_analyze_fetch_endpoints(self):
        engine = JSReconEngine()
        js_code = '''
        fetch('/api/v1/users', { method: 'GET' });
        fetch('https://api.example.com/data');
        axios.post('/api/login', credentials);
        '''
        findings = engine.analyze_js_content(js_code, source_url="https://example.com/app.js")
        endpoint_types = [f.type for f in findings]
        assert "fetch_endpoint" in endpoint_types or "fetch_url" in endpoint_types

    def test_analyze_websocket(self):
        engine = JSReconEngine()
        js_code = 'var ws = new WebSocket("wss://realtime.example.com/socket");'
        findings = engine.analyze_js_content(js_code)
        wss_findings = [f for f in findings if "wss" in f.type or "websocket" in f.type]
        assert len(wss_findings) > 0

    def test_analyze_ip_leaks(self):
        engine = JSReconEngine()
        js_code = 'var serverIp = "203.0.113.42"; var backupIp = "198.51.100.7";'
        findings = engine.analyze_js_content(js_code)
        leaked = engine.extract_ip_leaks(findings)
        assert "203.0.113.42" in leaked
        assert "198.51.100.7" in leaked

    def test_analyze_filters_private_ips(self):
        engine = JSReconEngine()
        js_code = 'var ip = "10.0.0.1"; var ip2 = "192.168.1.1";'
        findings = engine.analyze_js_content(js_code)
        leaked = engine.extract_ip_leaks(findings)
        # Private IPs should be filtered
        assert "10.0.0.1" not in leaked
        assert "192.168.1.1" not in leaked

    def test_analyze_api_base_urls(self):
        engine = JSReconEngine()
        js_code = 'const API_BASE_URL = "https://api.example.com/v2";'
        findings = engine.analyze_js_content(js_code)
        api_findings = [f for f in findings if "api" in f.type]
        assert len(api_findings) > 0

    def test_extract_api_endpoints(self):
        engine = JSReconEngine()
        js_code = 'fetch("https://api.example.com/users"); fetch("/api/v1/login");'
        findings = engine.analyze_js_content(js_code)
        endpoints = engine.extract_api_endpoints(findings)
        assert len(endpoints) >= 1

    def test_extract_sensitive_findings(self):
        engine = JSReconEngine()
        # Patterns match key names enclosed in quotes like config["apiKey"]
        js_code = 'var config = {"apiKey": "abc123", "password": "secret"};'
        findings = engine.analyze_js_content(js_code)
        sensitive = engine.extract_sensitive_findings(findings)
        assert len(sensitive) >= 1

    def test_extract_aws_keys(self):
        engine = JSReconEngine()
        # AWS docs example key, assembled so scanners don't flag it as a credential
        example_key = "AKIA" + "IOSFODNN7" + "EXAMPLE"
        js_code = f'AWS_ACCESS_KEY = "{example_key}";'
        findings = engine.analyze_js_content(js_code)
        aws_keys = [f for f in findings if f.type == "aws_key"]
        assert len(aws_keys) >= 1
        assert "AKIA" in aws_keys[0].value

    def test_extract_js_urls_from_html(self):
        engine = JSReconEngine()
        html = '''
        <script src="/static/app.js"></script>
        <script src="https://cdn.example.com/lib.js"></script>
        '''
        urls = engine.extract_js_urls_from_html(html)
        assert "/static/app.js" in urls
        assert "https://cdn.example.com/lib.js" in urls

    def test_empty_content(self):
        engine = JSReconEngine()
        findings = engine.analyze_js_content("")
        assert len(findings) == 0

    def test_confidence_boosts(self):
        engine = JSReconEngine()
        js_code = 'var ip = "203.0.113.42"; fetch("/api");'
        findings = engine.analyze_js_content(js_code)
        for f in findings:
            assert f.confidence_boost > 0


# ============================================================
# Scoring Engine Tests
# ============================================================


class TestScoringEngine:
    def _make_engine(self, **weight_overrides) -> ScoringEngine:
        weights = ScoringWeights(**weight_overrides)
        config = Config(scoring_weights=weights)
        return ScoringEngine(config)

    def test_score_non_cf_only(self):
        """Non-CF IP should get base score."""
        engine = self._make_engine()
        result = _make_enriched_result(confidence=40)
        engine.score(result)
        # Should be at least the base score (40)
        assert result.confidence >= 40

    def test_score_ssl_match(self):
        """SSL match should boost score."""
        engine = self._make_engine(ssl_match=30)
        result = _make_enriched_result(confidence=40)
        result.ssl_matches = True
        result.ssl_cn = "www.example.com"
        engine.score(result)
        assert result.confidence >= 70  # 40 + 30

    def test_score_ssl_san_match(self):
        """SAN match should boost score even without ssl_matches flag."""
        engine = self._make_engine(ssl_match=30)
        result = _make_enriched_result(confidence=40)
        result.ssl_san = ["api.example.com"]
        engine.set_target_domain("example.com")
        engine.score(result)
        assert result.confidence >= 55  # 40 + 30/2

    def test_score_hosting_provider(self):
        """Known hosting provider should boost score."""
        engine = self._make_engine(asn_match=15)
        result = _make_enriched_result(confidence=40)
        result.hosting_provider = "AWS"
        result.asn_org = "Amazon"
        engine.score(result)
        assert result.confidence >= 55  # 40 + 15

    def test_score_historical(self):
        """Historical DNS data should boost score."""
        engine = self._make_engine(historical=20)
        result = _make_enriched_result(confidence=40)
        result.is_historical = True
        engine.score(result)
        assert result.confidence >= 60  # 40 + 20

    def test_score_favicon_match(self):
        """Favicon hash match should boost score."""
        engine = self._make_engine(favicon_match=15)
        result = _make_enriched_result(confidence=40)
        result.favicon_match = True
        engine.score(result)
        assert result.confidence >= 55

    def test_score_js_recon(self):
        """JS Recon finding should boost score."""
        engine = self._make_engine(js_recon=25)
        result = _make_enriched_result(confidence=40)
        result.js_extracted = True
        engine.score(result)
        assert result.confidence >= 65

    def test_score_spf_dkim(self):
        """SPF/DKIM origin should boost score."""
        engine = self._make_engine(spf_dkim=15)
        result = _make_enriched_result(confidence=40)
        result.spf_dkim_origin = True
        engine.score(result)
        assert result.confidence >= 55

    def test_score_clamped_at_100(self):
        """Score should never exceed 100."""
        engine = self._make_engine(
            ssl_match=30, historical=20, favicon_match=15,
            asn_match=15, js_recon=25, spf_dkim=15, host_header=10,
        )
        result = _make_enriched_result(confidence=40)
        result.ssl_matches = True
        result.ssl_cn = "www.example.com"
        result.hosting_provider = "AWS"
        result.asn_org = "Amazon"
        result.is_historical = True
        result.favicon_match = True
        result.js_extracted = True
        result.spf_dkim_origin = True
        result.host_header_match = True
        engine.score(result)
        assert result.confidence == 100

    def test_determine_status_confirmed(self):
        """Confidence >= 70 should be CONFIRMED."""
        engine = self._make_engine()
        result = _make_enriched_result(confidence=85)
        engine.determine_status(result)
        assert result.status == ResultStatus.CONFIRMED

    def test_determine_status_potential(self):
        """Confidence 30-69 should be POTENTIAL."""
        engine = self._make_engine()
        result = _make_enriched_result(confidence=50)
        engine.determine_status(result)
        assert result.status == ResultStatus.POTENTIAL

    def test_determine_status_false_positive(self):
        """Confidence < 30 should be FALSE_POSITIVE."""
        engine = self._make_engine()
        result = _make_enriched_result(confidence=20)
        engine.determine_status(result)
        assert result.status == ResultStatus.FALSE_POSITIVE

    def test_score_batch(self):
        """Batch scoring should score all results."""
        engine = self._make_engine()
        results = [
            _make_enriched_result(ip="1.2.3.4", confidence=40),
            _make_enriched_result(ip="5.6.7.8", confidence=40),
        ]
        engine.score_batch(results)
        assert all(r.confidence >= 40 for r in results)

    def test_determine_status_batch(self):
        engine = self._make_engine()
        results = [
            _make_enriched_result(ip="1.2.3.4", confidence=80),
            _make_enriched_result(ip="5.6.7.8", confidence=20),
        ]
        engine.determine_status_batch(results)
        assert results[0].status == ResultStatus.CONFIRMED
        assert results[1].status == ResultStatus.FALSE_POSITIVE

    def test_set_target_domain(self):
        engine = self._make_engine()
        engine.set_target_domain("example.com")
        assert engine._target_domain == "example.com"


class TestResultDeduplicator:
    def test_deduplicate_same_ip(self):
        """Same IP should be deduplicated, keeping highest confidence."""
        results = [
            _make_enriched_result(ip="1.2.3.4", confidence=80),
            _make_enriched_result(ip="1.2.3.4", confidence=60, source="other"),
        ]
        deduped = ResultDeduplicator.deduplicate(results)
        assert len(deduped) == 1
        assert deduped[0].confidence == 80

    def test_deduplicate_different_ips(self):
        """Different IPs should both remain."""
        results = [
            _make_enriched_result(ip="1.2.3.4", confidence=80),
            _make_enriched_result(ip="5.6.7.8", confidence=70),
        ]
        deduped = ResultDeduplicator.deduplicate(results)
        assert len(deduped) == 2

    def test_deduplicate_sorted_by_confidence(self):
        """Results should be sorted by confidence descending."""
        results = [
            _make_enriched_result(ip="1.2.3.4", confidence=50),
            _make_enriched_result(ip="5.6.7.8", confidence=90),
            _make_enriched_result(ip="9.8.7.6", confidence=70),
        ]
        deduped = ResultDeduplicator.deduplicate(results)
        assert deduped[0].confidence == 90
        assert deduped[1].confidence == 70
        assert deduped[2].confidence == 50

    def test_deduplicate_empty(self):
        deduped = ResultDeduplicator.deduplicate([])
        assert len(deduped) == 0


# ============================================================
# False Positive Filter Tests
# ============================================================


class TestFalsePositiveFilter:
    def test_init(self):
        fp_filter = FalsePositiveFilter()
        assert len(fp_filter._fp_networks) > 0

    def test_check_clean_result(self):
        """Normal result should pass."""
        fp_filter = FalsePositiveFilter()
        result = _make_enriched_result(ip="203.0.113.42")
        filter_result = fp_filter.check(result)
        assert filter_result.is_false_positive is False

    def test_check_cloudflare_asn(self):
        """Cloudflare ASN should be filtered."""
        fp_filter = FalsePositiveFilter()
        result = _make_enriched_result(ip="1.2.3.4")
        result.asn_org = "Cloudflare, Inc."
        filter_result = fp_filter.check(result)
        assert filter_result.is_false_positive is True
        assert filter_result.fp_type == "waf"

    def test_check_akamai_ip_range(self):
        """Akamai IP range should be filtered."""
        fp_filter = FalsePositiveFilter()
        result = _make_enriched_result(ip="23.32.0.0")
        filter_result = fp_filter.check(result)
        assert filter_result.is_false_positive is True
        assert filter_result.fp_type == "cdn"

    def test_check_cdn_subdomain(self):
        """CDN subdomain pattern should be filtered."""
        fp_filter = FalsePositiveFilter()
        result = _make_enriched_result(ip="5.6.7.8", subdomain="cdn.example.com")
        filter_result = fp_filter.check(result)
        assert filter_result.is_false_positive is True
        assert "cdn" in filter_result.reason.lower()

    def test_check_cf_cert(self):
        """Cloudflare SSL cert should be filtered."""
        fp_filter = FalsePositiveFilter()
        result = _make_enriched_result(ip="1.2.3.4")
        result.ssl_is_cloudflare = True
        filter_result = fp_filter.check(result)
        assert filter_result.is_false_positive is True

    def test_check_batch(self):
        """Batch check should separate true from false positives."""
        fp_filter = FalsePositiveFilter()
        results = [
            _make_enriched_result(ip="203.0.113.42"),
            _make_enriched_result(ip="1.2.3.4", subdomain="cdn.example.com"),
            _make_enriched_result(ip="5.6.7.8"),
            _make_enriched_result(ip="9.8.7.6"),  # ASN CF
        ]
        results[3].asn_org = "Cloudflare, Inc."
        true_pos, false_pos = fp_filter.check_batch(results)
        assert len(true_pos) == 2
        assert len(false_pos) == 2

    def test_confidence_penalty_applied(self):
        """False positives should have reduced confidence."""
        fp_filter = FalsePositiveFilter()
        results = [
            _make_enriched_result(ip="1.2.3.4", subdomain="cdn.example.com", confidence=70),
        ]
        _, false_pos = fp_filter.check_batch(results)
        assert false_pos[0].confidence < 70


# ============================================================
# Enrichment Pipeline Tests
# ============================================================


class TestEnrichmentPipeline:
    def test_init_defaults(self):
        config = Config()
        pipeline = EnrichmentPipeline(config)
        assert pipeline.enable_ssl is True
        assert pipeline.enable_asn is True
        assert pipeline.enable_scoring is True
        assert pipeline.enable_fp_filter is True
        assert pipeline.enable_dedup is True

    def test_init_disabled(self):
        config = Config()
        pipeline = EnrichmentPipeline(
            config, enable_ssl=False, enable_asn=False,
            enable_scoring=False, enable_fp_filter=False, enable_dedup=False,
        )
        assert pipeline.enable_ssl is False
        assert pipeline.ssl_checker is None

    @pytest.mark.asyncio
    async def test_enrich_empty_results(self):
        config = Config()
        pipeline = EnrichmentPipeline(config)
        stats, results = await pipeline.enrich([], "example.com", show_progress=False)
        assert stats.total_enriched == 0
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_enrich_ssl_disabled(self):
        config = Config()
        pipeline = EnrichmentPipeline(config, enable_ssl=False)
        result = _make_enriched_result()
        stats, enriched = await pipeline.enrich([result], "example.com", show_progress=False)
        assert stats.ssl_checked == 0
        assert len(enriched) == 1

    @pytest.mark.asyncio
    async def test_enrich_ssl_error_handling(self):
        """SSL errors should not crash the pipeline."""
        config = Config()
        pipeline = EnrichmentPipeline(config, enable_ssl=True, enable_asn=False, enable_fp_filter=False)
        result = _make_enriched_result()
        stats, enriched = await pipeline.enrich([result], "example.com", show_progress=False)
        # Should complete without error
        assert len(enriched) == 1
        # SSL check attempted (may have failed for non-routable IP)
        assert stats.total_enriched == 1

    @pytest.mark.asyncio
    async def test_enrich_scoring_only(self):
        """Scoring-only pipeline."""
        config = Config()
        pipeline = EnrichmentPipeline(
            config, enable_ssl=False, enable_asn=False, enable_js=False,
            enable_fp_filter=False, enable_dedup=False,
        )
        result = _make_enriched_result(confidence=40)
        stats, enriched = await pipeline.enrich([result], "example.com", show_progress=False)
        assert len(enriched) == 1
        # Score should be applied
        assert enriched[0].confidence >= 40

    @pytest.mark.asyncio
    async def test_enrich_full_pipeline(self):
        """Full pipeline with mocked enrichers."""
        config = Config()
        pipeline = EnrichmentPipeline(config)

        result = _make_enriched_result(ip="203.0.113.42", confidence=40)

        with patch.object(pipeline.ssl_checker, "check_ssl_batch", new_callable=AsyncMock) as mock_ssl, \
             patch.object(pipeline.asn_lookup, "lookup_batch", new_callable=AsyncMock) as mock_asn:

            mock_ssl.return_value = [
                SSLInfo(ip="203.0.113.42", port=443, cn="www.example.com",
                         san=["api.example.com"], issuer_org="Let's Encrypt"),
            ]
            mock_asn.return_value = [
                ASNInfo(ip="203.0.113.42", asn=16509, asn_org="Amazon.com",
                        country="US", city="Ashburn", isp="Amazon",
                        hosting_provider="AWS", is_hosting=True),
            ]

            stats, enriched = await pipeline.enrich(
                [result], "example.com", show_progress=False
            )

        assert stats.total_enriched == 1
        assert stats.ssl_checked == 1
        assert stats.ssl_matched == 1
        assert stats.asn_lookups == 1
        assert stats.asn_hosting_found == 1
        assert len(enriched) == 1
        assert enriched[0].ssl_matches is True
        assert enriched[0].hosting_provider == "AWS"
        assert enriched[0].confidence > 40

    @pytest.mark.asyncio
    async def test_enrich_deduplication(self):
        """Pipeline should deduplicate results."""
        config = Config()
        pipeline = EnrichmentPipeline(config, enable_ssl=False, enable_asn=False)
        results = [
            _make_enriched_result(ip="1.2.3.4", confidence=80),
            _make_enriched_result(ip="1.2.3.4", confidence=60, source="other"),
            _make_enriched_result(ip="5.6.7.8", confidence=50),
        ]
        stats, enriched = await pipeline.enrich(results, "example.com", show_progress=False)
        assert stats.duplicates_removed == 1
        assert len(enriched) == 2

    @pytest.mark.asyncio
    async def test_enrich_fp_filter(self):
        """Pipeline should filter false positives."""
        config = Config()
        pipeline = EnrichmentPipeline(config, enable_ssl=False, enable_asn=False, enable_dedup=False)
        results = [
            _make_enriched_result(ip="203.0.113.42", confidence=70),
            _make_enriched_result(ip="1.2.3.4", subdomain="cdn.example.com", confidence=70),
        ]
        stats, enriched = await pipeline.enrich(results, "example.com", show_progress=False)
        assert stats.fp_filtered == 1
        assert len(enriched) == 1


class TestEnrichmentStats:
    def test_to_dict(self):
        stats = EnrichmentStats(
            total_enriched=10, ssl_checked=10, ssl_matched=3,
            asn_lookups=10, asn_hosting_found=5,
            fp_filtered=2, duplicates_removed=1,
        )
        d = stats.to_dict()
        assert d["total_enriched"] == 10
        assert d["ssl_matched"] == 3
        assert d["asn_hosting_found"] == 5
        assert "enrichment_duration" in d


# ============================================================
# EnrichedResult Model Tests (Phase 3 additions)
# ============================================================


class TestEnrichedResultPhase3:
    def test_new_fields_exist(self):
        """All Phase 3 fields should be accessible."""
        result = EnrichedResult(
            subdomain="www.example.com", ip="1.2.3.4",
            ssl_is_cloudflare=True, asn_city="Ashburn",
            isp="Amazon", is_hosting=True, is_datacenter=True,
            is_residential=False,
        )
        assert result.ssl_is_cloudflare is True
        assert result.asn_city == "Ashburn"
        assert result.isp == "Amazon"
        assert result.is_hosting is True
        assert result.is_datacenter is True
        assert result.is_residential is False

    def test_to_dict_includes_new_fields(self):
        result = EnrichedResult(
            subdomain="www.example.com", ip="1.2.3.4",
            asn_city="Ashburn", isp="Amazon", is_hosting=True,
        )
        d = result.to_dict()
        assert "ssl_is_cloudflare" in d
        assert "asn_city" in d
        assert "isp" in d
        assert "is_hosting" in d
        assert "is_datacenter" in d
        assert "is_residential" in d

    def test_from_source_result(self):
        sr = SourceResult(
            subdomain="www.example.com", ip="1.2.3.4",
            source="crtsh", is_historical=True, confidence_boost=5,
        )
        result = EnrichedResult.from_source_result(sr)
        assert result.ip == "1.2.3.4"
        assert result.source == "crtsh"
        assert result.is_historical is True
        assert result.confidence == 5


# ============================================================
# Enrichers __init__ Tests
# ============================================================


class TestEnrichersInit:
    def test_all_exports(self):
        from cloudkill.enrichers import (
            ASNInfo,
            ASNLookup,
            JSFinding,
            JSReconEngine,
            ResultDeduplicator,
            ScoringEngine,
            SSLChecker,
            SSLInfo,
        )
        assert SSLChecker is not None
        assert SSLInfo is not None
        assert ASNLookup is not None
        assert ASNInfo is not None
        assert JSReconEngine is not None
        assert JSFinding is not None
        assert ScoringEngine is not None
        assert ResultDeduplicator is not None
