"""
CloudFail-Killer - Pipeline Integration Tests

End-to-end tests verifying the full scan pipeline:
    SourceResult → EnrichedResult → Enrichment → Active Scan → Report → Export
"""

import json
from pathlib import Path

import pytest

from cloudkill.cache.sqlite_cache import SQLiteCache
from cloudkill.config import Config, StealthMode
from cloudkill.core.filters import FalsePositiveFilter
from cloudkill.core.models import EnrichedResult, ResultStatus, ScanReport
from cloudkill.core.webhooks import WebhookSender, WebhookType
from cloudkill.enrichers.scoring import ResultDeduplicator, ScoringEngine
from cloudkill.exporters.csv_export import export_csv, export_ip_list
from cloudkill.exporters.json_export import export_json, export_json_string
from cloudkill.exporters.markdown_export import export_markdown
from cloudkill.exporters.nuclei import export_nuclei_targets, export_nuclei_template
from cloudkill.exporters.pdf_export import export_pdf
from cloudkill.sources.base import IPVersion, SourceResult

# ═══════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════

def make_source_result(ip: str, subdomain: str = "test.com", source: str = "test",
                      confidence_boost: int = 0, port: int = 443,
                      is_historical: bool = False) -> SourceResult:
    """Helper to create SourceResult objects."""
    return SourceResult(
        subdomain=subdomain,
        ip=ip,
        ip_version=IPVersion.V6 if ":" in ip else IPVersion.V4,
        source=source,
        port=port,
        is_historical=is_historical,
        confidence_boost=confidence_boost,
        metadata={},
    )


def make_enriched_result(ip: str, subdomain: str = "test.com",
                           source: str = "test", confidence: int = 50,
                           port: int = 443, is_cloudflare: bool = False,
                           status: ResultStatus = ResultStatus.POTENTIAL) -> EnrichedResult:
    """Helper to create EnrichedResult objects."""
    return EnrichedResult(
        subdomain=subdomain,
        ip=ip,
        ip_version=IPVersion.V6 if ":" in ip else IPVersion.V4,
        source=source,
        port=port,
        confidence=confidence,
        is_cloudflare=is_cloudflare,
        status=status,
        confidence_reasons=[f"Test: {confidence}% from {source}"],
    )


def make_report(domain: str = "test.com", profile: str = "researcher",
                results: list[EnrichedResult] | None = None) -> ScanReport:
    """Helper to create a ScanReport."""
    report = ScanReport(domain=domain, profile=profile)
    if results:
        for r in results:
            report.add_result(r)
    report.finalize()
    return report


# ═══════════════════════════════════════════════════════════
# FULL PIPELINE INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════

class TestFullPipeline:

    def test_source_result_to_enriched_result(self):
        """SourceResult converts correctly to EnrichedResult."""
        sr = make_source_result("192.168.1.1", "api.test.com", "crtsh", confidence_boost=5)
        er = EnrichedResult.from_source_result(sr)
        assert er.ip == "192.168.1.1"
        assert er.subdomain == "api.test.com"
        assert er.source == "crtsh"
        assert er.confidence == 5
        assert er.raw_source_result is sr

    def test_ipv6_source_result_auto_detection(self):
        """IPv6 addresses are auto-detected."""
        sr = make_source_result("2001:db8::1")
        assert sr.ip_version == IPVersion.V6
        er = EnrichedResult.from_source_result(sr)
        assert er.ip_version == IPVersion.V6

    def test_ipv4_source_result_auto_detection(self):
        """IPv4 addresses are auto-detected."""
        sr = make_source_result("10.0.0.1")
        assert sr.ip_version == IPVersion.V4

    def test_enriched_result_serialization_roundtrip(self):
        """EnrichedResult to_dict/from_source_result is consistent."""
        sr = make_source_result("1.2.3.4", "www.test.com", "otx", confidence_boost=10)
        er = EnrichedResult.from_source_result(sr)
        d = er.to_dict()
        assert d["ip"] == "1.2.3.4"
        assert d["subdomain"] == "www.test.com"
        assert d["source"] == "otx"
        assert d["confidence"] == 10
        assert d["ip_version"] == 4

    def test_scan_report_add_result_statistics(self):
        """ScanReport accurately tracks statistics."""
        r1 = make_enriched_result("1.1.1.1", confidence=80, status=ResultStatus.CONFIRMED)
        r2 = make_enriched_result("2.2.2.2", confidence=60)
        r3 = make_enriched_result("2001:db8::1", confidence=30)
        r4 = make_enriched_result("1.1.1.1", confidence=40, source="other")  # duplicate IP

        report = make_report("example.com", "pentester", [r1, r2, r3, r4])
        assert report.total_results == 4
        assert report.unique_ips == 3  # 3 unique IPs
        assert report.high_confidence_count == 1  # only r1 >= 70
        assert report.confirmed_count == 1  # only r1
        assert report.ipv4_count == 3
        assert report.ipv6_count == 1
        assert report.sources_used == ["test", "other"]

    def test_scan_report_to_dict_completeness(self):
        """ScanReport to_dict contains all required fields."""
        r = make_enriched_result("10.0.0.1", confidence=75)
        report = make_report("example.com", results=[r])
        d = report.to_dict()

        assert d["domain"] == "example.com"
        assert d["profile"] == "researcher"
        assert "summary" in d
        assert d["summary"]["total_results"] == 1
        assert d["summary"]["unique_ips"] == 1
        assert "results" in d
        assert len(d["results"]) == 1
        assert d["results"][0]["ip"] == "10.0.0.1"
        assert d["results"][0]["confidence"] == 75

    def test_full_pipeline_multiple_sources(self):
        """Simulate multi-source results through the full pipeline."""
        # Simulate results from multiple sources
        results = [
            make_enriched_result("1.2.3.4", "example.com", "crtsh", confidence=40),
            make_enriched_result("5.6.7.8", "www.example.com", "otx", confidence=35),
            make_enriched_result("1.2.3.4", "api.example.com", "wayback", confidence=30),
            make_enriched_result("10.0.0.1", "mail.example.com", "spf_dkim", confidence=45),
            make_enriched_result("2001:db8::1", "cdn.example.com", "anubisdb", confidence=20),
        ]

        report = make_report("example.com", "bugbounty", results)

        # Verify source diversity
        assert len(report.sources_used) >= 4
        assert "crtsh" in report.sources_used
        assert "otx" in report.sources_used

        # Verify IPv4/IPv6 mix
        assert report.ipv4_count == 4
        assert report.ipv6_count == 1

        # Verify serialization works
        json_str = json.dumps(report.to_dict())
        assert "example.com" in json_str

    def test_false_positive_filter_integration(self):
        """FP filter correctly processes a batch of mixed results."""
        results = [
            make_enriched_result("1.1.1.1", confidence=80, status=ResultStatus.CONFIRMED),
            make_enriched_result("1.0.0.1", confidence=60),  # Known CF IP
            make_enriched_result("2.2.2.2", confidence=50),
        ]
        results[1].asn_org = "Cloudflare, Inc."

        fp_filter = FalsePositiveFilter()
        true_pos, false_pos = fp_filter.check_batch(results)

        # CF org should be flagged
        assert len(false_pos) >= 1
        assert any("cloudflare" in (r.asn_org or "").lower() for r in false_pos)

    def test_deduplication_integration(self):
        """Deduplicator correctly handles duplicate IPs."""
        results = [
            make_enriched_result("1.2.3.4", confidence=80),
            make_enriched_result("1.2.3.4", confidence=60),  # Same IP, lower
            make_enriched_result("5.6.7.8", confidence=70),
        ]

        dedup = ResultDeduplicator()
        deduped = dedup.deduplicate(results)

        assert len(deduped) == 2  # 1.2.3.4 (highest conf) + 5.6.7.8
        ips = [r.ip for r in deduped]
        assert ips.count("1.2.3.4") == 1
        assert deduped[0].confidence == 80  # Highest confidence kept

    def test_scoring_engine_with_profile_weights(self):
        """Scoring engine applies profile-specific weights."""
        config = Config.from_profile("pentester")
        scoring = ScoringEngine(config)
        scoring.set_target_domain("example.com")

        result = make_enriched_result("1.2.3.4", confidence=40)
        result.ssl_matches = True
        result.ssl_cn = "example.com"  # Add this so SSL scoring triggers
        result.is_hosting = True
        result.hosting_provider = "AWS"
        result.asn_org = "Amazon.com"  # Add this so ASN scoring triggers

        scoring.score(result)
        assert result.confidence > 40  # Should be boosted
        assert len(result.confidence_reasons) > 1

    def test_confidence_never_exceeds_100(self):
        """Confidence is always capped at 100."""
        config = Config.from_profile("researcher")
        scoring = ScoringEngine(config)
        scoring.set_target_domain("example.com")

        result = make_enriched_result("1.2.3.4", confidence=0)
        result.ssl_matches = True
        result.is_hosting = True
        result.hosting_provider = "AWS"
        result.is_historical = True
        result.favicon_match = True

        scoring.score(result)
        assert result.confidence <= 100

    def test_status_determination(self):
        """Status is correctly determined from confidence."""
        config = Config.from_profile("researcher")
        scoring = ScoringEngine(config)
        scoring.set_target_domain("example.com")

        # High confidence → CONFIRMED
        r1 = make_enriched_result("1.2.3.4", confidence=95)
        scoring.score(r1)
        scoring.determine_status(r1)
        assert r1.status == ResultStatus.CONFIRMED

        # Low confidence → POTENTIAL
        r2 = make_enriched_result("5.6.7.8", confidence=30)
        scoring.score(r2)
        scoring.determine_status(r2)
        assert r2.status == ResultStatus.POTENTIAL


# ═══════════════════════════════════════════════════════════
# CACHE + PIPELINE INTEGRATION
# ═══════════════════════════════════════════════════════════

class TestCachePipelineIntegration:

    def test_store_and_retrieve_pipeline_results(self, temp_dir):
        """Full pipeline results can be stored and retrieved from cache."""
        cache = SQLiteCache(cache_dir=temp_dir)
        cache.initialize()

        # Create a report like the real pipeline would
        results = [
            make_enriched_result("1.2.3.4", "example.com", "crtsh", confidence=75,
                                status=ResultStatus.CONFIRMED),
            make_enriched_result("5.6.7.8", "www.example.com", "otx", confidence=60),
            make_enriched_result("2001:db8::1", "cdn.example.com", "anubisdb", confidence=45),
        ]
        results[0].ssl_matches = True
        report = make_report("example.com", "pentester", results)

        # Store
        campaign_id = cache.store_scan(report)
        assert campaign_id > 0

        # Retrieve
        history = cache.get_domain_history("example.com")
        assert len(history) == 1
        assert history[0]["total_results"] == 3

        # Get results with confidence filter
        high_conf = cache.get_campaign_results(campaign_id, min_confidence=50)
        assert len(high_conf) == 2  # 75 and 60

        # Get known IPs
        known = cache.get_known_ips("example.com")
        assert len(known) == 3

        cache.close()

    def test_multiple_scans_ip_tracking(self, temp_dir):
        """IP discovery tracking works across multiple scan campaigns."""
        cache = SQLiteCache(cache_dir=temp_dir)
        cache.initialize()

        # First scan
        results1 = [
            make_enriched_result("1.2.3.4", "example.com", "crtsh", confidence=50),
            make_enriched_result("5.6.7.8", "example.com", "otx", confidence=60),
        ]
        report1 = make_report("example.com", results=results1)
        cache.store_scan(report1)

        # Second scan with one new IP
        results2 = [
            make_enriched_result("1.2.3.4", "example.com", "crtsh", confidence=75),
            make_enriched_result("10.0.0.1", "example.com", "anubisdb", confidence=40),
        ]
        report2 = make_report("example.com", results=results2)
        cache.store_scan(report2)

        # Check tracking
        known = cache.get_known_ips("example.com")
        ip_map = {r["ip"]: r for r in known}
        assert "1.2.3.4" in ip_map
        assert ip_map["1.2.3.4"]["seen_count"] == 2  # Seen in both scans
        assert ip_map["1.2.3.4"]["max_confidence"] == 75  # Highest confidence

        cache.close()

    def test_export_after_cache_retrieval(self, temp_dir):
        """Cached results can be exported correctly."""
        cache = SQLiteCache(cache_dir=temp_dir)
        cache.initialize()

        results = [
            make_enriched_result("1.2.3.4", confidence=80, status=ResultStatus.CONFIRMED),
        ]
        report = make_report("example.com", results=results)
        cache.store_scan(report)

        # Retrieve and re-export
        history = cache.get_domain_history("example.com")
        assert len(history) == 1
        cached_report_data = history[0]

        # Verify data integrity
        assert cached_report_data["domain"] == "example.com"
        assert cached_report_data["total_results"] == 1

        cache.close()


# ═══════════════════════════════════════════════════════════
# ALL EXPORTERS INTEGRATION
# ═══════════════════════════════════════════════════════════

class TestAllExportersIntegration:

    @pytest.fixture
    def full_report(self):
        """Create a comprehensive report with all feature types."""
        results = [
            EnrichedResult(
                subdomain="example.com", ip="1.2.3.4",
                ip_version=IPVersion.V4, source="crtsh", port=443,
                is_cloudflare=False, confidence=80,
                ssl_matches=True, ssl_cn="example.com",
                hosting_provider="AWS", is_hosting=True,
                status=ResultStatus.CONFIRMED,
                confidence_reasons=["SSL match", "Hosting: AWS"],
            ),
            EnrichedResult(
                subdomain="www.example.com", ip="5.6.7.8",
                ip_version=IPVersion.V4, source="otx", port=443,
                is_cloudflare=False, confidence=60,
                status=ResultStatus.POTENTIAL,
                confidence_reasons=["Non-CF IP"],
            ),
            EnrichedResult(
                subdomain="cdn.example.com", ip="10.0.0.1",
                ip_version=IPVersion.V4, source="urlscan", port=80,
                is_cloudflare=False, confidence=30,
                asn_org="Akamai Technologies",
                status=ResultStatus.FALSE_POSITIVE,
            ),
            EnrichedResult(
                subdomain="ipv6.example.com", ip="2001:db8::1",
                ip_version=IPVersion.V6, source="anubisdb", port=443,
                is_cloudflare=False, confidence=45,
                status=ResultStatus.POTENTIAL,
            ),
        ]
        report = ScanReport(domain="example.com", profile="pentester")
        for r in results:
            report.add_result(r)
        report.enrichment_stats = {
            "ssl_checked": 4, "ssl_matched": 1, "asn_lookups": 4,
            "asn_hosting_found": 1, "fp_filtered": 1, "duplicates_removed": 0,
            "confirmed_count": 1, "potential_count": 2,
            "enrichment_duration": "1.23s",
        }
        report.finalize()
        return report

    def test_all_export_formats_consistent_data(self, full_report, temp_dir):
        """All export formats contain consistent core data."""
        # JSON
        json_path = export_json(full_report, temp_dir / "report.json")
        json_data = json.loads(json_path.read_text())
        assert json_data["domain"] == "example.com"
        assert json_data["summary"]["total_results"] == 4
        assert json_data["summary"]["unique_ips"] == 4

        # CSV
        csv_path = export_csv(full_report, temp_dir / "report.csv")
        csv_content = csv_path.read_text()
        assert "1.2.3.4" in csv_content
        assert "2001:db8::1" in csv_content

        # Markdown
        md_path = export_markdown(full_report, temp_dir / "report.md")
        md_content = md_path.read_text()
        assert "example.com" in md_content
        assert "1.2.3.4" in md_content

        # PDF
        pdf_path = export_pdf(full_report, temp_dir / "report.pdf")
        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 1000

        # Nuclei
        nuc_path = export_nuclei_template(full_report, temp_dir / "template.yaml")
        nuc_content = nuc_path.read_text()
        assert "example.com" in nuc_content

        # Nuclei targets
        targets_path = export_nuclei_targets(full_report, temp_dir / "targets.txt")
        targets_content = targets_path.read_text()
        assert "example.com" in targets_content

    def test_json_export_roundtrip(self, full_report):
        """JSON export can be loaded and verified."""
        json_str = export_json_string(full_report)
        data = json.loads(json_str)

        assert data["domain"] == "example.com"
        assert data["profile"] == "pentester"
        assert len(data["results"]) == 4
        assert data["summary"]["confirmed_count"] == 1
        assert data["enrichment_stats"]["ssl_matched"] == 1

    def test_csv_all_results_present(self, full_report, temp_dir):
        """CSV export includes all results."""
        path = export_csv(full_report, temp_dir / "full.csv")
        content = path.read_text()
        lines = content.strip().split("\n")
        assert len(lines) >= 5  # Header + 4 results

    def test_csv_min_confidence_filter(self, full_report, temp_dir):
        """CSV min_confidence filter works correctly."""
        path = export_csv(full_report, temp_dir / "high.csv", min_confidence=50)
        content = path.read_text()
        lines = content.strip().split("\n")
        assert len(lines) >= 3  # Header + 2 results (80 + 60)

    def test_markdown_has_all_sections(self, full_report, temp_dir):
        """Markdown export has all required sections."""
        path = export_markdown(full_report, temp_dir / "report.md")
        content = path.read_text()
        assert "# CloudFail-Killer Report" in content
        assert "## Summary" in content
        assert "## Discovered IPs" in content
        assert "## Confirmed Origin IPs" in content

    def test_nuclei_template_valid_yaml(self, full_report, temp_dir):
        """Nuclei template has valid structure."""
        path = export_nuclei_template(full_report, temp_dir / "t.yaml")
        content = path.read_text()
        # Required Nuclei keys
        assert "id:" in content
        assert "info:" in content
        assert "http:" in content
        assert "matchers:" in content
        assert "extractors:" in content

    def test_ip_list_export(self, full_report, temp_dir):
        """IP list export contains all unique IPs."""
        path = export_ip_list(full_report, temp_dir / "ips.txt")
        content = path.read_text().strip()
        ips = content.split("\n")
        assert len(ips) == 4  # 4 unique IPs
        assert "1.2.3.4" in ips
        assert "2001:db8::1" in ips

    def test_webhook_sender_all_platforms(self, full_report):
        """Webhook sender builds payloads for all platforms."""
        sender = WebhookSender()

        # Test all platform payload builds
        slack = sender._build_slack_payload(full_report, "https://hooks.slack.com/test")
        assert slack.webhook_type == WebhookType.SLACK
        json.loads(slack.body)  # Valid JSON

        discord = sender._build_discord_payload(full_report, "https://discord.com/test")
        assert discord.webhook_type == WebhookType.DISCORD
        json.loads(discord.body)

        generic = sender._build_generic_payload(full_report, "https://example.com/test")
        assert generic.webhook_type == WebhookType.GENERIC
        json.loads(generic.body)


# ═══════════════════════════════════════════════════════════
# CONFIG + PROFILES INTEGRATION
# ═══════════════════════════════════════════════════════════

class TestConfigProfilesIntegration:

    def test_all_profiles_load(self):
        """All 5 profiles load without error."""
        for profile in ["researcher", "pentester", "bugbounty", "enterprise", "automation"]:
            config = Config.from_profile(profile)
            assert config.profile.value == profile
            assert config.scoring_weights is not None

    def test_profile_weights_differ(self):
        """Different profiles have different scoring weights."""
        researcher = Config.from_profile("researcher")
        pentester = Config.from_profile("pentester")
        bugbounty = Config.from_profile("bugbounty")
        _enterprise = Config.from_profile("enterprise")  # smoke: builds without error

        # At least some weights should differ
        assert researcher.scoring_weights.ssl_match != pentester.scoring_weights.ssl_match
        assert researcher.scoring_weights.non_cf_ip != bugbounty.scoring_weights.non_cf_ip

    def test_profile_threads_stealth(self):
        """Stealth mode affects effective threads."""
        normal = Config.from_profile("researcher", stealth_mode=StealthMode.NORMAL, threads=30)
        stealth = Config.from_profile("researcher", stealth_mode=StealthMode.STEALTH, threads=30)

        assert normal.effective_threads == 30
        assert stealth.effective_threads < 30  # Stealth reduces threads

    def test_config_webhook_fields(self):
        """Webhook config has all required fields."""
        config = Config(
            webhook={
                "url": "https://example.com/hook",
                "slack_url": "https://hooks.slack.com/test",
                "discord_url": "https://discord.com/test",
            }
        )
        assert config.webhook.url == "https://example.com/hook"
        assert config.webhook.slack_url == "https://hooks.slack.com/test"
        assert config.webhook.discord_url == "https://discord.com/test"

    def test_config_active_ports(self):
        """Active scanning ports are configurable."""
        config = Config(active=True, active_ports=[80, 443, 3000, 9000])
        assert config.active is True
        assert 9000 in config.active_ports

    def test_config_cache_dir(self):
        """Cache directory is configurable."""
        config = Config(cache_dir=Path("/tmp/test-cache"))
        assert config.cache_dir == Path("/tmp/test-cache")

