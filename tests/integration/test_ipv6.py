"""
CloudFail-Killer - IPv6 Integration Tests

Tests verifying IPv6 support across the entire pipeline:
    - SourceResult auto-detection
    - EnrichedResult serialization
    - Cache storage/retrieval
    - Exporter format compatibility
    - Model handling
"""

import json

import pytest

from cloudkill.cache.sqlite_cache import SQLiteCache
from cloudkill.core.models import EnrichedResult, ResultStatus, ScanReport
from cloudkill.exporters.csv_export import export_csv, export_ip_list
from cloudkill.exporters.json_export import export_json
from cloudkill.exporters.markdown_export import export_markdown
from cloudkill.exporters.nuclei import export_nuclei_template
from cloudkill.exporters.pdf_export import export_pdf
from cloudkill.sources.base import IPVersion, SourceResult

# ═══════════════════════════════════════════════════════════
# IPv6 SOURCE RESULT TESTS
# ═══════════════════════════════════════════════════════════

class TestIPv6SourceResult:

    def test_ipv4_detected(self):
        sr = SourceResult(subdomain="test.com", ip="192.168.1.1", source="test")
        assert sr.ip_version == IPVersion.V4

    def test_ipv6_detected(self):
        sr = SourceResult(subdomain="test.com", ip="2001:db8::1", source="test")
        assert sr.ip_version == IPVersion.V6

    def test_ipv6_full_address(self):
        sr = SourceResult(subdomain="test.com", ip="2606:4700:4700::1111", source="test")
        assert sr.ip_version == IPVersion.V6

    def test_ipv6_loopback(self):
        sr = SourceResult(subdomain="test.com", ip="::1", source="test")
        assert sr.ip_version == IPVersion.V6

    def test_ipv6_to_dict(self):
        sr = SourceResult(subdomain="test.com", ip="2001:db8::1", source="test")
        d = sr.to_dict()
        assert d["ip_version"] == 6
        assert d["ip"] == "2001:db8::1"

    def test_ipv4_to_dict(self):
        sr = SourceResult(subdomain="test.com", ip="10.0.0.1", source="test")
        d = sr.to_dict()
        assert d["ip_version"] == 4


# ═══════════════════════════════════════════════════════════
# IPv6 ENRICHED RESULT TESTS
# ═══════════════════════════════════════════════════════════

class TestIPv6EnrichedResult:

    def test_ipv6_from_source_result(self):
        sr = SourceResult(subdomain="test.com", ip="2001:db8::1", source="test")
        er = EnrichedResult.from_source_result(sr)
        assert er.ip == "2001:db8::1"
        assert er.ip_version == IPVersion.V6

    def test_ipv4_from_source_result(self):
        sr = SourceResult(subdomain="test.com", ip="1.2.3.4", source="test")
        er = EnrichedResult.from_source_result(sr)
        assert er.ip == "1.2.3.4"
        assert er.ip_version == IPVersion.V4

    def test_ipv6_enrichment_fields(self):
        """IPv6 results can have enrichment fields populated."""
        er = EnrichedResult(
            subdomain="test.com", ip="2001:db8::1",
            ip_version=IPVersion.V6, source="test",
            confidence=60, status=ResultStatus.POTENTIAL,
            asn_number=13335, asn_org="Cloudflare",
            asn_country="US",
            hosting_provider=None, is_hosting=True,
        )
        d = er.to_dict()
        assert d["ip_version"] == 6
        assert d["asn_number"] == 13335
        assert d["asn_org"] == "Cloudflare"


# ═══════════════════════════════════════════════════════════
# IPv6 SCAN REPORT TESTS
# ═══════════════════════════════════════════════════════════

class TestIPv6ScanReport:

    def _make_ipv6_report(self) -> ScanReport:
        report = ScanReport(domain="example.com", profile="researcher")
        report.add_result(EnrichedResult(
            subdomain="a.com", ip="1.2.3.4", ip_version=IPVersion.V4,
            source="crtsh", confidence=70,
        ))
        report.add_result(EnrichedResult(
            subdomain="b.com", ip="2001:db8::1", ip_version=IPVersion.V6,
            source="anubisdb", confidence=50,
        ))
        report.add_result(EnrichedResult(
            subdomain="c.com", ip="2606:4700:4700::1", ip_version=IPVersion.V6,
            source="otx", confidence=40,
        ))
        report.finalize()
        return report

    def test_ipv6_counts(self):
        report = self._make_ipv6_report()
        assert report.ipv4_count == 1
        assert report.ipv6_count == 2
        assert report.total_results == 3
        assert report.unique_ips == 3

    def test_ipv6_to_dict(self):
        report = self._make_ipv6_report()
        d = report.to_dict()
        assert d["summary"]["ipv4_count"] == 1
        assert d["summary"]["ipv6_count"] == 2

        # Verify individual result IP versions
        result_ips = [r["ip"] for r in d["results"]]
        assert "1.2.3.4" in result_ips
        assert "2001:db8::1" in result_ips
        assert "2606:4700:4700::1" in result_ips


# ═══════════════════════════════════════════════════════════
# IPv6 CACHE TESTS
# ═══════════════════════════════════════════════════════════

class TestIPv6Cache:

    def test_store_ipv6_results(self, temp_dir):
        """IPv6 results are stored and retrieved correctly."""
        cache = SQLiteCache(cache_dir=temp_dir)
        cache.initialize()

        report = ScanReport(domain="example.com", profile="researcher")
        report.add_result(EnrichedResult(
            subdomain="v6.com", ip="2001:db8::1",
            ip_version=IPVersion.V6, source="test", confidence=60,
        ))
        report.add_result(EnrichedResult(
            subdomain="v4.com", ip="10.0.0.1",
            ip_version=IPVersion.V4, source="test", confidence=50,
        ))
        report.finalize()

        cache.store_scan(report)

        # Retrieve and verify
        results = cache.get_known_ips("example.com")
        ips = {r["ip"] for r in results}
        assert "2001:db8::1" in ips
        assert "10.0.0.1" in ips

        cache.close()

    def test_ipv6_campaign_results(self, temp_dir):
        """IPv6 results in campaign results have correct version."""
        cache = SQLiteCache(cache_dir=temp_dir)
        cache.initialize()

        report = ScanReport(domain="example.com", profile="researcher")
        report.add_result(EnrichedResult(
            subdomain="v6.com", ip="2001:db8::1",
            ip_version=IPVersion.V6, source="test", confidence=60,
        ))
        report.finalize()

        campaign_id = cache.store_scan(report)
        results = cache.get_campaign_results(campaign_id)
        assert len(results) == 1
        assert results[0]["ip"] == "2001:db8::1"
        assert results[0]["ip_version"] == 6

        cache.close()


# ═══════════════════════════════════════════════════════════
# IPv6 EXPORTER TESTS
# ═══════════════════════════════════════════════════════════

class TestIPv6Exporters:

    @pytest.fixture
    def mixed_report(self):
        report = ScanReport(domain="example.com", profile="researcher")
        report.add_result(EnrichedResult(
            subdomain="a.com", ip="1.2.3.4", ip_version=IPVersion.V4,
            source="crtsh", confidence=70, is_cloudflare=False,
        ))
        report.add_result(EnrichedResult(
            subdomain="b.com", ip="2001:db8::1", ip_version=IPVersion.V6,
            source="anubisdb", confidence=50, is_cloudflare=False,
        ))
        report.add_result(EnrichedResult(
            subdomain="c.com", ip="::ffff:192.168.1.1", ip_version=IPVersion.V6,
            source="dns", confidence=30, is_cloudflare=False,
        ))
        report.finalize()
        return report

    def test_json_includes_ipv6(self, mixed_report, temp_dir):
        path = export_json(mixed_report, temp_dir / "report.json")
        data = json.loads(path.read_text())
        result_ips = [r["ip"] for r in data["results"]]
        assert "2001:db8::1" in result_ips
        assert "::ffff:192.168.1.1" in result_ips

    def test_csv_includes_ipv6(self, mixed_report, temp_dir):
        path = export_csv(mixed_report, temp_dir / "report.csv")
        content = path.read_text()
        assert "2001:db8::1" in content

    def test_ip_list_includes_ipv6(self, mixed_report, temp_dir):
        path = export_ip_list(mixed_report, temp_dir / "ips.txt")
        content = path.read_text()
        ips = content.strip().split("\n")
        assert "2001:db8::1" in ips
        assert "::ffff:192.168.1.1" in ips

    def test_markdown_includes_ipv6(self, mixed_report, temp_dir):
        path = export_markdown(mixed_report, temp_dir / "report.md")
        content = path.read_text()
        assert "2001:db8::1" in content

    def test_pdf_handles_ipv6(self, mixed_report, temp_dir):
        path = export_pdf(mixed_report, temp_dir / "report.pdf")
        assert path.exists()
        assert path.stat().st_size > 1000

    def test_nuclei_includes_ipv6(self, mixed_report, temp_dir):
        path = export_nuclei_template(mixed_report, temp_dir / "template.yaml")
        content = path.read_text()
        # IPv6 in variations or comments
        assert "2001:db8::1" in content


# ═══════════════════════════════════════════════════════════
# IPv6 MIXED DUAL-STACK TESTS
# ═══════════════════════════════════════════════════════════

class TestIPv6DualStack:

    def test_dual_stack_report(self):
        """Report with both IPv4 and IPv6 results is correct."""
        report = ScanReport(domain="dual.com", profile="researcher")
        report.add_result(EnrichedResult(
            subdomain="v4.dual.com", ip="10.0.0.1",
            ip_version=IPVersion.V4, source="test",
        ))
        report.add_result(EnrichedResult(
            subdomain="v6.dual.com", ip="2001:db8::1",
            ip_version=IPVersion.V6, source="test",
        ))
        report.finalize()

        assert report.ipv4_count == 1
        assert report.ipv6_count == 1
        assert report.unique_ips == 2

    def test_dual_stack_json_serialization(self):
        """Dual-stack results serialize correctly to JSON."""
        report = ScanReport(domain="dual.com", profile="researcher")
        report.add_result(EnrichedResult(
            subdomain="v4.dual.com", ip="10.0.0.1",
            ip_version=IPVersion.V4, source="test",
        ))
        report.add_result(EnrichedResult(
            subdomain="v6.dual.com", ip="2001:db8::1",
            ip_version=IPVersion.V6, source="test",
        ))
        report.finalize()

        json_str = json.dumps(report.to_dict(), indent=2)
        data = json.loads(json_str)

        versions = [r["ip_version"] for r in data["results"]]
        assert 4 in versions  # IPv4
        assert 6 in versions  # IPv6

    def test_ipv6_only_report(self):
        """IPv6-only report works correctly."""
        report = ScanReport(domain="v6only.com", profile="researcher")
        report.add_result(EnrichedResult(
            subdomain="a.com", ip="2001:db8::1", ip_version=IPVersion.V6,
        ))
        report.add_result(EnrichedResult(
            subdomain="b.com", ip="::1", ip_version=IPVersion.V6,
        ))
        report.finalize()

        assert report.ipv4_count == 0
        assert report.ipv6_count == 2
        assert report.unique_ips == 2
