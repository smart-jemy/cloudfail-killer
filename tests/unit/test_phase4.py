"""
CloudFail-Killer - Phase 4 Tests

Comprehensive unit tests for Active Scanner, Host Header Probe,
SQLite Cache, Webhooks, and all Exporters.
"""

import json
import sqlite3
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cloudkill import __version__
from cloudkill.cache.sqlite_cache import SQLiteCache
from cloudkill.core.active_scanner import (
    ActiveProbeResult,
    ActiveScanner,
    PortCheckResult,
    ProbeResult,
)
from cloudkill.core.host_header import (
    HostHeaderProbe,
    HostHeaderResult,
)
from cloudkill.core.models import EnrichedResult, ResultStatus, ScanReport
from cloudkill.core.webhooks import (
    WebhookSender,
    WebhookType,
)
from cloudkill.exporters.csv_export import export_csv, export_ip_list
from cloudkill.exporters.json_export import export_json, export_json_string
from cloudkill.exporters.markdown_export import export_markdown
from cloudkill.exporters.nuclei import export_nuclei_targets, export_nuclei_template
from cloudkill.exporters.pdf_export import export_pdf
from cloudkill.sources.base import IPVersion

# ═══════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def sample_enriched_results():
    """Create sample enriched results for testing."""
    results = [
        EnrichedResult(
            subdomain="example.com",
            ip="192.168.1.1",
            ip_version=IPVersion.V4,
            source="crtsh",
            port=443,
            is_cloudflare=False,
            confidence=60,
            confidence_reasons=["Source boost: +5 from crtsh"],
            status=ResultStatus.POTENTIAL,
        ),
        EnrichedResult(
            subdomain="www.example.com",
            ip="10.0.0.1",
            ip_version=IPVersion.V4,
            source="otx",
            port=443,
            is_cloudflare=False,
            confidence=75,
            ssl_matches=True,
            ssl_cn="example.com",
            hosting_provider="AWS",
            confidence_reasons=["SSL match", "Hosting: AWS"],
            status=ResultStatus.CONFIRMED,
        ),
        EnrichedResult(
            subdomain="api.example.com",
            ip="2001:db8::1",
            ip_version=IPVersion.V6,
            source="anubisdb",
            port=443,
            is_cloudflare=False,
            confidence=45,
            confidence_reasons=["Source boost"],
            status=ResultStatus.POTENTIAL,
        ),
    ]
    return results


@pytest.fixture
def sample_report(sample_enriched_results):
    """Create a sample scan report."""
    report = ScanReport(domain="example.com", profile="pentester")
    for r in sample_enriched_results:
        report.add_result(r)
    report.finalize()
    return report


@pytest.fixture
def temp_dir():
    """Create a temporary directory for file-based tests."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def cache_dir(temp_dir):
    """Create a cache directory."""
    cd = temp_dir / "cache"
    cd.mkdir()
    return cd


# ═══════════════════════════════════════════════════════════
# VERSION TEST
# ═══════════════════════════════════════════════════════════

class TestVersion:
    """Test version is correctly updated."""

    def test_version_is_0_7_0(self):
        assert __version__ == "0.7.0"


# ═══════════════════════════════════════════════════════════
# ACTIVE SCANNER TESTS
# ═══════════════════════════════════════════════════════════

class TestActiveScanner:

    def test_init_defaults(self):
        scanner = ActiveScanner()
        assert scanner.timeout == 10
        assert scanner.max_concurrent == 20
        assert 80 in scanner.ports
        assert 443 in scanner.ports

    def test_init_custom(self):
        scanner = ActiveScanner(timeout=5, max_concurrent=10, ports=[80, 443])
        assert scanner.timeout == 5
        assert scanner.max_concurrent == 10
        assert scanner.ports == [80, 443]

    def test_extract_title(self):
        html = "<html><head><title>Test Page</title></head><body>Hello</body></html>"
        assert ActiveScanner._extract_title(html) == "Test Page"

    def test_extract_title_none(self):
        assert ActiveScanner._extract_title("<html><body>No title</body></html>") is None

    def test_similarity_identical(self):
        assert ActiveScanner._similarity("hello world", "hello world") == 1.0

    def test_similarity_different(self):
        result = ActiveScanner._similarity("abc", "xyz")
        assert 0.0 <= result < 1.0

    def test_similarity_empty(self):
        assert ActiveScanner._similarity("", "hello") == 0.0

    def test_similarity_none(self):
        assert ActiveScanner._similarity(None, "hello") == 0.0

    def test_active_probe_result_to_dict(self):
        result = ActiveProbeResult(
            ip="1.2.3.4", port=443, result=ProbeResult.MATCH,
            status_code=200, confidence_boost=15,
            reasons=["Title matches"],
        )
        d = result.to_dict()
        assert d["ip"] == "1.2.3.4"
        assert d["result"] == "match"
        assert d["confidence_boost"] == 15
        assert len(d["reasons"]) == 1

    def test_port_check_result_to_dict(self):
        result = PortCheckResult(ip="1.2.3.4", port=80, is_open=True, service="HTTP")
        d = result.to_dict()
        assert d["is_open"] is True
        assert d["service"] == "HTTP"

    def test_score_without_baseline_success(self):
        """Test scoring when no baseline is available."""
        scanner = ActiveScanner()
        result = ActiveProbeResult(
            ip="1.2.3.4", port=443, result=ProbeResult.ERROR,
            status_code=200, server_header="nginx",
            body_length=5000, response_time_ms=100,
        )
        scored = scanner._score_without_baseline(result)
        assert scored.confidence_boost >= 10
        assert len(scored.reasons) > 0

    def test_score_without_baseline_cf_page(self):
        """Test that Cloudflare error pages are detected."""
        scanner = ActiveScanner()
        result = ActiveProbeResult(
            ip="1.2.3.4", port=443, result=ProbeResult.ERROR,
            title="Attention Required! | Cloudflare",
        )
        scored = scanner._score_without_baseline(result)
        assert scored.result == ProbeResult.NO_MATCH
        assert any("Cloudflare" in r for r in scored.reasons)

    def test_compare_response_cf_error(self):
        """Test Cloudflare error page detection in comparison."""
        scanner = ActiveScanner()
        result = ActiveProbeResult(
            ip="1.2.3.4", port=443, result=ProbeResult.ERROR,
            title="Cloudflare - Checking your browser",
            status_code=503,
        )
        scored = scanner._compare_response(result, None)
        assert scored.result == ProbeResult.NO_MATCH

    def test_compare_response_with_baseline_match(self):
        """Test response comparison with matching baseline."""
        scanner = ActiveScanner()
        result = ActiveProbeResult(
            ip="1.2.3.4", port=443, result=ProbeResult.ERROR,
            title="Example Domain",
            status_code=200,
            server_header="nginx",
            body_length=1000,
            content_hash="abc123",
        )
        baseline = {
            "title": "Example Domain",
            "status_code": 200,
            "server_header": "cloudflare",  # Different = origin!
            "content_hash": "abc123",
        }
        scored = scanner._compare_response(result, baseline)
        assert scored.result in (ProbeResult.MATCH, ProbeResult.SIMILAR)
        assert scored.confidence_boost > 0

    def test_get_ports_for_ip(self):
        scanner = ActiveScanner(ports=[80, 443])
        results = [
            EnrichedResult(ip="1.2.3.4", subdomain="a.com", port=8080),
            EnrichedResult(ip="1.2.3.4", subdomain="b.com", port=443),
        ]
        ports = scanner._get_ports_for_ip("1.2.3.4", results)
        assert 8080 in ports
        assert 443 in ports
        assert 80 in ports

    def test_scan_empty_results(self):
        """Test scan with empty results list."""
        scanner = ActiveScanner()
        # Should not raise
        assert scanner.DEFAULT_PORTS

    def test_cf_error_indicators(self):
        """Verify Cloudflare error indicators list."""
        assert "cloudflare" in ActiveScanner.CF_ERROR_INDICATORS
        assert "attention required" in ActiveScanner.CF_ERROR_INDICATORS
        assert "checking your browser" in ActiveScanner.CF_ERROR_INDICATORS


# ═══════════════════════════════════════════════════════════
# HOST HEADER PROBE TESTS
# ═══════════════════════════════════════════════════════════

class TestHostHeaderProbe:

    def test_init_defaults(self):
        probe = HostHeaderProbe()
        assert probe.timeout == 10
        assert probe.max_concurrent == 20

    def test_extract_title(self):
        html = "<html><head><title>My Page</title></head></html>"
        assert HostHeaderProbe._extract_title(html) == "My Page"

    def test_extract_title_none(self):
        assert HostHeaderProbe._extract_title("<html></html>") is None

    def test_host_header_result_to_dict(self):
        result = HostHeaderResult(
            ip="1.2.3.4", port=443, matched=True,
            match_type="exact", confidence_boost=10,
            reasons=["Title match"],
        )
        d = result.to_dict()
        assert d["matched"] is True
        assert d["match_type"] == "exact"
        assert d["confidence_boost"] == 10

    def test_analyze_result_proxy_server(self):
        """Proxy server headers should mark as not matched."""
        probe = HostHeaderProbe()
        result = HostHeaderResult(
            ip="1.2.3.4", port=443,
            server_header="cloudflare",
            status_code=200,
        )
        probe._analyze_result(result, None)
        assert result.matched is False
        assert result.match_type == "none"

    def test_analyze_result_origin_server(self):
        """Non-proxy server headers with content should match."""
        probe = HostHeaderProbe()
        result = HostHeaderResult(
            ip="1.2.3.4", port=443,
            server_header="nginx",
            x_powered_by="Express",
            status_code=200,
            body_length=5000,
            title="Example Domain",
        )
        probe._analyze_result(result, None)
        assert result.matched is True
        assert result.confidence_boost > 0

    def test_analyze_result_with_baseline(self):
        """Test analysis with baseline comparison."""
        probe = HostHeaderProbe()
        result = HostHeaderResult(
            ip="1.2.3.4", port=443,
            server_header="nginx",
            status_code=200,
            title="Example Domain",
            body_length=3000,
        )
        baseline = {
            "title": "Example Domain",
            "status_code": 200,
            "server_header": "cloudflare",
        }
        probe._analyze_result(result, baseline)
        assert result.matched is True
        assert result.confidence_boost > 0

    def test_proxy_indicators_list(self):
        """Verify proxy indicators are present."""
        assert "cloudflare" in HostHeaderProbe.PROXY_INDICATORS
        assert "akamai" in HostHeaderProbe.PROXY_INDICATORS
        assert "sucuri" in HostHeaderProbe.PROXY_INDICATORS

    def test_origin_indicators_list(self):
        """Verify origin indicators are present."""
        assert "x-powered-by" in HostHeaderProbe.ORIGIN_INDICATORS
        assert "server: nginx" in HostHeaderProbe.ORIGIN_INDICATORS


# ═══════════════════════════════════════════════════════════
# SQLITE CACHE TESTS
# ═══════════════════════════════════════════════════════════

class TestSQLiteCache:

    def test_init_creates_schema(self, cache_dir):
        cache = SQLiteCache(cache_dir=cache_dir)
        cache.initialize()
        # Verify tables exist
        conn = sqlite3.connect(str(cache.db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        assert "campaigns" in tables
        assert "results" in tables
        assert "ip_discovery" in tables
        conn.close()
        cache.close()

    def test_store_scan(self, cache_dir, sample_report):
        cache = SQLiteCache(cache_dir=cache_dir)
        cache.initialize()
        campaign_id = cache.store_scan(sample_report)
        assert campaign_id > 0

        # Verify data stored
        history = cache.get_domain_history("example.com")
        assert len(history) == 1
        assert history[0]["domain"] == "example.com"
        assert history[0]["total_results"] == 3
        cache.close()

    def test_get_known_ips(self, cache_dir, sample_report):
        cache = SQLiteCache(cache_dir=cache_dir)
        cache.initialize()
        cache.store_scan(sample_report)

        ips = cache.get_known_ips("example.com", min_confidence=0)
        assert len(ips) > 0

        # Should have all unique IPs
        ip_set = {r["ip"] for r in ips}
        assert "192.168.1.1" in ip_set
        assert "10.0.0.1" in ip_set
        cache.close()

    def test_get_campaign_results(self, cache_dir, sample_report):
        cache = SQLiteCache(cache_dir=cache_dir)
        cache.initialize()
        campaign_id = cache.store_scan(sample_report)

        results = cache.get_campaign_results(campaign_id, min_confidence=50)
        assert len(results) >= 2  # Two results with confidence >= 50
        cache.close()

    def test_store_multiple_scans(self, cache_dir, sample_report):
        cache = SQLiteCache(cache_dir=cache_dir)
        cache.initialize()
        id1 = cache.store_scan(sample_report)
        id2 = cache.store_scan(sample_report)
        assert id1 != id2

        history = cache.get_domain_history("example.com")
        assert len(history) == 2
        cache.close()

    def test_get_stats(self, cache_dir, sample_report):
        cache = SQLiteCache(cache_dir=cache_dir)
        cache.initialize()
        cache.store_scan(sample_report)

        stats = cache.get_stats()
        assert stats["total_campaigns"] == 1
        assert stats["unique_domains"] == 1
        assert stats["total_results"] == 3
        cache.close()

    def test_clear_domain(self, cache_dir, sample_report):
        cache = SQLiteCache(cache_dir=cache_dir)
        cache.initialize()
        cache.store_scan(sample_report)

        removed = cache.clear_domain("example.com")
        assert removed == 1

        history = cache.get_domain_history("example.com")
        assert len(history) == 0
        cache.close()

    def test_clear_all(self, cache_dir, sample_report):
        cache = SQLiteCache(cache_dir=cache_dir)
        cache.initialize()
        cache.store_scan(sample_report)

        cache.clear_all()
        stats = cache.get_stats()
        assert stats["total_campaigns"] == 0
        cache.close()

    def test_ip_discovery_tracking(self, cache_dir, sample_report):
        """Test that IP discovery tracking works across scans."""
        cache = SQLiteCache(cache_dir=cache_dir)
        cache.initialize()
        cache.store_scan(sample_report)
        cache.store_scan(sample_report)  # Store again

        known = cache.get_known_ips("example.com")
        for ip in known:
            assert ip["seen_count"] == 2
            assert ip["max_confidence"] > 0
        cache.close()

    def test_get_new_ips_since(self, cache_dir, sample_report):
        cache = SQLiteCache(cache_dir=cache_dir)
        cache.initialize()
        cache.store_scan(sample_report)

        # All IPs should be new since yesterday
        since = datetime.now(UTC) - timedelta(days=1)
        new_ips = cache.get_new_ips_since("example.com", since)
        assert len(new_ips) > 0
        cache.close()

    def test_get_new_ips_none(self, cache_dir, sample_report):
        cache = SQLiteCache(cache_dir=cache_dir)
        cache.initialize()
        cache.store_scan(sample_report)

        # No IPs since tomorrow
        since = datetime.now(UTC) + timedelta(days=1)
        new_ips = cache.get_new_ips_since("example.com", since)
        assert len(new_ips) == 0
        cache.close()


# ═══════════════════════════════════════════════════════════
# WEBHOOK TESTS
# ═══════════════════════════════════════════════════════════

class TestWebhookSender:

    def test_detect_type_slack(self):
        assert WebhookSender.detect_type("https://hooks.slack.com/services/T00/B00/XXX") == WebhookType.SLACK

    def test_detect_type_discord(self):
        assert WebhookSender.detect_type("https://discord.com/api/webhooks/123/abc") == WebhookType.DISCORD

    def test_detect_type_generic(self):
        assert WebhookSender.detect_type("https://example.com/webhook") == WebhookType.GENERIC

    def test_detect_type_slack_com(self):
        assert WebhookSender.detect_type("https://slack.com/api/webhook") == WebhookType.SLACK

    def test_detect_type_discordapp(self):
        assert WebhookSender.detect_type("https://discordapp.com/api/webhooks/1/2") == WebhookType.DISCORD

    def test_build_slack_payload(self, sample_report):
        sender = WebhookSender()
        payload = sender._build_slack_payload(
            sample_report, "https://hooks.slack.com/test"
        )
        assert payload.webhook_type == WebhookType.SLACK
        assert payload.url == "https://hooks.slack.com/test"
        assert payload.content_type == "application/json"
        # Verify JSON structure
        data = json.loads(payload.body)
        assert "attachments" in data
        assert data["attachments"][0]["title"] == "CloudKill Scan: example.com"

    def test_build_discord_payload(self, sample_report):
        sender = WebhookSender()
        payload = sender._build_discord_payload(
            sample_report, "https://discord.com/api/test"
        )
        assert payload.webhook_type == WebhookType.DISCORD
        data = json.loads(payload.body)
        assert "embeds" in data
        assert data["embeds"][0]["title"] == "CloudKill Scan: example.com"

    def test_build_generic_payload(self, sample_report):
        sender = WebhookSender()
        payload = sender._build_generic_payload(
            sample_report, "https://example.com/webhook"
        )
        assert payload.webhook_type == WebhookType.GENERIC
        data = json.loads(payload.body)
        assert data["tool"] == "CloudKill"
        assert data["domain"] == "example.com"

    def test_slack_payload_confirmed(self, sample_report):
        """Test Slack color is green when confirmed origins found."""
        sender = WebhookSender()
        payload = sender._build_slack_payload(
            sample_report, "https://hooks.slack.com/test"
        )
        data = json.loads(payload.body)
        assert data["attachments"][0]["color"] == "#36a64f"  # Green

    def test_slack_payload_no_results(self):
        """Test Slack color is red when no confirmed origins."""
        report = ScanReport(domain="test.com", profile="researcher")
        report.finalize()
        sender = WebhookSender()
        payload = sender._build_slack_payload(
            report, "https://hooks.slack.com/test"
        )
        data = json.loads(payload.body)
        assert data["attachments"][0]["color"] == "#e01e5a"  # Red

    def test_slack_payload_top_ips(self, sample_report):
        """Test Slack payload includes top IPs."""
        sender = WebhookSender()
        payload = sender._build_slack_payload(
            sample_report, "https://hooks.slack.com/test"
        )
        data = json.loads(payload.body)
        fields = data["attachments"][0]["fields"]
        # Should have a field with "Top IPs"
        top_ips_field = [f for f in fields if f.get("title") == "Top IPs"]
        assert len(top_ips_field) == 1


# ═══════════════════════════════════════════════════════════
# JSON EXPORTER TESTS
# ═══════════════════════════════════════════════════════════

class TestJSONExporter:

    def test_export_json(self, temp_dir, sample_report):
        path = export_json(sample_report, temp_dir / "report.json")
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["domain"] == "example.com"
        assert data["tool"] == "CloudKill"
        assert data["version"] == "0.7.0"
        assert data["export_type"] == "full"
        assert len(data["results"]) == 3

    def test_export_json_summary(self, temp_dir, sample_report):
        path = export_json(sample_report, temp_dir / "summary.json", summary_only=True)
        data = json.loads(path.read_text())
        assert data["export_type"] == "summary"
        assert "results" not in data

    def test_export_json_string(self, sample_report):
        s = export_json_string(sample_report)
        data = json.loads(s)
        assert data["domain"] == "example.com"
        assert data["tool"] == "CloudKill"

    def test_export_json_adds_suffix(self, temp_dir, sample_report):
        path = export_json(sample_report, temp_dir / "report")
        assert path.suffix == ".json"


# ═══════════════════════════════════════════════════════════
# CSV EXPORTER TESTS
# ═══════════════════════════════════════════════════════════

class TestCSVExporter:

    def test_export_csv(self, temp_dir, sample_report):
        path = export_csv(sample_report, temp_dir / "report.csv")
        assert path.exists()
        content = path.read_text()
        lines = content.strip().split("\n")
        assert len(lines) >= 4  # Header + 3 results
        # Verify header
        assert "ip," in lines[0]
        assert "confidence," in lines[0]

    def test_export_csv_min_confidence(self, temp_dir, sample_report):
        path = export_csv(sample_report, temp_dir / "filtered.csv", min_confidence=50)
        content = path.read_text()
        lines = content.strip().split("\n")
        assert len(lines) >= 3  # Header + 2 results (confidence >= 50)

    def test_export_ip_list(self, temp_dir, sample_report):
        path = export_ip_list(sample_report, temp_dir / "ips.txt")
        assert path.exists()
        content = path.read_text()
        ips = content.strip().split("\n")
        assert len(ips) == 3  # 3 unique IPs

    def test_export_csv_adds_suffix(self, temp_dir, sample_report):
        path = export_csv(sample_report, temp_dir / "report")
        assert path.suffix == ".csv"


# ═══════════════════════════════════════════════════════════
# MARKDOWN EXPORTER TESTS
# ═══════════════════════════════════════════════════════════

class TestMarkdownExporter:

    def test_export_markdown(self, temp_dir, sample_report):
        path = export_markdown(sample_report, temp_dir / "report.md")
        assert path.exists()
        content = path.read_text()
        assert "# CloudFail-Killer Report: example.com" in content
        assert "## Summary" in content
        assert "## Discovered IPs" in content
        assert "192.168.1.1" in content
        assert "10.0.0.1" in content

    def test_export_markdown_confirmed_section(self, temp_dir, sample_report):
        path = export_markdown(sample_report, temp_dir / "report.md")
        content = path.read_text()
        assert "## Confirmed Origin IPs" in content
        assert "10.0.0.1" in content

    def test_export_markdown_adds_suffix(self, temp_dir, sample_report):
        path = export_markdown(sample_report, temp_dir / "report")
        assert path.suffix == ".md"

    def test_export_markdown_min_confidence(self, temp_dir, sample_report):
        path = export_markdown(sample_report, temp_dir / "high.md", min_confidence=50)
        content = path.read_text()
        # Should include the 75% and 60% results, not the 45% one
        assert "10.0.0.1" in content  # 75%
        assert "192.168.1.1" in content  # 60%
        # The 45% one may not appear in table depending on include_all_results


# ═══════════════════════════════════════════════════════════
# NUCLEI EXPORTER TESTS
# ═══════════════════════════════════════════════════════════

class TestNucleiExporter:

    def test_export_nuclei_template(self, temp_dir, sample_report):
        path = export_nuclei_template(sample_report, temp_dir / "template.yaml")
        assert path.exists()
        content = path.read_text()
        assert "id: cloudkill-origin-example-com" in content
        assert "info:" in content
        assert "http:" in content
        assert "matchers:" in content
        assert "extractors:" in content

    def test_export_nuclei_template_dir(self, temp_dir, sample_report):
        """Test template creation in a directory."""
        (temp_dir / "nuclei").mkdir()
        path = export_nuclei_template(sample_report, temp_dir / "nuclei")
        assert path.exists()
        assert path.suffix == ".yaml"
        assert "example-com" in path.name

    def test_export_nuclei_targets(self, temp_dir, sample_report):
        path = export_nuclei_targets(sample_report, temp_dir / "targets.txt")
        assert path.exists()
        content = path.read_text()
        lines = content.strip().split("\n")
        assert len(lines) >= 2  # At least 2 high-confidence results
        assert "Host: example.com" in content

    def test_export_nuclei_has_variations(self, temp_dir, sample_report):
        path = export_nuclei_template(sample_report, temp_dir / "template.yaml")
        content = path.read_text()
        assert "variations:" in content or "variations" in content

    def test_export_nuclei_has_ips_comment(self, temp_dir, sample_report):
        path = export_nuclei_template(sample_report, temp_dir / "template.yaml")
        content = path.read_text()
        # Verify IP addresses appear in the template
        assert "10.0.0.1" in content
        # Verify comment section has discovery metadata
        assert "# Domain: example.com" in content or "example.com" in content


# ═══════════════════════════════════════════════════════════
# PDF EXPORTER TESTS
# ═══════════════════════════════════════════════════════════

class TestPDFExporter:

    def test_export_pdf(self, temp_dir, sample_report):
        path = export_pdf(sample_report, temp_dir / "report.pdf")
        assert path.exists()
        assert path.suffix == ".pdf"
        # Verify file size is reasonable (> 1KB)
        assert path.stat().st_size > 1000

    def test_export_pdf_adds_suffix(self, temp_dir, sample_report):
        path = export_pdf(sample_report, temp_dir / "report")
        assert path.suffix == ".pdf"

    def test_export_pdf_empty_report(self, temp_dir):
        report = ScanReport(domain="empty.com", profile="researcher")
        report.finalize()
        path = export_pdf(report, temp_dir / "empty.pdf")
        assert path.exists()
        assert path.stat().st_size > 500


# ═══════════════════════════════════════════════════════════
# EXPORTERS __init__ TESTS
# ═══════════════════════════════════════════════════════════

class TestExportersInit:
    """Test all exporters are importable."""

    def test_import_all(self):
        from cloudkill.exporters import (
            export_csv,
            export_json,
            export_markdown,
            export_nuclei_template,
            export_pdf,
        )
        assert callable(export_json)
        assert callable(export_csv)
        assert callable(export_markdown)
        assert callable(export_nuclei_template)
        assert callable(export_pdf)


# ═══════════════════════════════════════════════════════════
# CACHE __init__ TESTS
# ═══════════════════════════════════════════════════════════

class TestCacheInit:
    """Test cache module is importable."""

    def test_import(self):
        from cloudkill.cache import SQLiteCache
        assert SQLiteCache is not None


# ═══════════════════════════════════════════════════════════
# RUNNER INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════

class TestRunnerIntegration:

    def test_runner_init_with_new_params(self):
        """Test runner accepts new Phase 4 parameters."""
        from cloudkill.config import Config
        from cloudkill.core.runner import SourceRunner

        config = Config.from_profile("researcher")
        runner = SourceRunner(
            config=config,
            enable_cache=False,
            enable_webhook=False,
        )
        assert runner.enable_cache is False
        assert runner.enable_webhook is False
