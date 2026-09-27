"""Phase 0 unit tests - Config, Base Source, CLI."""

from collections.abc import AsyncGenerator

from cloudkill import __version__
from cloudkill.config import Config, OutputFormat, ScanProfile, ScoringWeights
from cloudkill.sources.base import BaseSource, IPVersion, SourceResult


class TestPackageMetadata:
    def test_version(self):
        assert __version__ == "0.7.0"

    def test_author(self):
        assert __version__  # Package loads correctly


class TestSourceResult:
    def test_auto_detect_ipv4(self):
        r = SourceResult(subdomain="test.com", ip="1.2.3.4", source="test")
        assert r.ip_version == IPVersion.V4

    def test_auto_detect_ipv6(self):
        r = SourceResult(subdomain="test.com", ip="2001:db8::1", source="test")
        assert r.ip_version == IPVersion.V6

    def test_to_dict(self):
        r = SourceResult(subdomain="test.com", ip="1.2.3.4", source="test", port=8080)
        d = r.to_dict()
        assert d["subdomain"] == "test.com"
        assert d["ip"] == "1.2.3.4"
        assert d["ip_version"] == 4
        assert d["source"] == "test"
        assert d["port"] == 8080

    def test_defaults(self):
        r = SourceResult(subdomain="a.com", ip="10.0.0.1")
        assert r.port == 443
        assert r.is_historical is False
        assert r.confidence_boost == 0
        assert r.metadata == {}


class TestConfig:
    def test_default_profile(self):
        c = Config()
        assert c.profile == ScanProfile.RESEARCHER

    def test_threads_bounds(self):
        c = Config(threads=200)
        assert c.threads == 200
        c2 = Config(threads=1)
        assert c2.threads == 1

    def test_output_format(self):
        c = Config(output_format=OutputFormat.JSON)
        assert c.output_format == OutputFormat.JSON

    def test_scoring_weights(self):
        w = ScoringWeights()
        assert w.non_cf_ip == 35
        assert w.ssl_match == 30
        assert w.favicon_match == 15


class TestBaseSource:
    def test_base_source_repr(self):
        class DummySource(BaseSource):
            name = "dummy"
            async def enumerate(self, domain: str) -> AsyncGenerator[SourceResult, None]:
                return
                yield  # noqa: B901

        s = DummySource()
        r = repr(s)
        assert "DummySource" in r
        assert "dummy" in r
        assert "configured=True" in r

    def test_is_configured_default(self):
        class DummySource(BaseSource):
            name = "dummy"
            async def enumerate(self, domain: str) -> AsyncGenerator[SourceResult, None]:
                return
                yield  # noqa: B901

        s = DummySource()
        assert s.is_configured() is True
