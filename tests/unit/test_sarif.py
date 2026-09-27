"""Tests for cloudkill.exporters.sarif_export — SARIF 2.1.0 output."""

from __future__ import annotations

import json

import pytest

from cloudkill.core.models import EnrichedResult
from cloudkill.exporters.sarif_export import export_sarif, report_to_sarif


@pytest.fixture()
def report():
    from cloudkill.core.models import ScanReport

    r = ScanReport(domain="example.com", profile="pentester")
    high = EnrichedResult(
        subdomain="direct.example.com", ip="198.51.100.10", source="crtsh",
        confidence=85, hosting_provider="OVH", asn_org="OVH SAS",
        confidence_reasons=["ssl match", "not cloudflare"],
    )
    mid = EnrichedResult(
        subdomain="www.example.com", ip="198.51.100.20", source="otx", confidence=60,
    )
    low = EnrichedResult(
        subdomain="old.example.com", ip="198.51.100.30", source="wayback", confidence=20,
    )
    r.add_result(high)
    r.add_result(mid)
    r.add_result(low)
    r.finalize()
    return r


class TestSarifStructure:
    def test_valid_sarif_skeleton(self, report):
        sarif = report_to_sarif(report)
        assert sarif["version"] == "2.1.0"
        assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "CloudKill"
        assert run["tool"]["driver"]["rules"][0]["id"] == "origin-discovered"

    def test_one_result_per_finding(self, report):
        sarif = report_to_sarif(report)
        assert len(sarif["runs"][0]["results"]) == 3

    def test_confidence_maps_to_level(self, report):
        sarif = report_to_sarif(report)
        levels = {res["properties"]["confidence"]: res["level"]
                  for res in sarif["runs"][0]["results"]}
        assert levels[85] == "error"
        assert levels[60] == "warning"
        assert levels[20] == "note"

    def test_fingerprint_stable(self, report):
        sarif = report_to_sarif(report)
        fp = sarif["runs"][0]["results"][0]["partialFingerprints"]
        assert fp["originHostPort/v1"] == "direct.example.com:198.51.100.10:443"


class TestSarifExportFile:
    def test_export_writes_sarif_extension(self, report, tmp_path):
        saved = export_sarif(report, tmp_path / "report")
        assert saved.suffix == ".sarif"
        data = json.loads(saved.read_text())
        assert data["version"] == "2.1.0"

    def test_export_valid_json_roundtrip(self, report, tmp_path):
        saved = export_sarif(report, tmp_path / "report.sarif")
        parsed = json.loads(saved.read_text())
        expected = report_to_sarif(report)
        # invocation timestamp is wall-clock — excluded from equality
        expected["runs"][0]["invocations"] = parsed["runs"][0]["invocations"]
        assert parsed == expected
