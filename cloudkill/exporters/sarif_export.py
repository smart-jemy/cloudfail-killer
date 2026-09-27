"""
CloudFail-Killer — SARIF Exporter

Export scan results as SARIF v2.1.0 so origin-discovery findings show up
directly in GitHub Security tab, VS Code, and any SARIF-capable pipeline.

Level mapping (from confidence score):
    confidence >= 80  -> "error"   (high-confidence origin candidate)
    confidence >= 50  -> "warning"
    confidence <  50  -> "note"
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from cloudkill import __version__
from cloudkill.core.models import ScanReport
from cloudkill.core.validator import safe_output_path

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def _level_for(confidence: int) -> str:
    if confidence >= 80:
        return "error"
    if confidence >= 50:
        return "warning"
    return "note"


def report_to_sarif(report: ScanReport) -> dict:
    """Build a SARIF 2.1.0 log dict from a ScanReport."""
    results = []
    for r in report.results:
        uri = (r.subdomain or report.domain or "target").lower()
        results.append({
            "ruleId": "origin-discovered",
            "level": _level_for(r.confidence),
            "message": {
                "text": (
                    f"Origin candidate {r.ip}:{r.port} for {r.subdomain} "
                    f"(confidence {r.confidence}/100, source: {r.source})"
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                },
                "logicalLocations": [{"name": r.subdomain, "fullyQualifiedName": f"{r.subdomain}:{r.port}"}],
            }],
            "partialFingerprints": {"originHostPort/v1": f"{r.subdomain}:{r.ip}:{r.port}"},
            "properties": {
                "ip": r.ip,
                "confidence": r.confidence,
                "source": r.source,
                "hostingProvider": r.hosting_provider,
                "asnOrg": r.asn_org,
                "isCloudflare": r.is_cloudflare,
                "reasons": r.confidence_reasons,
            },
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CloudKill",
                    "version": __version__,
                    "informationUri": "https://github.com/smart-jemy/cloudfail-killer",
                    "rules": [{
                        "id": "origin-discovered",
                        "name": "OriginDiscovered",
                        "shortDescription": {
                            "text": "A potential origin server IP behind Cloudflare was discovered."
                        },
                        "defaultConfiguration": {"level": "warning"},
                        "properties": {"tags": ["security", "reconnaissance", "cloudflare"]},
                    }],
                }
            },
            "originalUriBaseIds": {
                "%SRCROOT%": {"uri": "https://" + (report.domain or "target") + "/"}
            },
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(UTC).isoformat(),
            }],
            "results": results,
        }],
    }


def export_sarif(report: ScanReport, output_path: Path | str) -> Path:
    """
    Export scan report to SARIF 2.1.0 JSON.

    Returns:
        Path to the exported file
    """
    output_path = safe_output_path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.suffix.lower() not in (".sarif", ".json"):
        output_path = output_path.with_suffix(".sarif")
    output_path.write_text(json.dumps(report_to_sarif(report), indent=2))
    return output_path
