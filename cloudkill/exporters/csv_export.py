"""
CloudFail-Killer - CSV Exporter

Export scan results to CSV format for spreadsheet analysis.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

from cloudkill.core.models import ScanReport
from cloudkill.core.validator import safe_output_path

# CSV column headers
CSV_HEADERS = [
    "ip",
    "ip_version",
    "subdomain",
    "source",
    "port",
    "confidence",
    "status",
    "ssl_matches",
    "ssl_cn",
    "ssl_issuer",
    "asn_number",
    "asn_org",
    "asn_country",
    "hosting_provider",
    "is_hosting",
    "is_cloudflare",
    "is_historical",
    "favicon_hash",
    "host_header_match",
    "discovered_at",
]


def export_csv(
    report: ScanReport,
    output_path: Path | str,
    include_header: bool = True,
    min_confidence: int = 0,
) -> Path:
    """
    Export scan report to CSV file.

    Args:
        report: ScanReport to export
        output_path: Output file path
        include_header: Include CSV header row
        min_confidence: Minimum confidence threshold

    Returns:
        Path to the exported file
    """
    output_path = safe_output_path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.suffix != ".csv":
        output_path = output_path.with_suffix(".csv")

    results = [
        r for r in report.results if r.confidence >= min_confidence
    ]
    results.sort(key=lambda r: -r.confidence)

    buffer = io.StringIO()
    writer = csv.writer(buffer)

    if include_header:
        writer.writerow(CSV_HEADERS)

    for r in results:
        writer.writerow([
            r.ip,
            r.ip_version.value,
            r.subdomain,
            r.source,
            r.port,
            r.confidence,
            r.status.value,
            int(r.ssl_matches),
            r.ssl_cn or "",
            r.ssl_issuer or "",
            r.asn_number or "",
            r.asn_org or "",
            r.asn_country or "",
            r.hosting_provider or "",
            int(r.is_hosting),
            int(r.is_cloudflare),
            int(r.is_historical),
            r.favicon_hash or "",
            int(r.host_header_match),
            r.discovered_at.isoformat() if r.discovered_at else "",
        ])

    output_path.write_text(buffer.getvalue(), encoding="utf-8", newline="")
    return output_path


def export_ip_list(report: ScanReport, output_path: Path | str) -> Path:
    """
    Export only unique IP addresses (one per line).

    Args:
        report: ScanReport to export
        output_path: Output file path

    Returns:
        Path to the exported file
    """
    output_path = safe_output_path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    unique_ips = sorted({r.ip for r in report.results}, key=lambda ip: ip)

    output_path.write_text("\n".join(unique_ips) + "\n", encoding="utf-8")
    return output_path
