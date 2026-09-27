"""
CloudFail-Killer - Markdown Exporter

Export scan results to Markdown format for documentation and reporting.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cloudkill import __version__
from cloudkill.core.models import ScanReport
from cloudkill.core.validator import safe_output_path


def export_markdown(
    report: ScanReport,
    output_path: Path | str,
    include_all_results: bool = True,
    min_confidence: int = 0,
) -> Path:
    """
    Export scan report to Markdown file.

    Args:
        report: ScanReport to export
        output_path: Output file path
        include_all_results: Include all results (not just high-confidence)
        min_confidence: Minimum confidence threshold

    Returns:
        Path to the exported file
    """
    output_path = safe_output_path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.suffix != ".md":
        output_path = output_path.with_suffix(".md")

    lines: list[str] = []

    # Header
    lines.append(f"# CloudFail-Killer Report: {report.domain}")
    lines.append("")
    lines.append(f"**Date:** {report.completed_at or 'N/A'}")
    lines.append(f"**Profile:** {report.profile}")
    lines.append(f"**Version:** CloudKill v{__version__}")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| **Duration** | {report.scan_duration_seconds:.1f}s |")
    lines.append(f"| **Total Results** | {report.total_results} |")
    lines.append(f"| **Unique IPs** | {report.unique_ips} |")
    lines.append(f"| **Confirmed** | {report.confirmed_count} |")
    lines.append(f"| **High Confidence (>=70)** | {report.high_confidence_count} |")
    lines.append(f"| **IPv4** | {report.ipv4_count} |")
    lines.append(f"| **IPv6** | {report.ipv6_count} |")
    lines.append(f"| **CF Filtered** | {report.cloudflare_filtered} |")
    lines.append(f"| **Sources Used** | {', '.join(report.sources_used) or 'None'} |")
    lines.append("")

    # Enrichment stats
    if report.enrichment_stats:
        lines.append("## Enrichment Pipeline")
        lines.append("")
        stats = report.enrichment_stats
        lines.append("| Stage | Result |")
        lines.append("|-------|--------|")
        lines.append(f"| **SSL Checked** | {stats.get('ssl_checked', 'N/A')} |")
        lines.append(f"| **SSL Matched** | {stats.get('ssl_matched', 'N/A')} |")
        lines.append(f"| **ASN Lookups** | {stats.get('asn_lookups', 'N/A')} |")
        lines.append(f"| **Hosting Found** | {stats.get('asn_hosting_found', 'N/A')} |")
        lines.append(f"| **FP Filtered** | {stats.get('fp_filtered', 'N/A')} |")
        lines.append(f"| **Duplicates Removed** | {stats.get('duplicates_removed', 'N/A')} |")
        lines.append(f"| **Confirmed** | {stats.get('confirmed_count', 'N/A')} |")
        lines.append(f"| **Potential** | {stats.get('potential_count', 'N/A')} |")
        lines.append(f"| **Duration** | {stats.get('enrichment_duration', 'N/A')} |")
        lines.append("")

    # Results table
    lines.append("## Discovered IPs")
    lines.append("")

    results = [
        r for r in report.results if r.confidence >= min_confidence
    ]
    results.sort(key=lambda r: -r.confidence)

    if not results:
        lines.append("*No results found.*")
        lines.append("")
    else:
        lines.append(
            "| IP | Subdomain | Source | Port | Confidence | Status | Provider |"
        )
        lines.append(
            "|-----|-----------|--------|------|------------|--------|----------|"
        )

        for r in results:
            status = r.status.value.upper()
            provider = r.hosting_provider or r.asn_org or "-"
            ssl_badge = " [SSL]" if r.ssl_matches else ""

            if not include_all_results and r.confidence < 50:
                continue

            lines.append(
                f"| `{r.ip}` | {r.subdomain} | {r.source} | "
                f"{r.port} | **{r.confidence}%**{ssl_badge} | "
                f"{status} | {provider} |"
            )
        lines.append("")

    # Confirmed origins detail
    confirmed = [r for r in results if r.status.value == "confirmed"]
    if confirmed:
        lines.append("## Confirmed Origin IPs")
        lines.append("")
        for r in confirmed:
            lines.append(f"### `{r.ip}` (Port {r.port})")
            lines.append("")
            lines.append(f"- **Source:** {r.source}")
            lines.append(f"- **Confidence:** {r.confidence}%")
            if r.ssl_cn:
                lines.append(f"- **SSL CN:** {r.ssl_cn}")
            if r.hosting_provider:
                lines.append(f"- **Hosting:** {r.hosting_provider}")
            if r.asn_org:
                lines.append(f"- **ASN Org:** {r.asn_org}")
            if r.confidence_reasons:
                lines.append(f"- **Reasons:** {'; '.join(r.confidence_reasons[:3])}")
            lines.append("")

    # Errors
    if report.errors:
        lines.append("## Errors")
        lines.append("")
        for err in report.errors:
            lines.append(f"- {err}")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append(f"*Generated by CloudFail-Killer v{__version__} on {datetime.now(UTC).isoformat()}*")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path
