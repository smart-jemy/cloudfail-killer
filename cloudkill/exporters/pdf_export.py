"""
CloudFail-Killer - PDF Exporter

Generate professional PDF scan reports using ReportLab.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cloudkill import __author__, __version__
from cloudkill.core.models import ScanReport
from cloudkill.core.validator import safe_output_path


def export_pdf(
    report: ScanReport,
    output_path: Path | str,
    include_all_results: bool = True,
    min_confidence: int = 0,
) -> Path:
    """
    Export scan report to PDF file.

    Uses a simple approach with ReportLab for guaranteed rendering.

    Args:
        report: ScanReport to export
        output_path: Output file path
        include_all_results: Include all results (not just high-confidence)
        min_confidence: Minimum confidence threshold

    Returns:
        Path to the exported file
    """
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm, inch
    from reportlab.platypus import (
        HRFlowable,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    output_path = safe_output_path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.suffix != ".pdf":
        output_path = output_path.with_suffix(".pdf")

    # Register fonts — use built-in ReportLab fonts for cross-platform compatibility
    # Built-in ReportLab fonts for cross-platform compatibility
    font = 'Helvetica'
    font_bold = 'Helvetica-Bold'

    # Create document
    title_meta = os.path.splitext(os.path.basename(str(output_path)))[0]
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        title=title_meta,
        author=__author__,
        creator='CloudKill',
        subject=f'CloudFail-Killer scan report for {report.domain}',
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    cover_title_style = ParagraphStyle(
        name='CoverTitle',
        fontName=font_bold,
        fontSize=36,
        leading=44,
        alignment=TA_CENTER,
        spaceAfter=20,
    )

    cover_subtitle_style = ParagraphStyle(
        name='CoverSubtitle',
        fontName=font,
        fontSize=18,
        leading=24,
        alignment=TA_CENTER,
        spaceAfter=12,
    )

    cover_info_style = ParagraphStyle(
        name='CoverInfo',
        fontName=font,
        fontSize=12,
        leading=18,
        alignment=TA_CENTER,
        spaceAfter=6,
    )

    heading1_style = ParagraphStyle(
        name='Heading1Custom',
        fontName=font_bold,
        fontSize=18,
        leading=24,
        alignment=TA_LEFT,
        spaceBefore=18,
        spaceAfter=12,
        textColor=colors.HexColor('#1F4E79'),
    )

    heading2_style = ParagraphStyle(
        name='Heading2Custom',
        fontName=font_bold,
        fontSize=14,
        leading=20,
        alignment=TA_LEFT,
        spaceBefore=12,
        spaceAfter=8,
        textColor=colors.HexColor('#2E75B6'),
    )

    body_style = ParagraphStyle(
        name='BodyCustom',
        fontName=font,
        fontSize=10,
        leading=16,
        alignment=TA_JUSTIFY,
        spaceAfter=6,
    )

    table_header_style = ParagraphStyle(
        name='TableHeader',
        fontName=font_bold,
        fontSize=9,
        textColor=colors.white,
        alignment=TA_CENTER,
    )

    table_cell_style = ParagraphStyle(
        name='TableCell',
        fontName=font,
        fontSize=8,
        textColor=colors.black,
        alignment=TA_CENTER,
    )

    table_cell_left = ParagraphStyle(
        name='TableCellLeft',
        fontName=font,
        fontSize=8,
        textColor=colors.black,
        alignment=TA_LEFT,
    )

    # Build story
    story: list[Any] = []

    # Cover page
    story.append(Spacer(1, 120))
    story.append(Paragraph('<b>CloudFail-Killer</b>', cover_title_style))
    story.append(Spacer(1, 20))
    story.append(Paragraph('<b>Origin IP Discovery Report</b>', cover_subtitle_style))
    story.append(Spacer(1, 48))
    story.append(Paragraph(f'<b>Target:</b> {report.domain}', cover_info_style))
    story.append(Paragraph(f'<b>Profile:</b> {report.profile}', cover_info_style))
    story.append(Spacer(1, 24))
    story.append(Paragraph(f'<b>Date:</b> {report.completed_at or "N/A"}', cover_info_style))
    story.append(Paragraph(f'<b>Version:</b> CloudKill v{__version__}', cover_info_style))
    story.append(PageBreak())

    # Summary Section
    story.append(Paragraph('<b>1. Executive Summary</b>', heading1_style))
    story.append(Spacer(1, 6))

    summary_text = (
        f"This report presents the findings from an automated origin IP discovery scan "
        f"targeting <b>{report.domain}</b>. The scan was conducted using the CloudFail-Killer "
        f"tool with the <b>{report.profile}</b> profile. A total of <b>{report.total_results}</b> "
        f"potential origin IP addresses were identified, of which <b>{report.report.unique_ips if hasattr(report, 'report') else report.unique_ips}</b> "
        f"are unique. <b>{report.confirmed_count}</b> IPs were classified as confirmed origins "
        f"with high confidence, while <b>{report.high_confidence_count}</b> scored above 70% "
        f"on the confidence scale. The scan completed in {report.scan_duration_seconds:.1f} seconds "
        f"utilizing {len(report.sources_used)} data sources."
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 12))

    # Summary metrics table
    table_header_color = colors.HexColor('#1F4E79')
    table_row_odd = colors.HexColor('#F5F5F5')

    summary_data = [
        [Paragraph('<b>Metric</b>', table_header_style),
         Paragraph('<b>Value</b>', table_header_style)],
        [Paragraph('Domain', table_cell_style),
         Paragraph(report.domain, table_cell_style)],
        [Paragraph('Profile', table_cell_style),
         Paragraph(report.profile, table_cell_style)],
        [Paragraph('Duration', table_cell_style),
         Paragraph(f'{report.scan_duration_seconds:.1f}s', table_cell_style)],
        [Paragraph('Total Results', table_cell_style),
         Paragraph(str(report.total_results), table_cell_style)],
        [Paragraph('Unique IPs', table_cell_style),
         Paragraph(str(report.unique_ips), table_cell_style)],
        [Paragraph('Confirmed Origins', table_cell_style),
         Paragraph(str(report.confirmed_count), table_cell_style)],
        [Paragraph('High Confidence (>=70)', table_cell_style),
         Paragraph(str(report.high_confidence_count), table_cell_style)],
        [Paragraph('IPv4 / IPv6', table_cell_style),
         Paragraph(f'{report.ipv4_count} / {report.ipv6_count}', table_cell_style)],
        [Paragraph('CF Filtered', table_cell_style),
         Paragraph(str(report.cloudflare_filtered), table_cell_style)],
        [Paragraph('Sources', table_cell_style),
         Paragraph(', '.join(report.sources_used) or 'None', table_cell_left)],
    ]

    summary_table = Table(summary_data, colWidths=[3 * inch, 4 * inch])
    style_cmds = [
        ('BACKGROUND', (0, 0), (-1, 0), table_header_color),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]
    # Add alternating row colors
    for i in range(1, len(summary_data)):
        if i % 2 == 0:
            style_cmds.append(('BACKGROUND', (0, i), (-1, i), table_row_odd))

    summary_table.setStyle(TableStyle(style_cmds))
    story.append(Spacer(1, 18))
    story.append(summary_table)
    story.append(Spacer(1, 18))

    # Enrichment stats
    if report.enrichment_stats:
        story.append(Paragraph('<b>2. Enrichment Pipeline Results</b>', heading1_style))
        story.append(Spacer(1, 6))

        enrich_text = (
            "The enrichment pipeline applied multiple intelligence stages to the raw results, "
            "including SSL certificate validation, ASN/hosting provider identification, "
            "confidence scoring, false positive filtering, and deduplication. "
            "The following table summarizes the outcomes of each enrichment stage."
        )
        story.append(Paragraph(enrich_text, body_style))
        story.append(Spacer(1, 12))

        stats = report.enrichment_stats
        enrich_data = [
            [Paragraph('<b>Stage</b>', table_header_style),
             Paragraph('<b>Result</b>', table_header_style)],
            [Paragraph('SSL Certificates Checked', table_cell_left),
             Paragraph(str(stats.get('ssl_checked', 'N/A')), table_cell_style)],
            [Paragraph('SSL Matches Found', table_cell_left),
             Paragraph(str(stats.get('ssl_matched', 'N/A')), table_cell_style)],
            [Paragraph('ASN Lookups Performed', table_cell_left),
             Paragraph(str(stats.get('asn_lookups', 'N/A')), table_cell_style)],
            [Paragraph('Hosting Providers Found', table_cell_left),
             Paragraph(str(stats.get('asn_hosting_found', 'N/A')), table_cell_style)],
            [Paragraph('False Positives Filtered', table_cell_left),
             Paragraph(str(stats.get('fp_filtered', 'N/A')), table_cell_style)],
            [Paragraph('Duplicates Removed', table_cell_left),
             Paragraph(str(stats.get('duplicates_removed', 'N/A')), table_cell_style)],
            [Paragraph('Confirmed Origins', table_cell_left),
             Paragraph(str(stats.get('confirmed_count', 'N/A')), table_cell_style)],
            [Paragraph('Pipeline Duration', table_cell_left),
             Paragraph(str(stats.get('enrichment_duration', 'N/A')), table_cell_style)],
        ]

        enrich_table = Table(enrich_data, colWidths=[4 * inch, 3 * inch])
        enrich_cmds = [
            ('BACKGROUND', (0, 0), (-1, 0), table_header_color),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]
        for i in range(1, len(enrich_data)):
            if i % 2 == 0:
                enrich_cmds.append(('BACKGROUND', (0, i), (-1, i), table_row_odd))
        enrich_table.setStyle(TableStyle(enrich_cmds))

        story.append(Spacer(1, 18))
        story.append(enrich_table)
        story.append(Spacer(1, 18))

    # Results table
    section_num = "3" if report.enrichment_stats else "2"
    story.append(Paragraph(f'<b>{section_num}. Discovered IP Addresses</b>', heading1_style))
    story.append(Spacer(1, 6))

    results = [r for r in report.results if r.confidence >= min_confidence]
    results.sort(key=lambda r: -r.confidence)

    if not results:
        story.append(Paragraph("No results found meeting the confidence threshold.", body_style))
    else:
        results_text = (
            f"The following table lists all discovered IP addresses with a confidence "
            f"score of {min_confidence}% or higher. IPs are sorted by confidence in "
            f"descending order. Confirmed origins are those that passed multiple "
            f"verification stages including SSL certificate matching, hosting provider "
            f"identification, and false positive filtering."
        )
        story.append(Paragraph(results_text, body_style))
        story.append(Spacer(1, 12))

        # Limit display to top results
        display_results = results if include_all_results else [
            r for r in results if r.confidence >= 50
        ][:30]

        result_data = [
            [Paragraph('<b>IP</b>', table_header_style),
             Paragraph('<b>Port</b>', table_header_style),
             Paragraph('<b>Confidence</b>', table_header_style),
             Paragraph('<b>Status</b>', table_header_style),
             Paragraph('<b>Source</b>', table_header_style),
             Paragraph('<b>Provider</b>', table_header_style),
             ]
        ]

        for r in display_results:
            provider = (r.hosting_provider or r.asn_org or "-")[:20]
            result_data.append([
                Paragraph(r.ip, table_cell_left),
                Paragraph(str(r.port), table_cell_style),
                Paragraph(f'{r.confidence}%', table_cell_style),
                Paragraph(r.status.value.upper(), table_cell_style),
                Paragraph(r.source, table_cell_style),
                Paragraph(provider, table_cell_left),
            ])

        result_table = Table(result_data, colWidths=[1.8*inch, 0.5*inch, 0.9*inch, 0.9*inch, 1*inch, 1.9*inch])
        r_cmds = [
            ('BACKGROUND', (0, 0), (-1, 0), table_header_color),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]
        for i in range(1, len(result_data)):
            if i % 2 == 0:
                r_cmds.append(('BACKGROUND', (0, i), (-1, i), table_row_odd))
        result_table.setStyle(TableStyle(r_cmds))

        story.append(Spacer(1, 18))
        story.append(result_table)
        story.append(Spacer(1, 18))

        if len(results) > len(display_results):
            remaining = len(results) - len(display_results)
            story.append(Paragraph(
                f"<i>... and {remaining} more results (see full JSON export for details)</i>",
                body_style,
            ))

    # Errors section
    if report.errors:
        story.append(Spacer(1, 12))
        story.append(Paragraph('<b>Errors</b>', heading2_style))
        for err in report.errors[:10]:
            story.append(Paragraph(f"- {err}", body_style))

    # Footer
    story.append(Spacer(1, 24))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"<i>Generated by CloudKill v{__version__} on {datetime.now(UTC).isoformat()}</i>",
        ParagraphStyle(name='Footer', fontName=font, fontSize=8,
                       alignment=TA_CENTER, textColor=colors.grey),
    ))

    # Build PDF
    doc.build(story)
    return output_path
