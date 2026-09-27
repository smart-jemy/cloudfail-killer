"""
CloudFail-Killer - JSON Exporter

Export scan results to JSON format with full detail or summary modes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from cloudkill import __version__
from cloudkill.core.models import ScanReport
from cloudkill.core.validator import safe_output_path


def export_json(
    report: ScanReport,
    output_path: Path | str,
    indent: int = 2,
    summary_only: bool = False,
) -> Path:
    """
    Export scan report to JSON file.

    Args:
        report: ScanReport to export
        output_path: Output file path
        indent: JSON indentation level
        summary_only: If True, export summary without individual results

    Returns:
        Path to the exported file
    """
    output_path = safe_output_path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.suffix != ".json":
        output_path = output_path.with_suffix(".json")

    data = report.to_dict()

    if summary_only:
        # Remove individual results, keep summary only
        data.pop("results", None)
        data["export_type"] = "summary"
    else:
        data["export_type"] = "full"

    data["exported_at"] = datetime.now(UTC).isoformat()
    data["tool"] = "CloudKill"
    data["version"] = __version__

    output_path.write_text(
        json.dumps(data, indent=indent, ensure_ascii=False),
        encoding="utf-8",
    )

    return output_path


def export_json_string(report: ScanReport) -> str:
    """Export scan report as JSON string."""
    data = report.to_dict()
    data["exported_at"] = datetime.now(UTC).isoformat()
    data["tool"] = "CloudKill"
    data["version"] = __version__
    return json.dumps(data, indent=2, ensure_ascii=False)
