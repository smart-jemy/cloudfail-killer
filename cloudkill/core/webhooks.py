"""
CloudFail-Killer - Webhook Notifications

Send scan results and notifications to external services.
Supports Slack, Discord, and generic webhooks.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

import httpx

from cloudkill import __version__
from cloudkill.core.models import ScanReport

logger = logging.getLogger(__name__)


class WebhookType(str, Enum):
    """Supported webhook destination types."""
    SLACK = "slack"
    DISCORD = "discord"
    GENERIC = "generic"
    AUTO = "auto"  # Auto-detect from URL


@dataclass
class WebhookPayload:
    """Prepared webhook payload for sending."""
    url: str
    webhook_type: WebhookType
    headers: dict[str, str] = field(default_factory=dict)
    body: str | bytes = ""
    content_type: str = "application/json"


class WebhookSender:
    """
    Multi-platform webhook notification sender.

    Supports Slack, Discord, and generic webhook endpoints.
    Auto-detects the platform from the URL pattern.

    Usage:
        sender = WebhookSender(timeout=10)
        await sender.send(report, "https://hooks.slack.com/services/...")
        await sender.send_all(report, slack_url=..., discord_url=...)
    """

    SLACK_DOMAINS = {"hooks.slack.com", "slack.com"}
    DISCORD_DOMAINS = {"discord.com", "discordapp.com"}

    def __init__(
        self,
        timeout: int = 15,
        proxy: str | None = None,
    ) -> None:
        self.timeout = timeout
        self.proxy = proxy

    @classmethod
    def detect_type(cls, url: str) -> WebhookType:
        """Auto-detect webhook type from URL."""
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
            for slack_domain in cls.SLACK_DOMAINS:
                if slack_domain in domain:
                    return WebhookType.SLACK
            for discord_domain in cls.DISCORD_DOMAINS:
                if discord_domain in domain:
                    return WebhookType.DISCORD
        except Exception:
            pass
        return WebhookType.GENERIC

    async def send(
        self,
        report: ScanReport,
        url: str,
        webhook_type: WebhookType | None = None,
    ) -> bool:
        """
        Send a webhook notification with scan results.

        Args:
            report: ScanReport to send
            url: Webhook URL
            webhook_type: Force specific type (auto-detect if None)

        Returns:
            True if sent successfully
        """
        if webhook_type == WebhookType.AUTO or webhook_type is None:
            webhook_type = self.detect_type(url)

        try:
            payload = self._build_payload(report, url, webhook_type)

            async with httpx.AsyncClient(
                timeout=self.timeout,
                proxy=self.proxy,
            ) as client:
                response = await client.post(
                    payload.url,
                    content=payload.body,
                    headers=payload.headers,
                )

            if response.status_code in (200, 201, 204):
                logger.info(
                    "Webhook sent successfully to %s (status=%d)",
                    payload.url, response.status_code,
                )
                return True
            else:
                logger.warning(
                    "Webhook failed: %s returned status %d: %s",
                    payload.url, response.status_code, response.text[:200],
                )
                return False

        except Exception as e:
            logger.error("Webhook send error: %s", e)
            return False

    async def send_all(
        self,
        report: ScanReport,
        slack_url: str | None = None,
        discord_url: str | None = None,
        generic_url: str | None = None,
    ) -> dict[str, bool]:
        """
        Send notifications to multiple webhook endpoints.

        Args:
            report: ScanReport to send
            slack_url: Slack webhook URL
            discord_url: Discord webhook URL
            generic_url: Generic webhook URL

        Returns:
            Dictionary mapping platform to success status
        """
        results: dict[str, bool] = {}

        tasks = []
        if slack_url:
            tasks.append(("slack", self.send(report, slack_url, WebhookType.SLACK)))
        if discord_url:
            tasks.append(("discord", self.send(report, discord_url, WebhookType.DISCORD)))
        if generic_url:
            tasks.append(("generic", self.send(report, generic_url, WebhookType.GENERIC)))

        for name, task in tasks:
            try:
                results[name] = await task
            except Exception as e:
                logger.error("Webhook %s error: %s", name, e)
                results[name] = False

        return results

    def _build_payload(
        self,
        report: ScanReport,
        url: str,
        webhook_type: WebhookType,
    ) -> WebhookPayload:
        """Build the webhook payload based on platform type."""
        if webhook_type == WebhookType.SLACK:
            return self._build_slack_payload(report, url)
        elif webhook_type == WebhookType.DISCORD:
            return self._build_discord_payload(report, url)
        else:
            return self._build_generic_payload(report, url)

    def _build_slack_payload(self, report: ScanReport, url: str) -> WebhookPayload:
        """Build Slack webhook payload."""
        # Determine color based on results
        if report.confirmed_count > 0:
            color = "#36a64f"  # Green - confirmed origins found
        elif report.high_confidence_count > 0:
            color = "#f2c744"  # Yellow - high confidence found
        else:
            color = "#e01e5a"  # Red - no results

        # Build fields
        fields = [
            {"title": "Domain", "value": report.domain, "short": True},
            {"title": "Profile", "value": report.profile, "short": True},
            {"title": "Duration", "value": f"{report.scan_duration_seconds:.1f}s", "short": True},
            {"title": "Results", "value": str(report.total_results), "short": True},
            {"title": "Unique IPs", "value": str(report.unique_ips), "short": True},
            {"title": "Confirmed", "value": str(report.confirmed_count), "short": True},
        ]

        if report.high_confidence_count > 0:
            fields.append(
                {"title": "High Confidence", "value": str(report.high_confidence_count), "short": True}
            )

        # Top IPs
        top_ips = sorted(report.results, key=lambda r: -r.confidence)[:5]
        if top_ips:
            ip_lines = []
            for r in top_ips:
                badge = "CONFIRMED" if r.status.value == "confirmed" else "POTENTIAL"
                ip_lines.append(
                    f"*`{r.ip}`* ({r.confidence}%) via {r.source} [{badge}]"
                )
            fields.append({
                "title": "Top IPs",
                "value": "\n".join(ip_lines),
                "short": False,
            })

        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"CloudKill Scan: {report.domain}",
                    "title_link": f"https://{report.domain}",
                    "fields": fields,
                    "footer": f"CloudKill v{__version__} | {report.completed_at or 'N/A'}",
                    "footer_icon": "https://github.com/favicon.ico",
                    "ts": int(
                        report.completed_at.timestamp()
                    ) if report.completed_at and hasattr(report.completed_at, "timestamp") else 0,
                }
            ]
        }

        return WebhookPayload(
            url=url,
            webhook_type=WebhookType.SLACK,
            headers={"Content-Type": "application/json"},
            body=json.dumps(payload),
        )

    def _build_discord_payload(self, report: ScanReport, url: str) -> WebhookPayload:
        """Build Discord webhook payload."""
        # Determine color
        if report.confirmed_count > 0:
            color = 0x36a64f
        elif report.high_confidence_count > 0:
            color = 0xf2c744
        else:
            color = 0xe01e5a

        # Build description
        description_parts = [
            f"**Profile:** {report.profile}",
            f"**Duration:** {report.scan_duration_seconds:.1f}s",
            f"**Total Results:** {report.total_results}",
            f"**Unique IPs:** {report.unique_ips}",
            f"**Confirmed:** {report.confirmed_count}",
            f"**High Confidence:** {report.high_confidence_count}",
        ]

        if report.cloudflare_filtered:
            description_parts.append(f"**CF Filtered:** {report.cloudflare_filtered}")

        # Top IPs
        top_ips = sorted(report.results, key=lambda r: -r.confidence)[:5]
        if top_ips:
            ip_lines = []
            for r in top_ips:
                badge = "CONFIRMED" if r.status.value == "confirmed" else "POTENTIAL"
                ip_lines.append(
                    f"- `{r.ip}` ({r.confidence}%) via {r.source} [{badge}]"
                )
            description_parts.append("\n**Top IPs:**\n" + "\n".join(ip_lines))

        if report.errors:
            description_parts.append(f"\n**Errors:** {len(report.errors)}")

        payload = {
            "embeds": [
                {
                    "title": f"CloudKill Scan: {report.domain}",
                    "url": f"https://{report.domain}",
                    "description": "\n".join(description_parts),
                    "color": color,
                    "footer": {"text": f"CloudKill v{__version__}"},
                    "timestamp": (
                        report.completed_at.isoformat()
                        if report.completed_at else None
                    ),
                }
            ]
        }

        return WebhookPayload(
            url=url,
            webhook_type=WebhookType.DISCORD,
            headers={"Content-Type": "application/json"},
            body=json.dumps(payload),
        )

    def _build_generic_payload(self, report: ScanReport, url: str) -> WebhookPayload:
        """Build generic webhook payload (JSON)."""
        payload = report.to_dict()
        payload["tool"] = "CloudKill"
        payload["version"] = __version__

        return WebhookPayload(
            url=url,
            webhook_type=WebhookType.GENERIC,
            headers={"Content-Type": "application/json"},
            body=json.dumps(payload, indent=2),
        )
