"""
CloudFail-Killer - CertSpotter Source Plugin

Certificate Transparency log search via CertSpotter (sslmate.com) API.

Note: CertSpotter removed its free tier in 2024. This plugin now requires
an API key and is classified as low priority.

API: https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncGenerator
from typing import Any

from cloudkill import __version__
from cloudkill.sources.base import BaseSource, SourceResult

logger = logging.getLogger(__name__)


class CertSpotterSource(BaseSource):
    """
    Certificate Transparency log search via CertSpotter API.

    Requires API key (CERTSPOTTER_API_KEY env var).
    Free tier removed in 2024 - this source is optional/low priority.
    """

    name = "certspotter"
    description = "Certificate Transparency logs (CertSpotter)"
    requires_api_key = True
    supports_ipv6 = True
    default_enabled = False  # Disabled by default (needs API key)

    CERTSPOTTER_API = "https://api.certspotter.com/v1/issuances"
    TIMEOUT = 30

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._api_key = os.environ.get("CERTSPOTTER_API_KEY", "")

    def is_configured(self) -> bool:
        """Check if CertSpotter API key is available."""
        return bool(self._api_key)

    async def enumerate(
        self, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """
        Search CertSpotter for certificates issued to the target domain.

        Args:
            domain: Target domain

        Yields:
            SourceResult objects with discovered subdomains and IPs
        """
        if not self.is_configured():
            logger.info(
                "CertSpotter: No API key configured (set CERTSPOTTER_API_KEY env var)"
            )
            return

        import httpx

        params = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        }

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "User-Agent": f"CloudKill/{__version__}",
        }

        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
                response = await client.get(
                    self.CERTSPOTTER_API,
                    params=params,
                    headers=headers,
                )

                if response.status_code == 401:
                    logger.warning("CertSpotter: Invalid API key")
                    return
                if response.status_code == 429:
                    logger.warning("CertSpotter: Rate limited")
                    return

                response.raise_for_status()
                data = response.json()

        except Exception as e:
            logger.error("CertSpotter API error: %s", e)
            return

        seen_names: set[str] = set()
        count = 0

        for issuance in data:
            dns_names = issuance.get("dns_names", [])
            for name in dns_names:
                name = name.strip().lower()
                if not name or name in seen_names:
                    continue
                if not name.endswith(domain) and name != domain:
                    continue
                if name.startswith("*"):
                    continue

                seen_names.add(name)

                resolved = await self.resolve_with_fallback(name)
                for r in resolved:
                    r.source = self.name
                    r.metadata["certspotter"] = {
                        "issuer": issuance.get("issuer", {}).get("name", ""),
                        "not_before": issuance.get("not_before", ""),
                        "not_after": issuance.get("not_after", ""),
                    }
                    count += 1
                    yield r

        logger.info("CertSpotter found %d subdomains, %d IPs", len(seen_names), count)
