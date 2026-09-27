"""
CloudFail-Killer - GitHub Dorking Source Plugin

Search GitHub for sensitive information related to the target domain.

GitHub code search can reveal:
- Configuration files with IP addresses
- Infrastructure-as-code (Terraform, Ansible) with server IPs
- CI/CD pipelines with deployment targets
- Documentation with internal IP references
- .env files, docker-compose files, etc.

Uses GitHub Search API (unauthenticated: 10 requests/min).

API: https://api.github.com/search/code?q=example.com+ip
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import AsyncGenerator
from typing import Any

from cloudkill import __version__
from cloudkill.sources.base import BaseSource, IPVersion, SourceResult

logger = logging.getLogger(__name__)


class GitHubDorkSource(BaseSource):
    """
    Source code search via GitHub for infrastructure exposure.

    Searches GitHub for configuration files, IaC, and documentation
    that may contain origin IP addresses or internal infrastructure
    details for the target domain.

    Uses multiple dork queries to maximize discovery.
    """

    name = "github_dork"
    description = "Code search for exposed infrastructure (GitHub)"
    # GitHub code search REQUIRES authentication (401 otherwise)
    requires_api_key = True
    supports_ipv6 = True
    default_enabled = True

    GITHUB_API = "https://api.github.com/search/code"
    TIMEOUT = 30

    # Pre-built dork queries targeting different types of infrastructure exposure
    DORK_QUERIES = [
        # Configuration files with domain
        '{domain} "SERVER" "IP" in:file',
        '{domain} "host" "password" in:file',
        # Infrastructure as code
        '{domain} "resource" "aws_instance" in:file',
        '{domain} "server_ip" in:file',
        # Environment / deployment configs
        '{domain} "DB_HOST" OR "DATABASE_HOST" in:file',
        '{domain} "ALLOWED_HOSTS" OR "CORS" in:file',
        # Docker / Compose
        '{domain} "docker-compose" in:file',
        '{domain} "environment:" "REDIS_HOST" OR "POSTGRES_HOST" in:file',
        # DNS / hosting configs
        '{domain} "A record" OR "nameserver" in:file',
        # Internal docs
        '{domain} "internal" "server" in:file',
        '{domain} "production" "deploy" in:file',
    ]

    # IP address regex patterns
    IPV4_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )
    IPV6_PATTERN = re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    )

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        import os
        self._github_token = os.environ.get("GITHUB_TOKEN", "")

    def is_configured(self) -> bool:
        """GitHub code search requires a token (GITHUB_TOKEN)."""
        return bool(self._github_token)

    def _get_headers(self) -> dict[str, str]:
        """Get headers with optional GitHub token."""
        headers = {
            "User-Agent": f"CloudKill/{__version__}",
            "Accept": "application/vnd.github.v3+json",
        }
        if self._github_token:
            headers["Authorization"] = f"token {self._github_token}"
        return headers

    async def enumerate(
        self, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """
        Search GitHub for infrastructure exposure related to the target domain.

        Runs multiple dork queries and extracts IP addresses from
        matched file contents.

        Args:
            domain: Target domain

        Yields:
            SourceResult objects with discovered IPs
        """
        import httpx

        seen_ips: set[str] = set()
        total_files = 0

        # Limit dork queries to prevent rate limiting
        queries_to_run = self.DORK_QUERIES[:6]

        for dork_template in queries_to_run:
            query = dork_template.format(domain=domain)
            params = {
                "q": query,
                "per_page": 10,
                "sort": "indexed",
            }

            try:
                async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
                    response = await client.get(
                        self.GITHUB_API,
                        params=params,
                        headers=self._get_headers(),
                    )

                    if response.status_code == 403:
                        logger.warning("GitHub: Rate limited or abuse detection")
                        break

                    if response.status_code == 422:
                        logger.debug("GitHub: Invalid query format")
                        continue

                    if response.status_code == 401:
                        logger.warning("GitHub: Invalid token")
                        return

                    response.raise_for_status()
                    data = response.json()

            except Exception as e:
                logger.warning("GitHub search failed: %s", e)
                continue

            items = data.get("items", [])
            total_files += len(items)

            for item in items:
                ips = await self._extract_ips_from_file(
                    item, domain, seen_ips
                )
                for ip_data in ips:
                    yield ip_data

            # Rate limiting: GitHub allows 10 req/min unauthenticated
            await asyncio.sleep(7)

        logger.info(
            "GitHub Dorking: Searched %d files across %d queries, found %d IPs",
            total_files, len(queries_to_run), len(seen_ips),
        )

    async def _extract_ips_from_file(
        self,
        item: dict[str, Any],
        domain: str,
        seen_ips: set[str],
    ) -> list[SourceResult]:
        """Extract IP addresses from a GitHub file match."""
        import httpx

        results: list[SourceResult] = []

        # Try raw content URL
        raw_url = item.get("html_url", "").replace(
            "github.com", "raw.githubusercontent.com"
        ).replace("/blob/", "/")

        if not raw_url:
            return results

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(
                    raw_url,
                    headers=self._get_headers(),
                )
                if response.status_code != 200:
                    return results
                content = response.text

        except Exception:
            return results

        # Extract IPs from file content
        for match in self.IPV4_PATTERN.finditer(content):
            ip = match.group()
            if self._is_private_ip(ip) or ip in seen_ips:
                continue
            seen_ips.add(ip)

            repo_name = item.get("repository", {}).get("full_name", "")
            results.append(
                SourceResult(
                    subdomain=domain,
                    ip=ip,
                    ip_version=IPVersion.V4,
                    source=self.name,
                    confidence_boost=8,
                    metadata={
                        "github_repo": repo_name,
                        "github_file": item.get("path", ""),
                        "github_url": item.get("html_url", ""),
                        "github_source": "code_search",
                    },
                )
            )

        return results

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is a private/reserved address."""
        parts = [int(p) for p in ip.split(".")]
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        return parts[0] == 0

