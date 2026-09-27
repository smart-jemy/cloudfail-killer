"""
CloudFail-Killer - DNSDumpster Source Plugin

DNSDumpster provides DNS reconnaissance data including:
- DNS records (A, AAAA, MX, NS, TXT)
- Subdomain enumeration
- DNS map visualization data

Note: DNSDumpster requires scraping and may block automated requests.
This plugin is marked as optional and uses best-effort scraping with
anti-detection measures.

Website: https://dnsdumpster.com/
"""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncGenerator

from cloudkill.sources.base import BaseSource, IPVersion, SourceResult

logger = logging.getLogger(__name__)


class DNSDumpsterSource(BaseSource):
    """
    DNS reconnaissance via DNSDumpster.com.

    Free service but requires scraping. May block automated requests.
    Uses CSRF token handling for form submission.

    This source is marked as low priority due to scraping instability.
    """

    name = "dnsdumpster"
    description = "DNS reconnaissance (DNSDumpster)"
    requires_api_key = False
    supports_ipv6 = True
    default_enabled = False  # Disabled by default due to scraping instability

    DNSDUMSTER_URL = "https://dnsdumpster.com/"
    TIMEOUT = 30

    async def enumerate(
        self, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """
        Query DNSDumpster for DNS data about the target domain.

        Process:
        1. GET the main page to obtain CSRF token
        2. POST the domain with the CSRF token
        3. Parse the results table for DNS records

        Args:
            domain: Target domain

        Yields:
            SourceResult objects with discovered IPs
        """
        import httpx

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            ),
        }

        seen_ips: set[str] = set()

        try:
            async with httpx.AsyncClient(
                timeout=self.TIMEOUT,
                follow_redirects=True,
            ) as client:
                # Step 1: Get CSRF token
                response = await client.get(self.DNSDUMSTER_URL, headers=headers)

                if response.status_code == 403:
                    logger.warning("DNSDumpster: Access forbidden (likely blocked)")
                    return

                if response.status_code != 200:
                    logger.warning("DNSDumpster: Unexpected status %d", response.status_code)
                    return

                # Extract CSRF token from cookies
                csrf_token = ""
                for cookie in client.cookies.jar:
                    if "csrftoken" in cookie.name:
                        csrf_token = cookie.value
                        break

                if not csrf_token:
                    # Try extracting from HTML
                    csrf_match = re.search(
                        r'name="csrfmiddlewaretoken"\s+value="([^"]+)"',
                        response.text,
                    )
                    if csrf_match:
                        csrf_token = csrf_match.group(1)

                if not csrf_token:
                    logger.warning("DNSDumpster: Could not extract CSRF token")
                    return

                # Step 2: Submit domain search
                post_data = {
                    "csrfmiddlewaretoken": csrf_token,
                    "targetip": domain,
                    "user": "free",
                }

                response = await client.post(
                    self.DNSDUMSTER_URL,
                    data=post_data,
                    headers={
                        **headers,
                        "Referer": self.DNSDUMSTER_URL,
                        "X-CSRFToken": csrf_token,
                    },
                )

                if response.status_code != 200:
                    logger.warning("DNSDumpster: POST failed with status %d", response.status_code)
                    return

                # Step 3: Parse results
                text = response.text

                # Extract host-IP pairs from the response
                row_pattern = re.compile(
                    r'<td[^>]*>(\S+@\S+|\S+\.\S+)</td>\s*<td[^>]*>([^<]+)</td>',
                    re.IGNORECASE,
                )

                matches = row_pattern.findall(text)

                if not matches:
                    # Alternative pattern for the results table
                    row_pattern2 = re.compile(
                        r'<tr[^>]*>.*?<td[^>]*>([^<]+)</td>.*?<td[^>]*>([^<]+)</td>.*?</tr>',
                        re.DOTALL | re.IGNORECASE,
                    )
                    matches = row_pattern2.findall(text)

                for hostname, ip_or_type in matches:
                    hostname = hostname.strip().lower()
                    ip_or_type = ip_or_type.strip()

                    if not hostname:
                        continue

                    # Try to extract IP from the second column
                    ip_match = re.search(
                        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                        ip_or_type,
                    )
                    ipv6_match = re.search(
                        r'([0-9a-fA-F:]{2,}:[0-9a-fA-F:]+)',
                        ip_or_type,
                    )

                    ip = ""
                    if ip_match:
                        ip = ip_match.group(1)
                    elif ipv6_match:
                        ip = ipv6_match.group(1)

                    if not ip or ip in seen_ips:
                        continue

                    seen_ips.add(ip)

                    yield SourceResult(
                        subdomain=hostname,
                        ip=ip,
                        ip_version=IPVersion.V6 if ":" in ip else IPVersion.V4,
                        source=self.name,
                        confidence_boost=5,
                        metadata={"dnsdumpster_type": ip_or_type},
                    )

        except httpx.TimeoutException:
            logger.warning("DNSDumpster: Request timed out")
        except Exception as e:
            logger.error("DNSDumpster query failed: %s", e)

        logger.info("DNSDumpster: %d unique IPs discovered", len(seen_ips))
