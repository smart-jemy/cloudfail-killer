"""
CloudFail-Killer - JS Recon Engine

Extracts API endpoints, internal URLs, and sensitive information
from JavaScript files discovered during scanning.

Techniques (JS Recon 2.0):
    1. Endpoint extraction from fetch() and XMLHttpRequest calls
    2. API base URL detection
    3. WebSocket endpoint discovery
    4. Internal IP/hostname leakage in JS comments and strings
    5. Sensitive data exposure (keys, tokens, passwords in JS)

This module processes JavaScript URLs collected by the Wayback and URLScan
sources to extract actionable intelligence.

References:
    - https://github.com/m4ll0k/JSParser
    - https://github.com/nicois/JSParser
    - https://github.com/GerbenJavado/LinkFinder
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class JSFinding:
    """A finding from JavaScript analysis."""
    type: str  # "endpoint", "api_base", "websocket", "ip_leak", "sensitive"
    value: str
    context: str = ""  # Surrounding code context
    source_url: str = ""  # Where the JS file was found
    confidence_boost: int = 0


# Regex patterns for JS endpoint extraction
PATTERNS = {
    # fetch() API calls
    "fetch_endpoint": re.compile(
        r'fetch\s*\(\s*["\']([^"\']+?)["\']', re.IGNORECASE
    ),
    "fetch_url": re.compile(
        r'fetch\s*\(\s*["\']([^"\']+?)["\']\s*,', re.IGNORECASE
    ),

    # axios / XMLHttpRequest
    "axios_get": re.compile(
        r'(?:axios|http)\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+?)["\']', re.IGNORECASE
    ),
    "xhr_open": re.compile(
        r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH)\s*["\']\s*,\s*["\']([^"\']+?)["\']', re.IGNORECASE
    ),

    # WebSocket connections
    "websocket": re.compile(
        r'(?:new\s+)?(?:WebSocket|wss?://)(?:\s*\(\s*["\']([^"\']+?)["\'])?', re.IGNORECASE
    ),
    "wss_url": re.compile(
        r'(?:wss?://)([^\s"\'<>]+)', re.IGNORECASE
    ),

    # API base URLs
    "api_base": re.compile(
        r'(?:base[_-]?url|api[_-]?url|api[_-]?base)\s*[=:]\s*["\']([^"\']+?)["\']', re.IGNORECASE
    ),
    "api_const_url": re.compile(
        r'const\s+(?:API_URL|BASE_URL|API_BASE|ENDPOINT)\s*=\s*["\']([^"\']+?)["\']', re.IGNORECASE
    ),

    # Internal IP addresses in JS
    "ip_v4": re.compile(
        r'(?:["\'])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:["\'])'
    ),

    # Internal hostnames
    "internal_hostname": re.compile(
        r'["\']([\w.-]+\.(?:local|internal|staging|dev|test|prod)(?:\.\w+)?)["\']',
        re.IGNORECASE,
    ),

    # Sensitive data exposure
    "api_key": re.compile(
        r'(?:["\'])(?:api[_-]?key|apikey|api[_-]?secret|app[_-]?secret|client[_-]?secret)(?:["\'])',
        re.IGNORECASE,
    ),
    "password": re.compile(
        r'(?:["\'])(?:password|passwd|pwd|secret[_-]?key)(?:["\'])',
        re.IGNORECASE,
    ),
    "bearer_token": re.compile(
        r'(?:Bearer|Token)\s+([A-Za-z0-9\-._~+/]+=*)',
    ),
    "aws_key": re.compile(
        r'(?:AKIA|ASIA)[A-Z0-9]{16}',
    ),
}

# Patterns for finding JS file URLs in HTML pages
JS_URL_PATTERNS = [
    re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'(?:src|href)\s*=\s*["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE),
]


class JSReconEngine:
    """
    JavaScript reconnaissance engine.

    Extracts endpoints, API base URLs, internal IPs, and sensitive data
    from JavaScript files.

    Usage:
        engine = JSReconEngine(timeout=15)
        findings = await engine.analyze_js_file(js_url, js_content)
        leaked_ips = engine.extract_ip_leaks(findings)
    """

    def __init__(
        self,
        timeout: float = 15.0,
        max_concurrent: int = 20,
    ) -> None:
        self.timeout = timeout
        self.max_concurrent = max_concurrent

    def analyze_js_content(
        self,
        js_content: str,
        source_url: str = "",
    ) -> list[JSFinding]:
        """
        Analyze JavaScript content for endpoints and leaked data.

        Args:
            js_content: JavaScript source code as string
            source_url: URL where the JS file was found

        Returns:
            List of JSFinding objects
        """
        findings: list[JSFinding] = []

        for pattern_name, pattern in PATTERNS.items():
            for match in pattern.finditer(js_content):
                try:
                    value = match.group(2) if (match.lastindex and match.lastindex >= 2) else match.group(1)
                except IndexError:
                    value = match.group(0)

                # Skip empty or obviously false positives
                if not value or len(value) < 3:
                    continue

                # Skip non-URL values for certain patterns
                if pattern_name in ("ip_v4",):
                    # Validate IP
                    parts = value.split(".")
                    if len(parts) != 4:
                        continue
                    try:
                        if any(int(p) > 255 or int(p) < 0 for p in parts):
                            continue
                    except ValueError:
                        continue

                # Get context (surrounding characters)
                start = max(0, match.start() - 30)
                end = min(len(js_content), match.end() + 30)
                context = js_content[start:end].strip()

                finding = JSFinding(
                    type=pattern_name,
                    value=value,
                    context=f"...{context}...",
                    source_url=source_url,
                )

                # Assign confidence boosts
                finding.confidence_boost = self._estimate_confidence(finding)
                findings.append(finding)

        logger.info(
            "JS Recon: Analyzed %d chars from %s, found %d findings",
            len(js_content), source_url, len(findings),
        )
        return findings

    def extract_ip_leaks(self, findings: list[JSFinding]) -> list[str]:
        """Extract unique leaked IP addresses from JS findings."""
        leaked_ips: set[str] = set()
        for finding in findings:
            if finding.type == "ip_v4":
                ip = finding.value
                # Filter private IPs
                parts = [int(p) for p in ip.split(".")]
                if not (
                    parts[0] in (10, 127, 0)
                    or (parts[0] == 172 and 16 <= parts[1] <= 31)
                    or (parts[0] == 192 and parts[1] == 168)
                ):
                    leaked_ips.add(ip)
        return sorted(leaked_ips)

    def extract_api_endpoints(self, findings: list[JSFinding]) -> list[str]:
        """Extract unique API endpoints from JS findings."""
        endpoints: set[str] = set()
        endpoint_types = {"fetch_endpoint", "fetch_url", "axios_get", "xhr_open"}
        for finding in findings:
            if finding.type in endpoint_types:
                value = finding.value
                if value.startswith(("http://", "https://")) or value.startswith("/"):
                    endpoints.add(value)
        return sorted(endpoints)

    def extract_sensitive_findings(self, findings: list[JSFinding]) -> list[JSFinding]:
        """Extract findings related to sensitive data exposure."""
        sensitive_types = {"api_key", "password", "bearer_token", "aws_key"}
        return [f for f in findings if f.type in sensitive_types]

    def extract_js_urls_from_html(self, html_content: str) -> list[str]:
        """Extract JavaScript file URLs from HTML content."""
        urls: set[str] = set()
        for pattern in JS_URL_PATTERNS:
            for match in pattern.finditer(html_content):
                url = match.group(1)
                if url and not url.startswith(("data:", "//", "#")):
                    urls.add(url)
        return sorted(urls)

    @staticmethod
    def _estimate_confidence(finding: JSFinding) -> int:
        """Estimate confidence boost based on finding type."""
        confidence_map = {
            "ip_v4": 15,
            "fetch_endpoint": 5,
            "fetch_url": 5,
            "axios_get": 5,
            "xhr_open": 5,
            "websocket": 8,
            "wss_url": 8,
            "api_base": 10,
            "api_const_url": 10,
            "internal_hostname": 8,
            "api_key": 20,
            "password": 20,
            "bearer_token": 5,
            "aws_key": 15,
        }
        return confidence_map.get(finding.type, 5)
