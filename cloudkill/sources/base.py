"""
CloudFail-Killer - Base Source Plugin

Abstract base class that all data source plugins must implement.
Each source collects potential origin IPs from a different data source.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from enum import Enum

import aiodns

logger = logging.getLogger(__name__)


class IPVersion(int, Enum):
    """IP address version."""
    V4 = 4
    V6 = 6


@dataclass
class SourceResult:
    """A single result from a data source."""
    subdomain: str
    ip: str
    ip_version: IPVersion = IPVersion.V4
    source: str = ""
    port: int = 443
    is_historical: bool = False
    confidence_boost: int = 0
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Auto-detect IP version from address string."""
        if ":" in self.ip:
            self.ip_version = IPVersion.V6
        else:
            self.ip_version = IPVersion.V4

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "subdomain": self.subdomain,
            "ip": self.ip,
            "ip_version": self.ip_version.value,
            "source": self.source,
            "port": self.port,
            "is_historical": self.is_historical,
            "confidence_boost": self.confidence_boost,
            "metadata": self.metadata,
        }


class BaseSource(ABC):
    """
    Abstract base class for all data source plugins.

    Every source must:
    1. Set a unique `name`
    2. Implement the `enumerate()` async generator
    3. Optionally implement `is_configured()` for API-key sources
    """

    name: str = "base"
    description: str = "Base source plugin"
    requires_api_key: bool = False
    supports_ipv6: bool = True
    default_enabled: bool = True

    def __init__(
        self,
        engine: object | None = None,
        ipv6_preference: bool = False,
        dns_servers: list[str] | None = None,
        **kwargs,
    ) -> None:
        self.engine = engine
        self.ipv6_preference = ipv6_preference
        self.dns_servers = dns_servers or []
        self._resolver = None

    @property
    def resolver(self) -> aiodns.DNSResolver:
        """Lazy-initialized DNS resolver (uses configured nameservers)."""
        if self._resolver is None:
            if self.dns_servers:
                self._resolver = aiodns.DNSResolver(nameservers=list(self.dns_servers))
            else:
                self._resolver = aiodns.DNSResolver()
        return self._resolver

    @abstractmethod
    async def enumerate(
        self, domain: str
    ) -> AsyncGenerator[SourceResult, None]:
        """
        Enumerate potential origin IPs for the given domain.

        Args:
            domain: The target domain (e.g., "example.com")

        Yields:
            SourceResult objects with discovered IPs
        """
        yield  # pragma: no cover

    async def resolve_with_fallback(
        self,
        hostname: str,
        port: int = 443,
    ) -> list[SourceResult]:
        """
        Dual-stack DNS resolution with IPv4 and AAAA records.

        Args:
            hostname: Hostname to resolve
            port: Associated port number

        Returns:
            List of SourceResult with resolved IPs
        """
        results: list[SourceResult] = []

        # Try AAAA first if IPv6 preferred
        if self.ipv6_preference and self.supports_ipv6:
            try:
                answers = await self.resolver.query(hostname, "AAAA")
                for r in answers:
                    results.append(
                        SourceResult(
                            subdomain=hostname,
                            ip=r.host,
                            source=self.name,
                            port=port,
                        )
                    )
            except Exception as e:
                logger.debug("AAAA resolution failed for %s: %s", hostname, e)

        # Always try A record
        try:
            answers = await self.resolver.query(hostname, "A")
            for r in answers:
                results.append(
                    SourceResult(
                        subdomain=hostname,
                        ip=r.host,
                        source=self.name,
                        port=port,
                    )
                )
        except Exception as e:
            logger.debug("A record resolution failed for %s: %s", hostname, e)

        return results

    def is_configured(self) -> bool:
        """Check if this source has required configuration (API keys, etc.)."""
        # API-key sources must override this to actually check for their key;
        # the safe default is "not configured" so we never run keyless.
        return not self.requires_api_key

    def __repr__(self) -> str:
        configured = self.is_configured()
        return (
            f"<{self.__class__.__name__} "
            f"name={self.name!r} "
            f"configured={configured} "
            f"ipv6={self.supports_ipv6}>"
        )
