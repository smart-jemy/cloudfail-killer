"""
CloudFail-Killer - Data Models

Unified data models for scan results, enriched results, and scan reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from cloudkill.sources.base import IPVersion, SourceResult


class ResultStatus(str, Enum):
    """Status of an analyzed result."""
    POTENTIAL = "potential"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    UNKNOWN = "unknown"


@dataclass
class EnrichedResult:
    """A source result enriched with additional intelligence."""
    # Core fields from SourceResult
    subdomain: str
    ip: str
    ip_version: IPVersion = IPVersion.V4
    source: str = ""
    port: int = 443

    # Enrichment fields (populated by Phase 3)
    is_cloudflare: bool = True  # Assume CF until proven otherwise
    ssl_matches: bool = False
    ssl_cn: str | None = None
    ssl_san: list[str] = field(default_factory=list)
    ssl_issuer: str | None = None
    ssl_is_cloudflare: bool = False
    asn_number: int | None = None
    asn_org: str | None = None
    asn_country: str | None = None
    asn_city: str | None = None
    hosting_provider: str | None = None  # e.g., "AWS", "GCP", "OVH"
    isp: str | None = None
    is_hosting: bool = False
    is_datacenter: bool = False
    is_residential: bool = False
    is_historical: bool = False
    favicon_hash: str | None = None
    favicon_match: bool = False
    js_extracted: bool = False
    spf_dkim_origin: bool = False
    acme_configured: bool = False
    host_header_match: bool = False
    internetdb_match: bool = False
    internetdb_hostnames: list[str] = field(default_factory=list)
    internetdb_open_ports: list[int] = field(default_factory=list)

    # Confidence scoring
    confidence: int = 0
    confidence_reasons: list[str] = field(default_factory=list)
    status: ResultStatus = ResultStatus.POTENTIAL

    # Metadata
    discovered_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    raw_source_result: SourceResult | None = None

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON export."""
        return {
            "subdomain": self.subdomain,
            "ip": self.ip,
            "ip_version": self.ip_version.value,
            "source": self.source,
            "port": self.port,
            "is_cloudflare": self.is_cloudflare,
            "ssl_is_cloudflare": self.ssl_is_cloudflare,
            "ssl_matches": self.ssl_matches,
            "ssl_cn": self.ssl_cn,
            "ssl_san": self.ssl_san,
            "ssl_issuer": self.ssl_issuer,
            "asn_number": self.asn_number,
            "asn_org": self.asn_org,
            "asn_country": self.asn_country,
            "asn_city": self.asn_city,
            "hosting_provider": self.hosting_provider,
            "isp": self.isp,
            "is_hosting": self.is_hosting,
            "is_datacenter": self.is_datacenter,
            "is_residential": self.is_residential,
            "is_historical": self.is_historical,
            "favicon_hash": self.favicon_hash,
            "favicon_match": self.favicon_match,
            "js_extracted": self.js_extracted,
            "spf_dkim_origin": self.spf_dkim_origin,
            "internetdb_match": self.internetdb_match,
            "internetdb_hostnames": self.internetdb_hostnames,
            "internetdb_open_ports": self.internetdb_open_ports,
            "confidence": self.confidence,
            "confidence_reasons": self.confidence_reasons,
            "status": self.status.value,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
        }

    @classmethod
    def from_source_result(cls, result: SourceResult) -> EnrichedResult:
        """Create an EnrichedResult from a raw SourceResult."""
        return cls(
            subdomain=result.subdomain,
            ip=result.ip,
            ip_version=result.ip_version,
            source=result.source,
            port=result.port,
            is_historical=result.is_historical,
            confidence=result.confidence_boost,
            confidence_reasons=[f"Source boost: +{result.confidence_boost} from {result.source}"]
            if result.confidence_boost > 0 else [],
            raw_source_result=result,
        )


@dataclass
class ScanReport:
    """Complete scan report for a domain."""
    domain: str
    profile: str = "researcher"
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    total_results: int = 0
    unique_ips: int = 0
    high_confidence_count: int = 0  # confidence >= 70
    confirmed_count: int = 0
    results: list[EnrichedResult] = field(default_factory=list)
    sources_used: list[str] = field(default_factory=list)
    ipv4_count: int = 0
    ipv6_count: int = 0
    cloudflare_filtered: int = 0
    non_routable_filtered: int = 0
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    enrichment_stats: dict = field(default_factory=dict)

    def add_result(self, result: EnrichedResult) -> None:
        """Add a result and update statistics."""
        self.results.append(result)
        self.total_results += 1
        if result.ip_version == IPVersion.V4:
            self.ipv4_count += 1
        else:
            self.ipv6_count += 1
        if result.confidence >= 70:
            self.high_confidence_count += 1
        if result.status == ResultStatus.CONFIRMED:
            self.confirmed_count += 1
        if result.source not in self.sources_used:
            self.sources_used.append(result.source)

    def finalize(self) -> None:
        """Finalize the report after scan completion."""
        self.completed_at = datetime.now(UTC)
        self.scan_duration_seconds = (
            (self.completed_at - self.started_at).total_seconds()
            if self.completed_at
            else 0.0
        )
        unique = {r.ip for r in self.results}
        self.unique_ips = len(unique)

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON export."""
        return {
            "domain": self.domain,
            "profile": self.profile,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_duration_seconds": self.scan_duration_seconds,
            "summary": {
                "total_results": self.total_results,
                "unique_ips": self.unique_ips,
                "high_confidence_count": self.high_confidence_count,
                "confirmed_count": self.confirmed_count,
                "ipv4_count": self.ipv4_count,
                "ipv6_count": self.ipv6_count,
                "cloudflare_filtered": self.cloudflare_filtered,
                "non_routable_filtered": self.non_routable_filtered,
                "sources_used": self.sources_used,
            },
            "enrichment_stats": self.enrichment_stats,
            "results": [r.to_dict() for r in self.results],
            "errors": self.errors,
        }
