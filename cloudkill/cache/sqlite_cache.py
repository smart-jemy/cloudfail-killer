"""
CloudFail-Killer - SQLite Cache

Persistent storage for scan results, campaign history, and
domain-level IP discovery tracking.

Features:
    - Store and retrieve scan results by domain
    - Campaign tracking (multiple scans per domain over time)
    - Cache TTL for automatic expiration
    - Query historical results for trending analysis
    - IP discovery timeline
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cloudkill.core.models import ScanReport

logger = logging.getLogger(__name__)

# Default cache TTL: 7 days
DEFAULT_CACHE_TTL_DAYS = 7


class SQLiteCache:
    """
    SQLite-based cache for scan results and campaign history.

    Stores scan results with timestamps for:
    - Cross-scan IP deduplication
    - Historical trend analysis
    - Campaign tracking (repeated scans)
    - New IP discovery detection

    Usage:
        cache = SQLiteCache(cache_dir=Path("~/.cache/cloudkill"))
        await cache.initialize()
        await cache.store_scan(report)
        history = await cache.get_domain_history("example.com")
    """

    def __init__(
        self,
        cache_dir: Path | str | None = None,
        ttl_days: int = DEFAULT_CACHE_TTL_DAYS,
    ) -> None:
        if isinstance(cache_dir, str):
            cache_dir = Path(cache_dir)
        self.cache_dir = cache_dir or Path.home() / ".cache" / "cloudkill"
        self.db_path = self.cache_dir / "scan_cache.db"
        self.ttl_days = ttl_days
        self._conn: sqlite3.Connection | None = None

    def initialize(self) -> None:
        """Create database schema if not exists."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

        cursor = self._conn.cursor()

        # Scan campaigns table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                profile TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                duration_seconds REAL,
                total_results INTEGER DEFAULT 0,
                unique_ips INTEGER DEFAULT 0,
                high_confidence INTEGER DEFAULT 0,
                confirmed INTEGER DEFAULT 0,
                cloudflare_filtered INTEGER DEFAULT 0,
                errors TEXT,
                enrichment_stats TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Individual results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                ip TEXT NOT NULL,
                ip_version INTEGER DEFAULT 4,
                subdomain TEXT DEFAULT '',
                source TEXT DEFAULT '',
                port INTEGER DEFAULT 443,
                confidence INTEGER DEFAULT 0,
                status TEXT DEFAULT 'potential',
                ssl_matches INTEGER DEFAULT 0,
                ssl_cn TEXT,
                ssl_issuer TEXT,
                asn_number INTEGER,
                asn_org TEXT,
                hosting_provider TEXT,
                is_hosting INTEGER DEFAULT 0,
                is_cloudflare INTEGER DEFAULT 0,
                is_historical INTEGER DEFAULT 0,
                favicon_hash TEXT,
                host_header_match INTEGER DEFAULT 0,
                confidence_reasons TEXT,
                raw_data TEXT,
                discovered_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
            )
        """)

        # IP discovery tracking table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_discovery (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                ip TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                seen_count INTEGER DEFAULT 1,
                sources TEXT DEFAULT '[]',
                max_confidence INTEGER DEFAULT 0,
                UNIQUE(domain, ip)
            )
        """)

        # Create indexes
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_campaigns_domain ON campaigns(domain)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_results_campaign ON results(campaign_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_results_domain ON results(domain)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_results_ip ON results(ip)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_results_confidence ON results(confidence DESC)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_ip_discovery_domain ON ip_discovery(domain)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_ip_discovery_ip ON ip_discovery(ip)"
        )

        self._conn.commit()
        logger.info(
            "SQLite cache initialized: %s (TTL=%d days)",
            self.db_path, self.ttl_days,
        )

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def _ensure_connection(self) -> sqlite3.Connection:
        """Ensure database connection is open."""
        if self._conn is None:
            self.initialize()
        return self._conn  # type: ignore

    def store_scan(self, report: ScanReport) -> int:
        """
        Store a complete scan report and its results.

        Args:
            report: ScanReport to store

        Returns:
            Campaign ID
        """
        conn = self._ensure_connection()
        cursor = conn.cursor()

        # Clean up expired entries before inserting new data
        self._cleanup_expired()

        # Insert campaign
        cursor.execute("""
            INSERT INTO campaigns (
                domain, profile, started_at, completed_at,
                duration_seconds, total_results, unique_ips,
                high_confidence, confirmed, cloudflare_filtered,
                errors, enrichment_stats
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report.domain,
            report.profile,
            report.started_at.isoformat() if report.started_at else None,
            report.completed_at.isoformat() if report.completed_at else None,
            report.scan_duration_seconds,
            report.total_results,
            report.unique_ips,
            report.high_confidence_count,
            report.confirmed_count,
            report.cloudflare_filtered,
            json.dumps(report.errors) if report.errors else None,
            json.dumps(report.enrichment_stats) if report.enrichment_stats else None,
        ))

        campaign_id = cursor.lastrowid

        # Insert individual results
        for result in report.results:
            cursor.execute("""
                INSERT INTO results (
                    campaign_id, domain, ip, ip_version, subdomain, source,
                    port, confidence, status, ssl_matches, ssl_cn, ssl_issuer,
                    asn_number, asn_org, hosting_provider, is_hosting,
                    is_cloudflare, is_historical, favicon_hash,
                    host_header_match, confidence_reasons,
                    raw_data, discovered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                campaign_id,
                report.domain,
                result.ip,
                result.ip_version.value,
                result.subdomain,
                result.source,
                result.port,
                result.confidence,
                result.status.value,
                int(result.ssl_matches),
                result.ssl_cn,
                result.ssl_issuer,
                result.asn_number,
                result.asn_org,
                result.hosting_provider,
                int(result.is_hosting),
                int(result.is_cloudflare),
                int(result.is_historical),
                result.favicon_hash,
                int(result.host_header_match),
                json.dumps(result.confidence_reasons) if result.confidence_reasons else None,
                json.dumps(result.to_dict()) if result else None,
                result.discovered_at.isoformat() if result.discovered_at else None,
            ))

        # Update IP discovery tracking
        self._update_ip_discovery(report)

        conn.commit()
        logger.info(
            "Stored scan campaign %d: %s (%d results)",
            campaign_id, report.domain, report.total_results,
        )
        return campaign_id  # type: ignore

    def _update_ip_discovery(self, report: ScanReport) -> None:
        """Update IP discovery tracking table."""
        conn = self._ensure_connection()
        cursor = conn.cursor()

        now = datetime.now(UTC).isoformat()

        for result in report.results:
            # Try to get existing record
            cursor.execute(
                "SELECT seen_count, sources, max_confidence FROM ip_discovery WHERE domain=? AND ip=?",
                (report.domain, result.ip),
            )
            row = cursor.fetchone()

            if row:
                # Update existing
                seen_count = row["seen_count"] + 1
                sources = json.loads(row["sources"])
                if result.source and result.source not in sources:
                    sources.append(result.source)
                max_confidence = max(row["max_confidence"], result.confidence)

                cursor.execute("""
                    UPDATE ip_discovery SET
                        last_seen=?, seen_count=?, sources=?, max_confidence=?
                    WHERE domain=? AND ip=?
                """, (
                    now, seen_count, json.dumps(sources), max_confidence,
                    report.domain, result.ip,
                ))
            else:
                # Insert new
                sources = [result.source] if result.source else []
                cursor.execute("""
                    INSERT INTO ip_discovery (domain, ip, first_seen, last_seen, seen_count, sources, max_confidence)
                    VALUES (?, ?, ?, ?, 1, ?, ?)
                """, (
                    report.domain, result.ip, now, now,
                    json.dumps(sources), result.confidence,
                ))

    def get_domain_history(
        self,
        domain: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Get scan history for a domain.

        Args:
            domain: Target domain
            limit: Maximum number of campaigns to return

        Returns:
            List of campaign dictionaries
        """
        conn = self._ensure_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, domain, profile, started_at, completed_at,
                   duration_seconds, total_results, unique_ips,
                   high_confidence, confirmed, cloudflare_filtered
            FROM campaigns
            WHERE domain = ?
            ORDER BY created_at DESC
            LIMIT ?
        """, (domain, limit))

        campaigns = []
        for row in cursor.fetchall():
            campaigns.append(dict(row))

        return campaigns

    def get_known_ips(
        self,
        domain: str,
        min_confidence: int = 0,
        exclude_cloudflare: bool = True,
    ) -> list[dict[str, Any]]:
        """
        Get all known IPs for a domain from cache.

        Args:
            domain: Target domain
            min_confidence: Minimum confidence threshold
            exclude_cloudflare: Exclude Cloudflare IPs

        Returns:
            List of IP discovery records
        """
        conn = self._ensure_connection()
        cursor = conn.cursor()

        query = """
            SELECT domain, ip, first_seen, last_seen, seen_count,
                   sources, max_confidence
            FROM ip_discovery
            WHERE domain = ? AND max_confidence >= ?
        """
        params: list[Any] = [domain, min_confidence]

        if exclude_cloudflare:
            # Exclude CF IPs based on our tracking
            query += " AND max_confidence > 0"

        query += " ORDER BY max_confidence DESC, last_seen DESC"
        cursor.execute(query, params)

        results = []
        for row in cursor.fetchall():
            record = dict(row)
            record["sources"] = json.loads(record["sources"])
            results.append(record)

        return results

    def get_new_ips_since(
        self,
        domain: str,
        since: datetime,
    ) -> list[str]:
        """
        Get IPs first seen after a given date.

        Args:
            domain: Target domain
            since: Cutoff datetime

        Returns:
            List of IP strings
        """
        conn = self._ensure_connection()
        cursor = conn.cursor()

        since_iso = since.isoformat()
        cursor.execute("""
            SELECT ip FROM ip_discovery
            WHERE domain = ? AND first_seen > ?
            ORDER BY max_confidence DESC
        """, (domain, since_iso))

        return [row["ip"] for row in cursor.fetchall()]

    def get_campaign_results(
        self,
        campaign_id: int,
        min_confidence: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Get all results for a specific campaign.

        Args:
            campaign_id: Campaign ID
            min_confidence: Minimum confidence threshold

        Returns:
            List of result dictionaries
        """
        conn = self._ensure_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT ip, ip_version, subdomain, source, port, confidence,
                   status, ssl_matches, ssl_cn, asn_org, hosting_provider,
                   is_hosting, confidence_reasons
            FROM results
            WHERE campaign_id = ? AND confidence >= ?
            ORDER BY confidence DESC
        """, (campaign_id, min_confidence))

        results = []
        for row in cursor.fetchall():
            record = dict(row)
            if record.get("confidence_reasons"):
                record["confidence_reasons"] = json.loads(record["confidence_reasons"])
            results.append(record)

        return results

    def get_stats(self) -> dict[str, Any]:
        """Get overall cache statistics."""
        conn = self._ensure_connection()
        cursor = conn.cursor()

        stats: dict[str, Any] = {}

        cursor.execute("SELECT COUNT(*) as cnt FROM campaigns")
        stats["total_campaigns"] = cursor.fetchone()["cnt"]

        cursor.execute("SELECT COUNT(DISTINCT domain) as cnt FROM campaigns")
        stats["unique_domains"] = cursor.fetchone()["cnt"]

        cursor.execute("SELECT COUNT(*) as cnt FROM results")
        stats["total_results"] = cursor.fetchone()["cnt"]

        cursor.execute("SELECT COUNT(DISTINCT ip) as cnt FROM ip_discovery")
        stats["unique_ips_tracked"] = cursor.fetchone()["cnt"]

        cursor.execute("SELECT COUNT(*) as cnt FROM results WHERE confidence >= 70")
        stats["high_confidence_total"] = cursor.fetchone()["cnt"]

        cursor.execute("SELECT COUNT(*) as cnt FROM results WHERE status = 'confirmed'")
        stats["confirmed_total"] = cursor.fetchone()["cnt"]

        # DB file size
        try:
            stats["db_size_bytes"] = self.db_path.stat().st_size
            stats["db_size_mb"] = round(stats["db_size_bytes"] / (1024 * 1024), 2)
        except OSError:
            stats["db_size_bytes"] = 0
            stats["db_size_mb"] = 0.0

        return stats

    def _cleanup_expired(self) -> int:
        """Remove entries older than TTL. Returns count of removed rows."""
        conn = self._ensure_connection()
        cursor = conn.cursor()

        cutoff = (datetime.now(UTC) - timedelta(days=self.ttl_days)).isoformat()

        # Get campaign IDs to delete
        cursor.execute(
            "SELECT id FROM campaigns WHERE created_at < ?", (cutoff,)
        )
        expired_ids = [row["id"] for row in cursor.fetchall()]

        if not expired_ids:
            return 0

        # Delete results for expired campaigns
        placeholders = ",".join("?" * len(expired_ids))
        cursor.execute(
            f"DELETE FROM results WHERE campaign_id IN ({placeholders})",
            expired_ids,
        )

        # Delete expired campaigns
        cursor.execute(
            f"DELETE FROM campaigns WHERE id IN ({placeholders})",
            expired_ids,
        )

        conn.commit()

        removed = len(expired_ids)
        if removed:
            logger.debug("Cleaned up %d expired campaigns", removed)
        return removed

    def clear_domain(self, domain: str) -> int:
        """
        Clear all cached data for a specific domain.

        Returns:
            Number of campaigns removed
        """
        conn = self._ensure_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id FROM campaigns WHERE domain = ?", (domain,)
        )
        campaign_ids = [row["id"] for row in cursor.fetchall()]

        if not campaign_ids:
            return 0

        placeholders = ",".join("?" * len(campaign_ids))
        cursor.execute(
            f"DELETE FROM results WHERE campaign_id IN ({placeholders})",
            campaign_ids,
        )
        cursor.execute(
            "DELETE FROM campaigns WHERE domain = ?", (domain,)
        )
        cursor.execute(
            "DELETE FROM ip_discovery WHERE domain = ?", (domain,)
        )

        conn.commit()
        return len(campaign_ids)

    def clear_all(self) -> None:
        """Clear all cached data."""
        conn = self._ensure_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM results")
        cursor.execute("DELETE FROM campaigns")
        cursor.execute("DELETE FROM ip_discovery")
        conn.commit()
        logger.info("Cache cleared")
