"""
CloudFail-Killer - Enrichment Pipeline

Orchestrates the enrichment of raw scan results by running multiple enrichers
in parallel. The pipeline applies SSL checking, ASN lookup, JS recon, scoring,
false positive filtering, and deduplication in the correct order.

Pipeline stages:
    1. SSL Certificate Check (SSLChecker)
    2. ASN / Hosting Provider Lookup (ASNLookup)
    3. Shodan InternetDB Origin Verification (InternetDBLookup)
    4. JS Recon Analysis (JSReconEngine)
    5. Confidence Scoring (ScoringEngine)
    6. False Positive Filtering (FalsePositiveFilter)
    7. Deduplication (ResultDeduplicator)

MITRE ATT&CK: T1595.002 (SSL/TLS Inspection), T1590.001 (DNS)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console

from cloudkill.config import Config
from cloudkill.core.filters import FalsePositiveFilter
from cloudkill.core.models import EnrichedResult, ResultStatus
from cloudkill.enrichers.asn_lookup import ASNLookup
from cloudkill.enrichers.internetdb import InternetDBLookup
from cloudkill.enrichers.js_recon import JSReconEngine
from cloudkill.enrichers.scoring import ResultDeduplicator, ScoringEngine
from cloudkill.enrichers.ssl_checker import SSLChecker

logger = logging.getLogger(__name__)
console = Console()


@dataclass
class EnrichmentStats:
    """Statistics for the enrichment pipeline run."""
    total_enriched: int = 0
    ssl_checked: int = 0
    ssl_matched: int = 0
    asn_lookups: int = 0
    asn_hosting_found: int = 0
    js_analyzed: int = 0
    js_findings: int = 0
    internetdb_lookups: int = 0
    internetdb_matches: int = 0
    fp_filtered: int = 0
    duplicates_removed: int = 0
    confirmed_count: int = 0
    potential_count: int = 0
    enrichment_duration: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_enriched": self.total_enriched,
            "ssl_checked": self.ssl_checked,
            "ssl_matched": self.ssl_matched,
            "asn_lookups": self.asn_lookups,
            "asn_hosting_found": self.asn_hosting_found,
            "js_analyzed": self.js_analyzed,
            "js_findings": self.js_findings,
            "internetdb_lookups": self.internetdb_lookups,
            "internetdb_matches": self.internetdb_matches,
            "fp_filtered": self.fp_filtered,
            "duplicates_removed": self.duplicates_removed,
            "confirmed_count": self.confirmed_count,
            "potential_count": self.potential_count,
            "enrichment_duration": f"{self.enrichment_duration:.2f}s",
            "errors": self.errors,
        }


class EnrichmentPipeline:
    """
    Orchestrates the full enrichment pipeline for scan results.

    Takes raw EnrichedResults and enriches them with:
    - SSL certificate information (CN, SAN, issuer, expiry)
    - ASN and hosting provider data
    - JS Recon findings (endpoints, leaked IPs)
    - Confidence scoring with profile weights
    - False positive detection and removal
    - Deduplication

    Usage:
        pipeline = EnrichmentPipeline(config)
        stats, enriched = await pipeline.enrich(results, domain)
    """

    def __init__(
        self,
        config: Config,
        enable_ssl: bool = True,
        enable_asn: bool = True,
        enable_js: bool = False,
        enable_scoring: bool = True,
        enable_fp_filter: bool = True,
        enable_dedup: bool = True,
        enable_internetdb: bool = False,
    ) -> None:
        self.config = config
        self.enable_ssl = enable_ssl
        self.enable_asn = enable_asn
        self.enable_js = enable_js
        self.enable_internetdb = enable_internetdb
        self.enable_scoring = enable_scoring
        self.enable_fp_filter = enable_fp_filter
        self.enable_dedup = enable_dedup

        # Initialize enrichers
        self.ssl_checker = SSLChecker(
            timeout=config.timeout,
            max_concurrent=config.effective_threads,
        ) if enable_ssl else None

        self.asn_lookup = ASNLookup(
            timeout=config.timeout,
            max_concurrent=config.effective_threads,
        ) if enable_asn else None

        self.js_engine = JSReconEngine(
            timeout=config.timeout,
        ) if enable_js else None

        self.internetdb = InternetDBLookup(
            timeout=10.0,
            max_concurrent=min(config.effective_threads, 10),
        ) if enable_internetdb else None

        self.scoring_engine = ScoringEngine(config) if enable_scoring else None
        self.fp_filter = FalsePositiveFilter() if enable_fp_filter else None
        self.deduplicator = ResultDeduplicator() if enable_dedup else None

    async def enrich(
        self,
        results: list[EnrichedResult],
        domain: str,
        show_progress: bool = True,
    ) -> tuple[EnrichmentStats, list[EnrichedResult]]:
        """
        Run the full enrichment pipeline on a list of results.

        Args:
            results: List of enriched results from the source runner
            domain: Target domain for SSL matching and scoring
            show_progress: Whether to show Rich progress bars

        Returns:
            Tuple of (EnrichmentStats, enriched_results)
        """
        start_time = time.monotonic()
        stats = EnrichmentStats()
        stats.total_enriched = len(results)

        if not results:
            stats.enrichment_duration = time.monotonic() - start_time
            return stats, results

        # Stage 1: SSL Certificate Checking
        if self.enable_ssl and self.ssl_checker:
            results = await self._stage_ssl(results, domain, stats, show_progress)

        # Stage 2: ASN / Hosting Provider Lookup
        if self.enable_asn and self.asn_lookup:
            results = await self._stage_asn(results, stats, show_progress)

        # Stage 3: Shodan InternetDB origin verification
        if self.enable_internetdb and self.internetdb:
            results = await self._stage_internetdb(results, domain, stats, show_progress)

        # Stage 4: JS Recon Analysis (only if JS URLs are available)
        if self.enable_js and self.js_engine:
            await self._stage_js(results, stats, show_progress)

        # Stage 5: Confidence Scoring
        if self.enable_scoring and self.scoring_engine:
            self._stage_scoring(results, domain, stats)

        # Stage 6: False Positive Filtering
        if self.enable_fp_filter and self.fp_filter:
            results = self._stage_fp_filter(results, stats)

        # Stage 7: Deduplication
        if self.enable_dedup and self.deduplicator:
            before_dedup = len(results)
            results = self.deduplicator.deduplicate(results)
            stats.duplicates_removed = before_dedup - len(results)

        # Count statuses
        for r in results:
            if r.status == ResultStatus.CONFIRMED:
                stats.confirmed_count += 1
            elif r.status == ResultStatus.POTENTIAL:
                stats.potential_count += 1

        stats.enrichment_duration = time.monotonic() - start_time
        return stats, results

    async def _stage_ssl(
        self,
        results: list[EnrichedResult],
        domain: str,
        stats: EnrichmentStats,
        show_progress: bool,
    ) -> list[EnrichedResult]:
        """Stage 1: Check SSL certificates for all discovered IPs."""
        unique_ports = {(r.ip, r.port) for r in results}
        stats.ssl_checked = len(unique_ports)

        if not unique_ports:
            return results

        ip_port_list = list(unique_ports)

        if show_progress:
            console.print(f"\n  [bold]Stage 1:[/bold] SSL Certificate Check ({len(ip_port_list)} IPs)")

        try:
            ssl_infos = await self.ssl_checker.check_ssl_batch(ip_port_list)

            # Build a lookup map
            ssl_map: dict[tuple[str, int], Any] = {}
            for info in ssl_infos:
                ssl_map[(info.ip, info.port)] = info

            # Apply SSL data to results
            for result in results:
                info = ssl_map.get((result.ip, result.port))
                if info and info.is_valid:
                    result.ssl_cn = info.cn
                    result.ssl_san = info.san
                    result.ssl_issuer = info.issuer_org
                    result.ssl_is_cloudflare = info.is_cloudflare_cert

                    if info.matches_domain(domain):
                        result.ssl_matches = True
                        stats.ssl_matched += 1

                    # Store raw metadata for scoring
                    if result.raw_source_result:
                        result.raw_source_result.metadata["ssl_info"] = info.to_dict()
                        result.raw_source_result.metadata["self_signed"] = info.self_signed
                        result.raw_source_result.metadata["is_cloudflare_cert"] = info.is_cloudflare_cert

        except Exception as e:
            logger.error("SSL enrichment stage failed: %s", e)
            stats.errors.append(f"SSL check: {e}")

        if show_progress and stats.ssl_matched:
            console.print(f"    [green]{stats.ssl_matched} SSL certificate matches found[/green]")

        return results

    async def _stage_asn(
        self,
        results: list[EnrichedResult],
        stats: EnrichmentStats,
        show_progress: bool,
    ) -> list[EnrichedResult]:
        """Stage 2: Look up ASN and hosting provider for all unique IPs."""
        unique_ips = list({r.ip for r in results})
        stats.asn_lookups = len(unique_ips)

        if not unique_ips:
            return results

        if show_progress:
            console.print(f"  [bold]Stage 2:[/bold] ASN / Hosting Lookup ({len(unique_ips)} IPs)")

        try:
            asn_infos = await self.asn_lookup.lookup_batch(unique_ips)

            # Build lookup map
            asn_map: dict[str, Any] = {}
            for info in asn_infos:
                asn_map[info.ip] = info

            # Apply ASN data to results
            for result in results:
                info = asn_map.get(result.ip)
                if info and info.is_confidence_signal:
                    result.asn_number = info.asn
                    result.asn_org = info.asn_org
                    result.asn_country = info.country
                    result.asn_city = info.city
                    result.hosting_provider = info.hosting_provider
                    result.isp = info.isp
                    result.is_hosting = info.is_hosting
                    result.is_datacenter = info.is_datacenter
                    result.is_residential = info.is_residential

                    if info.hosting_provider:
                        stats.asn_hosting_found += 1

                    if info.lookup_error:
                        stats.errors.append(f"ASN lookup {result.ip}: {info.lookup_error}")

        except Exception as e:
            logger.error("ASN enrichment stage failed: %s", e)
            stats.errors.append(f"ASN lookup: {e}")

        if show_progress and stats.asn_hosting_found:
            console.print(f"    [green]{stats.asn_hosting_found} hosting providers identified[/green]")

        return results

    async def _stage_internetdb(
        self,
        results: list[EnrichedResult],
        domain: str,
        stats: EnrichmentStats,
        show_progress: bool,
    ) -> list[EnrichedResult]:
        """Stage 3: Verify candidate origins via Shodan InternetDB."""
        unique_ips = list({r.ip for r in results})
        if not unique_ips:
            return results

        if show_progress:
            console.print(f"  [bold]Stage 3:[/bold] Shodan InternetDB Verification ({len(unique_ips)} IPs)")

        stats.internetdb_lookups = len(unique_ips)

        try:
            infos = await self.internetdb.lookup_batch(unique_ips)
        except Exception as e:
            logger.error("InternetDB enrichment stage failed: %s", e)
            stats.errors.append(f"InternetDB: {e}")
            return results

        for result in results:
            info = infos.get(result.ip)
            if not info or not info.found:
                continue

            matched = info.domain_hostname_match(domain)
            if matched:
                result.internetdb_match = True
                result.internetdb_hostnames = info.hostnames
                result.internetdb_open_ports = info.web_ports_open()
                stats.internetdb_matches += 1
                if result.raw_source_result is not None:
                    result.raw_source_result.metadata["internetdb"] = info.to_dict()
            elif info.web_ports_open():
                result.internetdb_open_ports = info.web_ports_open()
                if result.raw_source_result is not None:
                    result.raw_source_result.metadata["internetdb"] = info.to_dict()

        if show_progress and stats.internetdb_matches:
            console.print(
                f"    [green]{stats.internetdb_matches} origin candidates verified via InternetDB hostnames[/green]"
            )

        return results

    async def _stage_js(
        self,
        results: list[EnrichedResult],
        stats: EnrichmentStats,
        show_progress: bool,
    ) -> list[EnrichedResult]:
        """Stage 3: Analyze JavaScript files for leaked IPs and endpoints."""
        # JS Recon requires fetching JS content - check if results have JS URLs
        js_urls: list[str] = []
        for result in results:
            meta = result.raw_source_result.metadata if result.raw_source_result else {}
            if meta.get("js_urls"):
                js_urls.extend(meta["js_urls"])

        if not js_urls:
            if show_progress:
                console.print("  [bold]Stage 4:[/bold] JS Recon (no JS URLs found)")
            return results

        stats.js_analyzed = len(js_urls)

        if show_progress:
            console.print(f"  [bold]Stage 4:[/bold] JS Recon Analysis ({len(js_urls)} JS files)")

        try:
            import httpx

            # Fetch and analyze JS files in batches
            leaked_ips: set[str] = set()
            all_findings: list[Any] = []

            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                for js_url in js_urls[:50]:  # Limit to 50 JS files max
                    try:
                        resp = await client.get(js_url, follow_redirects=True)
                        if resp.status_code == 200 and resp.text:
                            findings = self.js_engine.analyze_js_content(
                                resp.text, source_url=js_url
                            )
                            all_findings.extend(findings)
                            stats.js_findings += len(findings)

                            # Extract leaked IPs
                            ips = self.js_engine.extract_ip_leaks(findings)
                            leaked_ips.update(ips)

                    except Exception as e:
                        logger.debug("JS fetch failed for %s: %s", js_url, e)

            # Mark results that had JS analysis
            for result in results:
                meta = result.raw_source_result.metadata if result.raw_source_result else {}
                if meta.get("js_urls"):
                    result.js_extracted = True

            # If leaked IPs found, log them
            if leaked_ips:
                logger.info("JS Recon found %d leaked IPs", len(leaked_ips))
                if show_progress:
                    console.print(f"    [yellow]{len(leaked_ips)} potential IPs leaked in JS[/yellow]")

        except Exception as e:
            logger.error("JS Recon stage failed: %s", e)
            stats.errors.append(f"JS Recon: {e}")

        return results

    def _stage_scoring(
        self,
        results: list[EnrichedResult],
        domain: str,
        stats: EnrichmentStats,
    ) -> None:
        """Stage 4: Apply confidence scoring and status classification."""
        self.scoring_engine.set_target_domain(domain)

        for result in results:
            self.scoring_engine.score(result)
            self.scoring_engine.determine_status(result)

    def _stage_fp_filter(
        self,
        results: list[EnrichedResult],
        stats: EnrichmentStats,
    ) -> list[EnrichedResult]:
        """Stage 5: Filter out false positives."""
        true_positives, false_positives = self.fp_filter.check_batch(results)
        stats.fp_filtered = len(false_positives)

        if false_positives:
            logger.info(
                "False positive filter removed/penalized %d results",
                len(false_positives),
            )

        return true_positives
