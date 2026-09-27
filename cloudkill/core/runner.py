"""
CloudFail-Killer - Source Runner

Orchestrates concurrent execution of all data source plugins and
runs the enrichment pipeline for SSL, ASN, scoring, and dedup.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from cloudkill.config import Config
from cloudkill.core.engine import AsyncEngine
from cloudkill.core.models import EnrichedResult, ScanReport
from cloudkill.sources.base import BaseSource, SourceResult
from cloudkill.utils.cloudflare_ips import CloudflareIPChecker
from cloudkill.utils.ratelimit import RateLimiter
from cloudkill.utils.stealth import StealthManager

logger = logging.getLogger(__name__)

console = Console()

# NAT64 Well-Known Prefix (RFC 6052) — synthetic addresses, never real origins
NAT64_WELL_KNOWN_PREFIX = ipaddress.ip_network("64:ff9b::/96")


def is_non_routable_ip(ip: str) -> bool:
    """Check whether an IP cannot be a public origin server.

    Rejects loopback, RFC1918/RFC4193 private ranges, link-local, reserved,
    multicast, unspecified, and NAT64 well-known-prefix addresses.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # Unparseable IPs can't be origins either

    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return True
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return True
    return (
        isinstance(addr, ipaddress.IPv6Address) and addr in NAT64_WELL_KNOWN_PREFIX
    )


class SourceRunner:
    """
    Orchestrates concurrent execution of data source plugins and
    runs the enrichment pipeline.

    Usage:
        runner = SourceRunner(config)
        report = await runner.run("example.com", sources)
    """

    def __init__(
        self,
        config: Config,
        engine: AsyncEngine | None = None,
        cf_checker: CloudflareIPChecker | None = None,
        enable_enrichment: bool = True,
        enable_cache: bool = True,
        enable_webhook: bool = True,
    ) -> None:
        self.config = config
        self.engine = engine
        self.cf_checker = cf_checker or CloudflareIPChecker()
        # shared=True: concurrent batch scans draw from ONE budget per
        # source — 3 concurrent domains never mean 3× the allowed rate.
        self.rate_limiter = RateLimiter(default_rate=2.0, default_burst=5, shared=True)
        self.stealth = StealthManager(
            enabled=config.stealth_mode.value == "stealth",
            min_delay=config.random_delay_min,
            max_delay=config.random_delay_max,
        )
        self.enable_enrichment = enable_enrichment
        self.enable_cache = enable_cache
        self.enable_webhook = enable_webhook
        self._enrichment_stats: dict[str, Any] | None = None
        self._active_stats: dict[str, Any] | None = None
        self._host_header_stats: dict[str, Any] | None = None

    async def run(
        self,
        domain: str,
        sources: list[BaseSource],
    ) -> ScanReport:
        """
        Run all sources concurrently and return a consolidated report.

        Args:
            domain: Target domain
            sources: List of configured source plugins

        Returns:
            ScanReport with all discovered results
        """
        report = ScanReport(domain=domain, profile=self.config.profile.value)

        if not self.config.quiet:
            console.print(f"\n[bold]Starting scan for [cyan]{domain}[/cyan][/bold]")
            console.print(f"  Sources: {len(sources)} configured")
            console.print(f"  Threads: {self.config.effective_threads}")
            console.print(f"  Stealth: {self.config.stealth_mode.value}")
            console.print(f"  Enrichment: {'enabled' if self.enable_enrichment else 'disabled'}")
            console.print(f"  Active: {'enabled' if self.config.active else 'disabled'}")
            console.print(f"  Cache: {'enabled' if self.enable_cache else 'disabled'}")
            console.print()

        # Load Cloudflare IP ranges
        try:
            await self.cf_checker.load_ranges_async()
            if not self.config.quiet:
                cf_stats = self.cf_checker.get_stats()
                console.print(
                    f"  [dim]Cloudflare ranges: {cf_stats['v4_ranges']} IPv4 + "
                    f"{cf_stats['v6_ranges']} IPv6 (cached={cf_stats['cached']})[/dim]"
                )
        except Exception as e:
            logger.warning("Failed to load Cloudflare ranges: %s", e)
            report.errors.append(f"Cloudflare ranges load failed: {e}")

        console.print()

        # Initialize engine if needed
        engine_needs_close = False
        if self.engine is None:
            self.engine = AsyncEngine(config=self.config)
            await self.engine.start()
            engine_needs_close = True

        # ── Phase A: Data Collection (source plugins) ──
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
            disable=self.config.quiet,
        ) as progress:
            overall_task = progress.add_task("[bold cyan]Collecting data[/]", total=1)

            # Run sources concurrently
            results = await self._run_sources_concurrent(
                domain=domain,
                sources=sources,
                progress=progress,
            )

            progress.update(overall_task, completed=1)

        # Process and filter results (remove Cloudflare IPs)
        total_raw = len(results)
        enriched_results = await self._process_results(results, report)

        # ── Phase B: Enrichment Pipeline ──
        if self.enable_enrichment and enriched_results:
            enriched_results = await self._run_enrichment(
                enriched_results, domain, report
            )

        # ── Phase B2: Confidence Threshold Filter ──
        if self.config.min_confidence > 0 and enriched_results:
            before = len(enriched_results)
            enriched_results = [
                r for r in enriched_results
                if r.confidence >= self.config.min_confidence
            ]
            dropped = before - len(enriched_results)
            if dropped and not self.config.quiet:
                console.print(
                    f"  [dim]Confidence filter (--min-confidence "
                    f"{self.config.min_confidence}): dropped {dropped} result(s)[/dim]"
                )

        # ── Phase C: Active Scanning ──
        if self.config.active and enriched_results:
            enriched_results = await self._run_active_scan(
                enriched_results, domain, report
            )

        # ── Phase D: Host Header Probe ──
        if self.config.active and enriched_results:
            enriched_results = await self._run_host_header_probe(
                enriched_results, domain, report
            )

        # Finalize report
        report.cloudflare_filtered = total_raw - len(enriched_results)
        for r in enriched_results:
            report.add_result(r)
        report.finalize()

        # Store enrichment stats in report metadata
        if self._enrichment_stats:
            report.enrichment_stats = self._enrichment_stats  # type: ignore

        # ── Phase E: Cache Results ──
        if self.enable_cache:
            self._store_in_cache(report)

        # ── Phase F: Webhook Notification ──
        if self.enable_webhook and (self.config.webhook.url or self.config.webhook.slack_url or self.config.webhook.discord_url):
            await self._send_webhook(report)

        # Close engine if we created it
        if engine_needs_close and self.engine:
            await self.engine.stop()

        # Print summary
        self._print_summary(report)

        return report

    async def _run_enrichment(
        self,
        results: list[EnrichedResult],
        domain: str,
        report: ScanReport,
    ) -> list[EnrichedResult]:
        """Run the enrichment pipeline on discovered results."""
        from cloudkill.core.enrichment import EnrichmentPipeline

        if not self.config.quiet:
            console.print()
            console.rule("[bold cyan]Enrichment Pipeline[/bold cyan]")
            console.print()

        pipeline = EnrichmentPipeline(
            config=self.config,
            enable_ssl=True,
            enable_asn=True,
            enable_js=self.config.active,
            enable_scoring=True,
            enable_fp_filter=True,
            enable_dedup=True,
            enable_internetdb=self.config.internetdb_enabled,
        )

        stats, enriched = await pipeline.enrich(
            results, domain, show_progress=not self.config.quiet
        )

        self._enrichment_stats = stats.to_dict()

        # Log enrichment stats
        logger.info("Enrichment complete: %s", stats.to_dict())

        # Add enrichment errors to report
        for err in stats.errors:
            report.errors.append(f"Enrichment: {err}")

        console.print()
        console.print(
            f"  [dim]Enrichment completed in {stats.enrichment_duration}[/dim]"
        )
        if stats.ssl_matched:
            console.print(f"  [green]SSL matches: {stats.ssl_matched}[/green]")
        if stats.asn_hosting_found:
            console.print(f"  [green]Hosting providers: {stats.asn_hosting_found}[/green]")
        if stats.fp_filtered:
            console.print(f"  [yellow]False positives filtered: {stats.fp_filtered}[/yellow]")
        if stats.duplicates_removed:
            console.print(f"  [yellow]Duplicates removed: {stats.duplicates_removed}[/yellow]")
        if stats.confirmed_count:
            console.print(f"  [bold green]Confirmed origins: {stats.confirmed_count}[/bold green]")

        return enriched

    async def _run_sources_concurrent(
        self,
        domain: str,
        sources: list[BaseSource],
        progress: Progress,
    ) -> list[SourceResult]:
        """Run all sources concurrently with error isolation."""
        results: list[SourceResult] = []

        # Create tasks for each source
        tasks = {}
        for source in sources:
            if not source.is_configured():
                logger.debug("Source %s not configured, skipping", source.name)
                continue
            task = asyncio.create_task(
                self._run_single_source(source, domain),
                name=source.name,
            )
            tasks[task] = source

        # Create progress tasks for sources
        source_tasks = {}
        for source in sources:
            if not source.is_configured():
                continue
            st = progress.add_task(f"  {source.name}", total=None)
            source_tasks[source.name] = st

        # Execute concurrently with wait/FIRST_COMPLETED for streaming results
        # (asyncio.as_completed is broken in Python 3.13+ — yields wrapper coroutines
        #  that don't match the original task objects used as dict keys)
        pending = set(tasks.keys())
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                source = tasks[task]
                try:
                    source_results = task.result()
                    count = len(source_results)
                    results.extend(source_results)
                    logger.debug("Source %s yielded %d results", source.name, count)

                    if source.name in source_tasks:
                        progress.update(source_tasks[source.name], completed=count)

                except Exception as e:
                    logger.warning("Source %s failed: %s", source.name, e)
                    if self.config.verbose:
                        console.print(f"  [yellow]Source {source.name} failed: {e}[/yellow]")
                    if source.name in source_tasks:
                        progress.update(source_tasks[source.name], completed=0)

        # Complete all source progress bars
        for st in source_tasks.values():
            try:
                completed = progress.tasks[st].completed or 0
            except (AttributeError, KeyError):
                completed = 0
            progress.update(st, completed=completed)

        return results

    async def _run_single_source(
        self,
        source: BaseSource,
        domain: str,
    ) -> list[SourceResult]:
        """Run a single source and collect all results."""
        results: list[SourceResult] = []

        try:
            # Apply stealth delay
            await self.stealth.delay()

            # Rate limiting
            await self.rate_limiter.wait(source.name)

            async for result in source.enumerate(domain):
                results.append(result)

                # Validate result has required fields
                if not result.ip:
                    continue

        except asyncio.CancelledError:
            logger.debug("Source %s cancelled", source.name)

        return results

    async def _process_results(
        self,
        raw_results: list[SourceResult],
        report: ScanReport,
    ) -> list[EnrichedResult]:
        """Process raw results: filter non-routable/CF IPs, enrich results."""
        enriched: list[EnrichedResult] = []

        for result in raw_results:
            # Filter out non-routable addresses (loopback, RFC1918, link-local,
            # NAT64 well-known prefix, etc.) — an origin behind a CDN is by
            # definition a public address.
            if is_non_routable_ip(result.ip):
                logger.debug(
                    "Filtered non-routable IP: %s (%s)",
                    result.ip,
                    result.subdomain,
                )
                report.non_routable_filtered += 1
                continue

            # Filter out Cloudflare IPs
            if self.cf_checker.is_cloudflare_ip(result.ip):
                logger.debug(
                    "Filtered Cloudflare IP: %s (%s)",
                    result.ip,
                    result.subdomain,
                )
                continue

            # Create enriched result
            enriched_result = EnrichedResult.from_source_result(result)
            enriched_result.is_cloudflare = False

            # Initial confidence boost for being non-CF
            enriched_result.confidence += 40
            enriched_result.confidence_reasons.append(
                f"IP {result.ip} is NOT in Cloudflare ranges (+40)"
            )

            enriched.append(enriched_result)

        return enriched

    async def _run_active_scan(
        self,
        results: list[EnrichedResult],
        domain: str,
        report: ScanReport,
    ) -> list[EnrichedResult]:
        """Run active scanning (port checks + HTTP probes)."""
        from cloudkill.core.active_scanner import ActiveScanner

        console.print()
        console.rule("[bold cyan]Active Scanning[/bold cyan]")
        console.print()

        scanner = ActiveScanner(
            timeout=self.config.timeout,
            max_concurrent=self.config.effective_threads,
            ports=self.config.active_ports,
            cf_checker=self.cf_checker,
        )

        probe_results = await scanner.scan(domain, results)

        matched = sum(1 for p in probe_results if p.result.value in ("match", "similar"))
        self._active_stats = {
            "total_probes": len(probe_results),
            "matched": matched,
            "ports_scanned": len(scanner.ports),
        }

        # Apply active probe boosts to results
        for probe in probe_results:
            if probe.confidence_boost > 0:
                for r in results:
                    if r.ip == probe.ip:
                        r.confidence = min(100, r.confidence + probe.confidence_boost)
                        r.confidence_reasons.extend([
                            f"Active probe: {', '.join(probe.reasons[:2])} "
                            f"(+{probe.confidence_boost})"
                        ])
                        break

        if probe_results:
            console.print(f"  [dim]Active scan: {matched}/{len(probe_results)} matches[/dim]")
            if matched:
                console.print(f"  [green]{matched} IPs responded to active probing[/green]")

        # Run port checks on unique IPs
        unique_ips = list({r.ip for r in results})
        port_results = await scanner.scan_ports(unique_ips, self.config.active_ports)
        open_ports = sum(1 for p in port_results if p.is_open)
        self._active_stats["open_ports"] = open_ports

        if open_ports:
            console.print(f"  [green]{open_ports} open ports found[/green]")

        return results

    async def _run_host_header_probe(
        self,
        results: list[EnrichedResult],
        domain: str,
        report: ScanReport,
    ) -> list[EnrichedResult]:
        """Run host header injection probe."""
        from cloudkill.core.host_header import HostHeaderProbe

        console.print()
        console.rule("[bold cyan]Host Header Probe[/bold cyan]")
        console.print()

        probe = HostHeaderProbe(
            timeout=self.config.timeout,
            max_concurrent=self.config.effective_threads,
            cf_checker=self.cf_checker,
        )

        # Fetch baseline (optional, may fail behind CF)
        console.print("  [dim]Fetching baseline response...[/dim]")
        baseline = await probe.fetch_baseline(domain, verify_ssl=False)

        console.print("  [dim]Probing IPs with Host header...[/dim]")
        probe_results = await probe.probe(domain, results, baseline)

        matched = sum(1 for p in probe_results if p.matched)
        self._host_header_stats = {
            "total_probes": len(probe_results),
            "matched": matched,
            "baseline_fetched": bool(baseline),
        }

        # Apply host header boosts
        for hh in probe_results:
            if hh.confidence_boost > 0:
                for r in results:
                    if r.ip == hh.ip:
                        r.confidence = min(100, r.confidence + hh.confidence_boost)
                        r.host_header_match = True
                        r.confidence_reasons.extend([
                            f"Host header {hh.match_type}: "
                            f"{', '.join(hh.reasons[:2])} (+{hh.confidence_boost})"
                        ])
                        break

        if probe_results:
            console.print(f"  [dim]Host header probe: {matched}/{len(probe_results)} matched[/dim]")
            if matched:
                console.print(f"  [green]{matched} IPs respond to domain Host header[/green]")

        return results

    def _store_in_cache(self, report: ScanReport) -> None:
        """Store scan results in SQLite cache."""
        try:
            from cloudkill.cache.sqlite_cache import SQLiteCache

            cache = SQLiteCache(
                cache_dir=self.config.cache_dir,
                ttl_days=7,
            )
            try:
                cache.initialize()
                cache.store_scan(report)
                logger.info("Scan results cached for %s", report.domain)
                console.print("  [dim]Results cached in SQLite[/dim]")
            finally:
                cache.close()
        except Exception as e:
            logger.warning("Cache store failed: %s", e)

    async def _send_webhook(self, report: ScanReport) -> None:
        """Send webhook notification with scan results."""
        try:
            from cloudkill.core.webhooks import WebhookSender

            sender = WebhookSender(
                timeout=15,
                proxy=self.config.proxy,
            )
            results = await sender.send_all(
                report,
                slack_url=self.config.webhook.slack_url,
                discord_url=self.config.webhook.discord_url,
                generic_url=self.config.webhook.url,
            )
            for platform, success in results.items():
                if success:
                    console.print(f"  [green]Webhook sent to {platform}[/green]")
                else:
                    console.print(f"  [yellow]Webhook to {platform} failed[/yellow]")
        except Exception as e:
            logger.warning("Webhook notification failed: %s", e)

    def _print_summary(self, report: ScanReport) -> None:
        """Print the scan summary using Rich."""
        if self.config.quiet:
            return
        console.print()
        console.rule("[bold cyan]Scan Complete[/bold cyan]")
        console.print()

        summary_table_data = [
            ("Domain", report.domain),
            ("Profile", report.profile),
            ("Duration", f"{report.scan_duration_seconds:.1f}s"),
            ("Total Results", str(report.total_results)),
            ("Unique IPs", str(report.unique_ips)),
            ("High Confidence (>=70)", str(report.high_confidence_count)),
            ("Confirmed", str(report.confirmed_count)),
            ("IPv4 Results", str(report.ipv4_count)),
            ("IPv6 Results", str(report.ipv6_count)),
            ("CF Filtered", str(report.cloudflare_filtered)),
            ("Sources Used", ", ".join(report.sources_used)),
            ("Errors", str(len(report.errors)) or "None"),
        ]

        for key, value in summary_table_data:
            console.print(f"  [bold]{key}:[/] {value}")

        # Print enrichment stats if available
        if self._enrichment_stats:
            stats = self._enrichment_stats
            console.print()
            console.print(f"  [bold]Enrichment:[/] {stats.get('enrichment_duration', 'N/A')}")
            if stats.get('ssl_matched', 0):
                console.print(f"    SSL matches: {stats['ssl_matched']}")
            if stats.get('asn_hosting_found', 0):
                console.print(f"    Hosting providers: {stats['asn_hosting_found']}")
            if stats.get('fp_filtered', 0):
                console.print(f"    False positives: {stats['fp_filtered']}")
            if stats.get('duplicates_removed', 0):
                console.print(f"    Duplicates: {stats['duplicates_removed']}")

        # Print active scan stats
        if self._active_stats:
            console.print()
            console.print(f"  [bold]Active Scan:[/] {self._active_stats.get('matched', 0)}/{self._active_stats.get('total_probes', 0)} matched")
            if self._active_stats.get('open_ports', 0):
                console.print(f"    Open ports: {self._active_stats['open_ports']}")

        # Print host header stats
        if self._host_header_stats:
            hh = self._host_header_stats
            console.print(f"  [bold]Host Header:[/] {hh.get('matched', 0)}/{hh.get('total_probes', 0)} matched")

        # Print high-confidence results
        high_conf = [r for r in report.results if r.confidence >= 50]
        if high_conf:
            console.print()
            console.print("[bold green]Potential Origin IPs:[/bold green]")
            for r in sorted(high_conf, key=lambda x: -x.confidence):
                ip_display = f"[cyan]{r.ip}[/cyan]" if not r.is_cloudflare else f"[dim]{r.ip}[/dim]"
                provider_badge = ""
                if r.hosting_provider:
                    provider_badge = f" [dim][{r.hosting_provider}][/dim]"
                elif r.asn_org:
                    provider_badge = f" [dim]({r.asn_org[:30]})[/dim]"
                ssl_badge = " [bold blue][SSL][/bold blue]" if r.ssl_matches else ""
                status_badge = ""
                if r.status.value == "confirmed":
                    status_badge = " [bold green][CONFIRMED][/bold green]"
                elif r.status.value == "potential":
                    status_badge = " [yellow][POTENTIAL][/yellow]"

                console.print(
                    f"  {ip_display} "
                    f"[dim]via {r.source}[/dim] "
                    f"[dim]| {r.subdomain}[/dim]"
                    f"{provider_badge}"
                    f"{ssl_badge}"
                    f"{status_badge} "
                    f"[bold green]({r.confidence}%)[/bold green]"
                )

                # Show confidence reasons
                if self.config.verbose and r.confidence_reasons:
                    for reason in r.confidence_reasons[:3]:
                        console.print(f"    [dim]- {reason}[/dim]")

        if not high_conf:
            console.print()
            console.print("[yellow]No potential origin IPs found.[/yellow]")
            console.print("[dim]Try different profiles or enable active scanning with --active.[/dim]")
