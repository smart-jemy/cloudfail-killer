"""
CloudFail-Killer CLI Entry Point

Multi-profile CLI tool for discovering origin IPs behind Cloudflare.
Supports IPv6, stealth mode, batch scanning, and multiple output formats.

Usage:
    cloudkill scan example.com --profile pentester --ipv6
    cloudkill scan example.com --profile bugbounty --output results.json
    cloudkill scan --domains domains.txt --profile automation -f json -o out/
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from cloudkill import __author__, __version__
from cloudkill.config import Config, OutputFormat, ScanProfile, StealthMode, WebhookConfig
from cloudkill.core.models import ScanReport
from cloudkill.core.runner import SourceRunner
from cloudkill.core.validator import InputValidator, ValidationError

app = typer.Typer(
    name="cloudkill",
    help="CloudFail-Killer: Discover origin IPs behind Cloudflare",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()
validator = InputValidator()

# Maps file extensions to output formats. Extensions take priority over
# --format so `-o report.md` always produces Markdown regardless of the
# default format.
EXTENSION_FORMATS = {
    ".json": "json",
    ".csv": "csv",
    ".txt": "txt",
    ".md": "md",
    ".markdown": "md",
    ".pdf": "pdf",
    ".yaml": "nuclei",
    ".yml": "nuclei",
    ".sarif": "sarif",
}

LEGAL_BANNER = rf"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║   ██████╗ ███████╗ ██████╗     ██████╗ ██████╗  █████╗ ███╗   ██╗████████╗ ║
║  ██╔════╝ ██╔══╝██╔═══██╗    ██╔══██╗██╔══██╗██╔══██╗████╗  ██║╚══██╔══╝ ║
║  ██║  ███╗█████╗  ██║   ██║    ██████╔╝██████╔╝███████║██╔██╗ ██║   ██║    ║
║  ██║   ██║██╔══╝  ██║   ██║    ██╔═══╝ ██╔══██╗██╔══██║██╚██╗██║   ██║    ║
║  ╚██████╔╝███████╗╚██████╔╝    ██║     ██║  ██║██║  ██║██║ ╚████║   ██║    ║
║   ╚═════╝ ╚══════╝ ╚═════╝     ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝ ║
║                                                                            ║
║         [bold cyan]ORIGIN IP DISCOVERY TOOL v{__version__}[/]                    ║
║                   [dim]Developed by {__author__}[/dim]                     ║
║                                                                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  [bold yellow]DISCLAIMER:[/] This tool is intended for [bold]AUTHORIZED[/]             ║
║  security testing and educational purposes ONLY.                              ║
║                                                                            ║
║  Unauthorized use of this tool against systems you do not own or have       ║
║  explicit permission to test is [bold red]ILLEGAL[/].                           ║
║                                                                            ║
║  The developers assume [bold]NO LIABILITY[/] for misuse of this tool.             ║
║  By proceeding, you confirm you have proper authorization.                  ║
║                                                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


def show_banner() -> None:
    """Display the legal disclaimer banner."""
    console.print(
        Panel(
            Text.from_ansi(LEGAL_BANNER),
            border_style="bold red",
            padding=(0, 1),
        )
    )
    console.print()


@app.callback(invoke_without_command=True)
def main(
    version: bool = typer.Option(
        False, "--version", "-v", help="Show version and exit"
    ),
) -> None:
    """CloudKill: Advanced origin IP discovery behind Cloudflare."""
    if version:
        console.print(f"cloudkill v{__version__}")
        raise typer.Exit()


def _validate_domain_or_exit(domain: str) -> str:
    """Validate a target domain, exiting with a clear error when invalid."""
    try:
        return validator.validate_domain(domain)
    except ValidationError as e:
        console.print(f"[bold red]Invalid domain:[/] {e.message}")
        raise typer.Exit(1) from None


def _validate_webhooks_or_exit(
    webhook: str | None,
    slack_webhook: str | None,
    discord_webhook: str | None,
) -> None:
    """Validate webhook URLs before starting a scan."""
    for label, url in (
        ("--webhook", webhook),
        ("--slack-webhook", slack_webhook),
        ("--discord-webhook", discord_webhook),
    ):
        if url:
            try:
                validator.validate_webhook_url(url)
            except ValidationError as e:
                console.print(f"[bold red]Invalid {label}:[/] {e.message}")
                raise typer.Exit(1) from None


def _load_domains_file(path: str) -> list[str]:
    """Load and validate domains from a batch file."""
    file_path = Path(path)
    if not file_path.is_file():
        console.print(f"[bold red]Error:[/] Domains file not found: {path}")
        raise typer.Exit(1)

    valid: list[str] = []
    invalid: list[str] = []
    for line in file_path.read_text().splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        try:
            valid.append(validator.validate_domain(entry))
        except ValidationError:
            invalid.append(entry)

    if invalid:
        console.print(
            f"[yellow]Skipping {len(invalid)} invalid domain(s):[/] "
            f"{', '.join(invalid[:5])}{'…' if len(invalid) > 5 else ''}"
        )
    return valid


@app.command()
def scan(
    domain: str | None = typer.Argument(
        None,
        help="Target domain (e.g., example.com). Optional when --domains is used.",
    ),
    profile: str = typer.Option(
        "researcher",
        "--profile", "-p",
        help="Scan profile: researcher, pentester, bugbounty, enterprise, automation",
    ),
    ipv6: bool = typer.Option(
        False,
        "--ipv6", "-6",
        help="Prefer IPv6 resolution",
    ),
    active: bool = typer.Option(
        False,
        "--active",
        help="Enable light active probing (HTTP probes + port check)",
    ),
    output: str | None = typer.Option(
        None,
        "--output", "-o",
        help="Output file path (extension determines format: .json, .csv, .txt, .md)",
    ),
    threads: int = typer.Option(
        20,
        "--threads", "-t",
        help="Number of concurrent threads (1-200)",
    ),
    stealth: bool = typer.Option(
        False,
        "--stealth",
        help="Enable stealth mode (random delays + UA rotation)",
    ),
    fmt: str = typer.Option(
        "json",
        "--format", "-f",
        help="Output format: json, csv, txt, md, pdf, nuclei, sarif",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Show detailed output including low-confidence results",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet", "-q",
        help="Suppress all output except final results",
    ),
    domains: str | None = typer.Option(
        None,
        "--domains",
        help="File with list of domains to scan (batch mode)",
    ),
    webhook: str | None = typer.Option(
        None,
        "--webhook",
        help="Generic webhook URL for notifications",
    ),
    slack_webhook: str | None = typer.Option(
        None,
        "--slack-webhook",
        help="Slack webhook URL for notifications",
    ),
    discord_webhook: str | None = typer.Option(
        None,
        "--discord-webhook",
        help="Discord webhook URL for notifications",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Disable SQLite result caching",
    ),
    no_enrich: bool = typer.Option(
        False,
        "--no-enrich",
        help="Disable enrichment pipeline (SSL, ASN, scoring)",
    ),
    no_internetdb: bool = typer.Option(
        False,
        "--no-internetdb",
        help="Disable Shodan InternetDB origin verification",
    ),
    no_banner: bool = typer.Option(
        False,
        "--no-banner",
        help="Skip the legal disclaimer banner",
    ),
    proxy: str | None = typer.Option(
        None,
        "--proxy",
        help="HTTP/SOCKS proxy URL for all requests (e.g., socks5://127.0.0.1:9050)",
    ),
    timeout: int = typer.Option(
        30,
        "--timeout",
        help="Per-request timeout in seconds (5-120)",
    ),
    min_confidence: int = typer.Option(
        0,
        "--min-confidence",
        help="Drop results with confidence below this value (0-100)",
    ),
    dns: str | None = typer.Option(
        None,
        "--dns",
        help="Comma-separated DNS servers to query (e.g., 1.1.1.1,9.9.9.9)",
    ),
    ci: bool = typer.Option(
        False,
        "--ci",
        help="CI mode: quiet + SARIF artifact + GitHub annotations + strict exit codes",
    ),
    sign: bool = typer.Option(
        False,
        "--sign",
        help="Sign the output report with ed25519 (requires cloudkill[sign])",
    ),
    batch_concurrency: int = typer.Option(
        3,
        "--batch-concurrency",
        "-bc",
        min=1,
        max=10,
        help="Parallel domain scans in batch mode (rate limits stay fair: 1 shared budget per source)",
    ),
) -> None:
    """Scan a domain to discover origin IPs behind Cloudflare."""
    # Show legal banner unless suppressed
    if not no_banner and not quiet:
        show_banner()
        console.print()

    # Resolve targets: positional domain and/or --domains batch file
    targets: list[str] = []
    if domains:
        targets.extend(_load_domains_file(domains))
    if domain:
        targets.append(_validate_domain_or_exit(domain))
    if not targets:
        console.print("[bold red]Error:[/] No target domain given.")
        console.print("Usage: cloudkill scan example.com  |  cloudkill scan --domains domains.txt")
        raise typer.Exit(1)
    if len(targets) > 1 and output and Path(output).suffix == ".pdf":
        console.print("[bold red]Error:[/] PDF output is only supported for single-domain scans.")
        raise typer.Exit(1)

    # CI mode: quiet output, SARIF artifact by default, annotations on findings
    if ci:
        quiet = True
        if not output:
            output = f"cloudkill-{targets[0]}.sarif"
            if fmt == "json":
                fmt = "sarif"

    # Validate profile
    valid_profiles = [p.value for p in ScanProfile]
    if profile not in valid_profiles:
        console.print(f"[bold red]Error:[/] Invalid profile '{profile}'")
        console.print(f"Valid profiles: {', '.join(valid_profiles)}")
        raise typer.Exit(1)

    _validate_webhooks_or_exit(webhook, slack_webhook, discord_webhook)

    # Build configuration
    config_overrides: dict = {
        "ipv6_preference": ipv6,
        "active": active,
        "threads": threads,
        "timeout": timeout,
        "output": output,
        "verbose": verbose,
        "quiet": quiet,
        "min_confidence": min_confidence,
        "internetdb_enabled": not no_internetdb,
    }

    if proxy:
        config_overrides["proxy"] = proxy

    if dns:
        servers = [s.strip() for s in dns.split(",") if s.strip()]
        for server in servers:
            try:
                validator.validate_ip(server)
            except ValidationError:
                console.print(f"[bold red]Invalid --dns server:[/] {server}")
                raise typer.Exit(1) from None
        config_overrides["dns_servers"] = servers

    if stealth:
        config_overrides["stealth_mode"] = StealthMode.STEALTH

    try:
        config_overrides["output_format"] = OutputFormat(fmt)
    except ValueError:
        console.print(f"[bold red]Error:[/] Invalid format '{fmt}'")
        console.print(f"Valid formats: {', '.join(f.value for f in OutputFormat)}")
        raise typer.Exit(1) from None

    if webhook or slack_webhook or discord_webhook:
        config_overrides["webhook"] = WebhookConfig(
            url=webhook, slack_url=slack_webhook, discord_url=discord_webhook
        )

    try:
        scan_config = Config.from_profile(profile, **config_overrides)
    except Exception as e:
        console.print(f"[bold red]Configuration error:[/] {e}")
        raise typer.Exit(1) from None

    # Display scan configuration
    if not quiet:
        console.print(f"[bold cyan]CloudKill[/bold cyan] v{__version__}")
        console.print(f"[bold]Targets:[/] {len(targets)} ({', '.join(targets[:3])}{'…' if len(targets) > 3 else ''})")
        console.print(f"[bold]Profile:[/] {profile}")
        console.print(f"[bold]IPv6:[/] {'enabled' if ipv6 else 'disabled'}")
        console.print(f"[bold]Active:[/] {'enabled' if active else 'disabled'}")
        console.print(f"[bold]Stealth:[/] {scan_config.stealth_mode.value}")
        console.print(f"[bold]Threads:[/] {scan_config.effective_threads}")
        if not no_enrich:
            console.print("[bold]Enrichment:[/] SSL + ASN + InternetDB + Scoring + FP Filter")
        else:
            console.print("[bold]Enrichment:[/] [yellow]disabled[/yellow]")
        if output:
            console.print(f"[bold]Output:[/] {output}")
        console.print()

    # Run the scans
    reports: list[ScanReport] = []
    try:
        if len(targets) == 1 or batch_concurrency <= 1:
            for target in targets:
                if not quiet and len(targets) > 1:
                    console.print(f"[bold]── Scanning {target} ──[/]")
                reports.append(
                    asyncio.run(_run_scan(target, scan_config, enable_enrichment=not no_enrich))
                )
        else:
            # Parallel batch: N domains in flight, ONE shared rate-limit
            # budget per source (fairness), per-domain reports preserved.
            async def _run_batch() -> list:
                sem = asyncio.Semaphore(max(1, min(10, batch_concurrency)))

                async def _one(target: str) -> ScanReport:
                    async with sem:
                        if not quiet:
                            console.print(f"[bold]── Scanning {target} ──[/]")
                        return await _run_scan(
                            target, scan_config, enable_enrichment=not no_enrich
                        )

                return await asyncio.gather(
                    *(_one(t) for t in targets), return_exceptions=True
                )

            batch_results = asyncio.run(_run_batch())
            for item in batch_results:
                if isinstance(item, BaseException):
                    console.print(f"[red]Scan failed:[/] {item}")
                else:
                    reports.append(item)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        raise typer.Exit(130) from None

    # Save output if requested (empty reports are saved too — automation
    # needs the file to exist either way)
    if output:
        _save_reports(reports, output, fmt)

    # ed25519 signing — tamper-evident deliverables
    if sign and output:
        try:
            from cloudkill.signing import ensure_keypair, sign_file

            ensure_keypair()
            out_path = Path(output)
            if len(reports) > 1:
                signed = [
                    out_path.with_name(
                        f"{out_path.stem}_{r.domain.replace('.', '_')}{out_path.suffix}"
                    )
                    for r in reports
                ]
            else:
                signed = [out_path]
            for f in signed:
                if f.exists():
                    sig = sign_file(f)
                    console.print(f"[green]Signed:[/] {f} → {sig}")
        except Exception as e:
            console.print(f"[yellow]Signing skipped:[/] {e}")

    _summarize(reports, quiet=quiet)

    # CI mode: GitHub annotations + strict exit codes on any profile
    if ci:
        top = sorted(reports, key=lambda r: len(r.results), reverse=True)
        shown = 0
        for report in top:
            for res in report.results:
                if shown >= 5:
                    break
                console.print(
                    f"::warning title=Origin candidate::"
                    f"{res.subdomain} -> {res.ip} (confidence {res.confidence})"
                )
                shown += 1
        if not any(r.results for r in reports):
            raise typer.Exit(1)

    # Automation profile: clean, CI-friendly exit codes
    # 0 = results found, 1 = scan completed with no results
    if profile == ScanProfile.AUTOMATION.value and not any(
        r.results for r in reports
    ):
        raise typer.Exit(1)


async def _run_scan(domain: str, config: Config, enable_enrichment: bool = True) -> ScanReport:
    """Execute the scan using the SourceRunner."""
    from cloudkill.core.engine import AsyncEngine
    from cloudkill.sources import get_enabled_sources

    # Initialize engine first (sources may need it for HTTP requests)
    engine = AsyncEngine(config=config)
    await engine.start()

    # Get all enabled and configured source plugins
    sources = get_enabled_sources(config=config, engine=engine)

    if not sources:
        console.print("[yellow]No enabled data source plugins found.[/yellow]")
        console.print("[dim]Most sources work without API keys. Check --help for details.[/dim]")
        report = ScanReport(domain=domain, profile=config.profile.value)
        report.errors.append("No enabled sources")
        report.finalize()
        await engine.stop()
        return report

    # Show which sources will be used
    configured_count = sum(1 for s in sources if s.is_configured())
    if not config.quiet:
        console.print(f"  [bold]Sources enabled:[/] {len(sources)} ({configured_count} configured)")
        if config.verbose:
            for s in sources:
                status = "[green]OK[/green]" if s.is_configured() else "[yellow]no key[/yellow]"
                console.print(f"    {s.name:<20} {status}")
        console.print()

    # Run the scan
    runner = SourceRunner(config=config, engine=engine, enable_enrichment=enable_enrichment)
    try:
        report = await runner.run(domain, sources)
        return report
    finally:
        await engine.stop()


@app.command("sign")
def sign_report(
    file: str = typer.Argument(..., help="Report file to sign (any format)"),
    key: str | None = typer.Option(
        None, "--key", help="Private key path (default: ~/.cloudkill/keys/default.key)"
    ),
) -> None:
    """Sign a report with ed25519 — the client can prove it was never altered."""
    try:
        from cloudkill.signing import sign_file
    except Exception as e:
        console.print(f"[bold red]{e}[/bold red]")
        raise typer.Exit(1) from None
    try:
        sig = sign_file(file, key)
        console.print(f"[green]Signed ✓[/] {file}\n[dim]signature: {sig}[/dim]")
        console.print("[dim]Deliver both files. Verify with: cloudkill verify[/dim]")
    except Exception as e:
        console.print(f"[bold red]Signing failed:[/] {e}")
        raise typer.Exit(1) from None


@app.command("verify")
def verify_report(
    file: str = typer.Argument(..., help="The report file to check"),
    sig: str = typer.Option(
        ..., "--sig", help="Signature file (report.json.sig)"
    ),
    pubkey: str = typer.Option(
        ..., "--pubkey", help="Public key path (default: ~/.cloudkill/keys/default.pub)"
    ),
) -> None:
    """Verify a signed report — fails on ANY byte-level alteration."""
    from pathlib import Path as _Path

    from cloudkill.signing import verify_file

    if not (_Path(file).exists() and _Path(sig).exists() and _Path(pubkey).exists()):
        console.print("[bold red]Error:[/] file, signature or public key not found.")
        raise typer.Exit(1)

    if verify_file(file, sig, pubkey):
        console.print(f"[green]✓ VALID[/] — {file} is byte-for-byte what was signed.")
    else:
        console.print(f"[bold red]✗ INVALID[/] — {file} was modified or the signature is wrong.")
        raise typer.Exit(1)


def _report_format(output_path: str, fmt: str) -> str:
    """Decide the effective export format: extension wins over --format."""
    return EXTENSION_FORMATS.get(Path(output_path).suffix.lower(), fmt)


def _save_reports(reports: list[ScanReport], output_path: str, fmt: str) -> None:
    """Save one or more scan reports using exporters.

    Single-domain scans write exactly to output_path. Batch scans embed
    the domain in the file name so reports never overwrite each other.
    """
    effective_fmt = _report_format(output_path, fmt)
    path = Path(output_path)

    jobs: list[tuple[ScanReport, Path]] = []
    if len(reports) == 1:
        jobs.append((reports[0], path))
    else:
        for report in reports:
            safe_domain = report.domain.replace(".", "_")
            jobs.append((report, path.with_name(f"{path.stem}_{safe_domain}{path.suffix}")))

    for report, target_path in jobs:
        _save_report(report, target_path, effective_fmt)


def _save_report(report: ScanReport, path: Path, fmt: str) -> None:
    """Save a single scan report to file using exporters."""
    try:
        if fmt == "json":
            from cloudkill.exporters.json_export import export_json
            saved = export_json(report, path)
            console.print(f"\n[green]Results saved to [bold]{saved}[/bold][/green]")

        elif fmt == "csv":
            from cloudkill.exporters.csv_export import export_csv
            saved = export_csv(report, path)
            console.print(f"\n[green]Results saved to [bold]{saved}[/bold][/green]")

        elif fmt == "txt":
            from cloudkill.exporters.csv_export import export_ip_list
            saved = export_ip_list(report, path)
            console.print(f"\n[green]IP list saved to [bold]{saved}[/bold][/green]")

        elif fmt == "md":
            from cloudkill.exporters.markdown_export import export_markdown
            saved = export_markdown(report, path)
            console.print(f"\n[green]Markdown report saved to [bold]{saved}[/bold][/green]")

        elif fmt == "pdf":
            from cloudkill.exporters.pdf_export import export_pdf
            saved = export_pdf(report, path)
            console.print(f"\n[green]PDF report saved to [bold]{saved}[/bold][/green]")

        elif fmt == "sarif":
            from cloudkill.exporters.sarif_export import export_sarif
            saved = export_sarif(report, path)
            console.print(f"\n[green]SARIF report saved to [bold]{saved}[/bold][/green]")

        elif fmt == "nuclei":
            from cloudkill.exporters.nuclei import export_nuclei_template
            saved = export_nuclei_template(report, path)
            console.print(f"\n[green]Nuclei template saved to [bold]{saved}[/bold][/green]")

        else:
            # Unknown format fallback: JSON
            from cloudkill.exporters.json_export import export_json
            saved = export_json(report, path)
            console.print(f"\n[green]Results saved to [bold]{saved}[/bold][/green]")

    except Exception as e:
        console.print(f"[bold red]Error saving results:[/] {e}")


def _summarize(reports: list[ScanReport], quiet: bool = False) -> None:
    """Print a compact end-of-scan summary."""
    if quiet:
        for report in reports:
            ips = [r.ip for r in report.results]
            if ips:
                console.print(f"{report.domain}: " + ", ".join(ips))
            else:
                console.print(f"{report.domain}: no results")
        return

    for report in reports:
        confirmed = sum(1 for r in report.results if r.status.value == "confirmed")
        console.print(
            f"\n[bold]Summary {report.domain}:[/] "
            f"{report.unique_ips} unique IPs "
            f"({confirmed} confirmed, {report.high_confidence_count} high-confidence) "
            f"in {report.scan_duration_seconds:.1f}s"
        )


@app.command()
def profiles() -> None:
    """List available scan profiles with descriptions."""
    console.print("[bold]Available Scan Profiles:[/]\n")
    profiles_data = [
        ("researcher", "Comprehensive data collection with high accuracy", "JSON + CSV", "Multi-source, historical, smart scoring"),
        ("pentester", "Fast actionable results", "CLI Table + Nuclei", "Tuned scoring weights; combine with --active for probing"),
        ("bugbounty", "Discover hidden origins", "Markdown + Slack", "JS-Recon-weighted scoring, historical leaks"),
        ("enterprise", "Infrastructure monitoring", "PDF + JSON", "PDF report auto-added, SQLite history"),
        ("automation", "CI/CD integration", "JSON + Stdout", "Machine-readable output, clean exit codes"),
    ]
    for name, goal, output, features in profiles_data:
        console.print(f"  [bold cyan]{name}[/]")
        console.print(f"    Goal:     {goal}")
        console.print(f"    Output:   {output}")
        console.print(f"    Features: {features}")
        console.print()


@app.command()
def sources(verbose_list: bool = typer.Option(
        False, "--verbose", "-v", help="Show detailed source information"
)) -> None:
    """List available data sources and their status."""
    from cloudkill.sources import get_source_info

    source_info = get_source_info()

    console.print("[bold]Available Data Sources:[/]")
    console.print(f"  Total registered: {len(source_info)}\n")

    # Static priority mapping for display
    priority_map = {
        "favicon_hash": "CRITICAL",
        "otx": "HIGH",
        "wayback": "HIGH",
        "spf_dkim": "HIGH",
        "crtsh": "HIGH",
        "urlscan": "MEDIUM",
        "anubisdb": "MEDIUM",
        "github_dork": "MEDIUM",
        "rapiddns": "MEDIUM",
        "subdomain_center": "MEDIUM",
        "hackertarget": "LOW",
        "dnsdumpster": "LOW",
        "whoisxml": "LOW",
        "certspotter": "LOW",
        "acme_check": "REFERENCE",
    }

    if verbose_list:
        for info in source_info:
            name = info["name"]
            priority = priority_map.get(name, "MEDIUM")
            api_req = info["requires_api_key"]
            ipv6 = info["supports_ipv6"]
            enabled = info["default_enabled"]
            console.print(f"  [bold cyan]{name}[/]")
            console.print(f"    Description:     {info['description']}")
            console.print(f"    Priority:        {priority}")
            console.print(f"    API Key:         {'Required' if api_req == 'True' else 'Not required'}")
            console.print(f"    IPv6:            {'Yes' if ipv6 == 'True' else 'No'}")
            console.print(f"    Default Enabled: {'Yes' if enabled == 'True' else 'No'}")
            console.print()
    else:
        console.print(f"  {'Source':<20} {'Priority':<12} {'API Key':<12} {'IPv6':<6} {'Enabled':<8}")
        console.print(f"  {'─'*20} {'─'*12} {'─'*12} {'─'*6} {'─'*8}")
        for info in source_info:
            name = info["name"]
            priority = priority_map.get(name, "MEDIUM")
            console.print(
                f"  {name:<20} {priority:<12} "
                f"{'Yes' if info['requires_api_key'] == 'True' else 'No':<12} "
                f"{'Yes' if info['supports_ipv6'] == 'True' else 'No':<6} "
                f"{'Yes' if info['default_enabled'] == 'True' else 'No':<8}"
            )


if __name__ == "__main__":
    app()
