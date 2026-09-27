# Changelog

All notable changes to CloudFail-Killer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.8.0] - 2026-09-27

### Added
- **Signed reports (ed25519)**: `cloudkill sign report.json` / `cloudkill verify … --pubkey …`,
  plus `scan --sign` to deliver tamper-evident reports. Keys auto-generate at
  `~/.cloudkill/keys/` (`cloudkill[sign]` extra).
- **Plugin source system**: third-party data sources register via the
  `cloudkill.sources` entry-point group and load automatically — broken or
  non-conforming plugins are logged and skipped, never fatal
  (`cloudkill/sources/loader.py`, docs/plugins.md).
- **SARIF 2.1.0 export**: `--format sarif` / `-o report.sarif` — findings map to
  SARIF results with confidence-based levels (≥80 error · ≥50 warning · else note)
  and stable fingerprints for deduplication.
- **`--ci` mode**: quiet output, SARIF artifact by default, GitHub `::warning`
  annotations for the top findings, and strict exit codes (0 = findings,
  1 = none) on every profile — drops straight into security pipelines.
- **Fair batch parallelism**: `--batch-concurrency N` scans domains in flight
  while every data source draws from ONE shared token bucket — concurrency
  never multiplies the allowed request rate. Shared buckets re-bind their lock
  across event-loop restarts.
- **Documentation site**: mkdocs-material published to GitHub Pages
  (installation, profiles, sources, plugin authoring, signing, CI mode,
  batch scanning, architecture) with a real-terminal demo recording
  (`scripts/make-demo.py` → `docs/assets/demo.cast`).

### Fixed
- Rate limiter now re-checks the refill after waiting instead of granting an
  unrefilled token (found by the new fairness tests).

## [0.7.0] - 2026-09-26

### Added
- RapidDNS source: historical DNS subdomain database (keyless, IPv6-aware)
- SubdomainCenter source: aggregated subdomain intelligence (keyless, capped at 200)
- Shodan InternetDB origin verification (enrichment stage 3, keyless): verifies
  candidate origin IPs against hostnames observed on them; adds `internetdb_match`
  confidence signal with per-profile weights
- Batch scanning is now real: `--domains` scans every validated line of the file,
  writing per-domain output files (`results_example_com.json`)
- New CLI flags: `--proxy`, `--timeout`, `--min-confidence`, `--dns`,
  `--no-internetdb`
- Automation profile exit codes: 0 when results are found, 1 when a scan
  completes with no results
- Input validation wired into the CLI: target domains, batch entries and webhook
  URLs are validated before scanning starts (previously `InputValidator` was dead
  code)
- `--quiet` is now honored end to end (banner, progress bars, per-stage output,
  final summary)
- CI: GitHub Actions workflows for lint + tests (Python 3.11/3.12/3.13), Docker
  build, and PyPI release on tags
- Tests: 26 new unit tests covering the new sources, InternetDB verification,
  scoring signal, and output-format resolution (343 total)

### Fixed
- Output format detection: the file extension now takes priority over
  `--format`, so `-o report.md` no longer writes JSON into a `.md` file
- Empty scan results are now written to the output file (automation jobs need
  the artifact to exist either way)
- `BaseSource.is_configured()` no longer claims API-key sources are configured;
  the safe default is `False` until a source overrides the check
- `github_dork` requires `GITHUB_TOKEN` (GitHub code search returns 401 without
  authentication) — the source is skipped with a clear reason when unconfigured
- Host header probe: `domain` was referenced but never passed into
  `_analyze_result` (NameError on redirect analysis); scoring now receives it
- SSL checker: missing `cryptography.x509` import crashed CN/SAN/issuer
  extraction paths
- Cloudflare IP loader: missing `asyncio` import crashed the sync
  `load_ranges()` path
- Duplicate `ssl_match` key in the `enterprise` profile (both profiles.yaml
  copies); profile weights now include `internetdb_match`
- Host header baseline/status comparisons in `active_scanner` collapsed
  correctly; ~260 lint findings fixed, `ruff check` is now clean

### Changed
- Enrichment pipeline is now 7 stages: SSL → ASN → InternetDB → JS Recon →
  Scoring → FP Filter → Dedup
- `ScoringWeights` gained `internetdb_match` (profiles: researcher 20, pentester
  15, bugbounty 25, enterprise 15, automation 15)
- Scan profiles are documented honestly: they tune scoring weights only;
  probing/probes are controlled by `--active`
- User-Agent pool deduplicated into `cloudkill/utils/useragents.py` (single
  source of truth for engine + stealth)
- CLI profile list no longer advertises non-existent dashboards/scheduling
- Benchmark threshold for PDF export raised to 6s (environment-dependent)

## [0.6.0] - 2026-04-01

### Added
- Multi-arch Docker support (amd64 + arm64) with docker-compose
- Comprehensive README with badges, architecture diagram, CLI reference
- Full CONTRIBUTING guide with source/exporter development instructions
- SECURITY.md with responsible disclosure policy
- CHANGELOG.md for version tracking
- 317 tests covering unit, integration, and benchmark suites

## [0.5.0] - 2026-04-01

### Added
- Full pipeline integration tests (source → enrichment → active → export)
- IPv6 integration tests (SourceResult, EnrichedResult, Cache, Exporters)
- Performance benchmarks (object creation, serialization, filtering, scoring, export)

### Changed
- Updated test framework with conftest.py shared fixtures
- All tests passing (317 total)

## [0.4.0] - 2026-03-31

### Added
- Active HTTP/TCP probing with response comparison
- Host Header Injection probe (10 proxy + 8 origin indicators)
- SQLite cache with campaign history and IP discovery timeline (7-day TTL)
- Webhook notifications (Slack, Discord, Generic with auto-detection)
- PDF export with cover page, summary, tables (ReportLab)
- Nuclei YAML template + target list export
- JSON, CSV, Markdown export modules

### Changed
- Runner pipeline: Collection → Enrichment → Active → Host Header → Cache → Webhook → Export

## [0.3.0] - 2026-03-30

### Added
- 6-stage enrichment pipeline (SSL → ASN → JS → Scoring → FP Filter → Dedup)
- SSL Certificate Checker with wildcard support
- ASN Lookup (15+ hosting providers)
- JS Recon Engine (12 regex patterns)
- Multi-signal confidence scoring (0-100) with profile weights
- False Positive Filter (CDN/WAF/honeypot detection)
- Result deduplication

## [0.2.0] - 2026-03-29

### Added
- 13 passive data source plugins
- Favicon MurmurHash3 computation (Shodan/Censys query builders)
- Dual-stack DNS resolver (A + AAAA)
- Source registry with enable/disable

## [0.1.0] - 2026-03-28

### Added
- Async HTTP engine with httpx (HTTP/2, IPv6, retry, rate limiting)
- SourceRunner with concurrent execution
- Cloudflare IP range checker (v4 + v6)
- Stealth module (UA rotation, delays, Tor)
- 5 scan profiles with scoring weights
- Initial CLI (Typer + Rich)

## [0.0.1] - 2026-03-27

### Added
- Project foundation (pyproject.toml, MIT license, structure)
- Plugin architecture (BaseSource abstract class)
- Configuration system (Pydantic)
- SourceResult and EnrichedResult data models
