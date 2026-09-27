# CloudKill

<p align="center">
  <strong>Advanced Origin IP Discovery for Cloudflare-Protected Domains</strong>
  <br><sub>Developed by <a href="https://github.com/smart-jemy">smart-jemy</a></sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green?logo=opensourceinitiative" alt="License">
  <img src="https://img.shields.io/badge/Tests-343%20passed-success?logo=pytest" alt="Tests">
  <img src="https://img.shields.io/badge/IPv6-Native-orange?logo=ipv6" alt="IPv6">
  <img src="https://img.shields.io/badge/Sources-15%2B-informational" alt="Sources">
  <img src="https://img.shields.io/badge/Version-0.8.0-blue" alt="Version">
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#profiles">Profiles</a> •
  <a href="#data-sources">Data Sources</a> •
  <a href="#exports">Exports</a> •
  <a href="#docker">Docker</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#contributing">Contributing</a>
</p>

---

CloudKill (`cloudkill`) is a multi-source, IPv6-native reconnaissance tool designed to discover origin IP addresses hidden behind Cloudflare's proxy network. It combines 13+ passive and active data sources with a 6-stage enrichment pipeline to provide confidence-scored results.

Built for security researchers, penetration testers, and bug bounty hunters who need reliable origin IP enumeration.

## Features

- **15+ Data Sources**: crt.sh, CertSpotter, OTX, Wayback, URLScan, HackerTarget, DNSDumpster, WhoisXML, GitHub Dorking, Favicon Hash (Shodan/Censys), SPF/DKIM, ACME Audit, RapidDNS, SubdomainCenter
- **IPv6 Native**: Full dual-stack DNS resolution (A + AAAA), HTTP/2, IPv6-enriched results
- **7-Stage Enrichment Pipeline**: SSL Certificate Analysis → ASN/Hosting Detection → Shodan InternetDB Verification → JS Recon → Confidence Scoring → False Positive Filtering → Deduplication
- **Active Probing**: Safe HTTP-level probing (NOT SYN scans), Host Header Injection, TCP port checks
- **5 Scan Profiles**: Researcher, Pentester, Bug Bounty, Enterprise, Automation — each with tuned scoring weights (weights only; probing is controlled by `--active`)
- **Multi-Format Export**: JSON, CSV, IP List, Markdown Report, PDF (ReportLab), **SARIF 2.1.0**, Nuclei Templates
- **✍️ Signed Reports**: ed25519 signatures on every deliverable — clients verify the report was never altered
- **🧩 Plugin Sources**: community data sources via entry points — extend without touching the code
- **🤖 CI Mode**: `--ci` emits SARIF + GitHub annotations + strict exit codes for pipelines
- **⚖️ Fair Batch Parallelism**: `--batch-concurrency` scans domains in parallel while every source keeps ONE shared rate-limit budget
- **SQLite Cache**: Campaign history, IP discovery timeline, cross-scan tracking with 7-day TTL
- **Webhook Notifications**: Slack, Discord, Generic — auto-detected from URL
- **Stealth Mode**: Random delays, User-Agent rotation, Tor proxy support
- **Confidence Scoring**: Profile-weighted multi-signal scoring (0-100) with CONFIRMED/POTENTIAL/FALSE_POSITIVE classification

## Documentation

📘 **Full docs**: [smart-jemy.github.io/cloudfail-killer](https://smart-jemy.github.io/cloudfail-killer/) — installation, profiles, sources, [plugin authoring](https://smart-jemy.github.io/cloudfail-killer/plugins/), [signed reports](https://smart-jemy.github.io/cloudfail-killer/signing/), [CI mode & SARIF](https://smart-jemy.github.io/cloudfail-killer/ci/), and a [live demo](https://smart-jemy.github.io/cloudfail-killer/demo/).

## Installation

### From Source

```bash
git clone https://github.com/smart-jemy/cloudfail-killer.git
cd cloudfail-killer
python -m pip install -e ".[pdf,sign]"   # add [dev] for test/lint tooling
```

> Requires Python 3.11+. The package is not yet on PyPI — once published,
> `pip install cloudkill` will work and this note will be removed.

### Docker

```bash
# Build
docker build -f docker/Dockerfile -t cloudkill .

# Run
docker run --rm cloudkill scan example.com

# With volume for results
docker run --rm -v $(pwd)/results:/data cloudkill scan example.com -o /data/report.json
```

## Quick Start

```bash
# Basic scan with default researcher profile
cloudkill scan example.com

# Bug bounty mode with JSON output
cloudkill scan example.com --profile bugbounty -o results.json

# Pentester with active probing and Nuclei export
cloudkill scan example.com --profile pentester --active -f nuclei -o template.yaml

# Enterprise with PDF report and Slack notifications
cloudkill scan example.com --profile enterprise --format pdf -o report.pdf --slack-webhook https://hooks.slack.com/...

# IPv6 preference with stealth mode
cloudkill scan example.com --ipv6 --stealth --threads 10

# Batch scan multiple domains (per-domain output files)
cloudkill scan --domains domains.txt --profile pentester -f csv -o batch_results.csv

# Verify candidate origins against Shodan InternetDB (on by default) with a confidence floor
cloudkill scan example.com --min-confidence 40 -f md -o report.md

# Custom DNS servers + proxy (e.g., Tor)
cloudkill scan example.com --dns 1.1.1.1,9.9.9.9 --proxy socks5://127.0.0.1:9050

# CI/CD automation: JSON only, exit code 1 when nothing is found
cloudkill scan example.com --profile automation -f json -o out.json
```

## Profiles

| Profile | Best For | Output Format | Key Features |
|---------|----------|---------------|-------------|
| `researcher` | Deep analysis | JSON + CSV | Multi-source, historical data, smart scoring (default) |
| `pentester` | Fast actionable | CLI + Nuclei | Probing-weighted scoring; use with `--active` for probing |
| `bugbounty` | Hidden origins | Markdown + Slack | JS-Recon-weighted scoring, historical leaks |
| `enterprise` | Infrastructure monitoring | PDF + JSON | PDF report auto-added, SQLite history |
| `automation` | CI/CD integration | JSON + Stdout | API mode, Docker, clean exit codes |

## Data Sources

| Source | Type | API Key | Priority | Description |
|--------|------|---------|----------|-------------|
| `crtsh` | CT Logs | No | HIGH | Certificate Transparency logs via crt.sh |
| `certspotter` | CT Logs | Optional | LOW | CertSpotter certificate search API |
| `otx` | Threat Intel | No | HIGH | AlienVault OTX passive DNS + endpoints |
| `anubisdb` | Passive DNS | No | MEDIUM | AnubisDB subdomain enumeration |
| `wayback` | Historical | No | HIGH | Wayback Machine CDX API |
| `urlscan` | Historical | No | MEDIUM | URLScan.io DOM snapshots |
| `hackertarget` | DNS Lookup | No | LOW | HackerTarget DNS/hostsearch (50/day) |
| `dnsdumpster` | DNS Scraping | No | LOW | DNSDumpster DNS records |
| `whoisxml` | WHOIS/DNS | Optional | LOW | WhoisXML API (500 free) |
| `github_dork` | Code Search | Required | MEDIUM | GitHub code/IP search (`GITHUB_TOKEN`) |
| `favicon_hash` | Fingerprint | Optional | CRITICAL | MurmurHash3 favicon → Shodan/Censys |
| `spf_dkim` | Mail Records | No | HIGH | SPF/DKIM/DMARC origin correlation |
| `acme_check` | Config Audit | No | REFERENCE | ACME misconfiguration (CVE-2025-29441) |
| `rapiddns` | Historical DNS | No | MEDIUM | RapidDNS historical subdomain database |
| `subdomain_center` | Subdomains | No | MEDIUM | Subdomain.Center aggregated intelligence |

## CLI Reference

```
cloudkill scan <DOMAIN> [OPTIONS]

Options:
  -p, --profile TEXT       Scan profile [default: researcher]
  -6, --ipv6               Prefer IPv6 resolution
      --active             Enable light active probing
  -f, --format TEXT        Output: json, csv, txt, md, pdf, nuclei
  -o, --output PATH        Output file path
  -t, --threads INT        Concurrent threads [default: 20]
      --stealth            Enable stealth mode
      --verbose            Show detailed output
  -q, --quiet              Suppress output
      --domains PATH       Batch scan from file
      --webhook URL        Generic webhook URL
      --slack-webhook URL  Slack webhook URL
      --discord-webhook URL Discord webhook URL
      --no-cache           Disable SQLite caching
      --no-enrich          Disable enrichment pipeline
      --no-internetdb      Disable Shodan InternetDB verification
      --no-banner          Skip legal banner
      --proxy URL          HTTP/SOCKS proxy for all requests
      --timeout INT        Per-request timeout in seconds [default: 30]
      --min-confidence INT Drop results below this confidence (0-100)
      --dns SERVERS        Comma-separated DNS servers (e.g., 1.1.1.1,9.9.9.9)

Commands:
  profiles    List available scan profiles
  sources     List available data sources
  --version   Show version
```

## Exports

| Format | Extension | Description |
|--------|-----------|-------------|
| JSON | `.json` | Full structured report with metadata |
| CSV | `.csv` | Tabular results with filtering |
| IP List | `.txt` | Simple IP address list |
| Markdown | `.md` | Human-readable report with tables |
| PDF | `.pdf` | Professional report (cover page, summary, tables) |
| Nuclei | `.yaml` | Nuclei YAML template + target list |

## Docker

```bash
# Using docker-compose
cd docker
docker compose --profile scan up cloudkill

# Interactive shell
docker compose --profile shell run cloudkill-shell

# Custom scan
docker run --rm cloudkill scan example.com --profile pentester --active -f pdf -o /data/report.pdf
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CLOUDKILL_IPV6_PREFERENCE` | `false` | Prefer IPv6 DNS resolution |
| `CLOUDKILL_CACHE_DIR` | `~/.cache/cloudkill` | SQLite cache directory |
| `CLOUDKILL_STEALTH_MODE` | `normal` | Stealth mode: normal, stealth, tor |
| `OTX_API_KEY` | - | AlienVault OTX API key |
| `SHODAN_API_KEY` | - | Shodan API key (favicon hash) |
| `CENSYS_API_ID` | - | Censys API ID (favicon hash) |
| `CENSYS_API_SECRET` | - | Censys API secret (favicon hash) |
| `WHOISXML_API_KEY` | - | WhoisXML API key |
| `GITHUB_TOKEN` | - | GitHub token — required for `github_dork` |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      CLI (Typer + Rich)                  │
├─────────────────────────────────────────────────────────┤
│                    SourceRunner (Pipeline)               │
├─────────┬──────────┬───────────┬──────────┬────────────┤
│ Sources │Enrichment│Active Scan│Host Header│  Exporters  │
│  (13+)  │(6 stages)│  (HTTP)   │ (Inject)  │ (6 formats)│
├─────────┴──────────┴───────────┴──────────┴────────────┤
│ AsyncEngine │ SQLiteCache │ Webhooks │ Stealth │ RateLim │
└─────────────────────────────────────────────────────────┘
```

**Enrichment Pipeline Stages:**
1. **SSL Certificate Check** — CN/SAN/issuer matching, Cloudflare cert detection
2. **ASN/Hosting Lookup** — 15+ hosting providers (AWS/GCP/Azure/OVH/DO/etc.)
3. **Shodan InternetDB Verification** — keyless origin check: hostnames observed on a candidate IP that fall under the target domain confirm the origin
4. **JS Recon** — 12 regex patterns for endpoint/IP/key extraction
5. **Confidence Scoring** — Profile-weighted multi-signal (0-100)
6. **False Positive Filter** — CDN/WAF/honeypot detection with penalties
7. **Deduplication** — IP-based, keeps highest confidence

## Project Structure

```
cloudfail-killer/
├── cloudkill/
│   ├── cli.py              # Typer + Rich CLI
│   ├── config.py           # Pydantic config + profiles
│   ├── core/
│   │   ├── engine.py       # Async HTTP (IPv4+IPv6, HTTP/2)
│   │   ├── runner.py       # Pipeline orchestrator
│   │   ├── models.py       # Data models
│   │   ├── enrichment.py   # Enrichment pipeline
│   │   ├── active_scanner.py  # Safe active probing
│   │   ├── host_header.py  # Host header injection
│   │   ├── webhooks.py     # Slack/Discord/Generic
│   │   └── filters.py      # False positive filter
│   ├── sources/            # 15 data source plugins
│   ├── enrichers/          # SSL, ASN, InternetDB, JS, Scoring
│   ├── exporters/          # JSON, CSV, MD, PDF, Nuclei
│   ├── cache/              # SQLite campaign cache
│   ├── utils/              # DNS, favicon, stealth, rate limit
│   └── profiles/           # Scoring weights per profile
├── config/
│   └── profiles.yaml       # Profile configuration
├── tests/
│   ├── unit/               # Phase 0-5 unit tests
│   ├── integration/        # Pipeline + IPv6 integration
│   └── benchmarks/         # Performance benchmarks
├── docker/
│   ├── Dockerfile          # Multi-arch (amd64+arm64)
│   └── docker-compose.yml
├── .github/workflows/      # CI (lint + test matrix), Docker build, Release
└── pyproject.toml
```

## MITRE ATT&CK Mapping

| Technique | ID | Sources |
|-----------|-----|---------|
| DNS Resolution | T1590.002 | crt.sh, CertSpotter, SPF/DKIM |
| GitHub Search | T1593.002 | GitHub Dorking |
| JS Analysis | T1592.004 | JS Recon, Wayback |
| Historical Data | T1590.001 | Wayback, URLScan |
| Digital Fingerprint | T1596.005 | Favicon Hash (Shodan/Censys) |
| SSL/TLS Inspection | T1595.002 | SSL Checker |
| Active Probing | T1595.001 | Active Scanner, Host Header |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Disclaimer

**For authorized security testing and educational purposes only.** Unauthorized use against systems you do not own or have explicit permission to test is illegal. The developers assume no liability for misuse.

## License

MIT License — see [LICENSE](LICENSE) for details.
