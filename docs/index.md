# CloudKill — Origin IP Discovery

**CloudKill (`cloudkill`)** is a multi-source, IPv6-native reconnaissance tool
designed to discover origin IP addresses hidden behind Cloudflare's proxy
network. It combines 15+ passive and active data sources with a 6-stage
enrichment pipeline to provide confidence-scored results.

Built for security researchers, penetration testers, and bug bounty hunters
who need reliable, tamper-evident origin IP enumeration.

## Why CloudKill

| | |
|---|---|
| 🔎 **15+ data sources** | crt.sh, AlienVault OTX, Wayback, URLScan, RapidDNS, SubdomainCenter, Shodan InternetDB and more |
| 🧬 **IPv6-native** | Every stage resolves and reports IPv6 alongside IPv4 |
| 🎯 **Confidence scoring** | A 6-stage enrichment pipeline ranks candidates instead of dumping noise |
| ✍️ **Signed reports** | ed25519-signed deliverables — provably unaltered (see [Signing](signing.md)) |
| 🤖 **CI-ready** | SARIF 2.1.0 output, GitHub annotations, strict exit codes (see [CI Mode](ci.md)) |
| 🧩 **Plugin sources** | Community data sources via Python entry points (see [Plugins](plugins.md)) |
| ⚖️ **Fair batch mode** | Parallel domain scans that never multiply a source's rate limit |

## Quick taste

```bash
# Install
pip install "cloudkill[all]"

# Fast passive sweep
cloudkill scan example.com --profile researcher

# Bug-bounty depth with signed PDF deliverable
cloudkill scan target.com --profile bugbounty --format pdf --sign
```

Continue with [Installation](installation.md) and [Quick Start](quickstart.md).

## Authorization

CloudKill is intended for **authorized** security testing only. Scanning
domains you do not own or lack explicit permission to test is illegal. The
tool prints a legal banner and expects you to act accordingly.
