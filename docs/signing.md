# Signed Reports (ed25519)

CloudKill can sign every deliverable with **ed25519**, so your client — or
your lawyer — can prove the report you delivered is **byte-for-byte the file
the scan produced**, and that it came from the holder of your private key.

## Setup

```bash
pip install "cloudkill[sign]"
```

A keypair is generated automatically on first use at:

```
~/.cloudkill/keys/default.key   ← keep private, back it up
~/.cloudkill/keys/default.pub   ← give this to clients
```

## Sign during a scan

```bash
cloudkill scan target.com --profile pentester --format pdf --sign
# → report.pdf + report.pdf.sig
```

Or sign an existing report:

```bash
cloudkill sign report.json
# → report.json.sig
```

## Client-side verification (no CloudKill needed)

```bash
cloudkill verify report.json --sig report.json.sig --pubkey default.pub
# ✓ VALID — report.json is byte-for-byte what was signed.
```

Verification only needs the **public key** — hand `default.pub` to the client
and they can verify the report on any machine.

## What counts as tampering

Verification covers the **exact bytes** of the file. All of these invalidate
a signature:

- Editing a single IP address or confidence score
- Removing a finding
- Converting line endings (CRLF ↔ LF)
- Re-saving from a word processor
- Appending anything — even a trailing newline

## CI tip

Combine with [CI Mode](ci.md): `cloudkill scan --ci --sign` produces a
SARIF artifact **and** its signature in the same run.
