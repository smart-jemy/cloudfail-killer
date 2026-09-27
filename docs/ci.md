# CI Mode & SARIF

CloudKill plugs directly into security pipelines: `--ci` produces a
**SARIF 2.1.0** artifact, prints GitHub annotations, and uses strict exit
codes.

## GitHub Actions example

```yaml
name: origin-recon
on:
  schedule:
    - cron: "0 6 * * 1"   # weekly
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install "cloudkill[all]"
      - name: Scan
        run: cloudkill scan target.com --ci
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: sarif
          path: cloudkill-target.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: cloudkill-target.sarif
```

## What `--ci` changes

| Behavior | Normal | `--ci` |
|---|---|---|
| Console output | full | quiet |
| Artifact | `--output` optional | `cloudkill-<domain>.sarif` written always |
| Format | json default | **SARIF 2.1.0** |
| Findings | summary only | GitHub `::warning` annotations (top 5) |
| Exit code | 0 | **0** = origins found · **1** = no findings |

## Batch + CI

```bash
cloudkill scan --domains targets.txt --ci --batch-concurrency 4
```

One SARIF file per domain (`cloudkill-<domain>.sarif`), all scanned in
parallel with a single fair rate-limit budget per source.

## Level mapping

SARIF levels map from the confidence score:

| Confidence | SARIF level |
|---|---|
| ≥ 80 | `error` |
| 50 – 79 | `warning` |
| < 50 | `note` |
