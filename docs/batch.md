# Batch Scanning

Batch mode scans a list of domains — now with **real parallelism** and a
**single fair rate-limit budget per source**.

## Usage

```bash
# domains.txt — one domain per line
cloudkill scan --domains targets.txt --profile automation -f json -o results.json
```

Every validated line is scanned and written to its own file
(`results_example_com.json`) — automation jobs get an artifact per domain
either way.

## Parallelism without abuse

```bash
cloudkill scan --domains targets.txt --batch-concurrency 4
```

- `--batch-concurrency` (1–10, default 3) controls how many domains are
  scanned **in flight**.
- Each domain still goes through every enabled source with full enrichment.
- **Fairness guarantee:** all concurrent scans draw from **one shared token
  bucket per data source**. Running 4 domains in parallel never means 4× the
  allowed request rate against crt.sh, OTX or any other source — the tool
  waits instead of hammering.
- Shared buckets survive event-loop restarts (the lock re-binds), so
  sequential `asyncio.run()` calls and parallel runs behave identically.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All scans completed (findings written per domain) |
| 1 | Automation profile finished with no findings (CI signal) |
| 130 | Interrupted by user |
