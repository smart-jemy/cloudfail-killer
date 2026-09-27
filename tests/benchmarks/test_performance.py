"""
CloudFail-Killer - Performance Benchmarks

Measures execution speed of critical pipeline components to ensure
the tool meets performance targets specified in the roadmap.
"""

import json
import time
from dataclasses import dataclass

import pytest

from cloudkill.config import Config
from cloudkill.core.filters import FalsePositiveFilter
from cloudkill.core.models import EnrichedResult, ResultStatus, ScanReport
from cloudkill.enrichers.scoring import ResultDeduplicator, ScoringEngine
from cloudkill.exporters.csv_export import export_csv
from cloudkill.exporters.json_export import export_json, export_json_string
from cloudkill.exporters.markdown_export import export_markdown
from cloudkill.exporters.pdf_export import export_pdf
from cloudkill.sources.base import IPVersion, SourceResult

# ═══════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════

def make_result(ip: str, confidence: int = 50, source: str = "bench") -> EnrichedResult:
    return EnrichedResult(
        subdomain="bench.com", ip=ip,
        ip_version=IPVersion.V6 if ":" in ip else IPVersion.V4,
        source=source, confidence=confidence,
        is_cloudflare=False, status=ResultStatus.POTENTIAL,
        confidence_reasons=[f"Bench: {confidence}%"],
    )


@dataclass
class BenchResult:
    """Result of a single benchmark measurement."""
    name: str
    iterations: int
    total_seconds: float
    ops_per_second: float
    avg_ms: float


# ═══════════════════════════════════════════════════════════
# SOURCE RESULT CREATION BENCHMARK
# ═══════════════════════════════════════════════════════════

class TestSourceResultCreationBench:

    def test_create_1000_source_results(self):
        """Benchmark: creating 1000 SourceResult objects."""
        start = time.monotonic()
        for i in range(1000):
            SourceResult(
                subdomain=f"sub{i}.bench.com",
                ip=f"10.0.{i // 256}.{i % 256}",
                source="bench",
                port=443,
            )
        elapsed = time.monotonic() - start

        result = BenchResult(
            name="SourceResult creation (1000)",
            iterations=1000,
            total_seconds=elapsed,
            ops_per_second=1000 / elapsed,
            avg_ms=(elapsed / 1000) * 1000,
        )
        print(f"\n  [BENCH] {result.name}")
        print(f"    Total: {result.total_seconds:.4f}s | "
              f"{result.ops_per_second:.0f} ops/s | "
              f"{result.avg_ms:.3f}ms/op")
        assert result.avg_ms < 5.0  # Should be < 5ms per creation

    def test_create_10000_source_results(self):
        """Benchmark: creating 10000 SourceResult objects."""
        start = time.monotonic()
        for i in range(10000):
            SourceResult(
                subdomain=f"sub{i}.bench.com",
                ip=f"10.{i // 256 // 256}.{i % 256}.{i % 256}",
                source="bench",
            )
        elapsed = time.monotonic() - start

        result = BenchResult(
            name="SourceResult creation (10000)",
            iterations=10000,
            total_seconds=elapsed,
            ops_per_second=10000 / elapsed,
            avg_ms=(elapsed / 10000) * 1000,
        )
        print(f"\n  [BENCH] {result.name}")
        print(f"    Total: {result.total_seconds:.4f}s | "
              f"{result.ops_per_second:.0f} ops/s | "
              f"{result.avg_ms:.3f}ms/op")
        assert result.avg_ms < 1.0


# ═════════════════════════════════════════════════════════════
# ENRICHED RESULT CREATION BENCHMARK
# ═══════════════════════════════════════════════════════════

class TestEnrichedResultCreationBench:

    def test_create_1000_enriched_results(self):
        """Benchmark: creating 1000 EnrichedResult objects."""
        start = time.monotonic()
        for i in range(1000):
            EnrichedResult(
                subdomain=f"sub{i}.bench.com",
                ip=f"10.0.{i // 256}.{i % 256}",
                ip_version=IPVersion.V4,
                source="bench",
                confidence=50,
                is_cloudflare=False,
                status=ResultStatus.POTENTIAL,
                confidence_reasons=["Bench"],
            )
        elapsed = time.monotonic() - start

        result = BenchResult(
            name="EnrichedResult creation (1000)",
            iterations=1000,
            total_seconds=elapsed,
            ops_per_second=1000 / elapsed,
            avg_ms=(elapsed / 1000) * 1000,
        )
        print(f"\n  [BENCH] {result.name}")
        print(f"    Total: {result.total_seconds:.4f}s | "
              f"{result.ops_per_second:.0f} ops/s | "
              f"{result.avg_ms:.3f}ms/op")
        assert result.avg_ms < 5.0

    def test_from_source_result_1000(self):
        """Benchmark: EnrichedResult.from_source_result x1000."""
        results = []
        start = time.monotonic()
        for i in range(1000):
            sr = SourceResult(
                subdomain=f"sub{i}.bench.com",
                ip=f"10.0.{i // 256}.{i % 256}",
                source="bench",
            )
            results.append(EnrichedResult.from_source_result(sr))
        elapsed = time.monotonic() - start

        result = BenchResult(
            name="EnrichedResult.from_source_result (1000)",
            iterations=1000,
            total_seconds=elapsed,
            ops_per_second=1000 / elapsed,
            avg_ms=(elapsed / 1000) * 1000,
        )
        print(f"\n  [BENCH] {result.name}")
        print(f"    Total: {result.total_seconds:.4f}s | "
              f"{result.ops_per_second:.0f} ops/s | "
              f"{result.avg_ms:.3f}ms/op")
        assert len(results) == 1000


# ═══════════════════════════════════════════════════════════
# TO_DICT SERIALIZATION BENCHMARK
# ═══════════════════════════════════════════════════════════

class TestSerializationBench:

    def test_enriched_result_to_dict_1000(self):
        """Benchmark: EnrichedResult.to_dict() x1000."""
        results = [make_result(f"10.0.0.{i}") for i in range(1000)]

        start = time.monotonic()
        dicts = [r.to_dict() for r in results]
        elapsed = time.monotonic() - start

        result = BenchResult(
            name="EnrichedResult.to_dict (1000)",
            iterations=1000,
            total_seconds=elapsed,
            ops_per_second=1000 / elapsed,
            avg_ms=(elapsed / 1000) * 1000,
        )
        print(f"\n  [BENCH] {result.name}")
        print(f"    Total: {result.total_seconds:.4f}s | "
              f"{result.ops_per_second:.0f} ops/s | "
              f"{result.avg_ms:.3f}ms/op")
        assert len(dicts) == 1000

    def test_scan_report_to_dict_100(self):
        """Benchmark: ScanReport.to_dict() with 100 results."""
        report = ScanReport(domain="bench.com", profile="pentester")
        for i in range(100):
            report.add_result(make_result(f"10.0.{i // 256}.{i % 256}"))
        report.finalize()

        start = time.monotonic()
        for _ in range(100):
            _ = report.to_dict()
        elapsed = time.monotonic() - start

        result = BenchResult(
            name="ScanReport.to_dict (100 results, x100)",
            iterations=100,
            total_seconds=elapsed,
            ops_per_second=100 / elapsed,
            avg_ms=(elapsed / 100) * 1000,
        )
        print(f"\n Bench] {result.name}")
        print(f"    Total: {result.total_seconds:.4f}s | "
              f"{result.ops_per_second:.0f} ops/s | "
              f"{result.avg_ms:.3f}ms/op")
        assert result.avg_ms < 500  # Even with 100 results, should be < 500ms


# ═══════════════════════════════════════════════════════════
# FALSE POSITIVE FILTER BENCHMARK
# ═══════════════════════════════════════════════════════════

class TestFPFilterBench:

    def test_fp_filter_1000_results(self):
        """Benchmark: FP filter check_batch with 1000 results."""
        fp_filter = FalsePositiveFilter()
        results = [make_result(f"10.0.{i // 256}.{i % 256}") for i in range(1000)]

        start = time.monotonic()
        tp, fp = fp_filter.check_batch(results)
        elapsed = time.monotonic() - start

        result = BenchResult(
            name="FalsePositiveFilter.check_batch (1000)",
            iterations=1000,
            total_seconds=elapsed,
            ops_per_second=1000 / elapsed,
            avg_ms=(elapsed / 1000) * 1000,
        )
        print(f"\n  [BENCH] {result.name}")
        print(f"    Total: {result.total_seconds:.4f}s | "
              f"{result.ops_per_second:.0f} ops/s | "
              f"{result.avg_ms:.3f}ms/op")
        assert result.avg_ms < 1.0  # Should be very fast (no I/O)


# ═══════════════════════════════════════════════════════════
# DEDUPLICATION BENCHMARK
# ═══════════════════════════════════════════════════════════

class TestDedupBench:

    def test_dedup_1000_results_500_unique(self):
        """Benchmark: dedup with 1000 results (500 unique IPs)."""
        dedup = ResultDeduplicator()
        results = [
            make_result(f"10.0.0.{i % 500}",
                       confidence=50 + (i % 50))
            for i in range(1000)
        ]

        start = time.monotonic()
        deduped = dedup.deduplicate(results)
        elapsed = time.monotonic() - start

        result = BenchResult(
            name="ResultDeduplicator.deduplicate (1000 items, 500 unique)",
            iterations=1000,
            total_seconds=elapsed,
            ops_per_second=1000 / elapsed,
            avg_ms=(elapsed / 1000) * 1000,
        )
        print(f"\n  [BENCH] {result.name}")
        print(f"    Total: {result.total_seconds:.4f}s | "
              f"{result.ops_per_second:.0f} ops/s | "
              f"{result.avg_ms:.3f}ms/op")
        assert len(deduped) == 500  # 500 unique IPs


# ═══════════════════════════════════════════════════════════
# SCORING ENGINE BENCHMARK
# ═══════════════════════════════════════════════════════════

class TestScoringBench:

    def test_scoring_1000_results(self):
        """Benchmark: ScoringEngine.score() x1000."""
        config = Config.from_profile("researcher")
        scoring = ScoringEngine(config)
        scoring.set_target_domain("bench.com")

        results = [make_result(f"10.0.0.{i % 256}") for i in range(1000)]

        start = time.monotonic()
        for r in results:
            scoring.score(r)
        elapsed = time.monotonic() - start

        result = BenchResult(
            name="ScoringEngine.score (1000)",
            iterations=1000,
            total_seconds=elapsed,
            ops_per_second=1000 / elapsed,
            avg_ms=(elapsed / 1000) * 1000,
        )
        print(f"\n  [BENCH] {result.name}")
        print(f"    Total: {result.total_seconds:.4f}s | "
              f"{result.ops_per_second:.0f} ops/s | "
              f"{result.avg_ms:.3f}ms/op")
        assert result.avg_ms < 2.0


# ═══════════════════════════════════════════════════════════
# EXPORTER BENCHMARKS
# ═══════════════════════════════════════════════════════════

class TestExporterBench:

    @pytest.fixture
    def big_report(self):
        report = ScanReport(domain="bench.com", profile="pentester")
        for i in range(200):
            report.add_result(make_result(
                f"10.0.{i // 256}.{i % 256}",
                confidence=30 + (i % 60),
                source=["crtsh", "otx", "anubisdb", "wayback"][i % 4],
            ))
        report.finalize()
        return report

    def test_json_export_big_report(self, big_report, temp_dir):
        """Benchmark: JSON export with 200 results."""
        path = temp_dir / "big.json"
        start = time.monotonic()
        export_json(big_report, path)
        elapsed = time.monotonic() - start

        result = BenchResult(
            name="export_json (200 results)",
            iterations=1,
            total_seconds=elapsed,
            ops_per_second=1 / elapsed,
            avg_ms=elapsed * 1000,
        )
        print(f"\n  [BENCH] {result.name}")
        print(f"    Total: {result.total_seconds:.4f}s")
        assert result.avg_ms < 500  # < 500ms for 200 results

    def test_csv_export_big_report(self, big_report, temp_dir):
        """Benchmark: CSV export with 200 results."""
        path = temp_dir / "big.csv"
        start = time.monotonic()
        export_csv(big_report, path)
        elapsed = time.monotonic() - start

        result = BenchResult(
            name="export_csv (200 results)",
            iterations=1,
            total_seconds=elapsed,
            ops_per_second=1 / elapsed,
            avg_ms=elapsed * 1000,
        )
        print(f"\n  [BENCH] {result.name}")
        print(f"    Total: {result.total_seconds:.4f}s")
        assert result.avg_ms < 500

    def test_json_string_big_report(self, big_report):
        """Benchmark: JSON string export with 200 results."""
        start = time.monotonic()
        s = export_json_string(big_report)
        elapsed = time.monotonic() - start

        result = BenchResult(
            name="export_json_string (200 results)",
            iterations=1,
            total_seconds=elapsed,
            ops_per_second=1 / elapsed,
            avg_ms=elapsed * 1000,
        )
        print(f"\n  [BENCH] {result.name}")
        print(f"    Total: {result.total_seconds:.4f}s")
        assert len(json.loads(s)["results"]) == 200

    def test_markdown_export_big_report(self, big_report, temp_dir):
        """Benchmark: Markdown export with 200 results."""
        path = temp_dir / "big.md"
        start = time.monotonic()
        export_markdown(big_report, path)
        elapsed = time.monotonic() - start

        result = BenchResult(
            name="export_markdown (200 results)",
            iterations=1,
            total_seconds=elapsed,
            ops_per_second=1 / elapsed,
            avg_ms=elapsed * 1000,
        )
        print(f"\n  [BENCH] {result.name}")
        print(f"    Total: {result.total_seconds:.4f}s")
        assert result.avg_ms < 500

    def test_pdf_export_big_report(self, big_report, temp_dir):
        """Benchmark: PDF export with 200 results."""
        path = temp_dir / "big.pdf"
        start = time.monotonic()
        export_pdf(big_report, path)
        elapsed = time.monotonic() - start

        result = BenchResult(
            name="export_pdf (200 results)",
            iterations=1,
            total_seconds=elapsed,
            ops_per_second=1 / elapsed,
            avg_ms=elapsed * 1000,
        )
        print(f"\n [BENCH] {result.name}")
        print(f"    Total: {result.total_seconds:.4f}s")
        assert result.avg_ms < 6000  # PDF is heavier, allow generous time on slow CI runners

