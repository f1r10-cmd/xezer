"""§3.0 — baseline benchmark təkrarlanabilirliyi və reqressiya nəzarəti.

Bu test:
  1. Benchmark-ı İKİ DƏFƏ işlədir → eyni tapıntı və əhatə sayı (determinizm);
  2. Nəticəni `tests/benchmarks/baseline.json` ilə müqayisə edir →
     ƏHATƏ və TAPINTI sayı baseline-dan AŞAĞI DÜŞMƏMƏLİDİR.

Yalnız `127.0.0.1` loopback — heç bir xarici şəbəkə trafiki yoxdur.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib

_HERE = pathlib.Path(__file__).resolve().parent
_BENCH_PATH = _HERE / "benchmarks" / "run_baseline.py"

_spec = importlib.util.spec_from_file_location("bench_run_baseline", _BENCH_PATH)
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)


async def _once() -> dict:
    base, runner = await bench.start_fixture()
    try:
        return await bench.run_benchmark(base)
    finally:
        await runner.cleanup()


class TestBaselineBenchmark:
    async def test_reproducible(self):
        first = await _once()
        second = await _once()
        assert bench.bench_metrics(first) == bench.bench_metrics(second)
        assert first["unique_endpoints"] > 0
        assert first["evidence_records"] > 0

    async def test_no_regression_against_saved_baseline(self):
        baseline = json.loads(bench.BASELINE_PATH.read_text(encoding="utf-8"))
        current = await _once()
        cmp = bench.compare(baseline, current)
        assert cmp["regressions"] == [], (
            "optimizasiya əhatəni/tapıntını azaldıb: " + repr(cmp["regressions"]))
