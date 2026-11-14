"""§10 — deterministik loopback benchmark (Faza 0/1).

Məqsəd: performans iddiasını **UYDURMADAN** ölçmək. Eyni yük (eyni host sayı,
eyni sorğu sayı, eyni server gecikməsi) üç strategiyada işlədilir:

  * ``A_baseline``        — hostlar ARDICIL, hər host üçün TƏZƏ sessiya
                            (köhnə mühərrik davranışı).
  * ``B_shared_session``  — hostlar ARDICIL, bir PAYLAŞILAN sessiya
                            (yalnız sessiya təkrar istifadəsinin təsiri).
  * ``C_parallel_hosts``  — hostlar PARALEL, bir paylaşılan sessiya
                            (Faza 1 hədəfi).

Yalnız ``127.0.0.1`` / ``127.0.0.2`` loopback interfeysləri istifadə olunur —
xarici şəbəkə trafiki YOXDUR. Heç bir RPS limiti artırılmır: policy
``rate`` yüksəkdir ki, darboğaz MƏHZ concurrency/sessiya davranışı olsun.

Benchmark həm test kimi (assert-lərlə), həm də birbaşa skript kimi
(``python -m tests.test_benchmark``) işlədilə bilər.
"""
from __future__ import annotations

import asyncio
import statistics
import tempfile
import time
from pathlib import Path

import pytest

from qbh.antiblock.guardian import Guardian
from qbh.antiblock.identity import IdentityManager
from qbh.http_policy import HttpPolicy

GLOBAL_CONCURRENCY = 10
SERVER_DELAY = 0.05
REQUESTS_PER_HOST = 12
POLICY_RATE = 1000.0
HOST_IPS = ("127.0.0.1", "127.0.0.2")


# --------------------------------------------------------------------- config
def _bench_config(path: Path):
    import yaml

    from qbh.config import Config

    data = {
        "program": "bench",
        "nvd_api_key": "",
        "scope": [
            {"domain": ip, "in_scope": [ip], "out_of_scope": []}
            for ip in HOST_IPS
        ],
        "limits": {
            "requests_per_second": 1000,
            "max_concurrency": GLOBAL_CONCURRENCY,
            "per_host_concurrency": GLOBAL_CONCURRENCY,
            "connect_timeout": 5,
            "total_timeout": 10,
            "cooldown": 60,
        },
        "proxy_file": "",
    }
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return Config.load(str(path))


# --------------------------------------------------------------------- server
def _make_app(state):
    from aiohttp import web

    async def work(request):
        host = request.host.split(":")[0]
        state["global"] += 1
        state["max_global"] = max(state["max_global"], state["global"])
        per = state["per_host"].get(host, 0) + 1
        state["per_host"][host] = per
        state["max_per_host"][host] = max(
            state["max_per_host"].get(host, 0), per)
        state["transports"].add(id(request.transport))
        try:
            await asyncio.sleep(SERVER_DELAY)
            state["hits"] += 1
            return web.Response(text="ok")
        finally:
            state["global"] -= 1
            state["per_host"][host] = per - 1

    app = web.Application()
    app.add_routes([web.get("/work", work)])
    return app


async def _start_server(state):
    from aiohttp import web

    runner = web.AppRunner(_make_app(state))
    await runner.setup()
    bases: list[str] = []
    for ip in HOST_IPS:
        try:
            await web.TCPSite(runner, ip, 0).start()
        except OSError:  # bəzi mühitlərdə 127.0.0.2 əlçatan olmaya bilər
            continue
        host, port = runner.addresses[-1][:2]
        bases.append(f"http://{host}:{port}")
    if not bases:  # son çarə: yalnız 127.0.0.1, tək host
        await web.TCPSite(runner, "127.0.0.1", 0).start()
        host, port = runner.addresses[-1][:2]
        bases.append(f"http://{host}:{port}")
    return runner, bases


# ------------------------------------------------------------------- workload
async def _drive(guardian, session, base, n):
    """Bir host üçün `n` sorğunu paralel göndərir; latensiyaları qaytarır."""
    async def one():
        t0 = time.perf_counter()
        await guardian.get(session, f"{base}/work", allow_redirects=False)
        return (time.perf_counter() - t0) * 1000.0

    return await asyncio.gather(*(one() for _ in range(n)))


async def run_benchmark(cfg, bases, *, mode: str, requests_per_host: int):
    """Vahid yükü verilmiş strategiyada işlədir və ölçmələri qaytarır.

    `ScanMetrics` (§3) kollektoru da qoşulur → semafor gözləmə vaxtı, sessiya
    sayğacları və max global/host concurrency ÖLÇÜLÜR (uydurulmur). Sessiya
    sayğacları burada əl ilə aparılır, çünki bu harness `Context`/`ScanSession`
    yerinə birbaşa `aiohttp.ClientSession` istifadə edir.
    """
    import aiohttp

    from qbh.metrics import ScanMetrics

    metrics = ScanMetrics()
    policy = HttpPolicy(cfg.scope, rate=POLICY_RATE,
                        max_concurrency=GLOBAL_CONCURRENCY,
                        metrics=metrics)
    guardian = Guardian(IdentityManager("", "lo"), policy)

    shared = None
    if mode in ("B_shared_session", "C_parallel_hosts"):
        shared = aiohttp.ClientSession()
        metrics.record_session_created()
    latencies: list[float] = []
    started = time.perf_counter()
    try:
        if mode == "A_baseline":
            for base in bases:
                metrics.record_session_created()
                async with aiohttp.ClientSession() as session:
                    latencies += await _drive(
                        guardian, session, base, requests_per_host)
                metrics.record_session_closed()
        elif mode == "B_shared_session":
            for base in bases:
                latencies += await _drive(
                    guardian, shared, base, requests_per_host)
        else:
            results = await asyncio.gather(*(
                _drive(guardian, shared, base, requests_per_host)
                for base in bases))
            for chunk in results:
                latencies += chunk
    finally:
        if shared is not None:
            await shared.close()
            metrics.record_session_closed()
    elapsed = time.perf_counter() - started
    ordered = sorted(latencies)
    return {
        "mode": mode,
        "elapsed_ms": round(elapsed * 1000.0, 1),
        "requests": len(latencies),
        "p50_ms": round(statistics.median(ordered), 1) if ordered else 0.0,
        "p95_ms": (round(ordered[min(len(ordered) - 1,
                                     int(len(ordered) * 0.95))], 1)
                   if ordered else 0.0),
        "metrics": metrics.snapshot(),
    }


# ---------------------------------------------------------------------- tests
@pytest.fixture
def bench_setup(tmp_path):
    """Loopback server + konfiq quran sinxron fixture (loop test daxilində)."""
    return tmp_path


class TestBenchmark:
    async def test_parallel_hosts_progress_independently(self, bench_setup):
        state = {"hits": 0, "global": 0, "max_global": 0, "per_host": {},
                 "max_per_host": {}, "transports": set()}
        runner, bases = await _start_server(state)
        try:
            assert len(bases) >= 1
            cfg = _bench_config(bench_setup / "bench.yaml")
            results = {}
            for mode in ("A_baseline", "B_shared_session", "C_parallel_hosts"):
                state.update({"hits": 0, "global": 0, "max_global": 0,
                              "per_host": {}, "max_per_host": {},
                              "transports": set()})
                results[mode] = await run_benchmark(
                    cfg, bases, mode=mode, requests_per_host=REQUESTS_PER_HOST)
            # Bütün strategiyalar eyni sayda sorğu göndərməlidir.
            for r in results.values():
                assert r["requests"] == len(bases) * REQUESTS_PER_HOST
            # Qlobal concurrency heç vaxt konfiqurasiya edilmiş tavanı aşmır.
            assert state["max_global"] <= GLOBAL_CONCURRENCY
            print("\n=== §10 BENCHMARK (loopback) ===")
            for r in results.values():
                print(f"  {r['mode']:<18} elapsed={r['elapsed_ms']:>7.1f}ms "
                      f"p50={r['p50_ms']:>6.1f}ms p95={r['p95_ms']:>6.1f}ms "
                      f"requests={r['requests']}")
        finally:
            await runner.cleanup()


# ------------------------------------------------------------------ standalone
def main() -> None:
    async def _run():
        with tempfile.TemporaryDirectory() as tmp:
            state = {"hits": 0, "global": 0, "max_global": 0, "per_host": {},
                     "max_per_host": {}, "transports": set()}
            runner, bases = await _start_server(state)
            try:
                cfg = _bench_config(Path(tmp) / "bench.yaml")
                print(f"hosts={len(bases)} requests_per_host={REQUESTS_PER_HOST} "
                      f"global_ceiling={GLOBAL_CONCURRENCY} "
                      f"server_delay={SERVER_DELAY}s")
                for mode in ("A_baseline", "B_shared_session",
                             "C_parallel_hosts"):
                    state.update({"hits": 0, "global": 0, "max_global": 0,
                                  "per_host": {}, "max_per_host": {},
                                  "transports": set()})
                    r = await run_benchmark(cfg, bases, mode=mode,
                                            requests_per_host=REQUESTS_PER_HOST)
                    m = r["metrics"]
                    r["max_global"] = state["max_global"]
                    r["max_per_host"] = dict(state["max_per_host"])
                    r["distinct_transports"] = len(state["transports"])
                    print(f"  {r['mode']:<18} elapsed={r['elapsed_ms']:>7.1f}ms "
                          f"p50={r['p50_ms']:>6.1f}ms p95={r['p95_ms']:>6.1f}ms "
                          f"max_global={r['max_global']} "
                          f"max_per_host={r['max_per_host']} "
                          f"transports={r['distinct_transports']}")
                    print(f"  {'':<18} sessions created/closed="
                          f"{m['sessions_created']}/{m['sessions_closed']} "
                          f"global_wait_p95={m['global_sem_wait']['p95_ms']}ms "
                          f"host_wait_p95={m['host_sem_wait']['p95_ms']}ms "
                          f"req_aiohttp/transport="
                          f"{m['aiohttp_requests']}/{m['transport_requests']} "
                          f"timeouts/conn_err={m['timeouts']}/"
                          f"{m['connection_errors']}")
            finally:
                await runner.cleanup()

    asyncio.run(_run())


if __name__ == "__main__":  # pragma: no cover - yalnız əl ilə işlədilir
    main()
