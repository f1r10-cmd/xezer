"""§3.0 — Deterministik baseline benchmark (referans ölçmə bazası).

Bu skript loopback (`127.0.0.1`) aiohttp fixture-i üzərində SİNTETİK skan
işlədir və nəticəni `tests/benchmarks/baseline.json` faylına yazır.

Nəticə OPTİMİZASİYA REFERANSIDIR: hər optimizasiyadan sonra yenidən yaradılır
və müqayisə olunur. **Tapıntı sayı və ya əhatə (coverage) AZALARSA optimizasiya
YANLIŞDIR və düzəldilməlidir.**

Prinsiplər:
  * Heç bir XARİCİ şəbəkə trafiki yoxdur — yalnız `127.0.0.1`.
  * Ölçmə UYDURULMUR: hər rəqəm real icradan (HTTP cavabı, TaskLedger,
    Scheduler) götürülür. Aşkarlama siqnalı AVTOMATİK təsdiqə çevrilmir —
    tapıntı `tentative` inam səviyyəsi ilə qeyd olunur.
  * Determinist yük → təkrar işlədildikdə eyni tapıntı və əhatə sayı.

`python tests/benchmarks/run_baseline.py` ilə işlədilir.
"""
from __future__ import annotations

import asyncio
import json
import pathlib
import sys
import time
from collections import Counter
from urllib.parse import urlsplit

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from qbh import urlintel                                    # noqa: E402
from qbh.metrics import OrchestrationMetrics                # noqa: E402
from qbh.scheduler import Scheduler, SchedTask              # noqa: E402
from qbh.tasks import TaskLedger, task_identity             # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
BASELINE_PATH = HERE / "baseline.json"

#: urlintel-in qərar verdiyi mühərriklər (benchmark da bunları planlaşdırır).
ENGINES = urlintel.ENGINES

WORKERS = 8
GLOBAL_LIMIT = 8
PER_HOST_LIMIT = 4
QUEUE_LIMIT = 4096

#: Sintetik yükdə hər nümunədən neçə dəfə təkrarlanır (deterministik).
PATTERN_REPEAT = 12

#: Refleksiya detektoru üçün istifadə olunan yol (fixture parametri əks etdirir).
REFLECT_PATH = "/search"


# --------------------------------------------------------------------------- #
# Loopback fixture (yalnız 127.0.0.1)
# --------------------------------------------------------------------------- #
async def start_fixture():
    """Deterministik loopback aiohttp tətbiqi qaytarır: `(base, runner)`."""
    from aiohttp import web

    async def index(request):
        return web.Response(text="hello benchmark")

    async def product(request):
        pid = request.query.get("id", "")
        return web.Response(text=f"<html><body>product {pid}</body></html>",
                            content_type="text/html")

    async def search(request):
        q = request.query.get("q", "")
        return web.Response(text=f"<html><body>results for {q}</body></html>",
                            content_type="text/html")

    async def api_item(request):
        return web.Response(text='{"item":%s}' % request.match_info["id"],
                            content_type="application/json")

    async def go(request):
        return web.Response(status=302,
                            headers={"Location": "/home/1"})

    async def app_js(request):
        return web.Response(text="console.log('ok');",
                            content_type="application/javascript")

    async def css(request):
        return web.Response(text="body{color:#000}", content_type="text/css")

    async def logo(request):
        return web.Response(body=b"\x89PNG\r\n\x1a\n", content_type="image/png")

    async def openapi(request):
        return web.Response(text='{"openapi":"3.0.0"}',
                            content_type="application/json")

    async def rate_limited(request):
        return web.Response(status=429, headers={"Retry-After": "1"},
                            text="slow down")

    async def forbidden(request):
        return web.Response(status=403, text="forbidden")

    async def server_error(request):
        return web.Response(status=500, text="boom")

    async def gone(request):
        return web.Response(status=404, text="not found")

    app = web.Application()
    app.add_routes([
        web.get("/", index),
        web.get("/product", product),
        web.get("/search", search),
        web.get("/api/v1/items/{id}", api_item),
        web.get("/go", go),
        web.get("/app.js", app_js),
        web.get("/static/site.css", css),
        web.get("/img/logo.png", logo),
        web.get("/openapi.json", openapi),
        web.get("/429", rate_limited),
        web.get("/403", forbidden),
        web.get("/500", server_error),
        web.get("/404", gone),
    ])
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    return f"http://127.0.0.1:{port}", runner


# --------------------------------------------------------------------------- #
# Sintetik iş yükü (deterministik)
# --------------------------------------------------------------------------- #
def build_workload(base: str, *, repeat: int = PATTERN_REPEAT) -> list[dict]:
    """Deterministik kəşf nəticəsi: statik/dinamik/parametrli/JS/API nümunələri.

    `k = i % 10` → 8 fərqli nümunə + DUBLİKAT nümunəsi. Beləcə həm əhatə, həm
    də deduplikasiya real şəkildə ölçülür.
    """
    rows: list[dict] = []
    rid = 0

    def add(path: str, *, is_js: int = 0) -> None:
        nonlocal rid
        rid += 1
        rows.append({"id": rid, "url": f"{base}{path}", "is_js": is_js,
                     "source": "benchmark", "subdomain": "127.0.0.1"})

    total = repeat * 10
    for i in range(total):
        k = i % 10
        if k == 0:
            add(f"/product?id={i}")
        elif k == 1:
            add(f"/search?q=term{i}")
        elif k == 2:
            add(f"/api/v1/items/{i}")
        elif k == 3:
            add(f"/go?next=/home/{i}")
        elif k == 4:
            add("/app.js", is_js=1)
        elif k == 5:
            add("/static/site.css")
        elif k == 6:
            add("/img/logo.png")
        elif k == 7:
            add("/openapi.json")
        elif k == 8:
            add("/429")
        else:
            add(f"/product?id={i - 9}")     # DUBLİKAT (əvvəlki product id)
    return rows


# --------------------------------------------------------------------------- #
# Benchmark icrası
# --------------------------------------------------------------------------- #
async def run_benchmark(base: str, *, repeat: int = PATTERN_REPEAT) -> dict:
    """Sintetik skanı loopback fixture üzərində işlədir və metrikaları qaytarır."""
    import aiohttp

    rows = build_workload(base, repeat=repeat)
    om = OrchestrationMetrics()
    intel = urlintel.UrlIntelligence(metrics=om)
    intel.intake(rows)

    all_eps = [urlintel.analyze_row(r) for r in rows]
    unique_eps, _dups = urlintel.dedupe_endpoints(all_eps)
    param_combos = {
        (ep.identity, urlsplit(ep.normalized or ep.original).query)
        for ep in unique_eps if ep.identity
    }

    ledger = TaskLedger()
    sched = Scheduler(workers=WORKERS, queue_limit=QUEUE_LIMIT,
                      global_limit=GLOBAL_LIMIT, per_host_limit=PER_HOST_LIMIT,
                      metrics=om)

    eligible: Counter = Counter()
    excluded: Counter = Counter()
    deferred: Counter = Counter()
    exclusion_reasons: Counter = Counter()
    requests_per_engine: Counter = Counter()
    status_counts: Counter = Counter()
    findings: list[dict] = []
    service_time = {"total": 0.0}
    queue_wait = {"total": 0.0, "count": 0}

    connector = aiohttp.TCPConnector(limit=GLOBAL_LIMIT + 4)
    async with aiohttp.ClientSession(connector=connector) as session:

        def make_run(engine: str, ep: urlintel.Endpoint, task: SchedTask):
            async def _run():
                started = time.monotonic()
                queue_wait["total"] += started - task.meta.get("t_submit", started)
                queue_wait["count"] += 1
                t0 = time.monotonic()
                async with session.get(ep.original,
                                       allow_redirects=False) as resp:
                    raw = await resp.read()
                    status = resp.status
                body = raw.decode("utf-8", "ignore")
                dt = time.monotonic() - t0
                service_time["total"] += dt
                requests_per_engine[engine] += 1
                status_counts[status] += 1
                path = urlsplit(ep.normalized or ep.original).path
                if engine in ("xss", "sqli", "ssti") and path == REFLECT_PATH:
                    q = urlsplit(ep.original).query.split("q=", 1)[-1]
                    if q and q in body:
                        findings.append({
                            "engine": engine, "endpoint": ep.identity,
                            "severity": "medium", "confidence": "tentative",
                            "reason": "reflected_input (təsdiqlənməmiş)",
                        })
                return {"status": status, "len": len(body)}
            return _run

        submitted = 0
        for ep in all_eps:                       # DUBLİKATLAR DA daxil
            for engine in ENGINES:
                d = urlintel.evaluate(ep, engine)
                if d.eligible is not True:
                    if d.eligible is False:
                        excluded[engine] += 1
                        exclusion_reasons[d.reason] += 1
                    else:
                        deferred[engine] += 1
                    continue
                eligible[engine] += 1
                query = urlsplit(ep.original).query
                ident = task_identity(0, engine, ep.identity, param=query,
                                      test_type=engine)
                decision = ledger.consider(ident, engine=engine,
                                           endpoint=ep.identity, param=query,
                                           test_type=engine)
                if not decision.create:
                    continue
                task = SchedTask(identity=ident, engine=engine,
                                 host=ep.host, family=ep.family,
                                 priority=urlintel.priority(ep),
                                 run=lambda: None)
                task.meta["t_submit"] = time.monotonic()
                task.run = make_run(engine, ep, task)
                if await sched.submit(task):
                    submitted += 1

        t_start = time.perf_counter()
        await sched.run()
        total_duration = time.perf_counter() - t_start

    snap = sched.snapshot()
    sev = Counter(f["severity"] for f in findings)
    conf = Counter(f["confidence"] for f in findings)
    coverage = {
        eng: {
            "eligible": int(eligible[eng]),
            "executed": int(snap["engine_runs"].get(eng, 0)),
            "requests": int(requests_per_engine[eng]),
        }
        for eng in ENGINES
    }

    result = {
        "total_duration": round(total_duration, 4),
        "total_http_requests": int(sum(requests_per_engine.values())),
        "requests_per_engine": {k: int(v) for k, v in sorted(
            requests_per_engine.items())},
        "unique_endpoints": int(len(unique_eps)),
        "unique_endpoint_param_combos": int(len(param_combos)),
        "duplicate_tasks": int(ledger.stats.deduplicated),
        "skipped_tasks": int(sum(excluded.values())),
        "skipped_reasons": {k: int(v) for k, v in sorted(
            exclusion_reasons.items())},
        "deferred_tasks": int(sum(deferred.values())),
        "failed_tasks": int(snap["failed"]),
        "timed_out_tasks": 0,
        "scheduler_queue_time_avg": (round(queue_wait["total"]
                                           / queue_wait["count"], 6)
                                     if queue_wait["count"] else 0.0),
        "concurrency_avg": (round(service_time["total"] / total_duration, 4)
                            if total_duration > 0 else 0.0),
        "concurrency_peak": int(snap["peak_concurrency"]),
        "rate_limit_responses": int(status_counts.get(429, 0)),
        "status_counts": {str(k): int(v) for k, v in sorted(status_counts.items())},
        "findings_by_severity": {k: int(v) for k, v in sorted(sev.items())},
        "findings_by_confidence": {k: int(v) for k, v in sorted(conf.items())},
        "evidence_records": int(len(findings)),
        "engine_execution_coverage": coverage,
        # --- köməkçi (dedup/icra şəffaflığı) ---
        "submitted": int(submitted),
        "executed": int(snap["executed"]),
        "eligible_total": int(sum(eligible.values())),
        "excluded_by_engine": {k: int(v) for k, v in sorted(excluded.items())},
        "deferred_by_engine": {k: int(v) for k, v in sorted(deferred.items())},
    }
    return result


def bench_metrics(res: dict) -> dict:
    """Müqayisə üçün ƏSAS göstəricilər (əhatə + tapıntı)."""
    return {
        "unique_endpoints": res["unique_endpoints"],
        "unique_endpoint_param_combos": res["unique_endpoint_param_combos"],
        "eligible_total": res["eligible_total"],
        "executed": res["executed"],
        "evidence_records": res["evidence_records"],
        "engine_execution_coverage": res["engine_execution_coverage"],
    }


def compare(baseline: dict, current: dict) -> dict:
    """Baseline ilə cari nəticəni müqayisə edir (əhatə/tapıntı azalmamalı)."""
    base_m = bench_metrics(baseline)
    cur_m = bench_metrics(current)
    regressions = []
    for key in ("unique_endpoints", "unique_endpoint_param_combos",
                "eligible_total", "executed", "evidence_records"):
        if cur_m[key] < base_m[key]:
            regressions.append(f"{key}: {base_m[key]} → {cur_m[key]}")
    for eng, cov in base_m["engine_execution_coverage"].items():
        cur_cov = cur_m["engine_execution_coverage"].get(eng, {})
        if cur_cov.get("executed", 0) < cov.get("executed", 0):
            regressions.append(
                f"engine {eng} executed: {cov.get('executed', 0)} → "
                f"{cur_cov.get('executed', 0)}")
    return {"baseline": base_m, "current": cur_m, "regressions": regressions}


async def _amain(write: bool) -> dict:
    base, runner = await start_fixture()
    try:
        result = await run_benchmark(base)
    finally:
        await runner.cleanup()
    if write:
        BASELINE_PATH.write_text(json.dumps(result, indent=2, sort_keys=True),
                                 encoding="utf-8")
    return result


def main() -> None:  # pragma: no cover - yalnız əl ilə
    result = asyncio.run(_amain(write=True))
    print(json.dumps(result, indent=2, sort_keys=True))
    print(f"\n[baseline] yazıldı: {BASELINE_PATH}")


if __name__ == "__main__":  # pragma: no cover
    main()
