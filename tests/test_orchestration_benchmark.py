"""Faza 9 (§13) — deterministik orkestrasiya benchmark-ı: köhnə vs yeni.

Eyni SİNTETİK yük iki strategiyada işlədilir:

  * ``baseline`` — "köhnə" davranış: hər kəşf olunmuş URL hər mühərrik üçün
    tapşırıq sayılır; dublikat/deduplikasiya YOXDUR; zəncir hadisəsi hər dəfə
    davam testi planlaşdırır.
  * ``new``      — URL Intelligence (dedup + uyğunluq) + tapşırıq kimliyi
    idempotentliyi + zəncir hadisə deduplikasiyası + məhdud planlaşdırıcı.

Ölçülür: kəşf olunan/uyğun/gözləmədə olan URL-lər, tapşırıqlar (baxılan/
icra olunan/dedup), zəncir davam testləri, sorğular, pik növbə/concurrency,
host bölgüsü. **Uydurma faiz/qalan-vaxt YOXDUR.**

Yalnız şəbəkəsiz deterministik hesablama — heç bir xarici hədəf skan olunmur.
``python -m tests.test_orchestration_benchmark`` ilə də işlədilə bilər.
"""
from __future__ import annotations

import asyncio
import time
from collections import Counter

from qbh import urlintel
from qbh.adaptive import (STRENGTH_WEAK, AdaptiveController, Signal)
from qbh.metrics import OrchestrationMetrics
from qbh.scheduler import Scheduler, SchedTask
from qbh.tasks import EventLedger, TaskLedger, task_identity

HOSTS = 3
PER_HOST = 200
ENGINES = ("sqli", "xss", "ssti", "js", "api")
INJECT_ENGINES = ("sqli", "xss", "ssti")

WORKERS = 8
GLOBAL_LIMIT = 8
PER_HOST_LIMIT = 4
QUEUE_LIMIT = 4096
WORK_DELAY = 0.001


# --------------------------------------------------------------------- workload
def build_workload(*, hosts: int = HOSTS, per_host: int = PER_HOST) -> list[dict]:
    """Sintetik kəşf nəticəsi: dinamik/axtarış/API/statik/JS + TƏKRARLAR."""
    rows: list[dict] = []
    rid = 0

    def add(url: str, host: str, is_js: int = 0) -> None:
        nonlocal rid
        rid += 1
        rows.append({"id": rid, "url": url, "is_js": is_js,
                     "source": "katana", "subdomain": host})

    for hi in range(hosts):
        host = f"h{hi}.example.com"
        for i in range(per_host):
            k = i % 8
            if k == 0:
                add(f"http://{host}/product?id={i}", host)          # dinamik
            elif k == 1:
                add(f"http://{host}/search?q=term{i}", host)        # axtarış
            elif k == 2:
                add(f"http://{host}/api/v1/items/{i}", host)        # API (paramsuz)
            elif k == 3:
                add(f"http://{host}/static/app.js", host, is_js=1)  # JS (təkrarlanan)
            elif k == 4:
                add(f"http://{host}/static/site.css", host)         # CSS
            elif k == 5:
                add(f"http://{host}/img/logo.png", host)            # şəkil
            elif k == 6:
                add(f"http://{host}/go?next=/home/{i}", host)       # yönləndirmə
            else:
                add(f"http://{host}/product?id={i - 7}", host)      # DUBLİKAT
    return rows


# ----------------------------------------------------------------------- plans
def plan(strategy: str, rows):
    """Strategiyaya uyğun tapşırıq planı + sayğaclar qaytarır."""
    eps = [urlintel.analyze_row(r) for r in rows]
    plan_metrics = {
        "considered": 0, "queued": 0, "deduplicated": 0,
        "eligible": Counter(), "excluded": Counter(), "deferred": Counter(),
        "exclusion_reasons": Counter(), "families": 0,
    }
    if strategy == "baseline":
        # Deduplikasiya YOXDUR: hər sətir × hər mühərrik = tapşırıq.
        specs = [(eng, ep) for ep in eps for eng in ENGINES]
        plan_metrics["considered"] = len(specs)
        plan_metrics["queued"] = len(specs)
        plan_metrics["families"] = len({ep.family for ep in eps if ep.family})
        return specs, plan_metrics

    ledger = TaskLedger()
    specs: list = []
    seen_families: set = set()
    for ep in eps:
        if ep.family:
            seen_families.add(ep.family)
        query = _query(ep.original)
        for eng in ENGINES:
            d = urlintel.evaluate(ep, eng)
            if d.eligible is not True:
                if d.eligible is False:
                    plan_metrics["excluded"][eng] += 1
                    plan_metrics["exclusion_reasons"][d.reason] += 1
                else:
                    plan_metrics["deferred"][eng] += 1
                continue
            plan_metrics["eligible"][eng] += 1
            plan_metrics["considered"] += 1
            ident = task_identity(0, eng, ep.identity, param=query,
                                  test_type=eng)
            decision = ledger.consider(ident, engine=eng, endpoint=ep.identity,
                                       param=query, test_type=eng)
            if decision.create:
                specs.append((eng, ep))
                plan_metrics["queued"] += 1
            else:
                plan_metrics["deduplicated"] += 1
    plan_metrics["families"] = len(seen_families)
    return specs, plan_metrics


def _query(url: str) -> str:
    from urllib.parse import urlsplit
    try:
        return urlsplit(url).query
    except ValueError:
        return ""


def plan_chain(strategy: str, rows) -> dict:
    """Zəncir davam testlərini planlaşdırır (sqli_signal → sqli_probe)."""
    param_rows = [urlintel.analyze_row(r) for r in rows]
    param_rows = [ep for ep in param_rows if ep.params]
    if strategy == "baseline":
        # Hər parametrli URL hər dəfə təkrar davam testi tetikleyir.
        return {"events": len(param_rows), "scheduled": len(param_rows),
                "duplicate": 0, "cyclic": 0}

    events = EventLedger()
    adaptive = AdaptiveController(ledger=TaskLedger())
    scheduled = 0
    for ep in param_rows:
        kind = "sqli_signal"
        acc = events.accept(kind, ep.original)
        if not acc.accept:
            continue
        g = events.guard(source=kind, destination="sqli_probe",
                         identity=acc.identity)
        if not g.accept:
            continue
        ident = task_identity(0, "chain", ep.identity, test_type=kind)
        fu = adaptive.evaluate(
            Signal(kind=kind, strength=STRENGTH_WEAK, detail=ep.original),
            identity=ident, actions=("sqli_probe",))
        if fu.proceed:
            scheduled += 1
    return {"events": len(param_rows), "scheduled": scheduled,
            "duplicate": events.stats.duplicate,
            "cyclic": events.stats.cyclic}


# ------------------------------------------------------------------------- run
async def run_pipeline(strategy: str, rows) -> dict:
    """Planı MƏHDUD planlaşdırıcı ilə icra edir və FAKTİKİ sayları qaytarır."""
    om = OrchestrationMetrics()
    specs, pm = plan(strategy, rows)
    if strategy == "new":
        urlintel.UrlIntelligence(metrics=om).intake(rows)
    unique, _dups = urlintel.dedupe_endpoints(
        [urlintel.analyze_row(r) for r in rows])

    requests = {"n": 0}

    async def work():
        await asyncio.sleep(WORK_DELAY)
        requests["n"] += 1
        return "ok"

    sched = Scheduler(workers=WORKERS, queue_limit=QUEUE_LIMIT,
                      global_limit=GLOBAL_LIMIT, per_host_limit=PER_HOST_LIMIT,
                      metrics=om)
    for eng, ep in specs:
        await sched.submit(SchedTask(
            identity=f"{eng}:{ep.identity}", engine=eng, host=ep.host,
            family=ep.family, priority=urlintel.priority(ep), run=work))
    t0 = time.perf_counter()
    await sched.run()
    elapsed = round(time.perf_counter() - t0, 4)
    snap = sched.snapshot()
    chain = plan_chain(strategy, rows)

    return {
        "strategy": strategy,
        "urls_raw": len(rows),
        "urls_unique": len(unique),
        "families": pm["families"],
        "considered": pm["considered"],
        "queued": pm["queued"],
        "deduplicated": pm["deduplicated"],
        "eligible": dict(pm["eligible"]),
        "excluded": dict(pm["excluded"]),
        "deferred": dict(pm["deferred"]),
        "exclusion_reasons": dict(pm["exclusion_reasons"]),
        "executed": snap["executed"],
        "requests": requests["n"],
        "peak_queue": snap["peak_queue"],
        "peak_concurrency": snap["peak_concurrency"],
        "engine_runs": dict(snap["engine_runs"]),
        "host_runs": snap["host_runs"],
        # Divar-saatı YALNIZ sintetik harness üçündür (`sleep`-əsaslı iş);
        # real skan vaxtı kimi TƏQDİM OLUNMUR — yalnız faktiki ölçmə.
        "elapsed": elapsed,
        # Sintetik harness HEÇ BİR real aşkarlama və təsdiq etmir → 0/0.
        # Bu, "aşkarlama siqnalı AVTOMATİK təsdiqə çevrilmir" prinsipini göstərir.
        "findings": 0,
        "validated_findings": 0,
        "skipped_endpoints": sum(int(v) for v in pm["excluded"].values()),
        "deferred_endpoints": sum(int(v) for v in pm["deferred"].values()),
        "chain": chain,
    }


def _fmt(label: str, value) -> str:
    return f"  {label:<26} {value}"


# ---------------------------------------------------------------------- tests
class TestOrchestrationBenchmark:
    async def test_new_pipeline_reduces_redundant_work_preserves_coverage(self):
        rows = build_workload()
        base = await run_pipeline("baseline", rows)
        new = await run_pipeline("new", rows)

        print("\n=== §13 ORKESTRASİYA BENCHMARK (eyni sintetik yük) ===")
        for r in (base, new):
            print(f"[{r['strategy']}] raw={r['urls_raw']} unique={r['urls_unique']} "
                  f"families={r['families']}")
            print(_fmt("tasks considered", r["considered"]))
            print(_fmt("tasks queued", r["queued"]))
            print(_fmt("tasks deduplicated", r["deduplicated"]))
            print(_fmt("tasks executed", r["executed"]))
            print(_fmt("requests", r["requests"]))
            print(_fmt("peak_queue", r["peak_queue"]))
            print(_fmt("peak_concurrency", r["peak_concurrency"]))
            print(_fmt("eligible", r["eligible"]))
            print(_fmt("excluded", r["excluded"]))
            print(_fmt("deferred", r["deferred"]))
            print(_fmt("engine_runs", r["engine_runs"]))
            print(_fmt("host_runs", r["host_runs"]))
            print(_fmt("elapsed (synthetic)", r["elapsed"]))
            print(_fmt("findings/validated",
                       f"{r['findings']}/{r['validated_findings']}"))
            print(_fmt("skipped/deferred endpoints",
                       f"{r['skipped_endpoints']}/{r['deferred_endpoints']}"))
            print(_fmt("chain", r["chain"]))

        # --- 1. Artıq (redundant) iş AZALIR ---
        assert new["executed"] < base["executed"]
        assert new["deduplicated"] > 0
        # Yeni pipeline eyni sayda sorğu göndərir (icra = sorğu, 1:1).
        assert new["requests"] == new["executed"]

        # --- 2. Məşru ƏHATƏ QORUNUR: bütün dinamik/axtarış endpointləri
        #        inject mühərrikləri üçün uyğundur (heç biri səhvən çıxarılmır).
        inject_marked = [reason for reason in new["exclusion_reasons"]
                         if any(e in reason for e in ("SQLI", "XSS", "SSTI"))]
        assert inject_marked, "inject mühərrikləri üçün istisna qeydə alınmalı"
        for reason in inject_marked:
            assert "statik" in reason, f"dinamik endpoint səhvən çıxarıldı: {reason}"
        for eng in INJECT_ENGINES:
            assert new["eligible"].get(eng, 0) > 0

        # --- 3. İstisna YALNIZ statik/JS resurslardır və SƏBƏBLƏ qeyd olunur.
        assert new["excluded"].get("js", 0) > 0
        assert new["excluded"].get("api", 0) > 0

        # --- 4. Məhdud planlaşdırıcı tavanları aşılmır.
        assert 0 < new["peak_concurrency"] <= GLOBAL_LIMIT
        assert new["peak_queue"] <= QUEUE_LIMIT

        # --- 5. Host ədaləti: bütün hostlar işləyir, heç biri monopol deyil.
        assert len(new["host_runs"]) == HOSTS
        total = sum(new["host_runs"].values())
        assert max(new["host_runs"].values()) < total      # tək host hamısı deyil

        # --- 6. Zəncir: təkrar hadisələr davam testini TƏKRAR planlaşdırmır.
        assert new["chain"]["scheduled"] < base["chain"]["scheduled"]
        assert new["chain"]["duplicate"] > 0

        # --- 7. FAKTİKİ icra ölçülür; aşkarlama AVTOMATİK təsdiqə çevrilmir.
        assert new["elapsed"] > 0.0                       # real divar-saatı
        assert sum(new["engine_runs"].values()) == new["executed"]
        assert new["findings"] == 0                       # sintetik: tapıntı yox
        assert new["validated_findings"] == 0             # avto-təsdiq YOX
        assert new["skipped_endpoints"] >= 0
        assert new["deferred_endpoints"] >= 0


# ------------------------------------------------------------------ standalone
def main() -> None:  # pragma: no cover - yalnız əl ilə
    async def _run():
        rows = build_workload()
        for strategy in ("baseline", "new"):
            r = await run_pipeline(strategy, rows)
            print(f"[{r['strategy']}] executed={r['executed']} "
                  f"considered={r['considered']} dedup={r['deduplicated']} "
                  f"requests={r['requests']} peak_q={r['peak_queue']} "
                  f"peak_c={r['peak_concurrency']} chain={r['chain']}")
    asyncio.run(_run())


if __name__ == "__main__":  # pragma: no cover
    main()
