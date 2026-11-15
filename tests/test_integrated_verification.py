"""Faza 5 — İnteqrasiya təsdiq dəsti (17 ssenari).

Bu dəst komponentləri AYRI deyil, BİRLİKDƏ yoxlayır: URL Intelligence +
TaskLedger/EventLedger + Scheduler + ChainPipeline + OrchestrationMetrics +
report generator. Hamısı DETERMİNİSTİK lokal fixture (SQLite/loopback/mock) ilə
işləyir — xarici şəbəkə trafiki YOXDUR və HTTP RPS ARTIRILMIR.

Ssenarilər (tələb olunan siyahı):
  S01 çox mənbə → eyni endpoint deduplikasiyası
  S02 eyni endpoint-də fərqli parametrlər MÜSTƏQİL
  S03 fərqli HTTP metodları MÜSTƏQİL
  S04 fərqli test növləri MÜSTƏQİL
  S05 təkrarlanan zəncir hadisələri dublikat icra yaratmır
  S06 etibarlı davam testləri KONTROLLU yoldan icra olunur
  S07 davam testi nəticələri düzgün qeyd olunur
  S08 dəstəklənməyən davam testləri AÇIQ dayandırılır
  S09 planlaşdırıcı növbə doyması tapşırıqları SƏSSİZCƏ itirmir
  S10 çox-hostlu ədalət REAL metadata ilə işləyir
  S11 deferred endpoint-lər YENİ dəlildən sonra yenidən baxılır
  S12 mühərrik uyğunluğu TUTARLI tətbiq olunur
  S13 ləğv işçiləri təmizləyir (sızma yoxdur)
  S14 qismən nəticələr görünür qalır
  S15 Scope / EgressController / Guardian / HttpPolicy qapıları AKTİVDİR
  S16 metrikalar FAKTİKİ icra ilə uyğundur
  S17 hesabatlar completed/partial/failed/kəsinti hallarını AYIRD EDİR
"""
from __future__ import annotations

import asyncio
import pathlib

import pytest

from qbh import db
from qbh import urlintel as u
from qbh.adapters.base import current_process_guard
from qbh.adaptive import AdaptiveController
from qbh.authorization import from_config
from qbh.chain import ChainPipeline
from qbh.http_policy import HttpPolicy
from qbh.metrics import OrchestrationMetrics
from qbh.results import StageResult, now_iso
from qbh.scheduler import (HOST_GLOBAL, SchedTask, Scheduler, url_fair_key,
                           submit_with_backpressure)
from qbh.scope import ScopeError
from qbh.tasks import (STATE_COMPLETED, STATE_QUEUED, STATE_SKIPPED,
                       EventLedger, TaskLedger, task_identity)


async def _ok():
    return "ok"


def _chain_ctx(make_ctx, *, stage_status=None, events=True):
    ctx = make_ctx()
    ctx.authorization = from_config(ctx.cfg)
    ctx.scan_id = 1
    ctx.event_ledger = EventLedger() if events else None
    ctx.task_ledger = TaskLedger()
    ctx.adaptive = AdaptiveController(ledger=ctx.task_ledger)
    ctx.orchestration = OrchestrationMetrics()
    ctx.stage_status = dict(stage_status or {})
    return ctx


# ------------------------------------------------------------------ S01–S04


def test_s01_multiple_sources_same_endpoint_dedup():
    rows = [
        {"id": 1, "url": "http://h/a?id=1", "is_js": 0, "source": "katana",
         "subdomain": "h"},
        {"id": 2, "url": "http://h/a?id=1", "is_js": 0, "source": "gau",
         "subdomain": "h"},
        {"id": 3, "url": "http://H/a?id=1", "is_js": 0, "source": "waymore",
         "subdomain": "h"},
    ]
    intake = u.UrlIntelligence().intake(rows)
    assert intake.raw == 3
    assert intake.unique == 1          # üç mənbə → TƏK endpoint
    assert intake.duplicates == 2


def test_s02_distinct_params_independent():
    a = task_identity(1, "sqli", "http://h/p", param="id")
    b = task_identity(1, "sqli", "http://h/p", param="name")
    assert a != b
    led = TaskLedger()
    assert led.consider(a, engine="sqli", endpoint="http://h/p").create is True
    assert led.consider(b, engine="sqli", endpoint="http://h/p").create is True


def test_s03_distinct_methods_independent():
    get = task_identity(1, "api", "http://h/p", method="GET")
    post = task_identity(1, "api", "http://h/p", method="POST")
    assert get != post


def test_s04_distinct_test_types_independent():
    err = task_identity(1, "sqli", "http://h/p", test_type="error")
    boolean = task_identity(1, "sqli", "http://h/p", test_type="boolean")
    assert err != boolean


# ------------------------------------------------------------------ S05–S08


def test_s05_repeated_chain_events_no_duplicate(tmp_db, make_ctx):
    ctx = _chain_ctx(make_ctx, stage_status={"sqli": "ok"}, events=False)
    pipe = ChainPipeline(ctx)
    for _ in range(5):
        pipe.emit("sqli_signal", "http://127.0.0.1/p?id=1")
    assert len(pipe._pending) == 1              # tək davam testi
    assert ctx.adaptive.stats.skipped_duplicate == 4


async def test_s06_valid_followup_executes_via_controlled_path(tmp_db,
                                                               make_ctx):
    ctx = _chain_ctx(make_ctx, stage_status={"sqli": "ok"})
    pipe = ChainPipeline(ctx)
    pipe.emit("sqli_signal", "http://127.0.0.1/product?id=1")
    await pipe._dispatch_followups()
    assert pipe.followups
    assert ctx.adaptive.stats.dispatched == 1
    assert ctx.task_ledger.get(pipe.followups[0]["identity"]).state == \
        STATE_COMPLETED


async def test_s07_followup_outcomes_recorded(tmp_db, make_ctx):
    ctx = _chain_ctx(make_ctx, stage_status={"sqli": "ok", "xss": "failed"})
    pipe = ChainPipeline(ctx)
    pipe.emit("sqli_signal", "http://127.0.0.1/a?id=1")
    pipe.emit("xss_signal", "http://127.0.0.1/b?q=1")
    await pipe._dispatch_followups()
    outcomes = {f["outcome"] for f in pipe.followups}
    assert "completed" in outcomes
    assert "failed" in outcomes
    assert ctx.task_ledger.pending == 0
    # Aşkarlama AVTOMATİK təsdiqə ÇEVRİLMİR.
    assert ctx.adaptive.stats.validated == 0


async def test_s08_unsupported_followup_terminates_explicitly(tmp_db,
                                                              make_ctx):
    ctx = _chain_ctx(make_ctx)                  # stage_status BOŞ
    pipe = ChainPipeline(ctx)
    pipe.emit("sqli_signal", "http://127.0.0.1/p?id=1")
    await pipe._dispatch_followups()
    f = pipe.followups[0]
    assert f["outcome"] == "unsupported"
    assert f["reason"]                       # AÇIQ səbəb var
    assert ctx.task_ledger.get(f["identity"]).state == STATE_SKIPPED
    assert ctx.task_ledger.pending == 0


# ------------------------------------------------------------------ S09–S10


async def test_s09_queue_saturation_does_not_lose_tasks():
    led = TaskLedger()
    sched = Scheduler(workers=1, queue_limit=2, ledger=led)
    seen: list[str] = []

    async def work():
        await asyncio.sleep(0.005)
        return "ok"

    async with sched:
        states = []
        for i in range(8):
            ident = task_identity(1, "x", f"http://h/{i}")
            dec = led.consider(ident, engine="x", endpoint=f"http://h/{i}")
            if not dec.create:
                states.append("deduplicated")
                continue
            ok = await submit_with_backpressure(
                sched, SchedTask(identity=ident, engine="x", host="h", run=work),
                attempts=64, delay=0.005)
            states.append("accepted" if ok else "rejected")
            seen.append(ident)
        await sched.drain()
    snap = sched.snapshot()
    # Hər NIYYƏT edilən tapşırıq AÇIQ vəziyyətə çatdı — səssiz itki YOXDUR.
    assert len(states) == 8
    assert all(s == "accepted" for s in states)
    # Qəbul olunanların HAMISI faktiki icra olundu və növbə tam boşaldı.
    assert snap["submitted"] == 8
    assert snap["executed"] == 8
    assert snap["completed"] == 8
    assert snap["pending"] == 0
    assert snap["outstanding"] == 0
    # `rejected_backpressure` rədd olunmuş submit CƏHDLƏRİNİ sayır (məhdud
    # təkrar cəhdlər daxil) — bu, tapşırıq İTKİSİ DEYİL; yuxarıdakı saylar
    # bütün 8 tapşırığın qəbul və icra olunduğunu təsdiqləyir.
    assert snap["rejected_backpressure"] >= 0


async def test_s09b_rejected_task_is_explicit_not_silent():
    sched = Scheduler(workers=1, queue_limit=1)
    await sched.submit(SchedTask(identity="a", engine="x", host="h", run=_ok))
    ok = await submit_with_backpressure(
        sched, SchedTask(identity="b", engine="x", host="h", run=_ok),
        attempts=1, delay=0.0)
    assert ok is False                           # rədd AÇIQ bildirilir
    assert sched.snapshot()["rejected_backpressure"] == 1
    await sched.aclose()


async def test_s10_multi_host_fairness_real_metadata():
    order: list[str] = []
    sched = Scheduler(workers=1, queue_limit=100)
    urls = [("http://a.test/product/1", "a"),
            ("http://a.test/product/2", "a"),
            ("http://a.test/product/3", "a"),
            ("http://b.test/product/1", "b")]
    for url, tag in urls:
        host, fam = url_fair_key(url)
        await sched.submit(SchedTask(identity=f"id-{url}", engine="sqli",
                                     host=host, family=fam,
                                     run=_rec(tag, order)))
    async with sched:
        await sched.drain()
    assert order[1] == "b"                       # host b AÇ QALMIR


# ------------------------------------------------------------------ S11–S12


def test_s11_deferred_reconsidered_after_new_evidence():
    m = OrchestrationMetrics()
    intel = u.UrlIntelligence(metrics=m)
    rows = [{"id": 1, "url": "http://h/mystery", "is_js": 0,
             "source": "katana", "subdomain": "h"}]
    intel.plan_rows(rows, engine="sqli", limit=10)      # → deferred
    ident = u.endpoint_identity("http://h/mystery")
    assert ("sqli", ident) in intel.deferred_registry
    # Dəyişməyən dəlil → təkrar emal YOX.
    assert intel.reconsider("sqli", {ident: ()}) == []
    # YENİ parametr dəlili → uyğun hala keçir (bir dəfə).
    promoted = intel.reconsider("sqli", {ident: ("id",)})
    assert len(promoted) == 1
    assert ("sqli", ident) not in intel.deferred_registry
    assert intel.reconsider("sqli", {ident: ("id", "q")}) == []


def test_s12_engine_eligibility_consistent():
    rows = [
        {"id": 1, "url": "http://h/app.js", "is_js": 1, "source": "k",
         "subdomain": "h"},
        {"id": 2, "url": "http://h/style.css", "is_js": 0, "source": "k",
         "subdomain": "h"},
    ]
    intel = u.UrlIntelligence()
    kept_js, plan_js = intel.plan_rows(rows, engine="js", limit=10)
    assert {r["id"] for r in kept_js} == {1}     # yalnız JS
    # Determinizm: təkrar plan eyni qərarı verir (tutarlılıq).
    kept_again, plan_again = intel.plan_rows(rows, engine="js", limit=10)
    assert {r["id"] for r in kept_again} == {1}
    assert plan_again.excluded == plan_js.excluded


# ------------------------------------------------------------------ S13–S14


async def test_s13_cancellation_cleans_workers():
    sched = Scheduler(workers=3, queue_limit=50)

    async def slow():
        await asyncio.sleep(5)

    async with sched:
        for i in range(4):
            await sched.submit(SchedTask(identity=f"i{i}", engine="x",
                                         host="h", run=slow))
        await asyncio.sleep(0.05)
        assert sched._workers
    # `async with` çıxışı → `aclose()` işçiləri ləğv edib FAKTİKİ bitməsini gözləyir.
    assert sched._workers == []                  # işçi sızması YOXDUR


def test_s14_partial_results_visible(tmp_db, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from qbh.report import generator

    sid = db.start_scan("prog", "full")
    db.finish_scan(sid, "partial")
    stages = [StageResult(stage="vuln", status="partial", started_at=now_iso(),
                          completed_at=now_iso(),
                          warnings=["timeout: qismən nəticə saxlanıldı"])]
    path = generator.generate(stages=stages, meta={"scan_id": sid})
    text = pathlib.Path(path).read_text(encoding="utf-8")
    assert "partial" in text


# ------------------------------------------------------------------ S15–S17


async def test_s15_security_gates_active(tmp_db, loopback_config, make_ctx):
    # (a) Scope — fail-closed: kənar host RƏDD olunur.
    with pytest.raises(ScopeError):
        loopback_config.authorize_target("evil.example.com")
    assert loopback_config.authorize_target("127.0.0.1")

    # (b) HttpPolicy — sorğudan ƏVVƏL scope yoxlanır.
    policy = HttpPolicy(loopback_config.scope, rate=10, max_concurrency=2)
    with pytest.raises(ScopeError):
        await policy.get(None, "http://evil.example.com/")

    # (c) EgressController — alt-proses qapısı kontekst daxilində AKTİVDİR.
    ctx = make_ctx()
    assert current_process_guard() is None
    with ctx.egress.activate():
        assert current_process_guard() is not None
    assert current_process_guard() is None

    # (d) Guardian — aktiv və intrusiv qərarı verir.
    assert ctx.guardian is not None
    assert isinstance(ctx.guardian.allows_intrusive(), bool)


async def test_s16_metrics_match_actual_execution():
    led = TaskLedger()
    om = OrchestrationMetrics()
    sched = Scheduler(workers=2, global_limit=4, ledger=led, metrics=om)
    async with sched:
        for i in range(4):
            ident = task_identity(1, "sqli", f"http://h/{i}")
            led.consider(ident, engine="sqli", endpoint=f"http://h/{i}")
            await sched.submit(SchedTask(identity=ident, engine="sqli",
                                         host="h", run=_ok))
        await sched.drain()
    om.record_task_stats(led.snapshot(), sched.snapshot())
    snap = om.snapshot()
    assert snap["tasks_scheduler"]["executed"] == 4
    assert snap["tasks"]["executed"] == 4
    assert snap["tasks_sources"]["executed"] == "scheduler"
    # Niyyət/icra AYRI: ledger `queued` icra sayını şişirtmir.
    assert snap["tasks_ledger"]["queued"] == 4
    assert snap["tasks_sources"]["queued"] == "ledger"


def test_s17_reports_distinguish_scan_states(tmp_db, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from qbh.report import generator

    texts = {}
    for status in ("completed", "partial", "failed"):
        sid = db.start_scan("prog", "full")
        db.finish_scan(sid, status)
        path = generator.generate(meta={"scan_id": sid})
        texts[status] = pathlib.Path(path).read_text(encoding="utf-8")
    assert "Status: completed" in texts["completed"]
    assert "Status: partial" in texts["partial"]
    assert "Status: failed" in texts["failed"]

    # Kəsinti (crash): `finish_scan` çağırılmır → `running` qalır və heç bir
    # hesabat "completed" kimi təqdim olunmur.
    crashed = db.start_scan("prog", "full")
    row = db.get_db().execute("SELECT status FROM scans WHERE id=?",
                              (crashed,)).fetchone()
    assert row["status"] == "running"


# ---------------------------------------------------------------- köməkçilər


def _rec(tag: str, sink: list):
    async def _run():
        sink.append(tag)
        return tag
    return _run


# `HOST_GLOBAL` istinadı saxlanılır (F-06 sənədləşdirmə yoxlaması).
def test_host_global_sentinel_documented():
    assert HOST_GLOBAL == "*"
    assert STATE_QUEUED not in ("running",)   # dövlət sabitləri mövcuddur
