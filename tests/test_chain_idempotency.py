"""Zəncir idempotentliyi — təkrar siqnallar FAKTİKİ İCRANI artırmır (Faza 3 §7, Faza 8 §12).

Bu testlər LOQ YAZILARINI deyil, **FAKTİKİ İCRA SAYINI** ölçür:

  * Hadisə səviyyəsi deduplikasiya (`EventLedger.accept`) — eyni
    (kind, detail) təkrar emissiyası yenidən PLANLAŞDIRILMIR.
  * Tapşırıq-icra səviyyəsi deduplikasiya (`TaskLedger`) — eyni məntiqi
    tapşırıq yalnız BİR dəfə İCRA olunur.

İkisi AYRIDIR və bu fayl onları ayrı-ayrı sübut edir. Heç bir test xarici
hədəfə müraciət etmir — yalnız lokal/DB fixture.
"""
from __future__ import annotations

from qbh import urlintel
from qbh.adaptive import AdaptiveController
from qbh.authorization import from_config
from qbh.chain import ChainPipeline
from qbh.metrics import OrchestrationMetrics
from qbh.tasks import (STATE_COMPLETED, STATE_FAILED, STATE_RUNNING,
                       EventLedger, TaskLedger, task_identity)


def _ctx(make_ctx, *, events=True, adaptive=False, cfg=None):
    ctx = make_ctx(cfg)
    ctx.authorization = from_config(ctx.cfg)
    ctx.scan_id = 1
    ctx.event_ledger = EventLedger() if events else None
    ctx.task_ledger = TaskLedger()
    ctx.adaptive = AdaptiveController(ledger=ctx.task_ledger) if adaptive else None
    ctx.orchestration = OrchestrationMetrics()
    return ctx


def _ep(detail: str) -> str:
    """`chain._evaluate_signal` ilə eyni endpoint kimliyi çıxarışı."""
    try:
        return urlintel.endpoint_identity(detail) or detail
    except Exception:  # noqa: BLE001
        return detail


def _run_followup(pipe, action, endpoint, executed, *, param=""):
    """Konduktorun icra etdiyi məntiqi addımın idempotent variantı.

    Tapşırıq kimliyini `TaskLedger` ilə yoxlayır; YALNIZ qəbul olunan
    (`create=True`) tapşırıq FAKTİKİ İCRA sayğacına düşür.
    """
    ident = task_identity(pipe.store.scan_id, action, endpoint,
                          param=param, test_type=action)
    decision = pipe.task_ledger.consider(
        ident, engine=action, endpoint=endpoint, param=param, test_type=action)
    if decision.create:
        pipe.task_ledger.mark(ident, STATE_RUNNING)
        executed.append((action, param))
        pipe.task_ledger.mark(ident, STATE_COMPLETED)
    return decision


# --------------------------------------------------------------------------- #
# Təkrar siqnallar → tək icra
# --------------------------------------------------------------------------- #
class TestRepeatedSignals:
    def test_repeated_sqli_signal_executes_once(self, tmp_db, make_ctx):
        pipe = ChainPipeline(_ctx(make_ctx))
        executed: list = []
        detail = "http://127.0.0.1/product?id=1"
        ep = _ep(detail)
        for _ in range(6):
            actions = pipe.emit("sqli_signal", detail)
            for a in actions:
                _run_followup(pipe, a, ep, executed)
        # FAKTİKİ İCRA = 1, halbuki 6 hadisə emissiya olundu.
        assert executed == [("sqli_probe", "")]
        assert pipe.duplicates == 5
        assert pipe.event_ledger.stats.received == 6
        assert pipe.event_ledger.stats.emitted == 1

    def test_repeated_xss_signal_executes_once(self, tmp_db, make_ctx):
        pipe = ChainPipeline(_ctx(make_ctx))
        executed: list = []
        detail = "http://127.0.0.1/search?q=admin"
        ep = _ep(detail)
        for _ in range(5):
            for a in pipe.emit("xss_signal", detail):
                _run_followup(pipe, a, ep, executed)
        assert executed == [("xss_probe", "")]
        assert pipe.duplicates == 4

    def test_repeated_js_lib_signal_executes_once(self, tmp_db, make_ctx):
        pipe = ChainPipeline(_ctx(make_ctx))
        executed: list = []
        detail = "127.0.0.1:CVE-2020-0001"
        ep = _ep(detail)
        for _ in range(4):
            for a in pipe.emit("vuln_js_lib", detail):
                _run_followup(pipe, a, ep, executed)
        assert executed == [("library_cve_check", "")]
        assert pipe.duplicates == 3

    def test_repeated_signal_adaptive_schedules_once(self, tmp_db, make_ctx):
        # Hadisə deduplikasiyası SÖNDÜRÜLMÜŞ — adaptiv qat özü təkrarı tutur.
        ctx = _ctx(make_ctx, events=False, adaptive=True)
        pipe = ChainPipeline(ctx)
        for _ in range(4):
            pipe.emit("sqli_signal", "http://127.0.0.1/product?id=1")
        assert ctx.adaptive.stats.scheduled == 1
        assert ctx.adaptive.stats.skipped_duplicate == 3


# --------------------------------------------------------------------------- #
# Hadisə dedup ≠ tapşırıq-icra dedup
# --------------------------------------------------------------------------- #
class TestEventVsTaskDedup:
    def test_event_dedup_blocks_rescheduling(self, tmp_db, make_ctx):
        pipe = ChainPipeline(_ctx(make_ctx))
        detail = "http://127.0.0.1/a?id=1"
        assert pipe.emit("sqli_signal", detail) == ["sqli_probe"]
        # Eyni hadisə təkrar emissiya olunarsa yenidən planlaşdırılmır.
        assert pipe.emit("sqli_signal", detail) == []
        assert pipe.duplicates == 1

    def test_task_dedup_blocks_execution_without_event_dedup(self, tmp_db, make_ctx):
        # Hadisə deduplikasiyası YOXDUR → emit hər dəfə planlaşdırır,
        # L AKİN faktiki icra `TaskLedger` tərəfindən BİR dəfəyə salınır.
        ctx = _ctx(make_ctx, events=False)
        pipe = ChainPipeline(ctx)
        executed: list = []
        detail = "http://127.0.0.1/product?id=1"
        ep = _ep(detail)
        for _ in range(5):
            actions = pipe.emit("sqli_signal", detail)
            assert actions == ["sqli_probe"]
            for a in actions:
                _run_followup(pipe, a, ep, executed)
        assert executed == [("sqli_probe", "")]
        assert pipe.duplicates == 0
        assert ctx.task_ledger.stats.considered == 5
        assert ctx.task_ledger.stats.deduplicated == 4
        assert ctx.task_ledger.stats.to_dict()["executed"] == 1

    def test_local_step_gate_prevents_reexecution(self, tmp_db, make_ctx):
        pipe = ChainPipeline(_ctx(make_ctx))
        runs: list = []
        for _ in range(3):
            ident = pipe._begin("bypass_matrix", "bypass")
            if ident is not None:
                runs.append("bypass_matrix")   # FAKTİKİ İCRA
                pipe._done(ident)
        assert runs == ["bypass_matrix"]
        assert pipe.suppressed == 2


# --------------------------------------------------------------------------- #
# Məşru FƏRQLİ işlərin BOĞULMAMASI
# --------------------------------------------------------------------------- #
class TestIndependentWork:
    def test_distinct_parameters_distinct_tasks(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx, events=False)
        pipe = ChainPipeline(ctx)
        executed: list = []
        d1 = "http://127.0.0.1/product?id=1"
        d2 = "http://127.0.0.1/product?id=2"
        ep = _ep(d1)
        assert _ep(d2) == ep                     # eyni endpoint (ailə)
        pipe.emit("sqli_signal", d1)
        _run_followup(pipe, "sqli_probe", ep, executed, param="id=1")
        pipe.emit("sqli_signal", d2)
        _run_followup(pipe, "sqli_probe", ep, executed, param="id=2")
        # Fərqli parametrlər → 2 AYRI məşru icra (dedup BOĞMUR).
        assert len(executed) == 2
        assert executed == [("sqli_probe", "id=1"), ("sqli_probe", "id=2")]

    def test_distinct_endpoints_distinct_tasks(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx, events=False)
        pipe = ChainPipeline(ctx)
        executed: list = []
        for path in ("/a?id=1", "/b?id=1", "/c?id=1"):
            d = f"http://127.0.0.1{path}"
            pipe.emit("sqli_signal", d)
            _run_followup(pipe, "sqli_probe", _ep(d), executed)
        assert len(executed) == 3

    def test_independent_kinds_both_scheduled(self, tmp_db, make_ctx):
        pipe = ChainPipeline(_ctx(make_ctx))
        assert pipe.emit("sqli_signal", "http://127.0.0.1/p?id=1") == ["sqli_probe"]
        assert pipe.emit("xss_signal", "http://127.0.0.1/p?id=1") == ["xss_probe"]


# --------------------------------------------------------------------------- #
# Bounded retry — məşru, L AKİN məhdud
# --------------------------------------------------------------------------- #
class TestRetryPolicy:
    def test_retry_after_failure_executes_again(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx)
        pipe = ChainPipeline(ctx)
        executed: list = []
        ep = "http://127.0.0.1/x"
        d = _run_followup(pipe, "sqli_probe", ep, executed)
        assert d.create
        ctx.task_ledger.mark(d.identity, STATE_FAILED)
        d2 = _run_followup(pipe, "sqli_probe", ep, executed)
        assert d2.create                          # bounded retry icazəli
        assert len(executed) == 2

    def test_bounded_retry_limit(self, tmp_db):
        led = TaskLedger(max_attempts=2)
        ident = task_identity(1, "sqli", "http://h/product", test_type="sqli_probe")
        assert led.consider(ident, test_type="sqli_probe").create
        for _ in range(2):
            led.mark(ident, STATE_FAILED)
            assert led.consider(ident, test_type="sqli_probe").create
        led.mark(ident, STATE_FAILED)
        assert not led.consider(ident, test_type="sqli_probe").create  # limit

    def test_completed_not_retried(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx)
        pipe = ChainPipeline(ctx)
        executed: list = []
        ep = "http://127.0.0.1/y"
        _run_followup(pipe, "sqli_probe", ep, executed)   # completed
        _run_followup(pipe, "sqli_probe", ep, executed)
        assert len(executed) == 1


# --------------------------------------------------------------------------- #
# Dövr / həddindən artıq təkrar tetikleme nəzarəti
# --------------------------------------------------------------------------- #
class TestCycleControl:
    def test_guard_bounds_repeated_trigger(self, tmp_db):
        led = EventLedger(max_attempts=3)
        got = [led.guard(source="sqli_signal", destination="sqli_probe").accept
               for _ in range(5)]
        assert got == [True, True, True, False, False]
        assert led.stats.cyclic == 2
        assert led.stats.conditions_rejected == 2
        assert led.stats.scheduled == 3

    def test_guard_per_identity_independent(self, tmp_db):
        # FƏRQLİ hadisə kimlikləri → hər biri müstəqil (biri digərini boğmur).
        led = EventLedger(max_attempts=3)
        for i in range(5):
            d = led.guard(source="sqli_signal", destination="sqli_probe",
                          identity=f"ev{i}")
            assert d.accept is True
        assert led.stats.cyclic == 0
        assert led.stats.scheduled == 5

    def test_guard_depth_limit(self, tmp_db):
        led = EventLedger(max_depth=2)
        assert led.guard(source="a", destination="b", depth=2).accept
        assert not led.guard(source="a", destination="b", depth=3).accept
        assert led.stats.conditions_rejected == 1

    def test_distinct_events_not_over_suppressed(self, tmp_db, make_ctx):
        # FƏRQLİ endpoint siqnalları bir-birini boğmamalıdır (əhatə qorunur).
        pipe = ChainPipeline(_ctx(make_ctx))
        allowed = [len(pipe.emit("sqli_signal", f"http://127.0.0.1/p?id={i}"))
                   for i in range(5)]
        assert allowed == [1, 1, 1, 1, 1]
        assert pipe.suppressed == 0
        # Eyni hadisənin təkrarı isə hadisə səviyyəsində tutulur.
        assert pipe.emit("sqli_signal", "http://127.0.0.1/p?id=0") == []
        assert pipe.duplicates == 1
