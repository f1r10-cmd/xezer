"""F-01 — Zəncir davam testlərinin KONTROLLU icrası və nəticə qeydi.

Yoxlanılan prinsiplər (hamısı loopback/DB fixture — xarici şəbəkə YOXDUR):

  * `chain._evaluate_signal()` `adaptive.evaluate()` qaytardığı `FollowUp`-u
    AT MIR — planlaşdırılan davam testi növbəyə alınır.
  * Davam testinin nəticəsi YALNIZ REAL icradan sonra yazılır
    (`record_outcome`) — planlaşdırma anında DEYİL.
  * Heç bir davam tapşırığı `queued` vəziyyətində ƏBƏDİ qalmır.
  * Dəstəklənməyən / icra olunmayan hərəkətlər AÇIQ səbəblə qeyd olunur.
  * Təkrar siqnal DUBLİKAT davam testi planlaşdırmır.
  * Aşkarlama HEÇ VAXT avtomatik "təsdiqlənmiş" sayılmır (skipped→inconclusive).
"""
from __future__ import annotations

from qbh.adaptive import OUTCOME_COMPLETED, AdaptiveController
from qbh.authorization import from_config
from qbh.chain import ChainPipeline
from qbh.metrics import OrchestrationMetrics
from qbh.tasks import STATE_COMPLETED, STATE_PARTIAL, STATE_QUEUED, STATE_SKIPPED
from qbh.tasks import EventLedger, TaskLedger


def _ctx(make_ctx, *, stage_status=None, events=True):
    ctx = make_ctx()
    ctx.authorization = from_config(ctx.cfg)
    ctx.scan_id = 1
    ctx.event_ledger = EventLedger() if events else None
    ctx.task_ledger = TaskLedger()
    ctx.adaptive = AdaptiveController(ledger=ctx.task_ledger)
    ctx.orchestration = OrchestrationMetrics()
    ctx.stage_status = dict(stage_status or {})
    return ctx


class TestFollowUpScheduling:
    def test_signal_schedules_pending_followup(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx)
        pipe = ChainPipeline(ctx)
        pipe.emit("sqli_signal", "http://127.0.0.1/product?id=1")
        # FollowUp ATILMIR — növbəyə alınır.
        assert len(pipe._pending) == 1
        assert pipe._pending[0].actions == ("sqli_probe",)
        assert ctx.adaptive.stats.scheduled == 1

    def test_repeated_signal_single_pending(self, tmp_db, make_ctx):
        # Hadisə deduplikasiyası SÖNDÜRÜLMÜŞ olsa da adaptiv qat təkrarı tutur.
        ctx = _ctx(make_ctx, events=False)
        pipe = ChainPipeline(ctx)
        for _ in range(6):
            pipe.emit("sqli_signal", "http://127.0.0.1/product?id=1")
        assert len(pipe._pending) == 1
        assert ctx.adaptive.stats.skipped_duplicate == 5

    def test_distinct_endpoints_distinct_pending(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx, events=False)
        pipe = ChainPipeline(ctx)
        for path in ("/a?id=1", "/b?id=1", "/c?id=1"):
            pipe.emit("sqli_signal", f"http://127.0.0.1{path}")
        assert len(pipe._pending) == 3


class TestFollowUpOutcome:
    async def test_delegated_ok_records_completed(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx, stage_status={"sqli": "ok"})
        pipe = ChainPipeline(ctx)
        pipe.emit("sqli_signal", "http://127.0.0.1/product?id=1")
        await pipe._dispatch_followups()
        rec = ctx.task_ledger.get(pipe.followups[0]["identity"])
        assert rec.state == STATE_COMPLETED
        assert ctx.adaptive.stats.dispatched == 1
        assert ctx.task_ledger.pending == 0
        # Aşkarlama təsdiqə ÇEVRİLMİR: `validated` sayılmır.
        assert ctx.adaptive.stats.validated == 0

    async def test_delegated_skipped_is_inconclusive(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx, stage_status={"sqli": "skipped"})
        pipe = ChainPipeline(ctx)
        pipe.emit("sqli_signal", "http://127.0.0.1/p?id=1")
        await pipe._dispatch_followups()
        assert ctx.task_ledger.get(pipe.followups[0]["identity"]).state == \
            STATE_PARTIAL
        assert ctx.adaptive.stats.inconclusive == 1

    async def test_delegated_failed_is_failed(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx, stage_status={"xss": "failed"})
        pipe = ChainPipeline(ctx)
        pipe.emit("xss_signal", "http://127.0.0.1/p?q=1")
        await pipe._dispatch_followups()
        assert ctx.adaptive.stats.failed == 1

    async def test_delegated_cancelled_is_cancelled(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx, stage_status={"ssti": "cancelled"})
        pipe = ChainPipeline(ctx)
        pipe.emit("ssti_signal", "http://127.0.0.1/p?q=1")
        await pipe._dispatch_followups()
        assert ctx.adaptive.stats.cancelled == 1

    async def test_missing_stage_recorded_unsupported(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx)                 # stage_status BOŞ
        pipe = ChainPipeline(ctx)
        pipe.emit("sqli_signal", "http://127.0.0.1/p?id=1")
        await pipe._dispatch_followups()
        assert pipe.followups[0]["outcome"] == "unsupported"
        assert "icra olunmadı" in pipe.followups[0]["reason"]
        assert ctx.adaptive.stats.unsupported == 1
        assert ctx.task_ledger.get(
            pipe.followups[0]["identity"]).state == STATE_SKIPPED
        assert ctx.task_ledger.pending == 0

    async def test_no_identity_left_queued(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx, stage_status={"sqli": "ok", "xss": "failed"})
        pipe = ChainPipeline(ctx)
        pipe.emit("sqli_signal", "http://127.0.0.1/a?id=1")
        pipe.emit("xss_signal", "http://127.0.0.1/b?q=1")
        await pipe._dispatch_followups()
        assert ctx.task_ledger.pending == 0
        for f in pipe.followups:
            assert ctx.task_ledger.get(f["identity"]).state != STATE_QUEUED

    async def test_dispatch_is_idempotent(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx, stage_status={"sqli": "ok"})
        pipe = ChainPipeline(ctx)
        pipe.emit("sqli_signal", "http://127.0.0.1/p?id=1")
        await pipe._dispatch_followups()
        n = ctx.adaptive.stats.dispatched
        await pipe._dispatch_followups()      # ikinci çağırış — təkrar yox
        assert ctx.adaptive.stats.dispatched == n
        assert len(pipe.followups) == 1


class TestFollowUpResolution:
    def test_local_action_uses_executed_state(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx)
        pipe = ChainPipeline(ctx)
        pipe.executed.append("bypass_matrix")
        outcome, reason = pipe._followup_outcome(("bypass_matrix",))
        assert outcome == OUTCOME_COMPLETED
        assert "local:" in reason

    def test_local_action_not_executed_unsupported(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx)
        pipe = ChainPipeline(ctx)
        outcome, _ = pipe._followup_outcome(("bypass_matrix",))
        assert outcome is None

    def test_unknown_action_unsupported(self, tmp_db, make_ctx):
        pipe = ChainPipeline(_ctx(make_ctx))
        outcome, reason = pipe._followup_outcome(("totally_unknown_action",))
        assert outcome is None
        assert "dəstəklənmir" in reason


class TestRunIntegration:
    async def test_run_dispatches_followups_from_db(self, tmp_db, make_ctx):
        from qbh import db

        hid = db.upsert_host("127.0.0.1", status_code=200, scan_id=1)
        db.insert_url(hid, "http://127.0.0.1/product?id=1", "katana",
                      is_js=False, scan_id=1)
        ctx = _ctx(make_ctx, stage_status={"sqli": "ok", "xss": "ok"})
        pipe = ChainPipeline(ctx)
        res = await pipe.run()
        # DB-dən gələn parametrli URL → sqli/xss siqnalı → davam testləri.
        assert res.data["followups"]
        assert ctx.task_ledger.pending == 0
        outcomes = {f["outcome"] for f in res.data["followups"]}
        assert "completed" in outcomes
