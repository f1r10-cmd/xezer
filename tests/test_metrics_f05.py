"""F-05 — tapşırıq metrikaları: NIYYƏT (ledger) vs FAKTİKİ İCRA (scheduler).

Yoxlanılan prinsiplər (hamısı loopback/şəbəkəsiz):
  * `executed` YALNIZ faktiki icradan (scheduler) gəlir — `consider()` çağırışları
    və ya adaptiv niyyətlər onu ŞİŞİRTMİR.
  * Ledger və scheduler sayları AYRI saxlanılır (`tasks_ledger`/`tasks_scheduler`).
  * Scheduler məlumatı olmadıqda faktiki-icra metrikləri UYDURULMUR — mənbə
    `unavailable` kimi işarələnir.
  * Heç bir açar iki mənbədən CƏMLƏNMİR (ikiqat sayma yoxdur).
"""
from __future__ import annotations

from qbh.metrics import TASK_KEYS, OrchestrationMetrics
from qbh.scheduler import SchedTask, Scheduler
from qbh.tasks import (STATE_COMPLETED, STATE_RUNNING, TaskLedger,
                       task_identity)


async def _noop():
    return "ok"


class TestMetricsSeparation:
    def test_adaptive_intention_does_not_inflate_executed(self):
        """Yalnız `consider()` (niyyət) → `executed` UYDURULMUR."""
        om = OrchestrationMetrics()
        led = TaskLedger()
        for i in range(5):
            led.consider(task_identity(1, "sqli", f"http://h/p{i}"),
                         engine="sqli", endpoint=f"http://h/p{i}")
        om.record_task_stats(led.snapshot())          # scheduler YOXDUR
        snap = om.snapshot()
        assert snap["tasks"]["queued"] == 5
        assert snap["tasks"]["considered"] == 5
        assert snap["tasks"]["executed"] == 0
        assert snap["tasks_sources"]["executed"] == "unavailable"

    def test_all_task_keys_present(self):
        om = OrchestrationMetrics()
        om.record_task_stats({}, None)
        snap = om.snapshot()
        for key in TASK_KEYS:
            assert key in snap["tasks"]
            assert key in snap["tasks_sources"]

    async def test_executed_matches_scheduler_not_ledger_intention(self):
        om = OrchestrationMetrics()
        led = TaskLedger()
        sched = Scheduler(workers=4, ledger=led, metrics=om)
        runs = {"n": 0}

        async def work():
            runs["n"] += 1

        async with sched:
            for i in range(6):
                ident = task_identity(1, "sqli", f"http://h/p{i}")
                led.consider(ident, engine="sqli", endpoint=f"http://h/p{i}")
                await sched.submit(SchedTask(identity=ident, engine="sqli",
                                             host="h", run=work))
            await sched.drain()

        om.record_task_stats(led.snapshot(), sched.snapshot())
        snap = om.snapshot()
        assert snap["tasks"]["executed"] == 6 == runs["n"]
        assert snap["tasks"]["considered"] == 6
        assert snap["tasks"]["accepted"] == 6
        assert snap["tasks_sources"]["executed"] == "scheduler"
        # Mənbələr AYRI saxlanılır.
        assert snap["tasks_ledger"]["executed"] == 6       # ledger "started"
        assert snap["tasks_scheduler"]["executed"] == 6

    async def test_ledger_only_completion_is_not_executed(self):
        """Adaptiv/dəftər-tərəfli tamamlanma `executed`-i şişirtmir."""
        om = OrchestrationMetrics()
        led = TaskLedger()
        sched = Scheduler(workers=2, ledger=led)

        async with sched:
            ident = task_identity(1, "sqli", "http://h/a")
            led.consider(ident, engine="sqli", endpoint="http://h/a")
            await sched.submit(SchedTask(identity=ident, engine="sqli",
                                         host="h", run=_noop))
            await sched.drain()

        # Dəftərdə TAMAMLANAN, lakin planlaşdırıcıdan KEÇMƏYƏN əlavə niyyət.
        extra = task_identity(1, "chain", "http://h/b", test_type="sqli_signal")
        led.consider(extra, engine="chain", endpoint="http://h/b")
        led.mark(extra, STATE_RUNNING)
        led.mark(extra, STATE_COMPLETED)

        om.record_task_stats(led.snapshot(), sched.snapshot())
        snap = om.snapshot()
        assert snap["tasks"]["executed"] == 1            # YALNIZ faktiki icra
        assert snap["tasks"]["started"] == 2             # ledger `started`
        assert snap["tasks_ledger"]["completed"] == 2    # ledger 2 bilir
        assert snap["tasks"]["completed"] == 1           # icra realm-i

    async def test_no_double_count_within_snapshot(self):
        om = OrchestrationMetrics()
        led = TaskLedger()
        sched = Scheduler(workers=2, ledger=led)

        async with sched:
            ident = task_identity(1, "xss", "http://h/q", param="q=1")
            led.consider(ident, engine="xss", endpoint="http://h/q", param="q=1")
            await sched.submit(SchedTask(identity=ident, engine="xss",
                                         host="h", run=_noop))
            await sched.drain()

        om.record_task_stats(led.snapshot(), sched.snapshot())
        om.record_task_stats(led.snapshot(), sched.snapshot())   # təkrar çağırış
        snap = om.snapshot()
        # Təkrar `record_task_stats` sayları İKİQAT ARTIRMIR (set, topla yox).
        assert snap["tasks"]["executed"] == 1
        assert snap["tasks"]["considered"] == 1
        assert snap["tasks"]["accepted"] == 1

    def test_scheduler_absent_labels_unavailable_and_uses_ledger_terminal(self):
        om = OrchestrationMetrics()
        led = TaskLedger()
        ident = task_identity(1, "sqli", "http://h/z")
        led.consider(ident, engine="sqli", endpoint="http://h/z")
        led.mark(ident, STATE_RUNNING)
        led.mark(ident, STATE_COMPLETED)
        om.record_task_stats(led.snapshot())
        snap = om.snapshot()
        assert snap["tasks"]["executed"] == 0
        assert snap["tasks_sources"]["executed"] == "unavailable"
        assert snap["tasks_sources"]["accepted"] == "unavailable"
        assert snap["tasks_sources"]["rejected"] == "unavailable"
        # Terminal say ledger-dən götürülür və mənbə açıq işarələnir.
        assert snap["tasks"]["completed"] == 1
        assert snap["tasks_sources"]["completed"] == "ledger"
