"""Faza 4 (§8) — mərkəzləşdirilmiş məhdud planlaşdırıcı testləri.

Yoxlanılan prinsiplər (hamısı loopback/şəbəkəsiz):
  * Bütün tapşırıqlar icra olunur; faktiki İCRA sayı ölçülür.
  * Backpressure: növbə doyduqda `submit()` `False` qaytarır.
  * Qlobal / host / mühərrik concurrency tavanları GÖZLƏNİLİR.
  * Host və endpoint-ailəsi ədaləti (round-robin).
  * Ləğv (cancellation) işçi SIZMASI yaratmır.
  * Bir tapşırığın xətası digərlərini DAYANDIRMIR.
  * `TaskLedger` ilə birlikdə DUBLİKAT İCRA qarşısı alınır (yalnız log deyil).
"""
from __future__ import annotations

import asyncio

from qbh.scheduler import (SchedTask, Scheduler,  # noqa: I001
                           submit_with_backpressure)
from qbh.tasks import TaskLedger, STATE_COMPLETED, task_identity


async def _noop():
    return None


class TestSchedulerBasics:
    async def test_runs_all_tasks_and_counts(self):
        s = Scheduler(workers=4)
        seen: list[int] = []

        async def work(i):
            seen.append(i)

        async with s:
            for i in range(10):
                await s.submit(SchedTask(identity=f"t{i}", engine="e",
                                         host="h", run=lambda i=i: work(i)))
            await s.drain()
        assert sorted(seen) == list(range(10))
        assert s.executed == 10
        assert s.completed == 10

    async def test_snapshot_shape(self):
        s = Scheduler(workers=2)
        async with s:
            await s.submit(SchedTask(identity="a", engine="e", host="h",
                                     run=_noop))
            await s.drain()
        snap = s.snapshot()
        for key in ("submitted", "executed", "completed", "failed",
                    "cancelled", "rejected_backpressure", "peak_queue",
                    "peak_concurrency", "workers", "queue_limit"):
            assert key in snap


class TestConcurrency:
    async def test_global_limit_respected(self):
        s = Scheduler(workers=10, global_limit=3)
        active = 0
        peak = 0

        async def work():
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.02)
            active -= 1

        async with s:
            for i in range(20):
                await s.submit(SchedTask(identity=f"t{i}", engine="e",
                                         host="h", run=work))
            await s.drain()
        assert peak <= 3
        assert s.peak_concurrency <= 3

    async def test_per_host_limit_respected(self):
        s = Scheduler(workers=10, per_host_limit=2)
        active: dict[str, int] = {}
        peak: dict[str, int] = {}

        async def work(host):
            active[host] = active.get(host, 0) + 1
            peak[host] = max(peak.get(host, 0), active[host])
            await asyncio.sleep(0.02)
            active[host] -= 1

        async with s:
            for i in range(12):
                host = "h1" if i % 2 == 0 else "h2"
                await s.submit(SchedTask(identity=f"t{i}", engine="e",
                                         host=host,
                                         run=lambda h=host: work(h)))
            await s.drain()
        assert peak.get("h1", 0) <= 2
        assert peak.get("h2", 0) <= 2

    async def test_engine_limit_respected(self):
        s = Scheduler(workers=10, engine_limits={"sqli": 1})
        active = 0
        peak = 0

        async def work():
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.02)
            active -= 1

        async with s:
            for i in range(6):
                await s.submit(SchedTask(identity=f"t{i}", engine="sqli",
                                         host="h", run=work))
            await s.drain()
        assert peak <= 1


class TestBackpressure:
    async def test_queue_limit_rejects_overflow(self):
        s = Scheduler(workers=1, queue_limit=2)
        started = asyncio.Event()
        release = asyncio.Event()

        async def slow():
            started.set()
            await release.wait()

        s.start()
        try:
            await s.submit(SchedTask(identity="a", engine="e", host="h",
                                     run=slow))
            await started.wait()            # işçi "a" ilə məşğuldur
            assert await s.submit(SchedTask(identity="b", engine="e",
                                            host="h", run=_noop)) is True
            assert await s.submit(SchedTask(identity="c", engine="e",
                                            host="h", run=_noop)) is True
            assert await s.submit(SchedTask(identity="d", engine="e",
                                            host="h", run=_noop)) is False
            assert s.rejected == 1
            release.set()
            await s.drain()
        finally:
            await s.aclose()


class TestFairness:
    async def test_host_round_robin(self):
        s = Scheduler(workers=1)
        order: list[str] = []

        async def work(tag):
            order.append(tag)

        async with s:
            for i in range(4):
                await s.submit(SchedTask(identity=f"a{i}", engine="e",
                                         host="h1", run=lambda: work("h1")))
                await s.submit(SchedTask(identity=f"b{i}", engine="e",
                                         host="h2", run=lambda: work("h2")))
            await s.drain()
        assert order[:4] == ["h1", "h2", "h1", "h2"]

    async def test_endpoint_family_round_robin(self):
        s = Scheduler(workers=1)
        order: list[str] = []

        async def work(tag):
            order.append(tag)

        async with s:
            for i in range(3):
                await s.submit(SchedTask(identity=f"p{i}", engine="e", host="h",
                                         family="/a", run=lambda: work("a")))
                await s.submit(SchedTask(identity=f"q{i}", engine="e", host="h",
                                         family="/b", run=lambda: work("b")))
            await s.drain()
        assert order[:4] == ["a", "b", "a", "b"]

    async def test_priority_bucket_first(self):
        s = Scheduler(workers=1)
        order: list[str] = []

        async def work(tag):
            order.append(tag)

        async with s:
            await s.submit(SchedTask(identity="lo", engine="e", host="h",
                                     priority=0, run=lambda: work("lo")))
            await s.submit(SchedTask(identity="hi", engine="e", host="h",
                                     priority=5, run=lambda: work("hi")))
            await s.drain()
        assert order == ["hi", "lo"]


class TestCancellation:
    async def test_aclose_no_worker_leak(self):
        s = Scheduler(workers=3)
        s.start()
        workers = list(s._workers)
        assert len(workers) == 3
        await s.aclose()
        assert all(w.done() for w in workers)
        assert s._workers == []

    async def test_cancel_running_marks_cancelled(self):
        s = Scheduler(workers=1)
        started = asyncio.Event()

        async def slow():
            started.set()
            await asyncio.sleep(10)

        s.start()
        await s.submit(SchedTask(identity="a", engine="e", host="h", run=slow))
        await started.wait()
        await s.aclose()
        assert s.cancelled >= 1


class TestFailureIsolation:
    async def test_one_failure_does_not_stop_others(self):
        s = Scheduler(workers=2)
        done: list[str] = []

        async def ok(tag):
            done.append(tag)

        async def boom():
            raise RuntimeError("boom")

        async with s:
            await s.submit(SchedTask(identity="a", engine="e", host="h",
                                     run=boom))
            await s.submit(SchedTask(identity="b", engine="e", host="h",
                                     run=lambda: ok("b")))
            await s.submit(SchedTask(identity="c", engine="e", host="h",
                                     run=lambda: ok("c")))
            await s.drain()
        assert sorted(done) == ["b", "c"]
        assert s.failed == 1
        assert s.completed == 2


class TestLedgerIntegration:
    async def test_ledger_tracks_lifecycle(self):
        led = TaskLedger()
        s = Scheduler(workers=2, ledger=led)
        ident = task_identity(1, "sqli", "http://h/p", param="id=1")
        async with s:
            led.consider(ident, engine="sqli", endpoint="http://h/p")
            await s.submit(SchedTask(identity=ident, engine="sqli", host="h",
                                     run=_noop))
            await s.drain()
        assert led.get(ident).state == STATE_COMPLETED

    async def test_duplicate_task_executed_once(self):
        """İdempotentlik FAKTİKİ icra sayını azaldır (yalnız log deyil)."""
        led = TaskLedger()
        s = Scheduler(workers=4, ledger=led)
        runs = 0

        async def work():
            nonlocal runs
            runs += 1

        ident = task_identity(1, "sqli", "http://h/p", param="id=1")
        async with s:
            for _ in range(5):
                d = led.consider(ident, engine="sqli", endpoint="http://h/p")
                if d.create:
                    await s.submit(SchedTask(identity=ident, engine="sqli",
                                             host="h", run=work))
            await s.drain()
        assert runs == 1
        assert led.stats.deduplicated == 4
        assert s.executed == 1


class TestBackpressureHelper:
    """F-02: `submit_with_backpressure` MƏHDUD gözləmə ilə qəbul zəmanəti verir.

    Növbə doyduqda sonsuz gözləmir; cəhdlər bitərsə `False` qaytarır ki, çağıran
    mərhələni AÇIQ şəkildə qeyd edə bilsin (səssiz itki olmasın).
    """

    async def test_submits_when_space_available(self):
        s = Scheduler(workers=2)
        done: list[int] = []

        async def work():
            done.append(1)

        s.start()
        try:
            ok = await submit_with_backpressure(
                s, SchedTask(identity="a", engine="e", host="h", run=work))
            assert ok is True
            await s.drain()
        finally:
            await s.aclose()
        assert done == [1]
        assert s.executed == 1

    async def test_retries_until_queue_drains(self):
        s = Scheduler(workers=1, queue_limit=1)
        started = asyncio.Event()
        release = asyncio.Event()

        async def blocking():
            started.set()
            await release.wait()

        s.start()
        try:
            await s.submit(SchedTask(identity="busy", engine="e", host="h",
                                     run=blocking))
            await started.wait()
            await s.submit(SchedTask(identity="q", engine="e", host="h",
                                     run=_noop))   # növbə doldu (limit=1)

            async def releaser():
                await asyncio.sleep(0.05)
                release.set()

            t = asyncio.create_task(releaser())
            ok = await submit_with_backpressure(
                s, SchedTask(identity="c", engine="e", host="h", run=_noop),
                attempts=200, delay=0.01)
            await t
            assert ok is True
            await s.drain()
        finally:
            await s.aclose()
        assert s.completed == 3

    async def test_returns_false_when_bounded_attempts_exhausted(self):
        s = Scheduler(workers=1, queue_limit=1)
        started = asyncio.Event()
        release = asyncio.Event()

        async def blocking():
            started.set()
            await release.wait()

        s.start()
        try:
            await s.submit(SchedTask(identity="busy", engine="e", host="h",
                                     run=blocking))
            await started.wait()
            await s.submit(SchedTask(identity="q", engine="e", host="h",
                                     run=_noop))
            ok = await submit_with_backpressure(
                s, SchedTask(identity="c", engine="e", host="h", run=_noop),
                attempts=3, delay=0.01)
            assert ok is False
            assert s.rejected >= 1
            release.set()
            await s.drain()
        finally:
            await s.aclose()
