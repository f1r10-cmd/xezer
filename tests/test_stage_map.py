"""Faza 3 (F-04/F-06) — mərhələ asılılıq xəritəsi, ədalət açarları və
idempotentlik müqaviləsi testləri.

Yoxlanılan prinsiplər (hamısı şəbəkəsiz):
  * `STAGE_MAP` bütün pipeline mərhələlərini əhatə edir, prereq-lər mövcuddur,
    qraf DÖVRSÜZDÜR (DAG) və sıra zəmanəti pozulmur.
  * `stage_klass` naməlum mərhələ üçün ardıcıl (3) qaytarır — səssizcə paralel
    sayılmır.
  * `url_fair_key()` REAL `(host, ailə)` verir; etibarsız URL üçün host UYDURULMUR.
  * Hostları əhatə edən mərhələlər üçün `HOST_GLOBAL` sentinel istifadə olunur.
  * Ədalət REAL çox-hostlu/çox-ailəli metadata ilə işləyir (bir host digərini
    AÇ QOYMASIN).
  * İdempotentlik müqaviləsi: TƏK həqiqət mənbəyi `TaskLedger`-dir — eyni
    kimlik yalnız BİR dəfə icra olunur; dublikat səssizcə ATILMIR, AÇIQ
    `skipped` kimi qeyd olunur.
"""
from __future__ import annotations

import argparse
import asyncio

import pytest

from qbh import conductor as conductor_mod
from qbh.conductor import STAGE_MAP, Conductor, stage_klass
from qbh.results import EngineResult
from qbh.scheduler import (HOST_GLOBAL, SchedTask, Scheduler, url_fair_key,
                           submit_with_backpressure)
from qbh.tasks import (STATE_FAILED, TaskLedger, task_identity)

# ------------------------------------------------------------------ helpers


def _args() -> argparse.Namespace:
    return argparse.Namespace(
        config="", mode="full", aggressiveness=None, proxy="off", rate=None,
        severity="low", auto_install=False, dry_run=False, targets=None,
        active_fuzz=None, race_fixture=None, race_count=10, race_concurrency=4)


@pytest.fixture
def make_conductor(tmp_db, loopback_config):
    """Loopback konfiq üzərində real `Conductor` qurur (şəbəkəsiz)."""
    def _make(cfg=None) -> Conductor:
        return Conductor(cfg or loopback_config, _args())
    return _make


async def _run_sched(sched: Scheduler) -> None:
    async with sched:
        await sched.drain()


# ---------------------------------------------------------------- STAGE_MAP


class TestStageMap:
    def test_all_prereqs_declared(self):
        """Hər prereq adı xəritədə MÖVCUD olmalıdır (asılılıq qırılmır)."""
        missing = []
        for stage, meta in STAGE_MAP.items():
            for pre in meta.get("prereq", ()):
                if pre not in STAGE_MAP:
                    missing.append((stage, pre))
        assert missing == [], f"naməlum prereq: {missing}"

    def test_no_self_prereq(self):
        for stage, meta in STAGE_MAP.items():
            assert stage not in meta.get("prereq", ()), f"{stage} özünə asılıdır"

    def test_dag_is_acyclic(self):
        """Prereq qrafı DÖVRSÜZ olmalıdır (sıra zəmanəti üçün)."""
        visiting: set[str] = set()
        done: set[str] = set()

        def visit(node: str) -> None:
            if node in done:
                return
            assert node not in visiting, f"dövr aşkarlandı: {node}"
            visiting.add(node)
            for pre in STAGE_MAP.get(node, {}).get("prereq", ()):
                visit(pre)
            visiting.discard(node)
            done.add(node)

        for stage in STAGE_MAP:
            visit(stage)

    def test_classes_are_valid(self):
        for stage, meta in STAGE_MAP.items():
            assert meta.get("klass") in (1, 2, 3, 4), f"{stage}: {meta.get('klass')}"

    def test_stage_klass_defaults_serial(self):
        """Naməlum mərhələ səssizcə paralel SAYILMIR — 3 (ardıcıl)."""
        assert stage_klass("mövcud-olmayan-mərhələ") == 3

    def test_stage_klass_declared(self):
        assert stage_klass("validation") == 4
        assert stage_klass("chain") == 4
        assert stage_klass("api_enum") == 3

    def test_bounded_parallel_group_declared(self):
        """`_run_parallel` qrupu YALNIZ məhdud sinif (2) mərhələlərdən ibarətdir."""
        for stage in ("vuln", "js", "content", "ferox"):
            assert stage_klass(stage) == 2, stage

    def test_pipeline_order_preserved(self):
        """Kritik sıra zəmanətləri: fingerprint → vuln; validation → chain."""
        assert "fingerprint" in STAGE_MAP["vuln"]["prereq"]
        assert "validation" in STAGE_MAP["chain"]["prereq"]
        for pre in ("sqli", "xss", "ssti", "ssrf", "vuln"):
            assert pre in STAGE_MAP["validation"]["prereq"]


# ------------------------------------------------------------ ədalət açarları


class TestFairnessKeys:
    def test_url_fair_key_real_host_and_family(self):
        host, fam = url_fair_key("http://a.test/api/v1/users?id=1")
        assert host == "a.test"
        assert fam                      # ailə BOŞ deyil (uydurma deyil, real)

    def test_url_fair_key_distinct_hosts(self):
        assert url_fair_key("http://a.test/x") != url_fair_key("http://b.test/x")

    def test_url_fair_key_numeric_segments_share_family(self):
        """/product/1 və /product/2 AYNI ailədir (rəqəm {id} ilə əvəz olunur)."""
        _, f1 = url_fair_key("http://a.test/product/1")
        _, f2 = url_fair_key("http://a.test/product/2")
        assert f1 == f2

    def test_url_fair_key_no_fabrication_on_invalid(self):
        """Etibarsız URL üçün host UYDURULMUR — boş qalır."""
        assert url_fair_key("not a url") == ("", "")
        assert url_fair_key("") == ("", "")

    def test_host_global_sentinel(self):
        assert HOST_GLOBAL == "*"

    async def test_host_global_bucket_is_separate_per_stage(self):
        """Host-üzrə scope-u olmayan mərhələlər AYRI vedrəyə düşür (F-06)."""
        sched = Scheduler(workers=2, queue_limit=10)
        for stage in ("fingerprint", "takeover"):
            await sched.submit(SchedTask(
                identity=f"id-{stage}", engine=stage, host=HOST_GLOBAL,
                family=stage, run=lambda: _noop()))
        await _run_sched(sched)
        snap = sched.snapshot()
        assert snap["host_runs"].get(HOST_GLOBAL) == 2
        assert set(snap["engine_runs"]) == {"fingerprint", "takeover"}

    async def test_multi_host_fairness_real_metadata(self):
        """Bir host çoxlu işlə digər hostu AÇ QOYMASIN (round-robin)."""
        order: list[str] = []
        sched = Scheduler(workers=1, queue_limit=100)
        urls = [
            ("http://a.test/product/1", "a"),
            ("http://a.test/product/2", "a"),   # eyni host/ailə → bir vedrə
            ("http://a.test/product/3", "a"),
            ("http://b.test/product/1", "b"),   # fərqli host → fərqli vedrə
        ]
        for url, tag in urls:
            host, fam = url_fair_key(url)
            await sched.submit(SchedTask(
                identity=f"id-{url}", engine="sqli", host=host, family=fam,
                run=_recorder(order, tag)))
        await _run_sched(sched)
        # 2-ci icra aidiyyətcə `b` hostuna keçməlidir — `a`-nın qalan işi
        # `b`-ni gözlətməməlidir.
        assert order[1] == "b"

    async def test_scheduler_does_not_fabricate_fairness(self):
        """`url_fair_key` real host/ailə verir; boş dəyər verilmir (production)."""
        host, fam = url_fair_key("https://shop.example.com/item/42?x=1")
        assert host == "shop.example.com" and fam.startswith("https://")


# -------------------------------------------------------- idempotentlik müqaviləsi


class TestIdempotencyContract:
    async def test_concurrent_duplicate_consider_only_one_creates(self):
        """Eyni kimlik üçün paralel `consider` YALNIZ BİR dəfə icazə verir."""
        led = TaskLedger()
        ident = task_identity(7, "xss", "http://h/p", param="q")
        dec1 = led.consider(ident, engine="xss", endpoint="http://h/p")
        dec2 = led.consider(ident, engine="xss", endpoint="http://h/p")
        assert dec1.create is True
        assert dec2.create is False
        assert dec2.duplicate is True

    async def test_duplicate_submission_single_execution(self):
        """İki paralel təqdim — yalnız BİR faktiki icra (tək həqiqət mənbəyi)."""
        led = TaskLedger()
        runs: list[str] = []
        sched = Scheduler(workers=2, queue_limit=10, ledger=led)
        ident = task_identity(1, "sqli", "http://h/p")

        async def submit_once() -> bool:
            dec = led.consider(ident, engine="sqli", endpoint="http://h/p")
            if not dec.create:
                return False
            await submit_with_backpressure(sched, SchedTask(
                identity=ident, engine="sqli", host="h",
                run=_recorder(runs, "x")))
            return True

        async with sched:
            results = await asyncio.gather(submit_once(), submit_once())
            await sched.drain()
        assert sum(results) == 1, results
        assert len(runs) == 1
        assert sched.executed == 1

    async def test_submit_stage_duplicate_records_skip(self, make_conductor):
        """`_submit_stage` dublikatı SƏSSİZCƏ atmır — AÇIQ `skipped` yazır."""
        c = make_conductor()
        runs: list[str] = []

        async def factory():
            runs.append("vuln")
            return EngineResult(stage="vuln", ok=True)

        sched = Scheduler(workers=2, queue_limit=10, ledger=c.task_ledger)
        async with sched:
            await c._submit_stage(sched, "vuln", factory)
            await c._submit_stage(sched, "vuln", factory)   # dublikat
            await sched.drain()

        assert runs == ["vuln"]                       # yalnız BİR icra
        statuses = [s.status for s in c.stages]
        assert "skipped" in statuses                  # dublikat AÇIQ qeyd olundu
        assert any(any("idempotentlik" in w for w in s.warnings)
                   for s in c.stages if s.status == "skipped")

    async def test_submit_stage_backpressure_records_failed(self, make_conductor,
                                                            monkeypatch):
        """`submit()` rədd edərsə mərhələ AÇIQ `failed` olur, İTMİR."""
        c = make_conductor()

        async def factory():
            return EngineResult(stage="vuln", ok=True)

        async def _deny(sched, task, **kw) -> bool:
            return False

        monkeypatch.setattr(conductor_mod, "submit_with_backpressure", _deny)
        sched = Scheduler(workers=1, queue_limit=1, ledger=c.task_ledger)
        async with sched:
            await c._submit_stage(sched, "vuln", factory)

        assert any(s.status == "failed" for s in c.stages)
        ident = task_identity(c.scan_id, "vuln", "vuln", test_type="stage")
        rec = c.task_ledger.get(ident)
        assert rec is not None and rec.state == STATE_FAILED


# ------------------------------------------------------------------ köməkçilər


async def _noop():
    return "ok"


def _recorder(sink: list, tag: str):
    async def _run():
        sink.append(tag)
        return tag
    return _run
