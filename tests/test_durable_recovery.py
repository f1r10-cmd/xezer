"""Faza 2 (§4.2–§4.4) — davamlı icra və çökmədən bərpa testləri.

Yoxlanılan prinsiplər:
  * Yeni cədvəllər (`task_state`, `event_state`, `followup_queue`) additive
    miqrasiya ilə yaranır; mövcud data QORUNUR (v7).
  * `TaskLedger`/`EventLedger`/`AdaptiveController` vəziyyəti davamlı
    saxlamaya yazır — in-memory davranış DƏYİŞMİR.
  * `completed` tapşırıqlar bərpadan sonra TƏKRAR İCRA OLUNMUR; `running`
    (çökmüş) tapşırıqlar yenidən növbəyə alınır; `attempts` tarixçəsi QORUNUR.
  * Bərpa scope/avtorizasiya yoxlamasını KEÇMİR (fail-closed).
  * Skan izolyasiyası qorunur.
  * `--resume` REAL proses kill-dən sonra işləyir (§4.4).
"""
from __future__ import annotations

import asyncio
import os
import pathlib
import socket
import sqlite3
import subprocess
import sys

import pytest

import main as main_mod
from qbh import db
from qbh import recovery as rcv
from qbh.adaptive import (OUTCOME_COMPLETED, OUTCOME_FAILED, AdaptiveController,
                          Signal, STRENGTH_STRONG)
from qbh.tasks import (STATE_CANCELLED, STATE_COMPLETED, STATE_FAILED,
                       STATE_QUEUED, STATE_RUNNING,
                       EventLedger, TaskLedger, task_identity)

ROOT = pathlib.Path(__file__).resolve().parents[1]


# -------------------------------------------------------------------------- #
# fixture-lər
# -------------------------------------------------------------------------- #
@pytest.fixture
def durable_db(tmp_path, monkeypatch):
    """Davamlı sxemi olan təmiz baza + fayl yolu."""
    path = tmp_path / "durable.db"
    monkeypatch.setattr(db, "DB_PATH", str(path))
    db.close_db()
    db.init_db()
    yield db, path
    db.close_db()


@pytest.fixture
def store(durable_db):
    """`scan_id=1` üçün real `DurableStore`."""
    _, _ = durable_db
    sid = db.start_scan("davamlılıq", "vuln")
    return rcv.DurableStore(sid)


@pytest.fixture
def no_external_network(monkeypatch):
    """Xarici şəbəkə və subprocess çıxışını bloklayır (deterministik)."""
    async def _no_subprocess(*_a, **_kw):
        raise FileNotFoundError("test: subprocess qadağandır")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _no_subprocess)
    loopback = {"127.0.0.1", "localhost", "::1", "0.0.0.0", "", "none"}
    real = socket.getaddrinfo

    def _guard(host, *args, **kwargs):
        if str(host).strip("[]").lower() in loopback:
            return real(host, *args, **kwargs)
        raise socket.gaierror(socket.EAI_NONAME,
                              f"test: xarici DNS bloklandı ({host})")

    monkeypatch.setattr(socket, "getaddrinfo", _guard)
    yield


# -------------------------------------------------------------------------- #
# §4.2 — sxem və miqrasiya
# -------------------------------------------------------------------------- #
class TestSchemaPhase2:
    def test_new_tables_present(self, durable_db):
        conn = db.get_db()
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"task_state", "event_state", "followup_queue"} <= names

    def test_schema_version_bumped(self, durable_db):
        assert db.SCHEMA_VERSION == 10
        row = db.get_db().execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
        assert row[0] == "10"

    def test_new_indexes_present(self, durable_db):
        idx = {r[0] for r in db.get_db().execute(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        assert {"idx_task_state_scan", "idx_task_state_status",
                "idx_event_state_scan", "idx_followup_scan"} <= idx

    def test_legacy_db_migrates_without_data_loss(self, tmp_path, monkeypatch):
        """Köhnə (v2) baza açılır, data İTİRMİR, yeni cədvəllər yaranır."""
        path = tmp_path / "legacy.db"
        conn = sqlite3.connect(path)
        conn.executescript(
            "CREATE TABLE findings (id INTEGER PRIMARY KEY, host_id INTEGER,"
            " module TEXT, severity TEXT, title TEXT, created_at TEXT);")
        conn.execute("INSERT INTO findings(module,severity,title) "
                     "VALUES('old','low','köhnə tapıntı')")
        conn.commit()
        conn.close()

        monkeypatch.setattr(db, "DB_PATH", str(path))
        db.close_db()
        db.init_db()
        c = db.get_db()
        names = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"task_state", "event_state", "followup_queue"} <= names
        assert c.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
        assert c.execute("SELECT title FROM findings").fetchone()[0] == \
            "köhnə tapıntı"
        db.close_db()

    def test_task_state_accepts_all_lifecycle_states(self, store):
        for state in db.TASK_STATES:
            db.upsert_task_state(f"t-{state}", store.scan_id, status=state,
                                 identity_hash=f"t-{state}")
        rows = db.load_task_state(store.scan_id)
        assert {r["status"] for r in rows} == set(db.TASK_STATES)


# -------------------------------------------------------------------------- #
# §4.2 — DurableStore
# -------------------------------------------------------------------------- #
class TestDurableStore:
    def test_persist_task_roundtrip(self, store):
        rec = TaskLedger().consider("kimlik-1", engine="sqli",
                                    endpoint="http://h/p", param="id=1")
        ledger = TaskLedger(store=store)
        ledger.restore([])
        ledger.consider("kimlik-1", engine="sqli", endpoint="http://h/p",
                        param="id=1")
        rows = db.load_task_state(store.scan_id)
        assert len(rows) == 1
        assert rows[0]["task_id"] == "kimlik-1"
        assert rows[0]["engine"] == "sqli"
        assert rows[0]["status"] == STATE_QUEUED
        assert rec.create is True

    def test_created_at_preserved_on_upsert(self, store):
        db.upsert_task_state("t", store.scan_id, status="queued",
                             created_at="2020-01-01T00:00:00+00:00")
        db.upsert_task_state("t", store.scan_id, status="running")
        row = db.load_task_state(store.scan_id)[0]
        assert row["status"] == "running"
        assert row["created_at"] == "2020-01-01T00:00:00+00:00"

    def test_persist_event_roundtrip(self, store):
        store.persist_event("ev1", event_type="sqli_signal", count=2,
                            detail="x")
        rows = db.load_event_state(store.scan_id)
        assert len(rows) == 1
        assert rows[0]["event_type"] == "sqli_signal"

    def test_followup_insert_and_mark(self, store):
        store.persist_followup("fid-1", "sqli_probe", status="pending")
        pending = db.load_followups(store.scan_id, status="pending")
        assert len(pending) == 1
        assert pending[0]["proposed_action"] == "sqli_probe"
        n = store.mark_followup("fid-1", "executed")
        assert n == 1
        assert db.load_followups(store.scan_id, status="pending") == []
        done = db.load_followups(store.scan_id, status="executed")
        assert len(done) == 1 and done[0]["executed_at"]

    def test_invalid_status_normalised(self, store):
        db.upsert_task_state("bad", store.scan_id, status="uydurma")
        assert db.load_task_state(store.scan_id)[0]["status"] == "queued"


# -------------------------------------------------------------------------- #
# §4.2/§4.3 — TaskLedger davamlılıq + bərpa
# -------------------------------------------------------------------------- #
class TestTaskLedgerDurable:
    def test_transitions_persisted(self, store):
        led = TaskLedger(store=store)
        led.consider("a", engine="x", endpoint="http://h/a")
        led.mark("a", STATE_RUNNING)
        led.mark("a", STATE_COMPLETED)
        row = db.load_task_state(store.scan_id)[0]
        assert row["status"] == STATE_COMPLETED

    def test_no_store_is_memory_only(self, durable_db):
        led = TaskLedger()
        led.consider("a")
        assert led.persist_to_db() == 0
        # heç bir sətir yazılmır
        conn = db.get_db()
        n = conn.execute("SELECT COUNT(*) FROM task_state").fetchone()[0]
        assert n == 0

    def test_restore_running_becomes_requeued(self, store):
        records = rcv.task_records(store.scan_id)
        records.append(_rec("r1", STATE_RUNNING, attempts=1))
        led = TaskLedger(store=store)
        counts = led.restore(records)
        assert counts["requeued"] == 1
        assert led.get("r1").state == STATE_CANCELLED
        assert led.get("r1").attempts == 1        # tarixçə qorunur

    def test_restore_completed_is_terminal(self, store):
        led = TaskLedger(store=store)
        led.restore([_rec("c1", STATE_COMPLETED, attempts=2)])
        assert led.get("c1").state == STATE_COMPLETED
        # TƏKRAR İCRA OLUNMUR
        d = led.consider("c1", engine="x")
        assert d.create is False and d.duplicate is True

    def test_restore_preserves_attempts_and_reason(self, store):
        led = TaskLedger(store=store)
        led.restore([_rec("f1", STATE_FAILED, attempts=2)])
        rec = led.get("f1")
        assert rec.attempts == 2
        # parcial/təmamil olunmamış → yenidən növbəyə (bounded)
        d = led.consider("f1", engine="x")
        assert d.create is True
        assert led.get("f1").attempts == 3

    def test_restore_does_not_duplicate_existing(self, store):
        led = TaskLedger(store=store)
        led.consider("dup")
        led.mark("dup", STATE_COMPLETED)
        counts = led.restore([_rec("dup", STATE_QUEUED)])
        assert counts["restored"] == 0
        assert led.get("dup").state == STATE_COMPLETED


# -------------------------------------------------------------------------- #
# §4.2 — EventLedger davamlılıq
# -------------------------------------------------------------------------- #
class TestEventLedgerDurable:
    def test_event_persisted(self, store):
        led = EventLedger(store=store)
        led.accept("sqli_signal", "http://h/p")
        rows = db.load_event_state(store.scan_id)
        assert len(rows) == 1
        assert rows[0]["event_type"] == "sqli_signal"

    def test_restore_suppresses_duplicate(self, store):
        led = EventLedger(store=store)
        led.accept("sqli_signal", "http://h/p")
        events = rcv.event_records(store.scan_id)

        fresh = EventLedger(store=store)
        restored = fresh.restore(events)
        assert restored == 1
        # bərpadan sonra eyni hadisə DUBLİKAT sayılır (yenidən emal olunmur)
        d = fresh.accept("sqli_signal", "http://h/p")
        assert d.accept is False

    def test_persist_to_db_without_store(self, durable_db):
        led = EventLedger()
        led.accept("k", "d")
        assert led.persist_to_db() == 0


# -------------------------------------------------------------------------- #
# §4.2 — AdaptiveController davamlılıq
# -------------------------------------------------------------------------- #
class TestAdaptiveDurable:
    def test_pending_followup_persisted(self, store):
        ctrl = AdaptiveController(store=store)
        fu = ctrl.evaluate(Signal(kind="sqli_signal", strength=STRENGTH_STRONG),
                           identity="chain:http://h/p", actions=("sqli_probe",))
        assert fu.proceed is True
        rows = db.load_followups(store.scan_id, status="pending")
        assert len(rows) == 1
        assert rows[0]["prerequisite_hash"] == "chain:http://h/p"
        assert rows[0]["proposed_action"] == "sqli_probe"

    def test_outcome_marks_executed(self, store):
        ctrl = AdaptiveController(store=store)
        ctrl.evaluate(Signal(kind="k", strength=STRENGTH_STRONG),
                      identity="i1", actions=("a",))
        ctrl.record_outcome("i1", OUTCOME_COMPLETED)
        assert db.load_followups(store.scan_id, status="pending") == []
        assert len(db.load_followups(store.scan_id, status="executed")) == 1

    def test_failed_outcome_marks_failed(self, store):
        ctrl = AdaptiveController(store=store)
        ctrl.evaluate(Signal(kind="k", strength=STRENGTH_STRONG),
                      identity="i2", actions=("a",))
        ctrl.record_outcome("i2", OUTCOME_FAILED)
        assert len(db.load_followups(store.scan_id, status="failed")) == 1

    def test_restore_followups_rebuilds_decisions(self, store):
        ctrl = AdaptiveController(store=store)
        ctrl.evaluate(Signal(kind="k", strength=STRENGTH_STRONG),
                      identity="i3", actions=("a",))
        pending = rcv.followup_records(store.scan_id)
        fresh = AdaptiveController(store=store)
        n = fresh.restore_followups(pending)
        assert n == 1
        assert any(d["identity"] == "i3" for d in fresh.decisions)

    def test_no_store_is_safe(self, durable_db):
        ctrl = AdaptiveController()
        ctrl.evaluate(Signal(kind="k", strength=STRENGTH_STRONG),
                      identity="i", actions=("a",))


# -------------------------------------------------------------------------- #
# §4.3 — bərpa planı + scope yenidən yoxlaması
# -------------------------------------------------------------------------- #
class TestResumePlan:
    def test_requeue_and_terminal_split(self, store):
        sid = store.scan_id
        db.upsert_task_state("done", sid, status=STATE_COMPLETED)
        db.upsert_task_state("run", sid, status=STATE_RUNNING)
        db.upsert_task_state("q", sid, status=STATE_QUEUED)
        db.upsert_task_state("skip", sid, status="skipped")
        plan = rcv.build_resume_plan(sid)
        assert {t.identity for t in plan.terminal} == {"done", "skip"}
        assert {t.identity for t in plan.requeue} == {"run", "q"}
        assert plan.counts["running"] == 1

    def test_out_of_scope_marked_skipped(self, store):
        sid = store.scan_id
        db.upsert_task_state("in", sid, status=STATE_QUEUED,
                             endpoint="http://127.0.0.1/x")
        db.upsert_task_state("out", sid, status=STATE_QUEUED,
                             endpoint="http://evil.example.com/x")

        def authorize(host):
            if host == "127.0.0.1":
                return host
            raise ValueError("scope xarici")

        plan = rcv.build_resume_plan(sid, authorize=authorize)
        assert plan.out_of_scope == ["out"]
        out = next(t for t in plan.tasks if t.identity == "out")
        assert out.state == "skipped"
        assert "icazəli deyil" in out.reason
        # scope xarici tapşırıq REQUeue siyahısına DÜŞMÜR
        assert "out" not in {t.identity for t in plan.requeue}

    def test_scope_check_does_not_bypass(self, store):
        """Bərpa yoxlaması MƏCBURİDİR: authorize verilməzsə heç nə süzülmür,
        verildikdə isə scope qapısı işləyir (fail-closed)."""
        sid = store.scan_id
        db.upsert_task_state("o", sid, status=STATE_QUEUED,
                             endpoint="http://nope.example.org/a")
        assert rcv.build_resume_plan(sid).out_of_scope == []

        def deny(_host):
            raise ValueError("yox")

        assert rcv.build_resume_plan(sid, authorize=deny).out_of_scope == ["o"]

    def test_scan_id_isolation(self, store):
        other = rcv.DurableStore(db.start_scan("başqa", "vuln"))
        db.upsert_task_state("A", store.scan_id, status=STATE_COMPLETED)
        db.upsert_task_state("B", other.scan_id, status=STATE_QUEUED)

        plan_a = rcv.build_resume_plan(store.scan_id)
        assert [t.identity for t in plan_a.tasks] == ["A"]
        plan_b = rcv.build_resume_plan(other.scan_id)
        assert [t.identity for t in plan_b.tasks] == ["B"]

    def test_plan_to_dict(self, store):
        db.upsert_task_state("x", store.scan_id, status=STATE_QUEUED)
        d = rcv.build_resume_plan(store.scan_id).to_dict()
        assert d["tasks"] == 1 and d["requeue"] == 1 and d["terminal"] == 0

    def test_pending_scan_detection(self, store):
        assert [r["id"] for r in rcv.pending_scans()] == [store.scan_id]
        assert rcv.latest_pending_scan()["id"] == store.scan_id
        db.finish_scan(store.scan_id, "completed")
        assert rcv.latest_pending_scan() is None


# -------------------------------------------------------------------------- #
# §4.4 — REAL proses kill + `--resume`
# -------------------------------------------------------------------------- #
_CRASH_WORKER = '''
import os
import sys
import time

ROOT, DB = sys.argv[1], sys.argv[2]
sys.path.insert(0, ROOT)
os.environ["QBH_DB_PATH"] = DB

from qbh import db
from qbh.recovery import DurableStore
from qbh.tasks import (STATE_COMPLETED, STATE_FAILED, STATE_RUNNING,
                       TaskLedger, task_identity)

db.init_db()
scan_id = db.start_scan("crashprogram", "vuln")
led = TaskLedger(store=DurableStore(scan_id))


def ident(name, endpoint, test_type="stage"):
    return task_identity(scan_id, name, endpoint, test_type=test_type)


# 1) UĞURLA bitmiş mərhələ → bərpadan sonra TƏKRAR İCRA OLUNMAMALIDIR.
fp = ident("fingerprint", "fingerprint")
led.consider(fp, engine="fingerprint", endpoint="fingerprint",
             test_type="stage")
led.mark(fp, STATE_COMPLETED)

# 2) Yarımçıq (çökmüş) mərhələ + bounded retry tarixçəsi → yenidən növbə.
vu = ident("vuln", "vuln")
led.consider(vu, engine="vuln", endpoint="vuln", test_type="stage")
led.mark(vu, STATE_FAILED, "birinci cəhd uğursuz")
led.consider(vu, engine="vuln", endpoint="vuln", test_type="stage")
led.mark(vu, STATE_RUNNING)

# 3) Tarixçəsi (attempts) olan tapşırıq → bərpada QORUNMALIDIR.
sq = ident("sqli", "http://127.0.0.1/x", "sqli_probe")
led.consider(sq, engine="sqli", endpoint="http://127.0.0.1/x",
             test_type="sqli_probe")
led.mark(sq, STATE_FAILED, "xəta")
led.consider(sq, engine="sqli", endpoint="http://127.0.0.1/x",
             test_type="sqli_probe")

db.close_db()
print(scan_id, flush=True)
time.sleep(120)     # skan "davam edir" — ana proses bunu KILL edəcək
'''


def _rec(identity, state, attempts=0, endpoint=""):
    from qbh.tasks import TaskRecord

    return TaskRecord(identity=identity, state=state, attempts=attempts,
                      endpoint=endpoint)


class TestCrashRecovery:
    def test_kill_then_resume_recovers_state(
            self, durable_db, write_config, no_external_network,
            monkeypatch, tmp_path, capsys):
        """§4.4: real proses kill → `--resume` pending bərpa, completed
        TƏKRAR İCRA OLUNMUR, attempts QORUNUR."""
        _, db_path = durable_db
        worker = tmp_path / "_crash_worker.py"
        worker.write_text(_CRASH_WORKER, encoding="utf-8")

        env = dict(os.environ)
        env["QBH_DB_PATH"] = str(db_path)
        env["PYTHONPATH"] = str(ROOT)
        env["PYTHONUNBUFFERED"] = "1"
        proc = subprocess.Popen(
            [sys.executable, str(worker), str(ROOT), str(db_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", env=env)
        try:
            line = proc.stdout.readline()
            assert line.strip().isdigit(), \
                f"işçi skan id vermədi: {line!r} / {proc.stderr.read()!r}"
            scan_id = int(line.strip())
            # REAL proses kill (SIGKILL / TerminateProcess) — yarımçıq skan.
            proc.kill()
            proc.wait(timeout=20)
        finally:
            if proc.poll() is None:
                proc.kill()
        assert proc.returncode != 0        # proses HƏQİQƏTƏN öldürüldü

        # Çökmədən ƏVVƏL yazılmış davamlı vəziyyət QALIR.
        db.close_db()
        db.init_db()
        before = {r["task_id"]: r for r in db.load_task_state(scan_id)}
        assert before  # ən azı bir tapşırıq yazılıb
        assert db.get_scan(scan_id)["status"] == "running"

        # `--resume` ilə YENİ prosesdə bərpa (loopback, şəbəkəsiz).
        cfg = write_config([
            {"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
             "out_of_scope": []}])
        monkeypatch.chdir(tmp_path)
        rc = main_mod.main(["--config", cfg, "--resume", str(scan_id)])
        out, _ = capsys.readouterr()

        assert "[↻] Bərpa" in out
        assert "bərpa olunur" in out
        # Uğurla bitmiş mərhələ AÇIQ şəkildə ATLANDI (təkrar icra OLUNMADI).
        assert "idempotentlik: artıq uğurla tamamlanıb" in out
        assert rc in (main_mod.EXIT_OK, main_mod.EXIT_FAILURE)

        # Bərpa skanı bağladı (running → completed/partial).
        assert db.get_scan(scan_id)["status"] in ("completed", "partial")

        after = {r["task_id"]: r for r in db.load_task_state(scan_id)}
        fp = task_identity(scan_id, "fingerprint", "fingerprint",
                           test_type="stage")
        assert fp in after
        # 1) UĞURLU tapşırıq: status dəyişmədi, attempts ARTMADI (icra olunmadı)
        assert after[fp]["status"] == STATE_COMPLETED
        assert after[fp]["attempts"] == before[fp]["attempts"] == 0

        # 2) Yarımçıq (running) tapşırıq: təkrar növbəyə alındı → attempts artdı
        vu = task_identity(scan_id, "vuln", "vuln", test_type="stage")
        assert before[vu]["attempts"] == 1
        assert after[vu]["attempts"] == 2      # TARİXÇƏ QORUNDU
        assert after[vu]["status"] in (STATE_COMPLETED, STATE_FAILED)

        # 3) attempts tarixçəsi olan tapşırıq QORUNDU
        sq = task_identity(scan_id, "sqli", "http://127.0.0.1/x",
                           test_type="sqli_probe")
        assert after[sq]["attempts"] == before[sq]["attempts"] == 1

    def test_resume_without_pending_scan_is_honest(
            self, durable_db, write_config, monkeypatch, tmp_path, capsys):
        db.finish_scan(db.start_scan("bitmiş", "vuln"), "completed")
        cfg = write_config([
            {"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
             "out_of_scope": []}])
        monkeypatch.chdir(tmp_path)
        rc = main_mod.main(["--config", cfg, "--resume"])
        out, _ = capsys.readouterr()
        assert rc == main_mod.EXIT_FAILURE
        assert "skan tapılmadı" in out

    def test_resume_missing_scan_id_is_honest(
            self, durable_db, write_config, monkeypatch, tmp_path, capsys):
        cfg = write_config([
            {"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
             "out_of_scope": []}])
        monkeypatch.chdir(tmp_path)
        rc = main_mod.main(["--config", cfg, "--resume", "999"])
        assert rc == main_mod.EXIT_FAILURE


# -------------------------------------------------------------------------- #
# §4.2 — `--pending-followups` CLI
# -------------------------------------------------------------------------- #
class TestPendingFollowupsCli:
    def test_lists_pending_followups(self, durable_db, monkeypatch,
                                     tmp_path, capsys):
        sid = db.start_scan("p", "vuln")
        db.insert_followup(sid, "sqli_probe", prerequisite_hash="chain-1")
        monkeypatch.chdir(tmp_path)
        rc = main_mod.main(["--pending-followups", "--scan-id", str(sid)])
        out, _ = capsys.readouterr()
        assert rc == main_mod.EXIT_OK
        assert "1 gözləyən davam testi" in out
        assert "sqli_probe" in out

    def test_empty_is_honest(self, durable_db, monkeypatch, tmp_path, capsys):
        monkeypatch.chdir(tmp_path)
        rc = main_mod.main(["--pending-followups"])
        out, _ = capsys.readouterr()
        assert rc == main_mod.EXIT_OK
        assert "Heç bir skan tapılmadı" in out
