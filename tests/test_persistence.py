"""Faza 4 — davamlılıq və çökmə davranışı (DÜRÜST kəsinti idarəsi).

Yoxlanılan prinsiplər (hamısı şəbəkəsiz; yalnız lokal SQLite + tmp fayllar):
  * Son skan STATUSU hesabatdan ƏVVƏL yazılır → hesabat REAL nəticəni
    (completed/partial/failed/cancelled) göstərir, DB default-u `running`-i
    YOX (skan səhvən "tamamlanmış" kimi təqdim olunmur).
  * Ləğv edilmiş (Ctrl+C) skan hesabatında `cancelled` görünür.
  * Çökmə (SIGKILL/power-off) `finish_scan`-i HEÇ VAXT çağırmır → sətir
    `running` qalır; bu, KƏSİLMİŞ skanın dürüst göstəricisidir (hesabat yox).
  * Yenidən işə salma (rerun) ƏVVƏLKİ skanın tapşırıq vəziyyətini TƏKRAR
    İSTİFADƏ ETMİR: `TaskLedger` və `UrlIntelligence` hər `Conductor`
    nüsxəsində TƏZƏ yaradılır (proses-üzrə qlobal vəziyyət yoxdur).
"""
from __future__ import annotations

import argparse
import asyncio
import pathlib

import pytest

from qbh import db
from qbh import urlintel
from qbh.conductor import Conductor
from qbh.results import StageResult, now_iso
from qbh.tasks import task_identity

# ------------------------------------------------------------------ helpers


def _args() -> argparse.Namespace:
    return argparse.Namespace(
        config="", mode="full", aggressiveness=None, proxy="off", rate=None,
        severity="low", auto_install=False, dry_run=False, targets=None,
        active_fuzz=None, race_fixture=None, race_count=10, race_concurrency=4)


def _stage(name: str, status: str = "ok") -> StageResult:
    return StageResult(stage=name, status=status, started_at=now_iso())


def _scan_status(scan_id: int) -> str | None:
    row = db.get_db().execute(
        "SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
    return row["status"] if row else None


def _report_text(tmp_path: pathlib.Path) -> str:
    files = sorted((tmp_path / "reports").glob("*.md"))
    assert files, "hesabat faylı yaradılmadı"
    return files[-1].read_text(encoding="utf-8")


@pytest.fixture
def make_conductor(tmp_db, loopback_config):
    def _make(cfg=None) -> Conductor:
        return Conductor(cfg or loopback_config, _args())
    return _make


# ------------------------------------------------------- hesabat dürüstlüyü


class TestReportHonesty:
    async def test_completed_report_status_not_running(self, make_conductor,
                                                       tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        c = make_conductor()

        async def body():
            c.stages.append(_stage("recon", "ok"))

        await c._pipeline("full", body)
        text = _report_text(tmp_path)
        assert "Status: completed" in text        # REAL nəticə
        assert "Status: running" not in text      # default YOX

    async def test_partial_report_shows_partial(self, make_conductor, tmp_path,
                                                monkeypatch):
        monkeypatch.chdir(tmp_path)
        c = make_conductor()

        async def body():
            c.stages.append(_stage("recon", "ok"))
            c.stages.append(_stage("vuln", "failed"))

        await c._pipeline("full", body)
        assert _scan_status(c.scan_id) == "partial"
        assert "Status: partial" in _report_text(tmp_path)

    async def test_cancelled_report_shows_cancelled(self, make_conductor,
                                                    tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        c = make_conductor()
        monkeypatch.setattr(c.authorization, "cancel", lambda: None)

        async def body():
            raise asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            await c._pipeline("full", body)
        assert _scan_status(c.scan_id) == "cancelled"
        text = _report_text(tmp_path)
        assert "Status: cancelled" in text
        assert "Status: running" not in text


class TestInterruptedSignal:
    def test_unfinished_scan_stays_running(self, tmp_db):
        """Çökmə → `finish_scan` çağırılmır → `running` DÜRÜST kəsinti işarəsi."""
        sid = db.start_scan("prog", "full")
        assert _scan_status(sid) == "running"

    def test_finished_scan_differs_from_running(self, tmp_db):
        a = db.start_scan("prog", "full")
        b = db.start_scan("prog", "full")
        db.finish_scan(b, "completed")
        assert _scan_status(a) == "running"       # kəsildi
        assert _scan_status(b) == "completed"     # tamamlandı


class TestRerunIsolation:
    def test_rerun_uses_fresh_task_ledger(self, make_conductor):
        c1 = make_conductor()
        ident = task_identity(1, "sqli", "http://h/p")
        assert c1.task_ledger.consider(
            ident, engine="sqli", endpoint="http://h/p").create is True

        c2 = make_conductor()                     # rerun = TƏZƏ Conductor
        assert c2.task_ledger.get(ident) is None  # əvvəlki vəziyyət təkrar YOX
        assert c2.task_ledger.consider(
            ident, engine="sqli", endpoint="http://h/p").create is True

    def test_url_intelligence_is_per_context(self, make_conductor):
        """URL intellekti (deferred reyestri daxil) ctx-üzrə İZOLYASIYALIDIR."""
        c1 = make_conductor()
        c2 = make_conductor()
        assert (urlintel.get_url_intelligence(c1.ctx)
                is not urlintel.get_url_intelligence(c2.ctx))

    def test_event_ledger_fresh_per_scan(self, make_conductor):
        c1 = make_conductor()
        c2 = make_conductor()
        assert c1.event_ledger is not c2.event_ledger
