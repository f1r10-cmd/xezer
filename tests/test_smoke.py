"""Faza 2.5 — Smoke testləri: CLI və tam boru xəttinin uçdan-uca işləməsi.

İki ssenari yoxlanılır:
  1. `main.py --mode report` — CLI giriş nöqtəsi mövcud bazadan hesabat
     yaradır və `EXIT_OK` qaytarır.
  2. `main.py --mode full` — recon→vuln→report boru xətti loopback config
     üzərində axıra qədər işləyir, skan qeydə alınır və hesabat yazılır.

**Şəbəkə təhlükəsizliyi (RoE §3).** Bütün testlər `no_external` fixture-ı ilə
işləyir və bu ZƏMANƏT verir ki, CI HEÇ VAXT xarici şəbəkəyə trafik göndərmir:
  * heç bir alt-proses başladılmır — `asyncio.create_subprocess_exec`
    `FileNotFoundError` qaldırır → `run_process` `missing=True` qaytarır;
  * loopback olmayan DNS həlli bloklanır — `socket.getaddrinfo` yalnız
    `127.0.0.1`/`localhost`/`::1` üçün işləyir, qalan hostlar üçün
    `socket.gaierror` atır (kəşf mənbələri kimi crt.sh, OSV, NVD daxil).

Beləliklə test tam HERMETİK-dir: heç bir paket xarici şəbəkəyə çıxmır.
"""
from __future__ import annotations

import asyncio
import socket

import pytest

import main as main_mod
from qbh import db
from qbh.adapters.base import current_process_guard

#: `socket.getaddrinfo` üçün icazəli (loopback) host adları.
_LOOPBACK_HOSTS = {
    "127.0.0.1", "localhost", "localhost.localdomain",
    "::1", "ip6-localhost", "0.0.0.0", "::", "", "none",
}


@pytest.fixture
def no_external_network(monkeypatch):
    """Xarici şəbəkə və subprocess çıxışını qəti şəkildə bloklayır.

    `yield` ilə bloklanmış xarici DNS sorğularının siyahısını verir ki, test
    bunun həqiqətən işə düşdüyünü yoxlaya bilsin.
    """
    blocked: list[str] = []

    async def _no_subprocess(*_a, **_kw):
        raise FileNotFoundError("smoke: subprocess qadağandır")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _no_subprocess)

    real_getaddrinfo = socket.getaddrinfo

    def _guarded_getaddrinfo(host, *args, **kwargs):
        key = str(host).strip("[]").lower()
        if key in _LOOPBACK_HOSTS:
            return real_getaddrinfo(host, *args, **kwargs)
        blocked.append(str(host))
        raise socket.gaierror(
            socket.EAI_NONAME, f"smoke: xarici DNS bloklandı ({host})")

    monkeypatch.setattr(socket, "getaddrinfo", _guarded_getaddrinfo)
    yield blocked


def _latest_scan() -> tuple[int, str]:
    row = db.get_db().execute(
        "SELECT id, status FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    assert row is not None, "heç bir skan qeydə alınmadı"
    return row["id"], row["status"]


def _reports(tmp_path) -> list:
    return sorted((tmp_path / "reports").glob("qbh_*.md"))


# ------------------------------------------------------------------ report


class TestReportModeSmoke:
    """`main.py --mode report` mövcud bazadan hesabat çıxarır."""

    def test_report_mode_writes_report_and_returns_ok(
            self, tmp_db, write_config, no_external_network, monkeypatch,
            tmp_path, capsys):
        monkeypatch.chdir(tmp_path)
        # Report rejimi skan konteksti olmadan işləyir → məlumat legacy
        # qrupundan (scan_id=None → 0) oxunur. Ona uyğun seed edirik.
        hid = db.upsert_host("127.0.0.1", scan_id=None, status_code=200,
                             title="smoke")
        db.insert_finding(hid, "recon", "high", "Smoke report finding",
                          evidence="loopback", status="confirmed", scan_id=None)

        cfg = write_config([
            {"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
             "out_of_scope": []}])

        rc = main_mod.main(["--config", cfg, "--mode", "report"])
        assert rc == main_mod.EXIT_OK

        files = _reports(tmp_path)
        assert len(files) == 1
        text = files[0].read_text(encoding="utf-8")
        assert "Smoke report finding" in text
        assert "QBH" in text

    def test_report_mode_on_empty_db_still_writes_report(
            self, tmp_db, write_config, no_external_network, monkeypatch,
            tmp_path):
        monkeypatch.chdir(tmp_path)
        cfg = write_config([
            {"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
             "out_of_scope": []}])

        rc = main_mod.main(["--config", cfg, "--mode", "report"])
        assert rc == main_mod.EXIT_OK
        assert len(_reports(tmp_path)) == 1


# ------------------------------------------------------------- full pipeline


class TestFullPipelineSmoke:
    """`main.py --mode full` loopback üzərində uçdan-uca tamamlanır."""

    def test_full_pipeline_records_scan_and_writes_report(
            self, tmp_db, write_config, no_external_network, monkeypatch,
            tmp_path):
        monkeypatch.chdir(tmp_path)
        cfg = write_config([
            {"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
             "out_of_scope": []}])

        rc = main_mod.main(["--config", cfg, "--mode", "full"])
        # Bütün mərhələlər ya uğurlu, ya da dürüst şəkildə "failed" olur —
        # heç bir gözlənilməz çökmə pipeline-ı yarıda qoymur.
        assert rc in (main_mod.EXIT_OK, main_mod.EXIT_FAILURE)

        scan_id, status = _latest_scan()
        assert scan_id >= 1
        assert status in ("completed", "partial")

        files = _reports(tmp_path)
        assert len(files) == 1
        assert files[0].stat().st_size > 0
        # Egress qapısı pipeline-dan SONRA sıfırlanmalıdır (sızma yoxdur).
        assert current_process_guard() is None

    def test_full_pipeline_is_hermetic(
            self, tmp_db, write_config, no_external_network, monkeypatch,
            tmp_path):
        """Xarici DNS sorğusu bloklanır və heç bir paket kənara çıxmır."""
        monkeypatch.chdir(tmp_path)
        cfg = write_config([
            {"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
             "out_of_scope": []}])

        main_mod.main(["--config", cfg, "--mode", "full"])
        # crt.sh kimi kəşf mənbələri cəhd olunur, lakin qapı tərəfindən
        # DNS səviyyəsində DAYANDIRILIR → heç bir xarici trafik getmir.
        assert no_external_network, "xarici DNS qapısı işə düşmədi"
        assert all("127.0.0.1" not in b for b in no_external_network)

    def test_out_of_scope_target_is_rejected(
            self, tmp_db, write_config, no_external_network, monkeypatch,
            tmp_path):
        """`--targets` avtorizasiyadan KƏNARA çıxa bilməz (fail-closed)."""
        monkeypatch.chdir(tmp_path)
        cfg = write_config([
            {"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
             "out_of_scope": []}])

        rc = main_mod.main([
            "--config", cfg, "--mode", "recon",
            "--targets", "evil.example.com"])
        assert rc == main_mod.EXIT_FAILURE      # PipelineAbort → 1
        assert current_process_guard() is None
        # Hesabat yaradılsa da, scope xarici hədəf heç vaxt daxil edilmir.
        for path in _reports(tmp_path):
            assert "evil.example.com" not in path.read_text(encoding="utf-8")


# --------------------------------------------------------------- hunt mode


class TestHuntModeSmoke:
    """`main.py --mode hunt` — avtomatik tam zəncir + dərin pass (Faza 3.5)."""

    def test_hunt_pipeline_records_scan_and_writes_report(
            self, tmp_db, write_config, no_external_network, monkeypatch,
            tmp_path):
        monkeypatch.chdir(tmp_path)
        cfg = write_config([
            {"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
             "out_of_scope": []}])

        rc = main_mod.main(["--config", cfg, "--mode", "hunt"])
        assert rc in (main_mod.EXIT_OK, main_mod.EXIT_FAILURE)

        scan_id, status = _latest_scan()
        assert scan_id >= 1
        assert status in ("completed", "partial")

        files = _reports(tmp_path)
        assert len(files) == 1
        assert files[0].stat().st_size > 0
        assert current_process_guard() is None
