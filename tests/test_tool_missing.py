"""Faza 4.2 — "alət yoxdur" dürüst raportlaşdırma (loopback, şəbəkəsiz).

`run_process` alət binari-sini tapa bilmirsə `ProcResult(missing=True)`
qaytarır (bax: `qbh/adapters/base.py`). HƏR mühərrik bu vəziyyəti:
  * `res.warn(...)` ilə AÇIQ bildirməli,
  * graceful nəticə qaytarmalı (crash YOX),
  * HEÇ VAXT uydurma tapıntı (finding) yaratmamalıdır.

Test bütün alət çağırışlarını "tapılmadı"ya çevirir və heç bir xarici
şəbəkə trafiki yaratmır. Bu, `docs/SECURITY_VERIFICATION.md`-dəki
"Tool missing" sırasını PARTIAL → PASS edir.
"""
from __future__ import annotations

import importlib

from qbh import db
from qbh.adapters.base import ProcResult
from qbh.authorization import from_config

#: `run_process`-i modul səviyyəsində import edən mühərrik modulları —
#: monkeypatch həmin modulların daxilindəki istinadı da əvəz etməlidir.
_MODULE_LEVEL = (
    "qbh.engines.recon",
    "qbh.engines.vuln",
    "qbh.engines.content",
    "qbh.engines.ferox",
    "qbh.engines.api_enum",
    "qbh.engines.deep_enum",
    "qbh.engines.param_enum",
)


def _patch_all_missing(monkeypatch):
    """Bütün alət alt-prosesləri 'tapılmadı' qaytarır (şəbəkə YOXDUR)."""
    async def _missing(*args, **kwargs):
        return ProcResult(-1, missing=True)

    monkeypatch.setattr("qbh.adapters.base.run_process", _missing)
    for name in _MODULE_LEVEL:
        mod = importlib.import_module(name)
        if hasattr(mod, "run_process"):
            monkeypatch.setattr(mod, "run_process", _missing)


def _ctx(make_ctx, scan_id=1):
    ctx = make_ctx()
    ctx.authorization = from_config(ctx.cfg)
    ctx.scan_id = scan_id
    return ctx


def _seed_host(scan_id=1, url=None):
    hid = db.upsert_host("127.0.0.1", scan_id=scan_id, status_code=200)
    if url:
        db.insert_url(hid, url, "katana", False, scan_id=scan_id)
    return hid


def _finding_count() -> int:
    return db.get_db().execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"]


class TestToolMissingHonestReporting:
    """Alət olmadıqda mühərriklər dürüst xəbərdarlıq verir, uydurmur."""

    async def test_recon_warns_and_fabricates_nothing(
            self, tmp_db, make_ctx, monkeypatch):
        _patch_all_missing(monkeypatch)
        from qbh.engines.recon import ReconEngine

        res = await ReconEngine(_ctx(make_ctx)).run(
            "127.0.0.1", subdomains=["127.0.0.1"])
        assert res.ok is True                      # graceful, crash yox
        assert any("httpx tapılmadı" in w for w in res.warnings)
        assert any("gau tapılmadı" in w for w in res.warnings)
        assert res.findings == 0
        assert _finding_count() == 0

    async def test_vuln_warns_nuclei_missing(
            self, tmp_db, make_ctx, monkeypatch):
        _patch_all_missing(monkeypatch)
        _seed_host()
        from qbh.engines.vuln import VulnEngine

        res = await VulnEngine(_ctx(make_ctx)).run()
        assert res.ok is True
        assert any("nuclei tapılmadı" in w for w in res.warnings)
        assert res.findings == 0
        assert _finding_count() == 0

    async def test_content_warns_ffuf_missing(
            self, tmp_db, make_ctx, monkeypatch, tmp_path):
        _patch_all_missing(monkeypatch)
        wl = tmp_path / "words.txt"
        wl.write_text("admin\nlogin\n", encoding="utf-8")
        monkeypatch.setattr("qbh.engines.content.WORDLIST", str(wl))
        _seed_host()
        from qbh.engines.content import ContentEngine

        res = await ContentEngine(_ctx(make_ctx)).run()
        assert res.ok is True
        assert any("ffuf tapılmadı" in w for w in res.warnings)
        assert res.findings == 0
        assert _finding_count() == 0

    async def test_ferox_warns_feroxbuster_missing(
            self, tmp_db, make_ctx, monkeypatch, tmp_path):
        _patch_all_missing(monkeypatch)
        wl = tmp_path / "words.txt"
        wl.write_text("admin\nlogin\n", encoding="utf-8")
        monkeypatch.setattr("qbh.engines.ferox.FEROX_WORDLIST", str(wl))
        _seed_host()
        from qbh.engines.ferox import FeroxEngine

        res = await FeroxEngine(_ctx(make_ctx)).run()
        assert res.ok is True
        assert any("feroxbuster tapılmadı" in w for w in res.warnings)
        assert res.findings == 0
        assert _finding_count() == 0

    async def test_param_enum_warns_arjun_missing(
            self, tmp_db, make_ctx, monkeypatch):
        _patch_all_missing(monkeypatch)
        _seed_host(url="http://127.0.0.1/x?y=1")
        from qbh.engines.param_enum import ParamEnumEngine

        res = await ParamEnumEngine(_ctx(make_ctx)).run()
        assert res.ok is True
        assert any("arjun tapılmadı" in w for w in res.warnings)
        assert res.findings == 0
        assert _finding_count() == 0

    async def test_api_enum_is_graceful_without_tools(
            self, tmp_db, make_ctx, monkeypatch):
        _patch_all_missing(monkeypatch)
        _seed_host()
        from qbh.engines.api_enum import APIEnumEngine

        res = await APIEnumEngine(_ctx(make_ctx)).run()
        assert res.ok is True
        assert res.skipped is False
        assert _finding_count() == 0

    async def test_deep_enum_warns_and_fabricates_nothing(
            self, tmp_db, make_ctx, monkeypatch):
        _patch_all_missing(monkeypatch)
        from qbh.engines.deep_enum import DeepEnumEngine

        # crt.sh HTTP mənbəyi şəbəkəyə çıxır → loopback-də boş nəticə ilə əvəz
        # olunur (test hermetik qalır; qalan mənbələr `missing` qaytarır).
        async def _no_crtsh(self, domain):
            return set()

        monkeypatch.setattr(DeepEnumEngine, "_crtsh", _no_crtsh)
        res = await DeepEnumEngine(_ctx(make_ctx)).run("127.0.0.1")
        assert res.ok is True
        assert any("tapılmadı" in w for w in res.warnings)
        assert res.findings == 0
        assert _finding_count() == 0
