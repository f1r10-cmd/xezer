"""Faza 1 offensive mühərriklər + recon dərinləşdirmə testləri.

Yoxlanılan prinsiplər (loopback-only, heç bir xarici trafik yoxdur):
  * Alət binary-si yoxdursa mühərrik DÜRÜST şəkildə `skipped` qaytarır —
    "işlədi" iddiası verilmir.
  * RoE `active_fuzz` qadağan edərsə intrusiv mühərriklər işləmir.
  * `gate()` scope xarici hədəfi rədd edir; scope-daxili hədəfi qəbul edir.
  * `candidate → confirmed` keçidi YALNIZ sübutla (riyazi marker) baş verir.
  * `LibraryCVEEngine` kitabxana versiyalarını düzgün çıxarır.
"""
from __future__ import annotations

import shutil

import pytest_asyncio

from qbh import db
from qbh.authorization import from_config
from qbh.results import EngineResult
from qbh.engines.deepen import BBOTEngine, DnstwistEngine, WaymoreEngine
from qbh.engines.library_cve import LibraryCVEEngine, extract_libraries
from qbh.engines.offensive import OffensiveEngine
from qbh.engines.sqli import SQLiEngine
from qbh.engines.ssrf import SSRFEngine
from qbh.engines.ssti import SSTIEngine
from qbh.engines.wafdetect import WafDetectEngine
from qbh.engines.xss import XSSEngine


SSTI_MAP = {
    "{{7*7}}": "49", "{{8*8}}": "64", "${7*7}": "49", "#{7*7}": "49",
    "<%= 7*7 %>": "49", "*{7*7}": "49", "{{7*'7'}}": "7777777",
}


@pytest_asyncio.fixture
async def reflect_server():
    """Loopback: /echo markeri, /ssti riyazi markerləri qaytarır."""
    from aiohttp import web

    async def echo(request):
        q = request.query.get("q", "")
        return web.Response(text=f"<html>echo:{q}</html>")

    async def ssti(request):
        out = request.query.get("q", "")
        for k, v in SSTI_MAP.items():
            out = out.replace(k, v)
        return web.Response(text=f"<html>{out}</html>")

    app = web.Application()
    app.add_routes([web.get("/echo", echo), web.get("/ssti", ssti)])
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        await runner.cleanup()


def _ctx(make_ctx, *, forbidden=None, scan_id=1):
    ctx = make_ctx()
    if forbidden is not None:
        ctx.cfg.program_rules.forbidden = set(forbidden)
    ctx.authorization = from_config(ctx.cfg)
    ctx.scan_id = scan_id
    return ctx


def _seed_param_url(host="127.0.0.1", url=None, scan_id=1):
    hid = db.upsert_host(host, scan_id=scan_id, status_code=200)
    db.insert_url(hid, url or f"http://{host}/x?y=1", "katana")
    return hid


# --------------------------------------------------------------- tool missing
class TestToolMissing:
    def test_tool_present_false_when_which_none(self, tmp_db, make_ctx, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None)
        eng = SQLiEngine(_ctx(make_ctx))
        assert eng.tool_present() is False

    async def test_sqli_skips_without_tool(self, tmp_db, make_ctx, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None)
        _seed_param_url()
        res = await SQLiEngine(_ctx(make_ctx)).run()
        assert res.skipped is True
        assert any("mövcud deyil" in w for w in res.warnings)

    async def test_sourcecode_and_jwt_skip_without_tool(
            self, tmp_db, make_ctx, monkeypatch):
        from qbh.engines.jwt import JWTEngine
        from qbh.engines.sourcecode import SourceCodeEngine

        monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None)
        assert (await JWTEngine(_ctx(make_ctx)).run()).skipped is True
        assert (await SourceCodeEngine(_ctx(make_ctx)).run()).skipped is True


# ----------------------------------------------------------------- RoE gating
class TestRoeGating:
    async def test_active_fuzz_forbidden_skips_intrusive(self, tmp_db, make_ctx):
        _seed_param_url()
        ctx = _ctx(make_ctx, forbidden={"active_fuzz"})
        for eng in (SQLiEngine(ctx), XSSEngine(ctx), SSTIEngine(ctx),
                    SSRFEngine(ctx)):
            res = await eng.run()
            assert res.skipped is True
            assert any("aktiv fuzz" in w for w in res.warnings)


# ----------------------------------------------------------------- no targets
class TestNoTargets:
    async def test_sqli_skips_without_params(self, tmp_db, make_ctx):
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        res = await SQLiEngine(_ctx(make_ctx)).run()
        assert res.skipped is True

    async def test_wafdetect_skips_without_hosts(self, tmp_db, make_ctx):
        res = await WafDetectEngine(_ctx(make_ctx)).run()
        assert res.skipped is True

    async def test_library_cve_skips_without_js(self, tmp_db, make_ctx):
        res = await LibraryCVEEngine(_ctx(make_ctx)).run()
        assert res.skipped is True

    async def test_ssrf_skips_when_oob_inactive(self, tmp_db, make_ctx):
        # loopback konfiqində oob.domain yoxdur → blind təsdiq mümkün deyil.
        _seed_param_url(url="http://127.0.0.1/x?url=http://a.b/")
        res = await SSRFEngine(_ctx(make_ctx)).run()
        assert res.skipped is True
        assert any("OOB" in w for w in res.warnings)


# ---------------------------------------------------------------- gate / scope
class TestGate:
    async def test_gate_rejects_out_of_scope(self, tmp_db, make_ctx):
        eng = SQLiEngine(_ctx(make_ctx))
        res = EngineResult(stage="sqli")
        ok = await eng.gate("http://evil.test/x?y=1", res, host="evil.test")
        assert ok is False
        assert any("scope" in w for w in res.warnings)

    async def test_gate_accepts_loopback(self, tmp_db, make_ctx, reflect_server):
        eng = SQLiEngine(_ctx(make_ctx))
        res = EngineResult(stage="sqli")
        ok = await eng.gate(f"{reflect_server}/echo?q=1", res, host="127.0.0.1")
        assert ok is True


# --------------------------------------------------------- evidence-based proof
class TestEvidenceBasedConfirmation:
    async def test_ssti_confirms_only_with_marker(self, tmp_db, make_ctx,
                                                  reflect_server):
        _seed_param_url(url=f"{reflect_server}/ssti?q=1")
        ctx = _ctx(make_ctx)
        res = await SSTIEngine(ctx).run()
        assert res.findings >= 1
        confirmed = db.findings_by_status("confirmed", scan_id=ctx.scan_id)
        assert confirmed and confirmed[0]["module"] == "ssti"
        assert db.evidence_for(confirmed[0]["id"])

    async def test_xss_reflection_is_candidate_not_confirmed(
            self, tmp_db, make_ctx, reflect_server):
        _seed_param_url(url=f"{reflect_server}/echo?q=1")
        ctx = _ctx(make_ctx)
        res = await XSSEngine(ctx).run()
        assert res.findings >= 1
        # Refleksiya tək başına TƏSDİQ deyil → finding `candidate` qalər.
        assert db.findings_by_status("confirmed", scan_id=ctx.scan_id) == []
        candidates = db.findings_by_status("candidate", scan_id=ctx.scan_id)
        assert any(c["source"] == "reflection" for c in candidates)

    async def test_base_confirm_lifecycle(self, tmp_db, make_ctx):
        hid = db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx)
        eng = OffensiveEngine(ctx)
        fid = eng.record(hid, "high", "T", "D", evidence="e")
        assert db.findings_by_status("candidate", scan_id=ctx.scan_id)[0]["id"] == fid
        eng.confirm(fid, "marker", "marker evidence", confidence=0.9)
        confirmed = db.findings_by_status("confirmed", scan_id=ctx.scan_id)
        assert confirmed[0]["id"] == fid
        assert db.evidence_for(fid)


# -------------------------------------------------------------- library CVE
class TestLibraryExtraction:
    def test_extract_libraries(self):
        text = "jQuery v3.5.1 and React v16.0.0 and axios/0.21.1"
        found = extract_libraries(text)
        assert found["jquery"] == "3.5.1"
        assert found["react"] == "16.0.0"
        assert found["axios"] == "0.21.1"

    def test_extract_empty(self):
        assert extract_libraries("no libs here") == {}


# ----------------------------------------------------- recon deepening tools
class TestReconDeepening:
    async def test_bbot_rejects_out_of_scope(self, tmp_db, make_ctx):
        res = await BBOTEngine(_ctx(make_ctx)).run("evil.test")
        assert res.ok is False
        assert any("scope" in e for e in res.errors)

    async def test_waymore_rejects_out_of_scope(self, tmp_db, make_ctx):
        res = await WaymoreEngine(_ctx(make_ctx)).run("evil.test")
        assert res.ok is False

    async def test_bbot_skips_when_missing(self, tmp_db, make_ctx, monkeypatch):
        from qbh.adapters.base import ProcResult
        from qbh.egress import EgressController

        async def _missing(self, *a, **k):
            return ProcResult(-1, missing=True)

        # Faza 1.2: mühərriklər artıq `ctx.egress.run()` (TƏK qapı) işlədir.
        monkeypatch.setattr(EgressController, "run", _missing)
        res = await BBOTEngine(_ctx(make_ctx)).run("127.0.0.1")
        assert res.skipped is True

    async def test_dnstwist_rejects_out_of_scope(self, tmp_db, make_ctx):
        res = await DnstwistEngine(_ctx(make_ctx)).run("evil.test")
        assert res.ok is False

    def test_gowitness_declared(self):
        from qbh.engines.deepen import GowitnessEngine

        assert GowitnessEngine.name == "gowitness"
