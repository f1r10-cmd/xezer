"""Zəncirləmə pipeline testləri — 'finding maximization' (Faza 2).

Yoxlanılan prinsiplər:
  * `TRIGGERS` xəritəsi düzgün davam hərəkətlərini planlaşdırır.
  * `ChainPipeline.emit` icazəsiz (proqram qadağası) hərəkətləri atlayır və
    bunu audit üçün qeyd edir.
  * `_discover_triggers` DB vəziyyətindən trigger-ləri çıxarır.
  * `run()` həmişə `EngineResult` qaytarır; boş bazada şəbəkəyə çıxmır.
  * `FindingStore` lifecycle keçidlərini düzgün tətbiq edir.
  * Heç bir test xarici hədəfə müraciət etmir.
"""
from __future__ import annotations

import pytest_asyncio

from qbh import db
from qbh.authorization import from_config
from qbh.chain import (ACTION_EXEC, TRIGGERS, ChainPipeline, FindingStore)
from qbh.results import EngineResult


def _ctx_with_auth(make_ctx, cfg=None, **kw):
    ctx = make_ctx(cfg, **kw)
    ctx.authorization = from_config(ctx.cfg)
    return ctx


# ---------------------------------------------------------------- triggers map
class TestTriggers:
    def test_keys_present(self):
        for kind in ("subdomain", "js_file", "param", "openapi",
                     "interesting_endpoint", "cve", "blocked", "nuclei"):
            assert kind in TRIGGERS

    def test_every_action_has_exec_anatomy(self):
        for actions in TRIGGERS.values():
            for action in actions:
                assert action in ACTION_EXEC

    def test_subdomain_chain(self):
        assert TRIGGERS["subdomain"] == ["live_check", "fingerprint",
                                         "js_analysis"]


# ---------------------------------------------------------------- emit / gate
class TestEmitGate:
    def test_default_allows_all(self, tmp_db, make_ctx):
        pipe = ChainPipeline(_ctx_with_auth(make_ctx))
        assert pipe.enabled is True
        allowed = pipe.emit("subdomain", "a.example.com")
        assert allowed == ["live_check", "fingerprint", "js_analysis"]
        assert pipe.skipped == []

    def test_forbidden_active_fuzz_skips_fuzz(self, tmp_db, make_ctx):
        cfg = make_ctx().cfg
        # program rules: active_fuzz qadağan → param_fuzz atlanır
        cfg.program_rules.forbidden = {"active_fuzz"}
        ctx = make_ctx(cfg)
        ctx.authorization = from_config(cfg)
        pipe = ChainPipeline(ctx)
        allowed = pipe.emit("param", "?id=1")
        assert "param_fuzz" not in allowed
        assert "hidden_param_detect" in allowed
        assert any("aktiv fuzz" in s for s in pipe.skipped)

    def test_forbidden_bypass_skips_matrix(self, tmp_db, make_ctx):
        cfg = make_ctx().cfg
        cfg.program_rules.forbidden = {"bypass"}
        ctx = make_ctx(cfg)
        ctx.authorization = from_config(cfg)
        pipe = ChainPipeline(ctx)
        assert pipe.emit("blocked", "host HTTP 403") == []
        assert any("bypass" in s for s in pipe.skipped)

    def test_forbidden_cve_poc_skips(self, tmp_db, make_ctx):
        cfg = make_ctx().cfg
        cfg.program_rules.forbidden = {"cve_poc"}
        ctx = make_ctx(cfg)
        ctx.authorization = from_config(cfg)
        pipe = ChainPipeline(ctx)
        assert pipe.emit("cve", "CVE-2024-0001") == []

    def test_disabled_pipeline(self, tmp_db, make_ctx):
        cfg = make_ctx().cfg
        cfg.chain.enabled = False
        ctx = make_ctx(cfg)
        ctx.authorization = from_config(cfg)
        pipe = ChainPipeline(ctx)
        assert pipe.enabled is False


# ---------------------------------------------------------------- discovery
class TestDiscovery:
    def test_discovers_from_db(self, tmp_db, make_ctx, ):
        hid = db.upsert_host("example.com", status_code=200)
        db.insert_url(hid, "http://example.com/app.js", "recon", is_js=True)
        db.insert_url(hid, "http://example.com/admin/x", "ferox")
        db.insert_cve(hid, "CVE-2024-1", "nginx", "1.18", False, 0.5, "high")

        ctx = _ctx_with_auth(make_ctx)
        pipe = ChainPipeline(ctx)
        pipe._discover_triggers()
        kinds = {e.kind for e in pipe.events}
        assert "subdomain" in kinds
        assert "js_file" in kinds
        assert "interesting_endpoint" in kinds
        assert "cve" in kinds


# ---------------------------------------------------------------- run
class TestRun:
    async def test_run_returns_engine_result(self, tmp_db, make_ctx):
        hid = db.upsert_host("example.com", status_code=200)
        db.insert_cve(hid, "CVE-2024-1", "nginx", "1.18", False, 0.5, "high")
        pipe = ChainPipeline(_ctx_with_auth(make_ctx))
        res = await pipe.run()
        assert isinstance(res, EngineResult)
        assert res.stage == "chain"
        assert res.data["events"] >= 2
        # subdomain → delegated addımlar qeyd olunur
        assert "live_check" in res.data["delegated"]

    async def test_run_disabled_skips(self, tmp_db, make_ctx):
        cfg = make_ctx().cfg
        cfg.chain.enabled = False
        ctx = make_ctx(cfg)
        ctx.authorization = from_config(cfg)
        res = await ChainPipeline(ctx).run()
        assert res.skipped is True

    async def test_run_empty_db_no_network(self, tmp_db, make_ctx):
        res = await ChainPipeline(_ctx_with_auth(make_ctx)).run()
        assert isinstance(res, EngineResult)
        assert res.data["events"] == 0

    async def test_audit_shape(self, tmp_db, make_ctx):
        pipe = ChainPipeline(_ctx_with_auth(make_ctx))
        pipe.emit("subdomain", "a.example.com")
        audit = pipe.audit()
        assert audit["events"][0]["kind"] == "subdomain"
        assert "executed" in audit and "delegated" in audit

    async def test_boost_confidence_attaches_evidence(self, tmp_db, make_ctx):
        hid = db.upsert_host("example.com", status_code=200)
        fid = db.insert_finding(hid, "nuclei", "high", "CVE-2024-9 hit",
                                confidence=0.7, source="nuclei")
        pipe = ChainPipeline(_ctx_with_auth(make_ctx))
        res = await pipe.run()
        assert "boost_confidence" in res.data["executed"]
        # status candidate olaraq qalır (təsdiq uydurulmur), confidence artır
        assert db.findings_by_status("confirmed") == []
        assert any(e["kind"] == "note" for e in db.evidence_for(fid))


# ---------------------------------------------------------------- finding store
class TestFindingStore:
    def test_candidate_then_confirm(self, tmp_db):
        hid = db.upsert_host("example.com", status_code=200)
        store = FindingStore(scan_id=1)
        fid = store.candidate(hid, "bypass", "high", "Title")
        assert db.findings_by_status("candidate")[0]["id"] == fid
        store.confirm(fid, note="təsdiq", evidence="HTTP 200")
        confirmed = db.findings_by_status("confirmed")
        assert confirmed[0]["id"] == fid
        assert any(e["kind"] == "note" for e in db.evidence_for(fid))

    def test_reject_and_report(self, tmp_db):
        hid = db.upsert_host("example.com", status_code=200)
        store = FindingStore()
        f1 = store.candidate(hid, "js", "medium", "A")
        f2 = store.candidate(hid, "js", "medium", "B")
        store.reject(f1, note="404")
        store.report(f2)
        assert db.findings_by_status("rejected")[0]["id"] == f1
        assert db.findings_by_status("reported")[0]["id"] == f2

    def test_attach_evidence(self, tmp_db):
        hid = db.upsert_host("example.com", status_code=200)
        store = FindingStore()
        fid = store.candidate(hid, "content", "low", "C")
        assert store.attach(fid, "data", "marker") > 0
        assert len(db.evidence_for(fid)) == 1


# ---------------------------------------------------------------- confirm engine
@pytest_asyncio.fixture
async def confirm_server():
    """Lokal server: /app.js imza uyğun, /missing 404."""
    from aiohttp import web

    async def app_js(request):
        return web.Response(text="var APIKEY='x'; function f(){ return 1; }")

    async def missing(request):
        return web.Response(status=404, text="not found")

    app = web.Application()
    app.add_routes([web.get("/app.js", app_js),
                    web.get("/missing", missing)])
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        await runner.cleanup()


class TestConfirmEngine:
    async def test_signature_match_confirms(self, tmp_db, make_ctx, confirm_server):
        from qbh.engines.confirm import ConfirmEngine

        hid = db.upsert_host("127.0.0.1", status_code=200)
        url = f"{confirm_server}/app.js"
        fid = db.insert_finding(hid, "js", "high", "JS exposure",
                                curl_repro=f"curl -sk {url}")
        ctx = _ctx_with_auth(make_ctx)
        ctx.scan_id = 1
        res = await ConfirmEngine(ctx).run([fid])
        assert res.findings >= 1
        assert db.findings_by_status("confirmed")[0]["id"] == fid
        assert db.evidence_for(fid)

    async def test_404_rejects(self, tmp_db, make_ctx, confirm_server):
        from qbh.engines.confirm import ConfirmEngine

        hid = db.upsert_host("127.0.0.1", status_code=200)
        url = f"{confirm_server}/missing"
        fid = db.insert_finding(hid, "js", "high", "Gone",
                                curl_repro=f"curl -sk {url}")
        ctx = _ctx_with_auth(make_ctx)
        ctx.scan_id = 1
        res = await ConfirmEngine(ctx).run([fid])
        assert res.findings == 0
        assert db.findings_by_status("rejected")[0]["id"] == fid

    async def test_no_candidates_skips(self, tmp_db, make_ctx):
        from qbh.engines.confirm import ConfirmEngine

        res = await ConfirmEngine(_ctx_with_auth(make_ctx)).run()
        assert res.skipped is True

