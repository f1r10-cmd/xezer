"""Bypass engine + WAF/filter bypass payload matrisi testləri (Faza 2/3).

Yoxlanılan prinsiplər:
  * `payloads.build_matrix` path/header/verb texnikalarını generasiya edir və
    təkrarları silir.
  * `BypassEngine` YALNIZ 401/403 baseline olduqda matrisi sınayır.
  * Uğurlu bypass → `confirmed` tapıntı + sübut.
  * Uğursuz bypass → tapıntı yoxdur (uydurma qadağandır).
  * Yalnız `127.0.0.1` lokal fixture istifadə olunur — xarici şəbəkə YOXDUR.
"""
from __future__ import annotations

import pytest_asyncio

from qbh import db
from qbh.authorization import from_config
from qbh.payloads import (HEADER_TRICKS, VERBS, build_matrix, header_attempts,
                          path_attempts, verb_attempts)


# ---------------------------------------------------------------- payloads
class TestPayloads:
    def test_build_matrix_has_kinds(self):
        m = build_matrix("http://example.com/admin")
        labels = {a.label for a in m}
        assert any(lbl.startswith("path-") for lbl in labels)
        assert any(lbl.startswith("header-") for lbl in labels)
        assert any(lbl.startswith("verb-") for lbl in labels)

    def test_header_attempt_present(self):
        heads = header_attempts("http://example.com/admin")
        assert any("X-Forwarded-For" in a.headers for a in heads)

    def test_verb_attempts(self):
        verbs = verb_attempts("http://example.com/x")
        assert {a.method for a in verbs} == set(VERBS)

    def test_path_attempts_preserve_query(self):
        pa = path_attempts("http://example.com/a/b?x=1")
        assert all(a.url.endswith("?x=1") for a in pa)

    def test_matrix_deduped(self):
        m = build_matrix("http://example.com/admin")
        keys = [(a.method, a.url, tuple(sorted(a.headers.items()))) for a in m]
        assert len(keys) == len(set(keys))

    def test_header_tricks_non_empty(self):
        assert len(HEADER_TRICKS) >= 5


# ---------------------------------------------------------------- engine
@pytest_asyncio.fixture
async def bypass_server():
    """Lokal server: XFF başlığı olmadan 403, XFF=127.0.0.1 ilə 200."""
    from aiohttp import web

    async def handler(request):
        if request.headers.get("X-Forwarded-For") == "127.0.0.1":
            return web.Response(status=200, text="admin panel ok")
        return web.Response(status=403, text="forbidden")

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        await runner.cleanup()


def _ctx(make_ctx, cfg=None, **kw):
    ctx = make_ctx(cfg, **kw)
    ctx.authorization = from_config(ctx.cfg)
    ctx.scan_id = 1
    return ctx


class TestBypassEngine:
    async def test_skip_when_forbidden(self, tmp_db, make_ctx):
        from qbh.engines.bypass import BypassEngine

        cfg = make_ctx().cfg
        cfg.program_rules.forbidden = {"bypass"}
        ctx = make_ctx(cfg)
        ctx.authorization = from_config(cfg)
        res = await BypassEngine(ctx).run()
        assert res.skipped is True

    async def test_skip_on_empty_db(self, tmp_db, make_ctx):
        from qbh.engines.bypass import BypassEngine

        res = await BypassEngine(_ctx(make_ctx)).run()
        assert res.skipped is True

    async def test_successful_bypass_is_confirmed(self, tmp_db, make_ctx,
                                                  bypass_server):
        from qbh.engines.bypass import BypassEngine

        url = f"{bypass_server}/admin"
        # v4: host cari skanın (scan_id=1) altında olmalıdır — əks halda
        # `_record` onu tapmır (per-scan izolyasiya).
        hid = db.upsert_host("127.0.0.1", 1, status_code=200)
        db.insert_url(hid, url, "ferox")
        res = await BypassEngine(_ctx(make_ctx)).run([url])
        assert res.findings >= 1
        confirmed = [dict(r) for r in db.findings_by_status("confirmed")]
        assert any(f["module"] == "bypass" for f in confirmed)
        fid = confirmed[0]["id"]
        assert db.evidence_for(fid)  # sübut əlavə olundu

    async def test_failed_bypass_no_finding(self, tmp_db, make_ctx,
                                            local_server):
        from qbh.engines.bypass import BypassEngine

        url = f"{local_server['base']}/403"   # həmişə 403, bypass yoxdur
        hid = db.upsert_host("127.0.0.1", 1, status_code=200)
        db.insert_url(hid, url, "ferox")
        res = await BypassEngine(_ctx(make_ctx)).run([url])
        assert res.findings == 0
        assert db.findings_by_status("confirmed") == []

    async def test_out_of_scope_url_skipped(self, tmp_db, make_ctx):
        from qbh.engines.bypass import BypassEngine

        res = await BypassEngine(_ctx(make_ctx)).run(
            ["http://evil.example.com/admin"])
        assert res.findings == 0
