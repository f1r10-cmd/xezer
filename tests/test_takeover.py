"""Faza 3.3 testi — CNAME takeover (subdomain itkisi) detektoru.

Prinsiplər:
  * Heç bir test xarici DNS/HTTP-ə müraciət etmir — resolver-lər və URL
    qurucusu enjeksiya olunur; HTTP yalnız `127.0.0.1` fixture-a gedir.
  * CNAME hədəfinə HEÇ VAXT sorğu getmir — yalnız sətir müqayisəsi.
"""
from __future__ import annotations

from qbh import db
from qbh.engines.takeover import TakeoverEngine, match_provider

LOOPBACK_SCOPE = [{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
                   "out_of_scope": []}]


def _resolver(mapping):
    """Host → siyahı qaytaran sadə resolver fabriki (executor-da işləyir)."""
    return lambda host: list(mapping.get(host, []))


# ------------------------------------------------------------------ match
class TestMatchProvider:
    def test_exact_suffix(self):
        assert match_provider(["bucket.s3.amazonaws.com"])[0] == "AWS S3"

    def test_subdomain_of_suffix(self):
        assert match_provider(["foo.bar.github.io"])[0] == "GitHub Pages"

    def test_trailing_dot_and_case(self):
        assert match_provider(["Site.GitHub.IO."])[0] == "GitHub Pages"

    def test_unknown_provider(self):
        assert match_provider(["example.com"]) is None

    def test_empty(self):
        assert match_provider([]) is None


# ------------------------------------------------------------------ engine
class TestTakeoverEngine:
    async def test_dangling_cname_is_candidate(
            self, make_ctx, tmp_db):
        ctx = make_ctx()
        db.upsert_host("127.0.0.1", status_code=200, scan_id=ctx.scan_id)
        eng = TakeoverEngine(
            ctx,
            cname_resolver=_resolver({"127.0.0.1": ["old.s3.amazonaws.com"]}),
            address_resolver=_resolver({}))  # ünvan YOXDUR → qırıq zəncir
        res = await eng.run()
        assert res.findings == 1
        row = db.get_db().execute(
            "SELECT status, severity FROM findings WHERE module='takeover'"
        ).fetchone()
        assert row["status"] == "candidate"

    async def test_confirm_with_provider_signature(
            self, make_ctx, tmp_db, local_server):
        ctx = make_ctx()
        db.upsert_host("127.0.0.1", status_code=200, scan_id=ctx.scan_id)
        eng = TakeoverEngine(
            ctx,
            cname_resolver=_resolver({"127.0.0.1": ["site.github.io"]}),
            address_resolver=_resolver({"127.0.0.1": ["1.2.3.4"]}),
            url_builder=lambda h: f"{local_server['base']}/gh-pages-gone")
        res = await eng.run()
        assert res.findings == 1
        row = db.get_db().execute(
            "SELECT status FROM findings WHERE module='takeover'").fetchone()
        assert row["status"] == "confirmed"

    async def test_live_host_without_signature_is_silent(
            self, make_ctx, tmp_db, local_server):
        ctx = make_ctx()
        db.upsert_host("127.0.0.1", status_code=200, scan_id=ctx.scan_id)
        eng = TakeoverEngine(
            ctx,
            cname_resolver=_resolver({"127.0.0.1": ["site.github.io"]}),
            address_resolver=_resolver({"127.0.0.1": ["1.2.3.4"]}),
            url_builder=lambda h: local_server["base"])  # "hello qbh" → imza yox
        res = await eng.run()
        assert res.findings == 0

    async def test_out_of_scope_host_never_resolved(
            self, make_ctx, tmp_db):
        ctx = make_ctx()
        db.upsert_host("evil.test", status_code=200, scan_id=ctx.scan_id)
        calls: list[str] = []

        def _cname(host):
            calls.append(host)
            return ["old.s3.amazonaws.com"]

        eng = TakeoverEngine(
            ctx, cname_resolver=_cname, address_resolver=_resolver({}))
        res = await eng.run()
        assert res.findings == 0
        assert calls == []  # scope xarici host üçün DNS sorğusu yoxdur

    async def test_no_cname_no_finding(self, make_ctx, tmp_db):
        ctx = make_ctx()
        db.upsert_host("127.0.0.1", status_code=200, scan_id=ctx.scan_id)
        eng = TakeoverEngine(
            ctx, cname_resolver=_resolver({}), address_resolver=_resolver({}))
        res = await eng.run()
        assert res.findings == 0

    async def test_non_provider_cname_ignored(self, make_ctx, tmp_db):
        ctx = make_ctx()
        db.upsert_host("127.0.0.1", status_code=200, scan_id=ctx.scan_id)
        eng = TakeoverEngine(
            ctx,
            cname_resolver=_resolver({"127.0.0.1": ["example.com"]}),
            address_resolver=_resolver({}))
        res = await eng.run()
        assert res.findings == 0

    async def test_no_hosts_skips(self, make_ctx, tmp_db):
        ctx = make_ctx()
        res = await TakeoverEngine(ctx).run()
        assert res.skipped
