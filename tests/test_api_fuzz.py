"""Faza 0.3 regressiya testi — OpenAPI `servers` scope validasiyası.

Tarixi qüsur: `api_fuzz` YALNIZ OpenAPI sənədinin öz URL-ini yoxlayırdı;
sənədin içindəki `servers:` siyahısı yoxlanılmırdı → sənəd scope-daxili olsa
da, Schemathesis scope XARİCİ serverə qarşı trafik göndərə bilərdi.

Bu testlər sübut edir:
  * dəyişənlər (`variables[*].default`) əvəz olunur;
  * nisbi URL-lər sənədin əsasına görə həll olunur;
  * hər server `authorize()`-dən keçir; scope xarici server RƏDD edilir;
  * həll olunmamış dəyişən / etibarsız sxem → etibarsız sayılır;
  * boş `servers` → OpenAPI default-una (sənədin özü) düşür;
  * protocol-relative `//evil.example.com` kimi "escape" URL-ləri rədd olunur.

Heç bir test xarici şəbəkəyə müraciət etmir.
"""
from __future__ import annotations

from qbh.authorization import from_config
from qbh.engines.api_fuzz import APIFuzzEngine as E


def _auth(load_config):
    cfg = load_config([
        {"domain": "app.example.com", "in_scope": ["app.example.com"],
         "out_of_scope": []},
    ])
    return from_config(cfg)


DOC_URL = "https://app.example.com/openapi.json"


# --------------------------------------------------------------- effective_servers
class TestEffectiveServers:
    def test_absolute_in_scope(self):
        doc = {"servers": [{"url": "https://app.example.com/v1"}]}
        assert E.effective_servers(doc, DOC_URL) == ["https://app.example.com/v1"]

    def test_relative_resolved_against_doc(self):
        doc = {"servers": [{"url": "/api/v2"}]}
        assert E.effective_servers(doc, DOC_URL) == ["https://app.example.com/api/v2"]

    def test_variable_substitution(self):
        doc = {"servers": [{
            "url": "https://{host}/api",
            "variables": {"host": {"default": "app.example.com"}},
        }]}
        assert E.effective_servers(doc, DOC_URL) == \
            ["https://app.example.com/api"]

    def test_unresolved_variable_dropped(self):
        doc = {"servers": [{"url": "https://{host}/api"}]}
        assert E.effective_servers(doc, DOC_URL) == ["https://app.example.com/"]

    def test_multiple_servers_preserved(self):
        doc = {"servers": [{"url": "https://app.example.com/a"},
                           {"url": "https://app.example.com/b"}]}
        assert E.effective_servers(doc, DOC_URL) == [
            "https://app.example.com/a", "https://app.example.com/b"]

    def test_empty_servers_falls_back_to_doc_host(self):
        assert E.effective_servers({"servers": []}, DOC_URL) == \
            ["https://app.example.com/"]
        assert E.effective_servers({}, DOC_URL) == ["https://app.example.com/"]

    def test_malformed_scheme_dropped(self):
        doc = {"servers": [{"url": "ftp://app.example.com/x"}]}
        # ftp etibarsız sxemdir → atılır; səssizcə doc hostuna ƏVƏZLƏNMİR
        # (belə olsa mühərrik "scope-daxili server yoxdur" deyib atlar).
        assert E.effective_servers(doc, DOC_URL) == []

    def test_protocol_relative_escape_kept_as_host_absolute(self):
        doc = {"servers": [{"url": "//evil.example.com/api"}]}
        # urljoin → https://evil.example.com/api (host-absolut) — sonra
        # validate_servers onu scope xarici kimi RƏDD edəcək.
        assert E.effective_servers(doc, DOC_URL) == \
            ["https://evil.example.com/api"]

    def test_non_dict_doc_and_entries_are_safe(self):
        assert E.effective_servers(None, DOC_URL) == ["https://app.example.com/"]
        assert E.effective_servers("nope", DOC_URL) == ["https://app.example.com/"]
        assert E.effective_servers({"servers": [None, 3, "x"]}, DOC_URL) == \
            ["https://app.example.com/"]


# --------------------------------------------------------------- validate_servers
class TestValidateServers:
    def test_valid_same_scope_server(self, load_config):
        auth = _auth(load_config)
        good, bad = E.validate_servers(
            {"servers": [{"url": "https://app.example.com/v1"}]},
            DOC_URL, auth.authorize_url)
        assert good == ["https://app.example.com/v1"]
        assert bad == []

    def test_out_of_scope_server_rejected(self, load_config):
        auth = _auth(load_config)
        good, bad = E.validate_servers(
            {"servers": [{"url": "https://evil.example.com/v1"}]},
            DOC_URL, auth.authorize_url)
        assert good == []
        assert len(bad) == 1
        assert bad[0][0] == "https://evil.example.com/v1"
        assert bad[0][1]  # səbəb mesajı var

    def test_mixed_servers(self, load_config):
        auth = _auth(load_config)
        good, bad = E.validate_servers(
            {"servers": [
                {"url": "https://app.example.com/v1"},
                {"url": "https://evil.example.com/v1"},
                {"url": "/rel"},   # → app.example.com/rel (in-scope)
            ]},
            DOC_URL, auth.authorize_url)
        assert "https://app.example.com/v1" in good
        assert "https://app.example.com/rel" in good
        assert [u for u, _ in bad] == ["https://evil.example.com/v1"]

    def test_redirect_escape_via_protocol_relative(self, load_config):
        """`//evil.example.com` → host-absolut URL, scope xarici → rədd."""
        auth = _auth(load_config)
        good, bad = E.validate_servers(
            {"servers": [{"url": "//evil.example.com/api"}]},
            DOC_URL, auth.authorize_url)
        assert good == []
        assert [u for u, _ in bad] == ["https://evil.example.com/api"]

    def test_empty_servers_uses_doc_host_in_scope(self, load_config):
        auth = _auth(load_config)
        good, bad = E.validate_servers({"servers": []}, DOC_URL,
                                       auth.authorize_url)
        assert good == ["https://app.example.com/"]
        assert bad == []

    def test_all_out_of_scope_yields_no_good(self, load_config):
        auth = _auth(load_config)
        good, bad = E.validate_servers(
            {"servers": [{"url": "https://a.evil.test/"},
                         {"url": "https://b.evil.test/"}]},
            DOC_URL, auth.authorize_url)
        assert good == []
        assert len(bad) == 2


# ---------------------------------------------------------- engine-level guard
class TestEngineGuard:
    async def test_disabled_without_active_fuzz(self, tmp_db, make_ctx):
        ctx = make_ctx(active_fuzz=False)
        res = await E(ctx).run()
        assert res.skipped is True

    async def test_no_schema_skips(self, tmp_db, make_ctx):
        ctx = make_ctx(active_fuzz=True)
        ctx.scan_id = 1
        res = await E(ctx).run()
        assert res.skipped is True


# -------------------------------------------- OpenAPI yükləməsi (Faza 1.3)
class TestFetchDocumentPolicy:
    """Sübut: sxem sənədi artıq HttpPolicy (Guardian) qapısından keçir.

    Tarixi qüsur: `aiohttp.ClientSession().get()` birbaşa çağırılırdı →
    scope/redirect/rate yoxlaması YOX idi.
    """

    async def test_out_of_scope_doc_returns_none(self, tmp_db, make_ctx):
        import aiohttp

        eng = E(make_ctx())
        async with aiohttp.ClientSession() as session:
            doc = await eng._fetch_document(
                session, "http://evil.example.com/openapi.json")
        assert doc is None

    async def test_in_scope_loopback_doc_parsed(self, tmp_db, make_ctx):
        import aiohttp
        from aiohttp import web

        async def schema(request):
            return web.json_response({"openapi": "3.0.0",
                                      "servers": [{"url": "/v1"}]})

        app = web.Application()
        app.add_routes([web.get("/openapi.json", schema)])
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = runner.addresses[0][1]
        try:
            eng = E(make_ctx())
            async with aiohttp.ClientSession() as session:
                doc = await eng._fetch_document(
                    session, f"http://127.0.0.1:{port}/openapi.json")
        finally:
            await runner.cleanup()
        assert isinstance(doc, dict)
        assert doc["openapi"] == "3.0.0"

    async def test_non_json_doc_returns_none(self, tmp_db, make_ctx):
        import aiohttp
        from aiohttp import web

        async def html(request):
            return web.Response(text="<html>not json</html>",
                                content_type="text/html")

        app = web.Application()
        app.add_routes([web.get("/openapi.json", html)])
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = runner.addresses[0][1]
        try:
            eng = E(make_ctx())
            async with aiohttp.ClientSession() as session:
                doc = await eng._fetch_document(
                    session, f"http://127.0.0.1:{port}/openapi.json")
        finally:
            await runner.cleanup()
        assert doc is None

    async def test_fallback_without_guardian_enforces_scope(self, tmp_db,
                                                            loopback_config):
        """Guardian yoxdursa belə scope qapısı işləyir (fail-closed)."""
        import aiohttp

        from qbh.authorization import from_config

        auth = from_config(loopback_config)

        class _StubCtx:
            def __init__(self):
                self.cfg = loopback_config

            def authorize_url(self, url):
                return auth.authorize_url(url)

        eng = E(_StubCtx())
        async with aiohttp.ClientSession() as session:
            doc = await eng._fetch_document(
                session, "http://evil.example.com/openapi.json")
        assert doc is None
