"""QBH test dəsti — ümumi fixture-lər.

Prinsiplər:
  * Hər test İZOLYASİYALI müvəqqəti SQLite bazası ilə işləyir.
  * Heç bir test XARİCİ hədəfə müraciət etmir — yalnız `127.0.0.1` lokal
    HTTP fixture istifadə olunur.
  * Xarici alətlər (nuclei, ffuf, ...) mock-lanır və ya `missing` qaytarır.
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402


# --------------------------------------------------------------------------
# Baza
# --------------------------------------------------------------------------
@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Müvəqqəti bazada təmiz `qbh.db` təmin edir."""
    from qbh import db

    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    db.close_db()
    db.init_db()
    yield db
    db.close_db()


# --------------------------------------------------------------------------
# Konfiqurasiya
# --------------------------------------------------------------------------
@pytest.fixture
def write_config(tmp_path):
    """YAML konfiq faylı yazan köməkçi (fail-closed scope testləri üçün)."""
    import yaml

    def _write(scope_entries, *, limits=None, program="test",
               antiblock=None, extra=None, proxy_file=""):
        data = {
            "program": program,
            "nvd_api_key": "",
            "scope": scope_entries,
            "limits": limits or {
                "requests_per_second": 50,
                "max_concurrency": 5,
                "connect_timeout": 5,
                "total_timeout": 10,
                "cooldown": 1,
            },
            "proxy_file": proxy_file,
        }
        if antiblock is not None:
            data["antiblock"] = antiblock
        if extra:
            data.update(extra)
        path = tmp_path / "cfg.yaml"
        path.write_text(yaml.safe_dump(data), encoding="utf-8")
        return str(path)

    return _write


@pytest.fixture
def load_config(write_config):
    from qbh.config import Config

    def _load(scope_entries, **kw):
        return Config.load(write_config(scope_entries, **kw))

    return _load


@pytest.fixture
def loopback_config(load_config):
    """Yalnız 127.0.0.1-ə icazə verən konfiq (lokal testlər üçün)."""
    return load_config([
        {"domain": "127.0.0.1", "in_scope": ["127.0.0.1"], "out_of_scope": []}
    ])


# --------------------------------------------------------------------------
# Lokal HTTP fixture (XARİCİ ŞƏBƏKƏ YOXDUR)
# --------------------------------------------------------------------------
@pytest_asyncio.fixture
async def local_server():
    from aiohttp import web

    state = {"hits": 0, "conc": 0, "max_conc": 0}

    async def index(request):
        return web.Response(text="hello qbh")

    async def forbidden(request):
        return web.Response(status=403, text="forbidden")

    async def rate_limited(request):
        return web.Response(status=429, headers={"Retry-After": "2"},
                            text="slow down")

    async def escape(request):
        return web.Response(status=302,
                            headers={"Location": "http://evil.example.com/"})

    async def inside(request):
        return web.Response(status=302, headers={"Location": "/final"})

    async def final(request):
        return web.Response(text="final")

    async def big(request):
        return web.Response(text="A" * 5000)

    async def server_error(request):
        return web.Response(status=500, text="boom")

    async def slow(request):
        import asyncio
        await asyncio.sleep(2)
        return web.Response(text="late")

    async def count(request):
        state["hits"] += 1
        return web.Response(text=str(state["hits"]))

    async def conc(request):
        import asyncio
        state["conc"] += 1
        state["max_conc"] = max(state["max_conc"], state["conc"])
        await asyncio.sleep(0.15)
        state["conc"] -= 1
        return web.Response(text="ok")

    # Faza 3.2: secret replay fixture — yalnız düzgün bearer token ilə 200.
    async def secret_ok(request):
        auth = request.headers.get("Authorization", "")
        if auth == "Bearer valid-token-1234567890":
            return web.Response(text="granted-access-body")
        return web.Response(status=401, text="unauthorized")

    # Faza 3.3: CNAME takeover fixture — provayderin "sahibsiz" imzası.
    async def gh_pages_gone(request):
        return web.Response(status=404,
                            text="There isn't a GitHub Pages site here")

    app = web.Application()
    app.add_routes([
        web.get("/", index),
        web.get("/403", forbidden),
        web.get("/429", rate_limited),
        web.get("/escape", escape),
        web.get("/inside", inside),
        web.get("/final", final),
        web.get("/big", big),
        web.get("/500", server_error),
        web.get("/slow", slow),
        web.get("/count", count),
        web.get("/conc", conc),
        web.get("/secret", secret_ok),
        web.get("/gh-pages-gone", gh_pages_gone),
    ])
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    try:
        yield {"base": f"http://127.0.0.1:{port}", "state": state}
    finally:
        await runner.cleanup()


@pytest.fixture
def make_ctx(loopback_config):
    """Mühərrik testləri üçün real `Context` yaradır (şəbəkəsiz)."""
    import argparse

    from qbh.antiblock.guardian import Guardian
    from qbh.antiblock.identity import IdentityManager
    from qbh.context import Context
    from qbh.http_policy import HttpPolicy

    def _make(cfg=None, *, active_fuzz=None, race_fixture=None,
              race_count=10, race_concurrency=4):
        cfg = cfg or loopback_config
        policy = HttpPolicy(cfg.scope, rate=1000, max_concurrency=10)
        guardian = Guardian(IdentityManager("", "lo"), policy)
        args = argparse.Namespace(
            rate=1000, active_fuzz=active_fuzz, race_fixture=race_fixture,
            race_count=race_count, race_concurrency=race_concurrency)
        return Context(cfg=cfg, args=args, guardian=guardian, scan_id=None)

    return _make
