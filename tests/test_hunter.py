"""Faza 3.5 testi — Hunter orkestratoru (`qbh/hunter.py`).

Prinsiplər:
  * Yalnız `127.0.0.1` loopback istifadə olunur (heç bir xarici şəbəkə yoxdur).
  * Yüksək-dəyərli endpoint seçimi və dərin pass-ın bypass mərhələsini
    çağırması yoxlanılır.
"""
from __future__ import annotations

from qbh import db
from qbh.authorization import from_config
from qbh.hunter import Hunter
from qbh.results import EngineResult


class _FakeConductor:
    """`Hunter`-in ehtiyac duyduğu minimal Conductor interfeysi."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.authorization = ctx.authorization
        self.stages = []

    async def _run_stage(self, stage, target, factory):
        res = await factory()
        self.stages.append((stage, res))
        return res


def _ctx(make_ctx, scan_id=1):
    ctx = make_ctx()
    ctx.authorization = from_config(ctx.cfg)
    ctx.scan_id = scan_id
    return ctx


# ------------------------------------------------------------- high-value
class TestHighValueUrls:
    def test_selects_admin_login_not_blog(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx)
        hid = db.upsert_host("127.0.0.1", status_code=200, scan_id=1)
        db.insert_url(hid, "http://127.0.0.1:1/admin", "ferox", scan_id=1)
        db.insert_url(hid, "http://127.0.0.1:1/login", "ferox", scan_id=1)
        db.insert_url(hid, "http://127.0.0.1:1/blog", "ferox", scan_id=1)
        urls = Hunter(_FakeConductor(ctx))._high_value_urls()
        assert any("admin" in u for u in urls)
        assert any("login" in u for u in urls)
        assert not any("/blog" in u for u in urls)

    def test_empty_db(self, tmp_db, make_ctx):
        fake = _FakeConductor(_ctx(make_ctx))
        assert Hunter(fake)._high_value_urls() == []


# --------------------------------------------------------------- deep pass
class TestDeepPass:
    async def test_no_urls_no_stage(self, tmp_db, make_ctx):
        fake = _FakeConductor(_ctx(make_ctx))
        await Hunter(fake)._deep_pass()
        assert fake.stages == []

    async def test_runs_bypass_stage(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx)
        hid = db.upsert_host("127.0.0.1", status_code=200, scan_id=1)
        db.insert_url(hid, "http://127.0.0.1:1/admin", "ferox", scan_id=1)
        fake = _FakeConductor(ctx)
        await Hunter(fake)._deep_pass()
        assert len(fake.stages) == 1
        stage, res = fake.stages[0]
        assert stage == "hunter_deep"
        assert isinstance(res, EngineResult)
