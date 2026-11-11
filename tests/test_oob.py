"""Faza 1.4 — OOB (Out-of-Band) təsdiq infrastrukturu testləri.

Yoxlanılan prinsiplər:
  * Unikal correlation token-lər; yalnız qeydiyyatdan keçmiş token üçün
    callback qəbul olunur (uydurma təsdiq mümkün deyil).
  * `url_for` yalnız konfiqurasiya edilmiş domenlə URL qurur.
  * Domen yoxdursa OOB HONEST şəkildə `active=False` olur.
  * Yerli geri-zəng dinləyicisi (loopback) real HTTP callback-i qeyd edir və
    finding-i `confirmed` etmək üçün sübut verir.

Heç bir test xarici hədəfə müraciət etmir — dinləyici 127.0.0.1 üzərindədir.
"""
from __future__ import annotations

import re

import aiohttp

from qbh.oob import OOBManager, new_token


class TestTokens:
    def test_new_token_is_hex_and_unique(self):
        a, b = new_token(), new_token()
        assert re.fullmatch(r"[0-9a-f]{16}", a)
        assert a != b

    def test_register_unique_and_audited(self):
        mgr = OOBManager(domain="cb.example.com")
        t1, t2 = mgr.register(), mgr.register()
        assert t1 != t2
        assert all(e["event"] == "oob_register" for e in mgr.audit)

    def test_url_for_requires_domain(self):
        assert OOBManager(domain="").url_for("abc") == ""

    def test_url_for_builds_subdomain(self):
        mgr = OOBManager(domain="cb.example.com")
        assert mgr.url_for("tok123") == "http://tok123.cb.example.com/"
        assert mgr.url_for("tok123", "x") == "http://tok123.cb.example.com/x"
        assert mgr.url_for("tok123", "/y") == "http://tok123.cb.example.com/y"


class TestHits:
    def test_unregistered_token_rejected(self):
        mgr = OOBManager(domain="cb.example.com")
        assert mgr.record_hit("not-registered", remote="1.2.3.4") is None
        assert mgr.confirmed("not-registered") is False

    def test_registered_token_records_and_confirms(self):
        mgr = OOBManager(domain="cb.example.com")
        token = mgr.register()
        hit = mgr.record_hit(token, remote="9.9.9.9", method="GET",
                             path="/cb", detail="tok.cb.example.com")
        assert hit is not None
        assert mgr.confirmed(token) is True
        assert len(mgr.hits(token)) == 1
        assert mgr.poll()[token][0].remote == "9.9.9.9"

    def test_evidence_format(self):
        mgr = OOBManager(domain="cb.example.com")
        token = mgr.register()
        hit = mgr.record_hit(token, remote="9.9.9.9", method="POST", path="/z")
        text = hit.to_evidence()
        assert "POST" in text and "/z" in text and "9.9.9.9" in text

    def test_summary_shape(self):
        mgr = OOBManager(domain="cb.example.com")
        mgr.register()
        s = mgr.summary()
        assert s["active"] is True
        assert s["tokens"] == 1
        assert s["domain"] == "cb.example.com"


class TestActive:
    def test_domain_absent_is_inactive(self):
        mgr = OOBManager(domain="", enabled=True)
        assert mgr.active is False

    def test_enabled_false_is_inactive(self):
        mgr = OOBManager(domain="cb.example.com", enabled=False)
        assert mgr.active is False

    async def test_start_noop_when_inactive(self):
        mgr = OOBManager(domain="")
        await mgr.start()
        assert mgr.started is False

    async def test_start_noop_for_interactsh_backend(self):
        mgr = OOBManager(domain="cb.example.com", backend="interactsh")
        await mgr.start()
        assert mgr.started is False


class TestLoopbackCallback:
    async def test_local_callback_flips_to_confirmed(self):
        mgr = OOBManager(domain="127.0.0.1", backend="local",
                         listen_host="127.0.0.1", listen_port=0)
        await mgr.start()
        try:
            assert mgr.started is True
            port = mgr._server.bound_port
            assert port > 0
            token = mgr.register()
            # Geri-zəngi təqlid et: Host başlığında token alt-domeni.
            async with aiohttp.ClientSession() as session:
                async with session.get(
                        f"http://127.0.0.1:{port}/pixel",
                        headers={"Host": f"{token}.cb.test"}) as r:
                    assert r.status == 200
            assert mgr.confirmed(token) is True
            assert await mgr.wait_for(token, timeout=1.0, interval=0.05) is True
            hit = mgr.hits(token)[0]
            assert hit.path == "/pixel"
        finally:
            await mgr.stop()
        assert mgr.started is False

    async def test_unknown_token_callback_not_confirmed(self):
        mgr = OOBManager(domain="127.0.0.1", backend="local",
                         listen_host="127.0.0.1", listen_port=0)
        await mgr.start()
        try:
            port = mgr._server.bound_port
            async with aiohttp.ClientSession() as session:
                async with session.get(
                        f"http://127.0.0.1:{port}/x",
                        headers={"Host": "deadbeef.cb.test"}) as r:
                    assert r.status == 200
            assert mgr.confirmed("deadbeef") is False
        finally:
            await mgr.stop()
