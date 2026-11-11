"""Faza 0.2 regressiya testi — subprocess egress idarəsi.

Tarixi qüsur: subprocess mühərrikləri (nuclei, ffuf, feroxbuster, schemathesis,
kiterunner ...) `HttpPolicy`-ni keçərək öz şəbəkə trafikini idarə edirdi; onlara
verilən hədəfin scope-a uyğun olduğu sübut olunmurdu və halt/timeout zamanı
proses qrupu tam öldürülmürdü.

Bu testlər sübut edir:
  * `authorize_process_targets` yalnız scope-daxili hədəfləri qaytarır;
    scope xarici hədəflər rədd olunur və audit yazılır;
  * hədəf faylı YALNIZ icazəli hostları ehtiva edir;
  * DNS pinning işləyir və TTL bitəndə yenidən həll olunur;
  * timeout və ləğv (cancel_event) BÜTÖV proses qrupunu SIGKILL edir
    (uşaq proseslər də dayanır).

Heç bir test xarici hədəfə müraciət etmir — DNS mock-lanır, proseslər lokal.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time

import pytest

from qbh.adapters.base import kill_process_group, run_process
from qbh.authorization import from_config
from qbh.config import ConfigError
from qbh.egress import (EgressController, ProcessTargetSet, classify_target,
                        system_resolver)


# ------------------------------------------------------------------ helpers
def _auth(load_config):
    cfg = load_config([
        {"domain": "app.example.com", "in_scope": ["app.example.com"],
         "out_of_scope": ["internal.example.com"]},
    ])
    return from_config(cfg)


# ---------------------------------------------------------- target validasiyası
class TestAuthorizeProcessTargets:
    async def test_in_scope_hosts_pass(self, load_config):
        auth = _auth(load_config)
        ctl = EgressController(auth, resolver=lambda h: ["10.0.0.1"])
        tset = await ctl.authorize_process_targets(
            ["app.example.com", "https://app.example.com/x"])
        assert "app.example.com" in tset.hostnames
        assert "https://app.example.com/x" in tset.urls
        assert tset.rejected == []

    async def test_out_of_scope_rejected(self, load_config):
        auth = _auth(load_config)
        ctl = EgressController(auth, resolver=lambda h: ["1.2.3.4"])
        tset = await ctl.authorize_process_targets(
            ["https://evil.test/", "internal.example.com"])
        assert tset.hostnames == []
        assert tset.urls == []
        assert len(tset.rejected) == 2

    async def test_mixed_keeps_only_authorized(self, load_config):
        auth = _auth(load_config)
        ctl = EgressController(auth, resolver=lambda h: ["10.0.0.1"])
        tset = await ctl.authorize_process_targets(
            ["app.example.com", "evil.test", "https://app.example.com/a"])
        assert tset.hostnames == ["app.example.com"]
        assert tset.urls == ["https://app.example.com/a"]

    async def test_empty_and_noise_tokens_skipped(self, load_config):
        auth = _auth(load_config)
        ctl = EgressController(auth, resolver=lambda h: [])
        tset = await ctl.authorize_process_targets(["", "   ", None])
        assert tset.is_empty()
        assert tset.rejected == []

    async def test_audit_records_rejections_and_pins(self, load_config):
        auth = _auth(load_config)
        audit: list = []
        ctl = EgressController(auth, resolver=lambda h: ["10.0.0.1"],
                               audit=audit)
        await ctl.authorize_process_targets(
            ["app.example.com", "evil.test"])
        events = {e["event"] for e in audit}
        assert "egress_rejected" in events
        assert "egress_pinned" in events

    def test_classify(self):
        assert classify_target("https://x.test/a") == ("url", "https://x.test/a")
        assert classify_target("app.example.com:8443/x")[0] == "host"
        assert classify_target("app.example.com") == ("host", "app.example.com")
        assert classify_target("") == ("", "")


# ------------------------------------------------------------- target faylı
class TestTargetFile:
    def test_target_file_only_authorized(self):
        tset = ProcessTargetSet(hostnames=["a.example.com", "b.example.com"])
        path = tset.target_file()
        try:
            with open(path, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        finally:
            os.unlink(path)
        assert lines == ["a.example.com", "b.example.com"]


# --------------------------------------------------------------- DNS pinning
class TestDnsPinning:
    async def test_resolved_store_populated(self, load_config):
        auth = _auth(load_config)
        store: dict = {}
        ctl = EgressController(auth, resolver=lambda h: ["10.0.0.1", "10.0.0.2"],
                               resolved_store=store)
        tset = await ctl.authorize_process_targets(["app.example.com"])
        assert tset.resolved["app.example.com"] == ("10.0.0.1", "10.0.0.2")
        assert tset.ips == ["10.0.0.1", "10.0.0.2"]
        assert "app.example.com" in store

    async def test_ttl_caches_then_reresolves(self, load_config):
        auth = _auth(load_config)
        calls = {"n": 0}
        now = {"t": 1000.0}

        def resolver(host):
            calls["n"] += 1
            return [f"10.0.0.{calls['n']}"]

        ctl = EgressController(auth, resolver=resolver, ttl=10.0,
                               clock=lambda: now["t"])
        r1 = await ctl.authorize_process_targets(["app.example.com"])
        assert r1.resolved["app.example.com"] == ("10.0.0.1",)
        # TTL içində → yenidən həll YOX.
        r2 = await ctl.authorize_process_targets(["app.example.com"])
        assert r2.resolved["app.example.com"] == ("10.0.0.1",)
        assert calls["n"] == 1
        # TTL bitsin → yenidən həll olunmalıdır (re-resolve).
        now["t"] += 11.0
        r3 = await ctl.authorize_process_targets(["app.example.com"])
        assert r3.resolved["app.example.com"] == ("10.0.0.2",)
        assert calls["n"] == 2

    async def test_resolver_error_is_graceful(self, load_config):
        auth = _auth(load_config)

        def boom(host):
            raise OSError("dns down")

        ctl = EgressController(auth, resolver=boom)
        tset = await ctl.authorize_process_targets(["app.example.com"])
        assert tset.resolved["app.example.com"] == ()
        assert tset.hostnames == ["app.example.com"]

    def test_system_resolver_localhost(self):
        assert "127.0.0.1" in system_resolver("127.0.0.1")


# ---------------------------------------------------- proses qrupu öldürülməsi
class TestProcessKill:
    async def test_timeout_kills(self):
        t0 = time.monotonic()
        res = await run_process(
            [sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)
        assert res.timed_out is True
        assert time.monotonic() - t0 < 10

    async def test_cancel_event_kills(self):
        ev = asyncio.Event()
        asyncio.get_running_loop().call_later(0.3, ev.set)
        t0 = time.monotonic()
        res = await run_process(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout=30, cancel_event=ev)
        assert res.ok is False
        assert time.monotonic() - t0 < 10

    async def test_kill_process_group(self):
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-c", "import time; time.sleep(30)",
            start_new_session=True)
        await asyncio.sleep(0.1)
        kill_process_group(proc)
        rc = await asyncio.wait_for(proc.wait(), 5)
        assert rc != 0   # signal ilə öldürülüb

    async def test_group_kill_terminates_children(self, tmp_path):
        """Bütöv proses qrupu — uşaq proses də dayanmalıdır."""
        marker = tmp_path / "child_alive.txt"
        child_code = (
            "import time,pathlib; time.sleep(1.5);"
            f"pathlib.Path({str(marker)!r}).write_text('alive')")
        parent_code = (
            "import subprocess,sys,time\n"
            f"subprocess.Popen([sys.executable,'-c',{child_code!r}])\n"
            "time.sleep(30)\n")
        ev = asyncio.Event()
        asyncio.get_running_loop().call_later(0.4, ev.set)
        res = await run_process([sys.executable, "-c", parent_code],
                                timeout=30, cancel_event=ev)
        assert res.ok is False
        # Uşaq 1.5s sonra marker yazmalı idi; qrup öldüyü üçün yazmamalıdır.
        await asyncio.sleep(2.2)
        assert not marker.exists()


# --------------------------------------------------- API sərhədi (fail-closed)
class TestFailClosed:
    def test_empty_scope_rejected(self, load_config):
        # Boş in_scope → ConfigError (fail-closed).
        with pytest.raises(ConfigError):
            load_config([
                {"domain": "app.example.com", "in_scope": [], "out_of_scope": []},
            ])

    async def test_convenience_function(self, load_config):
        from qbh.egress import authorize_process_targets

        auth = _auth(load_config)
        tset = await authorize_process_targets(
            auth, ["app.example.com"], resolver=lambda h: ["10.0.0.1"])
        assert tset.resolved["app.example.com"] == ("10.0.0.1",)
