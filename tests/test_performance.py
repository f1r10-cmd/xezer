"""Faza 0 + Faza 1 (§9) — performans/izolyasiya testləri.

Yalnız MOCK və LOKAL LOOPBACK istifadə olunur — xarici şəbəkə trafiki YOXDUR.

Əhatə olunan qruplar (§9):
  * **Metrikalar** (Faza 0, §3): bounded reservoir, host/status sayğacları,
    sessiya sayğacları, həssas məlumat YOX, skan-üzrə izolyasiya.
  * **Sessiya həyat dövrü** (§4): bir skan bir sessiya, skanlar arası
    paylaşım YOX, uğur/xəta/ləğv halında bağlanma, bağlı sessiyanın təkrar
    istifadə olunmaması, cookie sızması YOX.
  * **Bağlantı təkrar istifadəsi** (§4): paylaşılan sessiya TCP-ni təkrar
    istifadə edir, ayrı sessiyalar etmir, connector limitləri tətbiq olunur,
    TLS yoxlaması AKTİVDİR, `ImpersonatingTransport` davranışı dəyişməyib.
  * **Concurrency izolyasiyası** (§5): host və qlobal tavanlar, iki hostun
    bir-birindən asılı olmayan tutumu, yavaş hostun qlobal tutumu işğal
    etməməsi, ləğv zamanı icazə sızması YOX, cooldown-un digər hostu
    bloklamaması.
  * **Rate və Guardian** (§6): host RPS tavanı dəyişməz, host-a xas rate
    azalması, Host B uğurunun Host A-nı təmizləməməsi, konkurent blok
    atribusiyası, skan-üzrə intrusiv təhlükəsizlik qapısı.
  * **Məhdud paralellik** (§7) və **mühərrik davranışı** (§9).
"""
from __future__ import annotations

import argparse
import asyncio
import json

import aiohttp
import pytest
import pytest_asyncio
from yarl import URL

from qbh.antiblock.guardian import Guardian
from qbh.antiblock.identity import IdentityManager
from qbh.conductor import Conductor
from qbh.http_policy import BlockEvent, HttpPolicy, TargetBlocked
from qbh.http_session import ScanSession
from qbh.metrics import ScanMetrics
from qbh.parallel import concurrency_limit, run_bounded
from qbh.scope import ScopeError

# --------------------------------------------------------------------- helpers


def _args(**kw) -> argparse.Namespace:
    return argparse.Namespace(
        config="", mode=kw.pop("mode", "full"), aggressiveness=None,
        proxy=kw.pop("proxy", "off"), rate=kw.pop("rate", None),
        severity=kw.pop("severity", "low"),
        auto_install=False, dry_run=False, targets=None,
        active_fuzz=kw.pop("active_fuzz", None),
        race_fixture=None, race_count=10, race_concurrency=4)


@pytest.fixture
def make_conductor(tmp_db, loopback_config):
    """Loopback konfiq üzərində real `Conductor` qurur (şəbəkəsiz)."""
    def _make(cfg=None, **kw) -> Conductor:
        return Conductor(cfg or loopback_config, _args(**kw))
    return _make


# --- fake aiohttp session/response (gerçək loop tələb etmir, mocksuz deyil) ---
class _FakeContent:
    def __init__(self, body: bytes = b""):
        self._body = body

    async def read(self, n: int = -1) -> bytes:
        return self._body


class _FakeResponse:
    def __init__(self, status: int, headers=None, body: bytes = b""):
        self.status = int(status)
        self.headers = dict(headers or {})
        self.content = _FakeContent(body)

    def get_encoding(self) -> str:
        return "utf-8"


class _FakeRequestCM:
    def __init__(self, resp: _FakeResponse, delay: float = 0.0):
        self._resp = resp
        self._delay = delay

    async def __aenter__(self) -> _FakeResponse:
        if self._delay:
            # Real konkurentlik: gözləmə zamanı digər tapşırıqlar irəliləyir.
            await asyncio.sleep(self._delay)
        return self._resp

    async def __aexit__(self, *exc) -> bool:
        return False


class FakeSession:
    """`HttpPolicy._fetch_once`-ın gözlədiyi minimal `session.request`."""

    def __init__(self, status: int = 200, *, statuses=None, delay: float = 0.0):
        self._status = int(status)
        self._statuses = dict(statuses or {})
        self.delay = delay
        self.calls: list[tuple] = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url))
        code = self._statuses.get(url, self._status)
        return _FakeRequestCM(_FakeResponse(code), delay=self.delay)


class _FakeTransportResp:
    def __init__(self, status: int = 200):
        self.status = int(status)
        self.headers = {"Server": "fake-transport"}
        self.text = "ok"
        self.truncated = False


class _FakeTransport:
    """`ImpersonatingTransport` interfeysini təqlid edən hazır transport."""

    available = True

    def __init__(self, status: int = 200):
        self.status = int(status)
        self.calls = 0

    async def request(self, method, url, **kwargs):
        self.calls += 1
        return _FakeTransportResp(self.status)


@pytest_asyncio.fixture
async def reuse_server():
    """TCP bağlantılarını izləyən minimal loopback server."""
    from aiohttp import web

    state: dict = {"transports": set()}

    async def work(request):
        state["transports"].add(request.transport)
        return web.Response(text="ok")

    app = web.Application()
    app.add_routes([web.get("/work", work)])
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    try:
        yield {"base": f"http://127.0.0.1:{port}", "state": state}
    finally:
        await runner.cleanup()


def _two_host_config(load_config):
    return load_config([
        {"domain": "127.0.0.1", "in_scope": ["127.0.0.1"], "out_of_scope": []},
        {"domain": "127.0.0.2", "in_scope": ["127.0.0.2"], "out_of_scope": []},
    ])


# ============================================================== Faza 0 metrikalar


class TestMetrics:
    def test_records_requests_by_host_and_status(self):
        m = ScanMetrics()
        m.record_request("h1", 200, 0.010)
        m.record_request("h1", 404, 0.020)
        m.record_request("h2", 200, 0.030)
        snap = m.snapshot()
        assert snap["requests_total"] == 3
        assert snap["requests_by_host"] == {"h1": 2, "h2": 1}
        assert snap["requests_by_status"] == {"200": 2, "404": 1}
        assert snap["latency"]["count"] == 3
        assert snap["aiohttp_requests"] == 3
        assert snap["transport_requests"] == 0

    def test_counts_timeout_and_connection_errors(self):
        m = ScanMetrics()
        m.record_error("timeout")
        m.record_error("timeout")
        m.record_error("connection")
        snap = m.snapshot()
        assert snap["timeouts"] == 2
        assert snap["connection_errors"] == 1

    def test_latency_sample_is_bounded_and_deterministic(self):
        def build():
            m = ScanMetrics(sample_cap=16, host_cap=2)
            for i in range(500):
                m.record_request("h", 200, i * 0.001)
            return m

        a, b = build(), build()
        # Bounded yaddaş: fərdi ölçmələrin limitsiz siyahısı saxlanılmır.
        assert a.latency.count == 500
        assert len(a.latency.samples) == 16
        # Sabit toxum → eyni yük eyni nəticə (təkrar istehsal oluna bilən).
        assert a.latency.samples == b.latency.samples
        assert a.latency.percentile(50) <= a.latency.percentile(95)

    def test_host_buckets_are_capped(self):
        m = ScanMetrics(host_cap=2)
        for host in ("h1", "h2", "h3", "h4", "h5"):
            m.record_request(host, 200, 0.001)
        keys = set(m.snapshot()["requests_by_host"])
        assert keys == {"h1", "h2", "__other__"}

    def test_snapshot_is_json_serializable_without_urls(self):
        m = ScanMetrics()
        m.record_request("127.0.0.1", 200, 0.01)
        m.record_request("127.0.0.2", 403, 0.02)
        text = json.dumps(m.snapshot())
        # Həssas məlumat / tam URL saxlanılmır-loglanmır.
        assert "http://" not in text
        assert "https://" not in text

    def test_metrics_are_isolated_per_scan(self):
        a, b = ScanMetrics(), ScanMetrics()
        a.record_request("h", 200, 0.01)
        assert a.snapshot()["requests_total"] == 1
        assert b.snapshot()["requests_total"] == 0

    def test_session_counters(self):
        m = ScanMetrics()
        assert m.snapshot()["sessions_created"] == 0
        m.record_session_created()
        m.record_session_closed()
        snap = m.snapshot()
        assert snap["sessions_created"] == 1
        assert snap["sessions_closed"] == 1

    async def test_policy_records_metrics_end_to_end(self, local_server,
                                                    loopback_config):
        m = ScanMetrics()
        policy = HttpPolicy(loopback_config.scope, rate=1000,
                            max_concurrency=5, metrics=m)
        async with aiohttp.ClientSession() as session:
            resp = await policy.get(session, f"{local_server['base']}/")
        assert resp.status == 200
        snap = m.snapshot()
        assert snap["requests_total"] == 1
        assert snap["requests_by_host"]["127.0.0.1"] == 1
        assert snap["requests_by_status"]["200"] == 1
        assert snap["aiohttp_requests"] == 1
        assert snap["transport_requests"] == 0
        assert snap["latency"]["count"] == 1
        assert snap["max_global_concurrency"] >= 1
        assert snap["max_host_concurrency"]["127.0.0.1"] >= 1

    async def test_timeout_recorded_as_timeout_error(self, local_server,
                                                     loopback_config):
        m = ScanMetrics()
        policy = HttpPolicy(loopback_config.scope, rate=1000,
                            total_timeout=0.3, max_retries=0, metrics=m)
        async with aiohttp.ClientSession() as session:
            with pytest.raises(asyncio.TimeoutError):
                await policy.get(session, f"{local_server['base']}/slow")
        snap = m.snapshot()
        assert snap["timeouts"] == 1
        assert snap["connection_errors"] == 0

    async def test_transport_requests_counted_separately(self, loopback_config):
        m = ScanMetrics()
        transport = _FakeTransport(status=200)
        policy = HttpPolicy(loopback_config.scope, rate=1000,
                            transport=transport, metrics=m)
        session = FakeSession(status=200)
        resp = await policy.get(session, "http://127.0.0.1/")
        assert resp.status == 200
        assert transport.calls == 1
        assert session.calls == []          # aiohttp istifadə OLUNMADI
        snap = m.snapshot()
        assert snap["transport_requests"] == 1
        assert snap["aiohttp_requests"] == 0


# ====================================================== §4 sessiya həyat dövrü


class TestSessionLifecycle:
    async def test_context_reuses_a_single_session(self, make_ctx):
        ctx = make_ctx()
        first = ctx.http_session()
        second = ctx.http_session()
        assert first is second
        assert ctx.scan_session.created is True
        await ctx.aclose()

    async def test_independent_scans_do_not_share_sessions(self, make_ctx):
        c1, c2 = make_ctx(), make_ctx()
        s1, s2 = c1.http_session(), c2.http_session()
        assert s1 is not s2
        assert c1.scan_session is not c2.scan_session
        await c1.aclose()
        await c2.aclose()

    async def test_shared_cm_does_not_close_shared_session(self, make_ctx):
        ctx = make_ctx()
        shared = ctx.http_session()
        async with ctx.http_session_cm() as got:
            assert got is shared
        # `async with` çıxışı paylaşılan sessiyanı BAĞLAMAMALIDIR (sahib Context).
        assert shared.closed is False
        await ctx.aclose()
        assert shared.closed is True

    async def test_session_closed_after_normal_completion(self, make_conductor,
                                                         monkeypatch):
        c = make_conductor()
        monkeypatch.setattr(c, "generate_report", lambda: "r")
        holder: dict = {}

        async def body():
            holder["session"] = c.ctx.http_session()

        await c._pipeline("full", body)
        assert holder["session"].closed is True
        assert c.ctx.scan_session.created is False

    async def test_session_closed_after_exception(self, make_conductor,
                                                  monkeypatch):
        c = make_conductor()
        monkeypatch.setattr(c, "generate_report", lambda: "r")
        holder: dict = {}

        async def body():
            holder["session"] = c.ctx.http_session()
            raise RuntimeError("gözlənilməyən çökmə")

        with pytest.raises(RuntimeError):
            await c._pipeline("full", body)
        assert holder["session"].closed is True

    async def test_session_closed_after_cancellation(self, make_conductor,
                                                     monkeypatch):
        c = make_conductor()
        monkeypatch.setattr(c, "generate_report", lambda: "r")
        monkeypatch.setattr(c.authorization, "cancel", lambda: None)
        holder: dict = {}

        async def body():
            holder["session"] = c.ctx.http_session()
            raise asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            await c._pipeline("full", body)
        assert holder["session"].closed is True

    async def test_aclose_is_idempotent(self, make_ctx):
        ctx = make_ctx()
        session = ctx.http_session()
        await ctx.aclose()
        await ctx.aclose()
        assert session.closed is True

    async def test_closed_session_is_not_reused(self, make_ctx):
        ctx = make_ctx()
        first = ctx.http_session()
        await ctx.aclose()
        assert first.closed is True
        assert ctx.scan_session.created is False

    async def test_cookie_state_does_not_leak_between_scans(self, make_ctx):
        c1, c2 = make_ctx(), make_ctx()
        s1, s2 = c1.http_session(), c2.http_session()
        s1.cookie_jar.update_cookies(
            {"sid": "abc"}, response_url=URL("http://scan-a.invalid/"))
        assert [(c.key, c.value) for c in s1.cookie_jar] == [("sid", "abc")]
        assert list(s2.cookie_jar) == []
        await c1.aclose()
        await c2.aclose()


# ====================================================== §4 bağlantı təkrar istifadəsi


class TestConnectionReuse:
    async def test_shared_session_reuses_connections(self, reuse_server,
                                                      loopback_config):
        policy = HttpPolicy(loopback_config.scope, rate=1000, max_concurrency=1)
        scan = ScanSession(total_limit=10, per_host_limit=1)
        try:
            for _ in range(5):
                resp = await policy.get(scan.session,
                                        f"{reuse_server['base']}/work")
                assert resp.status == 200
        finally:
            await scan.aclose()
        # Bir TCP bağlantısı 5 sorğu boyu təkrar istifadə olundu.
        assert len(reuse_server["state"]["transports"]) == 1

    async def test_separate_sessions_do_not_reuse_connections(
            self, reuse_server, loopback_config):
        policy = HttpPolicy(loopback_config.scope, rate=1000, max_concurrency=1)
        for _ in range(4):
            async with aiohttp.ClientSession() as session:
                resp = await policy.get(session, f"{reuse_server['base']}/work")
                assert resp.status == 200
        # Hər sessiya öz hovuzu → ayrı TCP bağlantısı (təkrar istifadə YOX).
        assert len(reuse_server["state"]["transports"]) == 4

    async def test_connector_limits_are_enforced(self):
        scan = ScanSession(total_limit=4, per_host_limit=2)
        try:
            connector = scan.session.connector
            assert connector.limit == 4
            assert connector.limit_per_host == 2
            assert connector._keepalive_timeout == 15.0
        finally:
            await scan.aclose()

    async def test_tls_verification_stays_enabled(self):
        scan = ScanSession(total_limit=3, per_host_limit=1)
        try:
            # `ssl=False` HEÇ VAXT verilmir → aiohttp default-u (doğrulama) aktiv.
            assert scan.session.connector._ssl is True
        finally:
            await scan.aclose()

    async def test_context_session_uses_configured_limits(self, make_ctx):
        ctx = make_ctx()
        try:
            connector = ctx.http_session().connector
            assert connector.limit == int(ctx.cfg.effective_concurrency)
            assert connector.limit_per_host >= 1
        finally:
            await ctx.aclose()

    async def test_transport_branch_behaviour_unchanged(self, loopback_config):
        # `ImpersonatingTransport` hazır olduqda aiohttp YOLU işlədilmir —
        # mövcud davranış qorunur (transport öz hovuzunu saxlayır).
        transport = _FakeTransport(status=204)
        policy = HttpPolicy(loopback_config.scope, rate=1000,
                            transport=transport)
        assert policy._use_transport() is True
        session = FakeSession(status=200)
        resp = await policy.get(session, "http://127.0.0.1/thing")
        assert resp.status == 204
        assert transport.calls == 1
        assert session.calls == []
        assert policy.transport_requests == 1

    def test_transport_unavailable_falls_back_to_aiohttp(self, loopback_config):
        class _Unavailable:
            available = False

        policy = HttpPolicy(loopback_config.scope, rate=1000,
                            transport=_Unavailable())
        assert policy._use_transport() is False


# ====================================================== §5 concurrency izolyasiyası


class TestConcurrencyIsolation:
    async def test_per_host_concurrency_is_enforced(self, local_server,
                                                    loopback_config):
        m = ScanMetrics()
        policy = HttpPolicy(loopback_config.scope, rate=1000,
                            max_concurrency=10, per_host_concurrency=3,
                            metrics=m)
        async with aiohttp.ClientSession() as session:
            await asyncio.gather(*(
                policy.get(session, f"{local_server['base']}/conc")
                for _ in range(8)))
        assert local_server["state"]["max_conc"] <= 3
        snap = m.snapshot()
        assert snap["max_host_concurrency"]["127.0.0.1"] <= 3
        assert snap["max_global_concurrency"] <= 10

    async def test_global_concurrency_is_enforced(self, local_server,
                                                  loopback_config):
        m = ScanMetrics()
        policy = HttpPolicy(loopback_config.scope, rate=1000,
                            max_concurrency=3, per_host_concurrency=10,
                            metrics=m)
        async with aiohttp.ClientSession() as session:
            await asyncio.gather(*(
                policy.get(session, f"{local_server['base']}/conc")
                for _ in range(9)))
        assert local_server["state"]["max_conc"] <= 3
        assert m.snapshot()["max_global_concurrency"] <= 3

    async def test_two_hosts_have_independent_capacity(self, loopback_config):
        policy = HttpPolicy(loopback_config.scope, rate=1000,
                            max_concurrency=4, per_host_concurrency=2)
        active = 0
        per_host = {"a": 0, "b": 0}
        peak = {"a": 0, "b": 0}
        all_four = asyncio.Event()
        release = asyncio.Event()

        async def worker(host):
            nonlocal active
            async with policy._slot(host):
                active += 1
                per_host[host] += 1
                peak[host] = max(peak[host], per_host[host])
                if active == 4:
                    all_four.set()
                await release.wait()
                per_host[host] -= 1
                active -= 1

        tasks = ([asyncio.create_task(worker("a")) for _ in range(2)] +
                 [asyncio.create_task(worker("b")) for _ in range(2)])
        try:
            # Host A 2 slot, Host B 2 slot — EYNİ ANDA → bir-birindən asılı deyil.
            await asyncio.wait_for(all_four.wait(), 2.0)
            assert peak["a"] == 2
            assert peak["b"] == 2
        finally:
            release.set()
            await asyncio.gather(*tasks)

    async def test_slow_host_does_not_consume_other_host_capacity(
            self, loopback_config):
        policy = HttpPolicy(loopback_config.scope, rate=1000,
                            max_concurrency=6, per_host_concurrency=3)
        a_release = asyncio.Event()
        b_done = asyncio.Event()
        b_count = 0

        async def slow_a():
            async with policy._slot("a"):
                await a_release.wait()

        async def fast_b():
            nonlocal b_count
            async with policy._slot("b"):
                b_count += 1
                if b_count >= 3:
                    b_done.set()

        a_tasks = [asyncio.create_task(slow_a()) for _ in range(3)]
        b_tasks: list = []
        try:
            await asyncio.sleep(0.05)          # A-nın slotları tutuldu
            b_tasks = [asyncio.create_task(fast_b()) for _ in range(3)]
            # Yavaş Host A qlobal tutumu işğal etsə də Host B irəliləyir.
            await asyncio.wait_for(b_done.wait(), 2.0)
            assert b_count >= 3
        finally:
            a_release.set()
            await asyncio.gather(*a_tasks, *b_tasks)

    async def test_cancellation_does_not_leak_permits(self, loopback_config):
        policy = HttpPolicy(loopback_config.scope, rate=1000,
                            max_concurrency=2, per_host_concurrency=2)
        entered = 0
        both = asyncio.Event()
        hold = asyncio.Event()

        async def holder(host):
            nonlocal entered
            async with policy._slot(host):
                entered += 1
                if entered == 2:
                    both.set()
                await hold.wait()

        tasks = [asyncio.create_task(holder("h")) for _ in range(2)]
        await asyncio.wait_for(both.wait(), 2.0)
        for task in tasks:
            task.cancel()
        for task in tasks:
            with pytest.raises(asyncio.CancelledError):
                await task
        # Ləğv BÜTÜN slotları azad etməlidir → heç bir icazə sızmır.
        for _ in range(2):
            await asyncio.wait_for(policy._sem.acquire(), 1.0)
        for _ in range(2):
            policy._sem.release()
        for _ in range(2):
            await asyncio.wait_for(policy._host_sem("h").acquire(), 1.0)
        for _ in range(2):
            policy._host_sem("h").release()

    async def test_host_cooldown_does_not_block_unrelated_host(
            self, loopback_config):
        policy = HttpPolicy(loopback_config.scope, rate=1000, cooldown=30.0)
        policy.record("127.0.0.1", 429)
        assert policy.is_halted("127.0.0.1") is True
        with pytest.raises(TargetBlocked):
            await policy.acquire("127.0.0.1")
        # Əlaqəsiz host cooldown-dan TƏSİRLƏNMƏMƏLİDİR.
        await policy.acquire("127.0.0.2")
        assert policy.is_halted("127.0.0.2") is False


# ====================================================== §6 rate və Guardian


class TestRateAndGuardian:
    def test_per_host_rps_ceiling_is_unchanged(self, loopback_config):
        base = 7.5
        policy = HttpPolicy(loopback_config.scope, rate=base)
        assert policy.rate == base
        assert policy.effective_rate("127.0.0.1") == pytest.approx(base)
        policy.set_host_rate_factor("127.0.0.1", 0.25)
        assert policy.effective_rate("127.0.0.1") <= base
        # Faktor tavanı AŞA BİLMƏZ → RPS heç vaxt artmır.
        policy.set_host_rate_factor("127.0.0.1", 5.0)
        assert policy.effective_rate("127.0.0.1") == pytest.approx(base)

    def test_host_rate_reduction_is_host_scoped(self, loopback_config):
        policy = HttpPolicy(loopback_config.scope, rate=10.0)
        policy.set_host_rate_factor("a", 0.5)
        assert policy.effective_rate("a") == pytest.approx(5.0)
        # Host B-nin konfiqurasiya olunmuş rate-i TOXUNULMAZ qalır.
        assert policy.effective_rate("b") == pytest.approx(10.0)
        assert policy.host_rate_factor("b") == 1.0

    def test_host_success_does_not_clear_another_host_block(
            self, loopback_config):
        policy = HttpPolicy(loopback_config.scope, rate=1000, cooldown=30.0)
        guardian = Guardian(IdentityManager("", "lo"), policy)
        policy.record("a.invalid", 403)
        assert policy.is_halted("a.invalid") is True
        event = BlockEvent("a.invalid", 403, "t", "r")
        guardian._note_events([event])
        guardian._note_events([event])          # səviyyə 3 → faktor 0.6
        assert policy.host_rate_factor("a.invalid") == pytest.approx(0.6)
        # Host B-nin uğuru Host A-nın blokunu/rate-ini TƏMİZLƏMƏMƏLİDİR.
        guardian._on_host_success("b.invalid")
        assert policy.is_halted("a.invalid") is True
        assert policy.host_rate_factor("a.invalid") == pytest.approx(0.6)
        assert policy.host_rate_factor("b.invalid") == 1.0

    async def test_block_events_are_per_request(self, load_config):
        cfg = _two_host_config(load_config)
        policy = HttpPolicy(cfg.scope, rate=1000, max_concurrency=4,
                            block_403="escalate_bypass", cooldown=0.0)
        session = FakeSession(status=403, delay=0.005)
        results = await asyncio.gather(
            policy.get(session, "http://127.0.0.1/x"),
            policy.get(session, "http://127.0.0.2/y"),
            return_exceptions=True)
        assert all(isinstance(r, TargetBlocked) for r in results)
        # HƏR sorğu YALNIZ öz hostuna aid blok hadisəsini görür.
        assert [e.host for e in results[0].block_events] == ["127.0.0.1"]
        assert [e.host for e in results[1].block_events] == ["127.0.0.2"]

    async def test_concurrent_block_events_are_attributed_correctly(
            self, load_config):
        cfg = _two_host_config(load_config)
        policy = HttpPolicy(cfg.scope, rate=1000, max_concurrency=8,
                            block_403="escalate_bypass", cooldown=0.0)
        guardian = Guardian(IdentityManager("", "lo"), policy)
        session = FakeSession(status=403, delay=0.005)
        n = 6
        calls = ([guardian.request(session, "GET", "http://127.0.0.1/blocked")
                  for _ in range(n)] +
                 [guardian.request(session, "GET", "http://127.0.0.2/blocked")
                  for _ in range(n)])
        results = await asyncio.gather(*calls, return_exceptions=True)
        assert all(isinstance(r, TargetBlocked) for r in results)
        for i, res in enumerate(results):
            expected = "127.0.0.1" if i < n else "127.0.0.2"
            assert len(res.block_events) == 1
            assert res.block_events[0].host == expected
        # Konkurentlikdə də hər host DƏQİQ öz sayını alır (paylaşılan dilim YOX).
        assert guardian._host_ladder("127.0.0.1").blocks == n
        assert guardian._host_ladder("127.0.0.2").blocks == n
        assert len(policy.block_events) == 2 * n

    def test_scan_wide_intrusive_safety_stays_conservative(
            self, loopback_config):
        policy = HttpPolicy(loopback_config.scope, rate=1000)
        guardian = Guardian(IdentityManager("", "lo"), policy)
        assert guardian.allows_intrusive() is True
        for _ in range(5):
            guardian._note_events([BlockEvent("a.invalid", 403, "t", "r")])
        # Skan-üzrə təhlükəsizlik qapısı: ardıcıl bloklardan sonra intrusiv
        # fazalar TƏXİRƏ SALINIR (host izolyasiyası bunu zəiflətmir).
        assert guardian.ladder.state()["level"] == 5
        assert guardian.allows_intrusive() is False
        # Digər host-un rate-i isə TOXUNULMAZ qalır.
        assert policy.host_rate_factor("b.invalid") == 1.0


# ====================================================== §7 məhdud paralellik


class TestBoundedParallelism:
    async def test_preserves_order_and_results(self):
        async def worker(x):
            await asyncio.sleep(0)
            return x * 2

        out = await run_bounded([1, 2, 3, 4, 5], worker, limit=2)
        assert out == [2, 4, 6, 8, 10]

    async def test_one_failure_does_not_abort_others(self):
        async def worker(x):
            if x == 3:
                raise RuntimeError("boom")
            return x

        out = await run_bounded([1, 2, 3, 4], worker, limit=4)
        assert out[0] == 1 and out[1] == 2 and out[3] == 4
        assert isinstance(out[2], RuntimeError)

    async def test_concurrency_is_bounded(self):
        active = 0
        peak = 0

        async def worker(x):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return x

        out = await run_bounded(range(20), worker, limit=3)
        assert peak <= 3
        assert out == list(range(20))

    async def test_empty_input(self):
        async def worker(x):  # pragma: no cover - çağırılmır
            return x

        assert await run_bounded([], worker, limit=3) == []

    async def test_cancellation_propagates(self):
        async def worker(x):  # pragma: no cover - ləğv edilir
            await asyncio.sleep(5)
            return x

        task = asyncio.create_task(run_bounded(range(4), worker, limit=2))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    def test_concurrency_limit_caps_at_global_ceiling(self):
        class _Cfg:
            effective_concurrency = 6

        assert concurrency_limit(_Cfg(), 100) == 6
        assert concurrency_limit(_Cfg(), 2) == 2
        assert concurrency_limit(_Cfg(), 0) == 1

    def test_concurrency_limit_falls_back_on_bad_config(self):
        class _Bad:
            @property
            def effective_concurrency(self):
                raise ValueError("konfiq yoxdur")

        assert concurrency_limit(_Bad(), 100, default=4) == 4


# ====================================================== §9 mühərrik davranışı


class TestEngineBehaviour:
    async def test_fingerprint_host_failure_does_not_stop_others(
            self, make_ctx, monkeypatch):
        from qbh.engines import fingerprint as fp

        ctx = make_ctx()
        monkeypatch.setattr(fp.db, "alive_hosts", lambda sid: [
            {"subdomain": "good.example", "id": 1, "tech_raw": ""},
            {"subdomain": "bad.example", "id": 2, "tech_raw": ""},
            {"subdomain": "second.example", "id": 3, "tech_raw": ""},
        ])

        async def fake_fingerprint(self, row, res, resolver, session):
            if row["subdomain"] == "bad.example":
                raise RuntimeError("boom")
            return {"host": row["subdomain"], "product": "nginx",
                    "version": "1.0", "confidence": 0.8}

        monkeypatch.setattr(fp.FingerprintEngine, "_fingerprint", fake_fingerprint)
        engine = fp.FingerprintEngine(ctx)
        try:
            result = await engine.run()
        finally:
            await ctx.aclose()
        found = {t["host"] for t in result.data.get("technologies", [])}
        # Bir host-un çökməsi DİGƏR hostların emalını dayandırmır.
        assert found == {"good.example", "second.example"}
        assert any("gözlənilməz xəta" in w for w in result.warnings)

    async def test_scope_rejection_still_works(self, local_server,
                                               loopback_config):
        policy = HttpPolicy(loopback_config.scope, rate=1000)
        async with aiohttp.ClientSession() as session:
            with pytest.raises(ScopeError):
                await policy.get(session, "http://evil.example.com/")

    async def test_guardian_cooldown_still_works(self, local_server,
                                                 loopback_config):
        policy = HttpPolicy(loopback_config.scope, rate=1000,
                            block_429="respect", cooldown=30.0)
        guardian = Guardian(IdentityManager("", "lo"), policy)
        async with aiohttp.ClientSession() as session:
            with pytest.raises(TargetBlocked):
                await guardian.get(session, f"{local_server['base']}/429")
            with pytest.raises(TargetBlocked):
                await guardian.get(session, f"{local_server['base']}/429")
        assert policy.is_halted("127.0.0.1") is True

    async def test_timeout_behaviour_unchanged(self, local_server,
                                               loopback_config):
        policy = HttpPolicy(loopback_config.scope, rate=1000,
                            total_timeout=0.3, max_retries=0)
        async with aiohttp.ClientSession() as session:
            with pytest.raises(asyncio.TimeoutError):
                await policy.get(session, f"{local_server['base']}/slow")
