"""Faza 4 — Deterministik xəta inyeksiyası (fault injection) testləri.

Məqsəd: real runtime uğursuzluq yollarını TƏKRARLANA BİLƏN şəkildə sınamaq və
HƏM gözlənilən xəta vəziyyətini, HƏM də resurs təmizlənməsini yoxlamaq.

Prinsiplər:
  * HEÇ BİR xarici hədəf istifadə olunmur — yalnız `127.0.0.1` loopback
    serverləri, mock-lar və müvəqqəti fayllar.
  * Hər test DETERMİNİSTİKDİR (sabit loopback, mock, `sys.executable`).
  * `asyncio.CancelledError` udulmur; qalıq "pending" tapşırıq YOXDUR.

Əhatə olunan 15 ssenari:
  1  Şəbəkə timeout              9  Disk/yazma uğursuzluğu
  2  Bağlantı kəsilməsi (reset) 10  Tapşırıq ləğvi (cancellation)
  3  HTTP 500                   11  Konkurent exception-lar
  4  Etibarsız JSON             12  Sessiya bağlanması
  5  Boş cavablar               13  Semafor sızması
  6  Alt-proses sıfırdan fərqli çıxış kodu
  7  Alt-proses timeout         14  Zədəli konfiqurasiya
  8  Baza kilidli               15  Çatışmayan xarici alətlər
"""
from __future__ import annotations

import asyncio
import sqlite3
import sys

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web

from qbh.adapters.base import ProcResult, limited_wordlist, run_process
from qbh.config import Config, ConfigError
from qbh.engines import cve_intel, library_cve
from qbh.http_policy import HttpPolicy
from qbh.http_session import ScanSession, _SharedSessionCM
from qbh.parallel import run_bounded


# =============================================================== köməkçilər
def _policy(cfg, **kw) -> HttpPolicy:
    """Sürətli, deterministik `HttpPolicy` (backoff yox, rate yüksək)."""
    return HttpPolicy(
        cfg.scope,
        rate=kw.pop("rate", 1000.0),
        max_concurrency=kw.pop("max_concurrency", 4),
        connect_timeout=kw.pop("connect_timeout", 2.0),
        total_timeout=kw.pop("total_timeout", 5.0),
        max_retries=kw.pop("max_retries", 0),
        backoff_base=kw.pop("backoff_base", 0.0),
        **kw,
    )


@pytest_asyncio.fixture
async def fault_server():
    """Loopback HTTP server — deterministik xəta cavabları verir."""
    async def ok(request):
        return web.Response(text="ok")

    async def empty(request):
        return web.Response(text="")

    async def slow(request):
        await asyncio.sleep(5)
        return web.Response(text="late")

    async def err500(request):
        return web.Response(status=500, text="boom")

    async def badjson(request):
        return web.Response(text="{not valid json",
                            content_type="application/json")

    app = web.Application()
    app.router.add_route("GET", "/ok", ok)
    app.router.add_route("*", "/empty", empty)
    app.router.add_route("GET", "/slow", slow)
    app.router.add_route("GET", "/500", err500)
    app.router.add_route("GET", "/badjson", badjson)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    try:
        yield {"base": f"http://127.0.0.1:{port}"}
    finally:
        await runner.cleanup()


@pytest_asyncio.fixture
async def reset_server():
    """Qəbul edib DƏRHAL bağlanan xam TCP server → bağlantı kəsilməsi."""
    async def handle(reader, writer):
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # pragma: no cover - təmizləmə ən yaxşı səy
            pass

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.close()
        await server.wait_closed()


# ==================================================== 1. Şəbəkə timeout
class TestNetworkTimeout:
    async def test_timeout_is_raised_and_slot_released(
            self, loopback_config, fault_server):
        policy = _policy(loopback_config, total_timeout=0.4, max_concurrency=1)
        async with aiohttp.ClientSession() as session:
            with pytest.raises(asyncio.TimeoutError):
                await policy.request(session, "GET",
                                     f"{fault_server['base']}/slow")
        # Timeout-dan sonra semafor TAM azaddır (sızma yoxdur).
        assert policy._sem._value == 1
        assert policy._host_sem("127.0.0.1")._value == 1


# =============================================== 2. Bağlantı kəsilməsi
class TestConnectionReset:
    async def test_connection_reset_propagates(self, loopback_config,
                                               reset_server):
        policy = _policy(loopback_config, max_retries=0)
        async with aiohttp.ClientSession() as session:
            with pytest.raises((aiohttp.ClientError, OSError)):
                await policy.request(session, "GET", reset_server)
        assert policy._sem._value == policy.max_concurrency


# ============================================================ 3. HTTP 500
class TestHttp500:
    async def test_500_returned_not_raised_and_not_blocked(
            self, loopback_config, fault_server):
        policy = _policy(loopback_config)
        async with aiohttp.ClientSession() as session:
            r = await policy.request(session, "GET",
                                     f"{fault_server['base']}/500")
        assert r.status == 500
        # 500 blok siqnalı DEYİL → cooldown yoxdur, blok hadisəsi yoxdur.
        assert policy.block_events == []
        assert policy.is_halted("127.0.0.1") is False


# ======================================================== 4. Etibarsız JSON
class TestInvalidJson:
    async def test_invalid_json_returns_none(self, fault_server):
        async with aiohttp.ClientSession() as session:
            data = await cve_intel._get_json(
                session, f"{fault_server['base']}/badjson")
        assert data is None  # uydurma/qismən struktur YOXDUR

    async def test_osv_invalid_json_returns_empty_list(
            self, fault_server, monkeypatch):
        monkeypatch.setattr(
            library_cve, "OSV_URL", f"{fault_server['base']}/badjson")
        async with aiohttp.ClientSession() as session:
            out = await library_cve.osv_npm(session, "jquery", "1.2.3")
        assert out == []


# ========================================================= 5. Boş cavablar
class TestEmptyResponses:
    async def test_empty_body_yields_none(self, fault_server):
        async with aiohttp.ClientSession() as session:
            data = await cve_intel._get_json(
                session, f"{fault_server['base']}/empty")
        assert data is None

    async def test_osv_empty_body_yields_empty_list(self, fault_server,
                                                    monkeypatch):
        monkeypatch.setattr(
            library_cve, "OSV_URL", f"{fault_server['base']}/empty")
        async with aiohttp.ClientSession() as session:
            out = await library_cve.osv_npm(session, "jquery", "1.2.3")
        assert out == []


# ============================== 6. Alt-proses sıfırdan fərqli çıxış kodu
class TestSubprocessNonzeroExit:
    async def test_nonzero_returncode_is_reported(self):
        res = await run_process(
            [sys.executable, "-c", "import sys; sys.exit(3)"], timeout=15)
        assert res.returncode == 3
        assert res.ok is False
        assert res.missing is False and res.timed_out is False
        assert isinstance(res, ProcResult)


# ============================================== 7. Alt-proses timeout
class TestSubprocessTimeout:
    async def test_timeout_is_marked_and_partial_preserved(self):
        res = await run_process(
            [sys.executable, "-c",
             "import sys,time; print('partial', flush=True); time.sleep(30)"],
            timeout=0.5)
        assert res.timed_out is True
        assert res.returncode == -1
        assert res.ok is False
        # Öldürülməzdən ƏVVƏL çap olunan qismən çıxış İTİRİLMİR.
        assert b"partial" in res.stdout

    async def test_cancel_event_kills_and_leaves_no_pending_tasks(self):
        before = set(asyncio.all_tasks())
        ev = asyncio.Event()
        task = asyncio.create_task(run_process(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cancel_event=ev, timeout=60))
        await asyncio.sleep(0.4)
        ev.set()
        res = await task
        assert res.ok is False  # öldürüldü (timeout DEYİL, cancel_event)
        assert res.timed_out is False
        await asyncio.sleep(0)  # loop-un oturmasına imkan ver
        me = asyncio.current_task()
        leftover = [t for t in asyncio.all_tasks() - before
                    if t is not me and not t.done()]
        assert leftover == []  # "Task was destroyed but it is pending" YOXDUR


# ======================================================== 8. Baza kilidli
class TestDatabaseLocked:
    def test_locked_write_surfaces_error_and_recovers(self, tmp_db,
                                                      monkeypatch):
        path = tmp_db.DB_PATH
        blocker = sqlite3.connect(path, timeout=0.0, isolation_level=None)
        blocker.execute("BEGIN IMMEDIATE")  # yazma kilidi tutulur
        short = sqlite3.connect(path, timeout=0.2)
        short.row_factory = sqlite3.Row
        try:
            with monkeypatch.context() as m:
                m.setattr(tmp_db, "get_db", lambda: short)
                with pytest.raises(sqlite3.OperationalError):
                    tmp_db.start_scan("prog", "full")
        finally:
            blocker.rollback()
            blocker.close()
            short.close()
        # Kilid buraxıldıqdan sonra baza yenidən istifadə oluna bilər
        # (uğursuz tranzaksiya daimi kilid buraxmır).
        sid = tmp_db.start_scan("prog", "full")
        assert sid >= 1


# ============================================== 9. Disk/yazma uğursuzluğu
class TestDiskWriteFailure:
    def test_wordlist_write_failure_cleans_temp_file(self, tmp_path,
                                                     monkeypatch):
        src = tmp_path / "words.txt"
        src.write_text("\n".join(f"w{i}" for i in range(50)), encoding="utf-8")

        created: list[str] = []
        real_mkstemp = __import__("tempfile").mkstemp

        def _mkstemp(*a, **kw):
            kw.setdefault("dir", str(tmp_path))
            fd, p = real_mkstemp(*a, **kw)
            created.append(p)
            return fd, p

        import tempfile as _tf
        monkeypatch.setattr(_tf, "mkstemp", _mkstemp)

        def _boom(*a, **kw):
            raise OSError("disk full")

        monkeypatch.setattr("qbh.adapters.base.os.fdopen", _boom)

        with pytest.raises(OSError):
            limited_wordlist(str(src), cap=5)

        # Müvəqqəti fayl yerində QALMAMALIDIR (çağıran onu hələ almamışdı).
        assert created  # mkstemp çağırıldı
        assert not any(__import__("os").path.exists(p) for p in created)


# =================================================== 10. Tapşırıq ləğvi
class TestTaskCancellation:
    async def test_run_bounded_cancel_propagates_and_awaits_workers(self):
        started = asyncio.Event()
        count = {"n": 0}

        async def worker(i):
            count["n"] += 1
            if count["n"] >= 3:
                started.set()
            await asyncio.sleep(30)
            return i

        task = asyncio.create_task(run_bounded(range(9), worker, limit=3))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        # Ləğv udulmayıb VƏ işçilər tam bitib → qalıq pending task yoxdur.
        me = asyncio.current_task()
        pending = [t for t in asyncio.all_tasks()
                   if t is not me and not t.done()]
        assert pending == []


# ============================================== 11. Konkurent exception-lar
class TestConcurrentExceptions:
    async def test_one_worker_exception_does_not_stop_others(self):
        async def worker(i):
            if i == 2:
                raise ValueError("boom")
            return i * 2

        out = await run_bounded(range(5), worker, limit=3)
        assert isinstance(out[2], ValueError)
        assert [out[0], out[1], out[3], out[4]] == [0, 2, 6, 8]

    async def test_cancelled_error_is_not_swallowed(self):
        async def worker(i):
            if i == 1:
                raise asyncio.CancelledError()
            return i

        with pytest.raises(asyncio.CancelledError):
            await run_bounded(range(4), worker, limit=2)


# ==================================================== 12. Sessiya bağlanması
class TestSessionClosure:
    async def test_aclose_is_idempotent_and_only_closes_owned(self):
        ss = ScanSession()
        _ = ss.session  # lazy yaranır
        assert ss.created is True
        await ss.aclose()
        assert ss.created is False
        await ss.aclose()  # ikinci çağırış TƏHLÜKƏSİZDİR
        assert ss.created is False

    async def test_injected_session_is_not_closed(self):
        class _Fake:
            def __init__(self):
                self.closed = False

            async def close(self):
                self.closed = True

        ss = ScanSession()
        fake = _Fake()
        ss.inject(fake)
        await ss.aclose()
        assert fake.closed is False  # sahib olmadığı üçün bağlanmır

    async def test_shared_cm_does_not_close_shared_session(self):
        ss = ScanSession()
        session = ss.session
        async with _SharedSessionCM(session) as got:
            assert got is session
        assert ss.created is True  # paylaşılan sessiya açıq qalır
        await ss.aclose()


# ====================================================== 13. Semafor sızması
class TestSemaphoreLeak:
    async def test_slots_released_after_success_and_after_error(
            self, loopback_config, fault_server, reset_server):
        policy = _policy(loopback_config, max_concurrency=1, max_retries=0,
                         total_timeout=0.5)
        async with aiohttp.ClientSession() as session:
            r = await policy.request(session, "GET",
                                     f"{fault_server['base']}/ok")
            assert r.status == 200
            assert policy._sem._value == 1
            with pytest.raises((aiohttp.ClientError, OSError,
                                asyncio.TimeoutError)):
                await policy.request(session, "GET", reset_server)
            # Xəta yolunda da hər iki semafor azaddır.
            assert policy._sem._value == 1
            assert policy._host_sem("127.0.0.1")._value == 1


# ================================================ 14. Zədəli konfiqurasiya
class TestMalformedConfiguration:
    def test_non_numeric_limit_rejected(self, write_config):
        with pytest.raises(ConfigError):
            Config.load(write_config(
                [{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
                  "out_of_scope": []}],
                limits={"requests_per_second": "fast"}))

    def test_below_minimum_limit_rejected(self, write_config):
        with pytest.raises(ConfigError):
            Config.load(write_config(
                [{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
                  "out_of_scope": []}],
                limits={"max_concurrency": 0}))

    def test_empty_scope_rejected(self, write_config):
        with pytest.raises(ConfigError):
            Config.load(write_config([]))

    def test_types_not_accepted_as_numbers(self, write_config):
        with pytest.raises(ConfigError):
            Config.load(write_config(
                [{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
                  "out_of_scope": []}],
                limits={"cooldown": True}))


# ============================================== 15. Çatışmayan xarici alət
class TestMissingExternalTools:
    async def test_missing_binary_reported_as_missing(self):
        res = await run_process(["_qbh_no_such_tool_xyz123_"], timeout=10)
        assert res.missing is True
        assert res.ok is False
        assert res.returncode == -1
