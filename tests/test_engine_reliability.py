"""Fingerprint / WAFDetect / Content / API Enum etibarlılıq testləri.

Yoxlanılan prinsiplər (loopback + mock; HEÇ BİR xarici şəbəkə trafiki YOXDUR):
  * Protokol (HTTP/HTTPS) seçimi host başına təhlükəsiz aparılır; yalnız
    HTTP-də xidmət göstərən host da düzgün skan olunur.
  * Əlaqə uğursuzluqları növlərə ayrılır (timeout / refused / DNS / TLS).
  * Bir host-un timeout-u bütün mərhələni DAYANDIRMIR.
  * Guardian cooldown/scope qapıları HEÇ VAXT keçilmir.
  * ffuf timeout/çıxış kodu halında qismən JSON nəticələri oxunur; zədələnmiş
    fayldan tapıntı YARADILMIR; mərhələ `partial` kimi raportlanır.
  * Kiterunner binari-sinin və route fayllarının mövcudluğu AYRI yoxlanılır;
    yalnız GET İCRA səviyyəsində məcbur edilir; OpenAPI fallback həmişə işləyir.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import ssl
import tempfile

import aiohttp
import pytest

from qbh import db
from qbh.adapters.base import ProcResult
from qbh.authorization import from_config
from qbh.config import ConfigError
from qbh.engines.api_enum import (APIEnumEngine, KR_FILES,
                                  collect_route_files)
from qbh.engines.content import ContentEngine
from qbh.engines.fingerprint import FingerprintEngine
from qbh.engines.wafdetect import WafDetectEngine
from qbh.http_policy import HttpResponse
from qbh.results import EngineResult
from qbh.service_url import (KIND_DNS, KIND_OTHER, KIND_REFUSED, KIND_TIMEOUT,
                             KIND_TLS, ServiceEndpoint, ServiceResolver,
                             classify_error)

# ------------------------------------------------------------------ helpers


def _http(url, status=200, headers=None, text=""):
    return HttpResponse(status=status, headers=headers or {}, text=text,
                        url=url, elapsed=0.0)


def _install_get(monkeypatch, guardian, handler):
    """`guardian.get`-i deterministik mock ilə əvəz edir; çağırış URL-lərini qaytarır.

    `handler(url)` ya `HttpResponse`, ya da `BaseException` nüsxəsi qaytarır.
    """
    calls: list[str] = []

    async def _get(session, url, **kwargs):
        calls.append(url)
        result = handler(url)
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr(guardian, "get", _get)
    return calls


def _ctx(make_ctx, *, cfg=None, scan_id=1, forbidden=None):
    ctx = make_ctx(cfg=cfg) if cfg is not None else make_ctx()
    if forbidden is not None:
        ctx.cfg.program_rules.forbidden = set(forbidden)
    ctx.authorization = from_config(ctx.cfg)
    ctx.scan_id = scan_id
    return ctx


def _tech_raw(host: str) -> str | None:
    row = db.get_db().execute(
        "SELECT tech_raw FROM hosts WHERE subdomain=?", (host,)).fetchone()
    return row["tech_raw"] if row else None


def _urls_by_source(source: str) -> int:
    return db.get_db().execute(
        "SELECT COUNT(*) AS n FROM urls WHERE source=?", (source,)
    ).fetchone()["n"]


# ================================================================ resolver


class TestClassifyError:
    def test_timeout(self):
        assert classify_error(asyncio.TimeoutError()) == KIND_TIMEOUT

    def test_refused(self):
        assert classify_error(ConnectionRefusedError()) == KIND_REFUSED

    def test_dns(self):
        assert classify_error(socket.gaierror()) == KIND_DNS

    def test_tls(self):
        assert classify_error(ssl.SSLError("bad handshake")) == KIND_TLS

    def test_other(self):
        assert classify_error(RuntimeError("boom")) == KIND_OTHER


class TestServiceResolver:
    async def test_hint_is_tried_first(self, tmp_db, make_ctx, monkeypatch):
        ctx = _ctx(make_ctx)
        resolver = ServiceResolver(ctx.guardian)
        calls = _install_get(monkeypatch, ctx.guardian,
                             lambda url: _http(url, 200))
        async with aiohttp.ClientSession() as session:
            ep = await resolver.resolve(session, "127.0.0.1", hint="http")
        assert ep.ok is True and ep.scheme == "http"
        assert len(calls) == 1 and calls[0].startswith("http://")

    async def test_successful_endpoint_is_cached(self, tmp_db, make_ctx,
                                                 monkeypatch):
        ctx = _ctx(make_ctx)
        resolver = ServiceResolver(ctx.guardian)
        calls = _install_get(monkeypatch, ctx.guardian,
                             lambda url: _http(url, 200))
        async with aiohttp.ClientSession() as session:
            ep1 = await resolver.resolve(session, "127.0.0.1")
            ep2 = await resolver.resolve(session, "127.0.0.1")
        assert ep1.scheme == ep2.scheme == "https"
        assert len(calls) == 1  # ikinci çağırış keşdən oxunur

    async def test_falls_back_to_second_scheme(self, tmp_db, make_ctx,
                                               monkeypatch):
        ctx = _ctx(make_ctx)
        resolver = ServiceResolver(ctx.guardian)

        def handler(url):
            if url.startswith("https://"):
                return ConnectionRefusedError()
            return _http(url, 200)

        _install_get(monkeypatch, ctx.guardian, handler)
        async with aiohttp.ClientSession() as session:
            ep = await resolver.resolve(session, "127.0.0.1")
        assert ep.ok is True and ep.scheme == "http"

    async def test_out_of_scope_raises_scope_error(self, tmp_db, make_ctx):
        ctx = _ctx(make_ctx)
        resolver = ServiceResolver(ctx.guardian)
        from qbh.scope import ScopeError

        async with aiohttp.ClientSession() as session:
            with pytest.raises(ScopeError):
                await resolver.resolve(session, "evil.example.com")

    async def test_cache_is_isolated_between_resolvers(self, tmp_db, make_ctx,
                                                       monkeypatch):
        """Ayrı resolver nüsxələri keş PAYLAŞMIR → skanlar arası sızma YOXDUR."""
        ctx = _ctx(make_ctx)
        calls = _install_get(monkeypatch, ctx.guardian,
                             lambda url: _http(url, 200))
        r1 = ServiceResolver(ctx.guardian)
        r2 = ServiceResolver(ctx.guardian)
        assert r1._cache is not r2._cache  # ayrı keş obyektləri
        async with aiohttp.ClientSession() as session:
            ep1 = await r1.resolve(session, "127.0.0.1", hint="http")
        assert ep1.scheme == "http"
        # r2-nin keşi BOŞdur → r1-in qərarı sızmır; hint özü zondlanır.
        assert r2.cached("127.0.0.1") is None
        async with aiohttp.ClientSession() as session:
            ep2 = await r2.resolve(session, "127.0.0.1", hint="https")
        assert ep2.scheme == "https"
        assert len(calls) == 2  # hər resolver yalnız öz (maks. 1) zondunu edir


# ============================================================== fingerprint


class TestFingerprintProtocol:
    async def test_http_up_https_down(self, tmp_db, make_ctx, monkeypatch):
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx)

        def handler(url):
            if url.startswith("https://"):
                return ConnectionRefusedError()
            if url.endswith("/wp-login.php"):
                return _http(url, 404)
            return _http(url, 200, headers={"Server": "nginx/1.24.0"},
                         text="hello")

        calls = _install_get(monkeypatch, ctx.guardian, handler)
        res = await FingerprintEngine(ctx).run()
        assert res.ok is True
        assert any(c.startswith("http://") for c in calls)
        assert not any("heç bir protokol" in w for w in res.warnings)
        assert "nginx" in (_tech_raw("127.0.0.1") or "")

    async def test_https_up_http_down(self, tmp_db, make_ctx, monkeypatch):
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx)

        def handler(url):
            if url.startswith("http://"):
                return ConnectionRefusedError()
            if url.endswith("/readme.html"):
                return _http(url, 404)
            return _http(url, 200, text="<html>wp-content</html>")

        calls = _install_get(monkeypatch, ctx.guardian, handler)
        res = await FingerprintEngine(ctx).run()
        assert res.ok is True
        assert all(c.startswith("https://") for c in calls)
        assert "wordpress" in (_tech_raw("127.0.0.1") or "")

    async def test_both_protocols_unavailable(self, tmp_db, make_ctx,
                                              monkeypatch):
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx)
        _install_get(monkeypatch, ctx.guardian,
                     lambda url: ConnectionRefusedError())
        res = await FingerprintEngine(ctx).run()
        assert res.ok is True
        assert any("heç bir protokol əlçatan deyil" in w for w in res.warnings)
        assert any("əlaqə rədd edildi" in w for w in res.warnings)
        assert _tech_raw("127.0.0.1") in (None, "")

    async def test_connection_timeout(self, tmp_db, make_ctx, monkeypatch):
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx)
        _install_get(monkeypatch, ctx.guardian,
                     lambda url: asyncio.TimeoutError())
        res = await FingerprintEngine(ctx).run()
        assert res.ok is True
        assert any("timeout" in w for w in res.warnings)

    async def test_dns_resolution_failure(self, tmp_db, make_ctx, monkeypatch):
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx)
        _install_get(monkeypatch, ctx.guardian, lambda url: socket.gaierror())
        res = await FingerprintEngine(ctx).run()
        assert res.ok is True
        assert any("DNS həll olunmadı" in w for w in res.warnings)

    async def test_guardian_halt_skips_host(self, tmp_db, make_ctx, monkeypatch):
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx)
        ctx.guardian.policy.record("127.0.0.1", 429, {"Retry-After": "30"})
        calls = _install_get(monkeypatch, ctx.guardian,
                             lambda url: _http(url, 200))
        res = await FingerprintEngine(ctx).run()
        assert res.ok is True
        assert any("cooldown" in w for w in res.warnings)
        assert calls == []  # cooldown-dakı host-a HEÇ BİR sorğu getmir

    async def test_out_of_scope_host_rejected(self, tmp_db, make_ctx):
        db.upsert_host("evil.example.com", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx)
        res = await FingerprintEngine(ctx).run()
        assert res.ok is True
        assert any("scope" in w.lower() for w in res.warnings)
        assert _tech_raw("evil.example.com") in (None, "")

    async def test_existing_tech_raw_preserved(self, tmp_db, make_ctx,
                                               monkeypatch):
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200,
                       tech_raw="nginx,php")
        ctx = _ctx(make_ctx)

        def handler(url):
            if "/wp-login.php" in url or "/readme.html" in url:
                return _http(url, 404)
            return _http(url, 200, headers={"Server": "Custom/1.0"}, text="ok")

        _install_get(monkeypatch, ctx.guardian, handler)
        res = await FingerprintEngine(ctx).run()
        assert res.ok is True
        raw = _tech_raw("127.0.0.1") or ""
        assert "nginx" in raw and "php" in raw


# ================================================================ wafdetect


class TestWafDetectReliability:
    async def test_waf_detected_over_http(self, tmp_db, make_ctx, monkeypatch):
        hid = db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        db.insert_url(hid, "http://127.0.0.1/x", "katana", scan_id=1)
        ctx = _ctx(make_ctx)
        calls = _install_get(monkeypatch, ctx.guardian,
                             lambda url: _http(url, 200,
                                               headers={"CF-Ray": "abc-LAX"}))
        res = await WafDetectEngine(ctx).run()
        assert res.data["detected"] == 1
        assert "127.0.0.1" in res.data["hosts"]
        assert calls and all(c.startswith("http://") for c in calls)

    async def test_waf_detected_over_https(self, tmp_db, make_ctx, monkeypatch):
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx)
        calls = _install_get(monkeypatch, ctx.guardian,
                             lambda url: _http(url, 200,
                                               headers={"CF-Ray": "abc-LAX"}))
        res = await WafDetectEngine(ctx).run()
        assert res.data["detected"] == 1
        assert calls and all(c.startswith("https://") for c in calls)

    async def test_one_host_timeout_does_not_stop_others(
            self, tmp_db, make_ctx, monkeypatch, load_config):
        cfg = load_config([{"domain": "127.0.0.1",
                            "in_scope": ["127.0.0.1", "127.0.0.2"],
                            "out_of_scope": []}])
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        db.upsert_host("127.0.0.2", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx, cfg=cfg)

        def handler(url):
            if "127.0.0.1" in url:
                return asyncio.TimeoutError()
            return _http(url, 200, headers={"CF-Ray": "abc-LAX"})

        _install_get(monkeypatch, ctx.guardian, handler)
        res = await WafDetectEngine(ctx).run()
        assert res.data["timed_out"] == 1
        assert res.data["detected"] == 1
        assert "127.0.0.2" in res.data["hosts"]

    async def test_guardian_cooldown_preserved(self, tmp_db, make_ctx,
                                               monkeypatch):
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx)
        ctx.guardian.policy.record("127.0.0.1", 429, {"Retry-After": "30"})
        calls = _install_get(monkeypatch, ctx.guardian,
                             lambda url: _http(url, 200))
        res = await WafDetectEngine(ctx).run()
        assert res.data["skipped"] == 1
        assert any("cooldown" in w for w in res.warnings)
        assert calls == []

    async def test_no_active_probe_without_active_fuzz(
            self, tmp_db, make_ctx, monkeypatch):
        hid = db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        db.insert_url(hid, "http://127.0.0.1/x", "katana", scan_id=1)
        ctx = _ctx(make_ctx, forbidden={"active_fuzz"})
        calls = _install_get(monkeypatch, ctx.guardian,
                             lambda url: _http(url, 200, text="hello"))
        res = await WafDetectEngine(ctx).run()
        assert res.data["active_probe"] is False
        assert not any("?qbh=" in c for c in calls)

    async def test_failed_detection_is_not_reported_as_absent(
            self, tmp_db, make_ctx, monkeypatch):
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx)
        state = {"n": 0}

        def handler(url):
            state["n"] += 1
            if state["n"] == 1:  # resolver-in ilk sorğusu uğurlu
                return _http(url, 200, text="hello")
            return asyncio.TimeoutError()

        _install_get(monkeypatch, ctx.guardian, handler)
        res = await WafDetectEngine(ctx).run()
        assert res.ok is True
        assert res.data["detected"] == 0
        assert any("natamam" in w for w in res.warnings)
        assert not any("WAF yoxdur" in w for w in res.warnings)


# ================================================================== content

_VALID_JSON = json.dumps({"results": [
    {"url": "https://127.0.0.1/admin", "status": 200, "length": 900},
    {"url": "https://127.0.0.1/secret", "status": 200, "length": 700},
]})


def _mk_run(json_text=None, *, rc=0, timed_out=False, missing=False,
            cancel=False):
    async def _run(args, **kwargs):
        if cancel:
            raise asyncio.CancelledError()
        if missing:
            return ProcResult(-1, missing=True)
        if json_text is not None:
            out = args[args.index("-o") + 1]
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(json_text)
        return ProcResult(rc, stdout=b"", stderr=b"", timed_out=timed_out)

    return _run


class TestContentReliability:
    def _prep(self, tmp_path, monkeypatch, runner, *, lines=5):
        wl = tmp_path / "words.txt"
        wl.write_text("\n".join(f"w{i}" for i in range(lines)), encoding="utf-8")
        monkeypatch.setattr("qbh.engines.content.WORDLIST", str(wl))
        monkeypatch.setattr("qbh.engines.content.run_process", runner)

    async def test_normal_json_output(self, tmp_db, make_ctx, monkeypatch,
                                      tmp_path):
        self._prep(tmp_path, monkeypatch, _mk_run(_VALID_JSON))
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        res = await ContentEngine(_ctx(make_ctx)).run()
        assert res.ok is True and res.partial is False
        assert res.urls == 2
        assert res.findings == 2

    async def test_content_type_feeds_urlintel_refinement(self, tmp_db, make_ctx,
                                                          monkeypatch, tmp_path):
        # Faza 2: ffuf-in artıq çəkdiyi cavabın `content-type`-ı URL
        # Intelligence təsnifatını dəqiqləşdirir (əlavə HTTP sorğusu YOX).
        payload = json.dumps({"results": [
            {"url": "https://127.0.0.1/mystery", "status": 200, "length": 900,
             "content-type": "text/html"},
        ]})
        self._prep(tmp_path, monkeypatch, _mk_run(payload))
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx)
        res = await ContentEngine(ctx).run()
        assert res.urls == 1
        intel = ctx._urlintel
        ref = intel.refinements["https://127.0.0.1/mystery"]
        assert ref.applied is True
        assert ref.to_category == "html"
        assert "ffuf" in ref.evidence

    async def test_valid_partial_json_after_timeout(self, tmp_db, make_ctx,
                                                    monkeypatch, tmp_path):
        self._prep(tmp_path, monkeypatch, _mk_run(_VALID_JSON, timed_out=True))
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        res = await ContentEngine(_ctx(make_ctx)).run()
        assert res.partial is True
        assert res.urls == 2
        assert any("timeout" in w for w in res.warnings)

    async def test_corrupt_json_after_timeout(self, tmp_db, make_ctx,
                                              monkeypatch, tmp_path):
        self._prep(tmp_path, monkeypatch, _mk_run("{not json", timed_out=True))
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        res = await ContentEngine(_ctx(make_ctx)).run()
        assert res.partial is True
        assert res.urls == 0 and res.findings == 0
        assert any("JSON" in w for w in res.warnings)
        assert db.get_db().execute(
            "SELECT COUNT(*) AS n FROM findings").fetchone()["n"] == 0

    async def test_valid_json_with_nonzero_returncode(self, tmp_db, make_ctx,
                                                      monkeypatch, tmp_path):
        self._prep(tmp_path, monkeypatch, _mk_run(_VALID_JSON, rc=2))
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        res = await ContentEngine(_ctx(make_ctx)).run()
        assert res.partial is True
        assert res.urls == 2

    async def test_ffuf_missing(self, tmp_db, make_ctx, monkeypatch, tmp_path):
        self._prep(tmp_path, monkeypatch, _mk_run(missing=True))
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        res = await ContentEngine(_ctx(make_ctx)).run()
        assert res.ok is True and res.partial is False
        assert any("ffuf tapılmadı" in w for w in res.warnings)

    async def test_out_of_scope_url_rejected(self, tmp_db, make_ctx,
                                             monkeypatch, tmp_path):
        payload = json.dumps({"results": [
            {"url": "https://evil.example.com/admin", "status": 200,
             "length": 900}]})
        self._prep(tmp_path, monkeypatch, _mk_run(payload))
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        res = await ContentEngine(_ctx(make_ctx)).run()
        assert res.urls == 0
        assert any("scope xaricində" in w for w in res.warnings)

    async def test_max_results_limit(self, tmp_db, make_ctx, monkeypatch,
                                     tmp_path, load_config):
        cfg = load_config([{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
                            "out_of_scope": []}],
                          extra={"content": {"max_results": 1}})
        self._prep(tmp_path, monkeypatch, _mk_run(_VALID_JSON))
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        res = await ContentEngine(_ctx(make_ctx, cfg=cfg)).run()
        assert res.urls == 1

    async def test_max_words_limit(self, tmp_db, make_ctx, monkeypatch,
                                   tmp_path, load_config):
        cfg = load_config([{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
                            "out_of_scope": []}],
                          extra={"content": {"max_words": 2}})
        self._prep(tmp_path, monkeypatch, _mk_run(_VALID_JSON), lines=5)
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        res = await ContentEngine(_ctx(make_ctx, cfg=cfg)).run()
        # Wordlist kəsildi → əhatə tam deyil → mərhələ natamamdır.
        assert res.partial is True
        assert any("2 sətrə məhdudlaşdırıldı" in w for w in res.warnings)

    async def test_max_hosts_limit_marks_partial(self, tmp_db, make_ctx,
                                                 monkeypatch, tmp_path,
                                                 load_config):
        cfg = load_config([{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
                            "out_of_scope": []}],
                          extra={"content": {"max_hosts": 1}})
        self._prep(tmp_path, monkeypatch, _mk_run(_VALID_JSON))
        for host in ("127.0.0.1", "127.0.0.2"):
            db.upsert_host(host, scan_id=1, status_code=200)
        res = await ContentEngine(_ctx(make_ctx, cfg=cfg)).run()
        assert res.partial is True
        assert any("content.max_hosts=1" in w for w in res.warnings)

    async def test_no_partial_when_within_limits(self, tmp_db, make_ctx,
                                                 monkeypatch, tmp_path):
        # Default limitlər daxilində: nə wordlist, nə host kəsilir → partial YOX.
        self._prep(tmp_path, monkeypatch, _mk_run(_VALID_JSON), lines=5)
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        res = await ContentEngine(_ctx(make_ctx)).run()
        assert res.partial is False
        assert not any("məhdudlaşdırıldı" in w for w in res.warnings)

    async def test_temp_files_cleaned_after_cancel(self, tmp_db, make_ctx,
                                                   monkeypatch, tmp_path):
        self._prep(tmp_path, monkeypatch, _mk_run(cancel=True))
        created: list[str] = []
        real_mkstemp = tempfile.mkstemp

        def _mkstemp(*args, **kwargs):
            kwargs.setdefault("dir", str(tmp_path))
            fd, path = real_mkstemp(*args, **kwargs)
            created.append(path)
            return fd, path

        monkeypatch.setattr(tempfile, "mkstemp", _mkstemp)
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        with pytest.raises(asyncio.CancelledError):
            await ContentEngine(_ctx(make_ctx)).run()
        assert created  # ffuf çıxış faylı yaradıldı
        assert not any(os.path.exists(p) for p in created)


# ================================================================ api enum


class TestCollectRouteFiles:
    def test_alternative_directory(self, tmp_path):
        d = tmp_path / "routes"
        d.mkdir()
        (d / "a.kite").write_text("x", encoding="utf-8")
        (d / "b.txt").write_text("x", encoding="utf-8")
        (d / "sub").mkdir()
        (d / "sub" / "c.kite").write_text("x", encoding="utf-8")
        found, checked = collect_route_files([str(d)])
        names = [os.path.basename(p) for p in found]
        assert "a.kite" in names
        assert "b.txt" not in names          # yalnız .kite
        assert "c.kite" not in names         # rekursiv deyil
        assert str(d) in checked

    def test_missing_files_report_checked_locations(self):
        found, checked = collect_route_files(["/no/such/routes"])
        assert found == []
        assert "/no/such/routes" in checked
        assert set(KR_FILES).issubset(set(checked))

    def test_duplicate_paths_are_deduplicated(self, tmp_path):
        f = tmp_path / "r.kite"
        f.write_text("x", encoding="utf-8")
        found, _ = collect_route_files([str(f), str(f), str(tmp_path)])
        assert found == [str(f)]


class TestAPIEnumReliability:
    def _kr_available(self, monkeypatch):
        monkeypatch.setattr(
            shutil, "which",
            lambda name, *a, **k: "/usr/bin/kr" if name == "kr" else None)

    def _kr_missing(self, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda *a, **k: None)

    def _route_dir(self, tmp_path):
        d = tmp_path / "routes"
        d.mkdir()
        (d / "api.kite").write_text("x", encoding="utf-8")
        return d

    def _cfg_with_routes(self, load_config, tmp_path):
        d = self._route_dir(tmp_path)
        cfg = load_config(
            [{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
              "out_of_scope": []}],
            extra={"api_enum": {"route_paths": [str(d)]}})
        return cfg, d

    @staticmethod
    def _probe_only_ok(url):
        """Yalnız resolver zonduna (kök "/") 200, qalan zondlara 404."""
        return _http(url, 200, text="ok") if url.endswith("/") \
            else _http(url, 404)

    async def test_kiterunner_and_routes_available(self, tmp_db, make_ctx,
                                                   monkeypatch, tmp_path,
                                                   load_config):
        cfg, d = self._cfg_with_routes(load_config, tmp_path)
        self._kr_available(monkeypatch)
        seen: list[list] = []

        async def _run(args, **kwargs):
            seen.append(list(args))
            return ProcResult(0,
                              stdout=b"200 GET /api/v1/users\n403 GET /admin\n")

        monkeypatch.setattr("qbh.engines.api_enum.run_process", _run)
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx, cfg=cfg)
        _install_get(monkeypatch, ctx.guardian, self._probe_only_ok)
        res = await APIEnumEngine(ctx).run()
        assert res.ok is True
        assert res.urls == 2 and res.findings == 1
        assert _urls_by_source("kiterunner") == 2
        # GET icra səviyyəsində məcbur edilir (yalnız çıxışı süzməklə DEYİL).
        assert seen and "--force-method" in seen[0] and "GET" in seen[0]
        assert str(d / "api.kite") in seen[0]

    async def test_route_files_missing_reports_checked(self, tmp_db, make_ctx,
                                                       monkeypatch, load_config):
        cfg = load_config(
            [{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
              "out_of_scope": []}],
            extra={"api_enum": {"route_paths": ["/no/such/routes"]}})
        self._kr_available(monkeypatch)
        started: list = []

        async def _run(args, **kwargs):  # route faylı yoxdur → çağırılmamalı
            started.append(args)
            return ProcResult(0)

        monkeypatch.setattr("qbh.engines.api_enum.run_process", _run)
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx, cfg=cfg)
        _install_get(monkeypatch, ctx.guardian, self._probe_only_ok)
        res = await APIEnumEngine(ctx).run()
        assert res.ok is True
        assert started == []
        warned = " ".join(res.warnings)
        assert "route faylı (.kite) tapılmadı" in warned
        assert "/no/such/routes" in warned

    async def test_kr_binary_missing_reported_separately(
            self, tmp_db, make_ctx, monkeypatch, tmp_path, load_config):
        cfg, _ = self._cfg_with_routes(load_config, tmp_path)
        self._kr_missing(monkeypatch)
        started: list = []

        async def _run(args, **kwargs):
            started.append(args)
            return ProcResult(0)

        monkeypatch.setattr("qbh.engines.api_enum.run_process", _run)
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx, cfg=cfg)
        _install_get(monkeypatch, ctx.guardian, self._probe_only_ok)
        res = await APIEnumEngine(ctx).run()
        assert res.ok is True
        assert started == []  # 'kr' yoxdur → Kiterunner icra olunmur
        warned = " ".join(res.warnings)
        assert "kiterunner (kr) tapılmadı" in warned
        # route faylları MÖVCUDDUR → onlar üçün ayrı xəbərdarlıq verilmir.
        assert "route faylı (.kite) tapılmadı" not in warned

    async def test_kiterunner_timeout_keeps_partial(self, tmp_db, make_ctx,
                                                    monkeypatch, tmp_path,
                                                    load_config):
        cfg, _ = self._cfg_with_routes(load_config, tmp_path)
        self._kr_available(monkeypatch)

        async def _run(args, **kwargs):
            return ProcResult(1, stdout=b"200 GET /api/v1/users\n",
                              timed_out=True)

        monkeypatch.setattr("qbh.engines.api_enum.run_process", _run)
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx, cfg=cfg)

        def handler(url):  # fallback da nəticə tapır → fallback uğuru qorunur
            if url.endswith("/openapi.json") or url.endswith("/"):
                return _http(url, 200, text="{}")
            return _http(url, 404)

        _install_get(monkeypatch, ctx.guardian, handler)
        res = await APIEnumEngine(ctx).run()
        # Timeout → mərhələ NATAMAM, lakin uydurma uğursuzluq yoxdur.
        assert res.partial is True and res.ok is True
        assert any("timeout" in w for w in res.warnings)
        # Həm Kiterunner qismən nəticəsi, həm fallback tapıntısı saxlanılır.
        assert _urls_by_source("kiterunner") == 1
        assert _urls_by_source("api-enum") >= 1
        assert res.findings >= 2

    async def test_kr_missing_is_not_partial(self, tmp_db, make_ctx,
                                             monkeypatch, load_config):
        # 'kr' yoxdur → timeout DEYİL → mərhələ partial olmamalıdır.
        cfg = load_config([{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
                            "out_of_scope": []}])
        self._kr_missing(monkeypatch)
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx, cfg=cfg)
        _install_get(monkeypatch, ctx.guardian, self._probe_only_ok)
        res = await APIEnumEngine(ctx).run()
        assert res.partial is False
        assert any("kiterunner (kr) tapılmadı" in w for w in res.warnings)

    async def test_route_files_missing_is_not_partial(self, tmp_db, make_ctx,
                                                      monkeypatch, load_config):
        # Route faylı yoxdur → timeout DEYİL → mərhələ partial olmamalıdır.
        cfg = load_config(
            [{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
              "out_of_scope": []}],
            extra={"api_enum": {"route_paths": ["/no/such/routes"]}})
        self._kr_available(monkeypatch)
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx, cfg=cfg)
        _install_get(monkeypatch, ctx.guardian, self._probe_only_ok)
        res = await APIEnumEngine(ctx).run()
        assert res.partial is False
        assert any("route faylı (.kite) tapılmadı" in w for w in res.warnings)

    async def test_openapi_fallback_works(self, tmp_db, make_ctx,
                                          monkeypatch, load_config):
        cfg = load_config([{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
                            "out_of_scope": []}])
        self._kr_missing(monkeypatch)
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx, cfg=cfg)

        def handler(url):
            if url.endswith("/openapi.json") or url.endswith("/"):
                return _http(url, 200, text="{}")
            return _http(url, 404)

        _install_get(monkeypatch, ctx.guardian, handler)
        res = await APIEnumEngine(ctx).run()
        assert res.ok is True
        assert _urls_by_source("api-enum") >= 1
        assert res.findings >= 1

    async def test_http_only_host_checked(self, tmp_db, make_ctx,
                                          monkeypatch, load_config):
        cfg = load_config([{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
                            "out_of_scope": []}])
        self._kr_missing(monkeypatch)
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx, cfg=cfg)

        def handler(url):
            if url.startswith("https://"):
                return ConnectionRefusedError()
            if url.endswith("/openapi.json") or url.endswith("/"):
                return _http(url, 200, text="{}")
            return _http(url, 404)

        calls = _install_get(monkeypatch, ctx.guardian, handler)
        res = await APIEnumEngine(ctx).run()
        assert res.ok is True
        assert any(c.startswith("http://") for c in calls)
        rows = db.get_db().execute(
            "SELECT url FROM urls WHERE source='api-enum'").fetchall()
        assert rows and all(r["url"].startswith("http://") for r in rows)

    async def test_only_get_results_accepted(self, tmp_db, make_ctx,
                                             monkeypatch, tmp_path, load_config):
        cfg, _ = self._cfg_with_routes(load_config, tmp_path)
        self._kr_available(monkeypatch)

        async def _run(args, **kwargs):
            return ProcResult(0, stdout=(b"200 POST /api/v1/users\n"
                                         b"201 DELETE /api/v2/users\n"
                                         b"200 GET /api/v3/users\n"))

        monkeypatch.setattr("qbh.engines.api_enum.run_process", _run)
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx, cfg=cfg)
        _install_get(monkeypatch, ctx.guardian, self._probe_only_ok)
        await APIEnumEngine(ctx).run()
        assert _urls_by_source("kiterunner") == 1
        row = db.get_db().execute(
            "SELECT url FROM urls WHERE source='kiterunner'").fetchone()
        assert row["url"].endswith("/api/v3/users")

    async def test_duplicate_routes_no_duplicate_records(
            self, tmp_db, make_ctx, monkeypatch, tmp_path, load_config):
        cfg, _ = self._cfg_with_routes(load_config, tmp_path)
        self._kr_available(monkeypatch)

        async def _run(args, **kwargs):
            return ProcResult(0, stdout=b"200 GET /api/v1/users\n"
                                       b"200 GET /api/v1/users\n")

        monkeypatch.setattr("qbh.engines.api_enum.run_process", _run)
        db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx, cfg=cfg)
        _install_get(monkeypatch, ctx.guardian, self._probe_only_ok)
        await APIEnumEngine(ctx).run()
        assert _urls_by_source("kiterunner") == 1

    async def test_out_of_scope_routes_rejected(self, tmp_db, make_ctx):
        hid = db.upsert_host("127.0.0.1", scan_id=1, status_code=200)
        ctx = _ctx(make_ctx)
        eng = APIEnumEngine(ctx)
        res = EngineResult(stage="api_enum")
        ep = ServiceEndpoint(host="evil.example.com", scheme="https", ok=True)
        eng._parse_kr({"id": hid, "subdomain": "127.0.0.1"},
                      "200 GET /admin\n", ep, res)
        assert res.urls == 0
        assert any("scope xaricində" in w for w in res.warnings)
        assert _urls_by_source("kiterunner") == 0


class TestConfigValidation:
    """Yeni konfiq limitləri CİDDİ şəkildə validasiya olunur."""

    def test_content_limits_must_be_positive_int(self, write_config):
        from qbh.config import Config

        with pytest.raises(ConfigError):
            Config.load(write_config(
                [{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
                  "out_of_scope": []}],
                extra={"content": {"max_results": 0}}))

    def test_content_timeout_must_be_number(self, write_config):
        from qbh.config import Config

        with pytest.raises(ConfigError):
            Config.load(write_config(
                [{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
                  "out_of_scope": []}],
                extra={"content": {"timeout_seconds": True}}))

    def test_api_enum_route_paths_must_be_list(self, write_config):
        from qbh.config import Config

        with pytest.raises(ConfigError):
            Config.load(write_config(
                [{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
                  "out_of_scope": []}],
                extra={"api_enum": {"route_paths": "not-a-list"}}))

    def test_defaults_preserve_prior_behavior(self, load_config):
        cfg = load_config([{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
                            "out_of_scope": []}])
        assert cfg.content.timeout_seconds == 600.0
        assert cfg.content.max_words == 20_000
        assert cfg.content.max_hosts == 10
        assert cfg.content.max_results == 30
        assert cfg.api_enum.route_paths == []
