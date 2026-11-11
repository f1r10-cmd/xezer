"""HTTP Request Policy testləri — rate, cooldown, redirect scope, Retry-After.

Bütün testlər yalnız `127.0.0.1` lokal fixture ilə işləyir.
"""
from __future__ import annotations

import asyncio
import time

import aiohttp
import pytest

from qbh.http_policy import (HttpPolicy, TargetBlocked, parse_retry_after)
from qbh.scope import ScopeEnforcer, ScopeError


def scope(in_scope):
    return ScopeEnforcer.from_entries([
        {"domain": "x", "in_scope": list(in_scope), "out_of_scope": []}])


# ---------------------------------------------------------------- Retry-After
class TestParseRetryAfter:
    def test_numeric(self):
        assert parse_retry_after("5") == 5.0
        assert parse_retry_after(" 12 ") == 12.0
        assert parse_retry_after("0") == 0.0

    def test_none_and_garbage(self):
        assert parse_retry_after(None) == 0.0
        assert parse_retry_after("") == 0.0
        assert parse_retry_after("soon") == 0.0

    def test_http_date_past(self):
        assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0

    def test_http_date_future(self):
        from email.utils import format_datetime
        from datetime import datetime, timedelta, timezone
        future = datetime.now(timezone.utc) + timedelta(seconds=30)
        value = parse_retry_after(format_datetime(future))
        assert 20 <= value <= 35


# ---------------------------------------------------------------- scope
async def test_request_out_of_scope_blocked(local_server):
    policy = HttpPolicy(scope(["example.com"]), rate=1000)
    async with aiohttp.ClientSession() as s:
        with pytest.raises(ScopeError):
            await policy.get(s, f"{local_server['base']}/")


async def test_scope_check_happens_before_any_request(local_server):
    policy = HttpPolicy(scope(["example.com"]), rate=1000)
    async with aiohttp.ClientSession() as s:
        with pytest.raises(ScopeError):
            await policy.get(s, f"{local_server['base']}/count")
    assert local_server["state"]["hits"] == 0  # heç bir sorğu getmədi


# ---------------------------------------------------------------- circuit breaker
async def test_403_triggers_cooldown_not_evasion(local_server):
    policy = HttpPolicy(scope(["127.0.0.1"]), rate=1000, cooldown=30)
    base = local_server["base"]
    async with aiohttp.ClientSession() as s:
        with pytest.raises(TargetBlocked):
            await policy.get(s, f"{base}/403")
    assert policy.is_halted("127.0.0.1")
    assert policy.audit() and policy.audit()[0]["status"] == 403

    # Cooldown aktiv olduğu müddətdə YENİ sorğu göndərilmir
    async with aiohttp.ClientSession() as s:
        with pytest.raises(TargetBlocked):
            await policy.get(s, f"{base}/count")


async def test_429_honours_retry_after(local_server):
    policy = HttpPolicy(scope(["127.0.0.1"]), rate=1000, cooldown=1,
                        max_cooldown=600)
    with pytest.raises(TargetBlocked):
        async with aiohttp.ClientSession() as s:
            await policy.get(s, f"{local_server['base']}/429")
    # Retry-After=2 > cooldown=1 → ən azı 2s gözlənilir
    assert policy.halt_remaining("127.0.0.1") >= 1.5
    assert any("Retry-After" in e["reason"] for e in policy.audit())


def test_record_success_resets_circuit_breaker():
    policy = HttpPolicy(scope(["127.0.0.1"]), rate=1000, cooldown=30)
    policy.record("127.0.0.1", 403)
    assert policy.is_halted("127.0.0.1")
    policy.record("127.0.0.1", 200)
    assert not policy.is_halted("127.0.0.1")


def test_repeated_blocks_grow_cooldown_capped():
    policy = HttpPolicy(scope(["127.0.0.1"]), rate=1000, cooldown=10,
                        max_cooldown=25)
    policy.record("127.0.0.1", 403)          # 10s
    policy.record("127.0.0.1", 403)          # 20s
    policy.record("127.0.0.1", 403)          # 40 -> capped 25s
    assert policy.halt_remaining("127.0.0.1") <= 25.5


# ---------------------------------------------------------------- redirects
async def test_redirect_within_scope_followed(local_server):
    policy = HttpPolicy(scope(["127.0.0.1"]), rate=1000)
    async with aiohttp.ClientSession() as s:
        r = await policy.get(s, f"{local_server['base']}/inside",
                             allow_redirects=True)
    assert r.status == 200
    assert r.url.endswith("/final")


async def test_redirect_escape_blocked(local_server):
    policy = HttpPolicy(scope(["127.0.0.1"]), rate=1000)
    async with aiohttp.ClientSession() as s:
        with pytest.raises(ScopeError):
            await policy.get(s, f"{local_server['base']}/escape",
                             allow_redirects=True)


# ---------------------------------------------------------------- misc
async def test_server_error_returned_not_raised(local_server):
    policy = HttpPolicy(scope(["127.0.0.1"]), rate=1000)
    async with aiohttp.ClientSession() as s:
        r = await policy.get(s, f"{local_server['base']}/500")
    assert r.status == 500


async def test_body_truncation(local_server):
    policy = HttpPolicy(scope(["127.0.0.1"]), rate=1000, max_body=64)
    async with aiohttp.ClientSession() as s:
        r = await policy.get(s, f"{local_server['base']}/big")
    assert r.truncated
    assert len(r.text) <= 64


async def test_rate_limit_delays_requests():
    policy = HttpPolicy(scope(["127.0.0.1"]), rate=2)
    t0 = time.monotonic()
    await policy.acquire("127.0.0.1")
    await policy.acquire("127.0.0.1")
    assert time.monotonic() - t0 >= 0.4


async def test_concurrency_semaphore_bounds_parallel_requests(local_server):
    policy = HttpPolicy(scope(["127.0.0.1"]), rate=1000, max_concurrency=2)
    base = local_server["base"]
    async with aiohttp.ClientSession() as s:
        await asyncio.gather(*[policy.get(s, f"{base}/conc") for _ in range(6)])
    assert local_server["state"]["max_conc"] <= 2


async def test_cancellation_propagates(local_server):
    policy = HttpPolicy(scope(["127.0.0.1"]), rate=1000, total_timeout=30)
    async with aiohttp.ClientSession() as s:
        task = asyncio.create_task(policy.get(s, f"{local_server['base']}/slow"))
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


def test_summary_reports_blocks():
    policy = HttpPolicy(scope(["127.0.0.1"]), rate=5, max_concurrency=3)
    policy.record("127.0.0.1", 403)
    summ = policy.summary()
    assert summ["blocks"] == 1
    assert "127.0.0.1" in summ["blocked_hosts"]
    assert summ["rate"] == 5
