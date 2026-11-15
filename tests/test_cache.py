"""Zəkalı cavab keşi testləri (Faza 1, §3.5).

Yoxlanılan qəti müqavilələr:
  * Keş HIT/MISS — eyni açar üçün cavab təkrar şəbəkəyə getmir.
  * Keş YALNIZ cavab METADATA-sını saxlayır (tam gövdə yox).
  * Etibarsızlıq: fingerprint dəyişikliyi, strategiya versiyası dəyişikliyi,
    auth konteksti dəyişikliyi, TTL bitməsi → keş MISS.
  * **TARİXİ TAPINTILAR VƏ DƏLİLLƏR HEÇ VAXT SİLİNMİR** — `prune()` və
    `invalidate()` yalnız cavab metadata-sına toxunur.
  * `HttpPolicy` keşi OPSİONAL istifadə edir; keş/`cache_meta` verilmədikdə
    davranış ƏVVƏLKİ kimidir (geriyə uyğun).

Bütün şəbəkə testləri yalnız `127.0.0.1` lokal fixture ilə işləyir.
"""
from __future__ import annotations

import aiohttp
import pytest

from qbh.cache import (DEFAULT_BODY_HEAD, STRATEGY_VERSION, CacheManager,
                       cache_key)
from qbh.http_policy import HttpPolicy
from qbh.scope import ScopeEnforcer, ScopeError


def scope_loopback():
    return ScopeEnforcer.from_entries([
        {"domain": "127.0.0.1", "in_scope": ["127.0.0.1"], "out_of_scope": []}])


def fake_clock(start: float = 1000.0):
    """Dəyişdirilə bilən monoton saat — TTL testləri üçün."""
    now = [float(start)]
    return now, (lambda: now[0])


# ------------------------------------------------------------- keş açarı (§3.5)
class TestCacheKey:
    def test_deterministic(self):
        assert cache_key(target="h", endpoint="/a") == cache_key(
            target="h", endpoint="/a")

    def test_target_is_case_insensitive(self):
        assert cache_key(target="H", endpoint="/a") == cache_key(
            target="h", endpoint="/a")

    def test_params_order_independent(self):
        assert cache_key(target="h", endpoint="/a",
                         params={"b": 2, "a": 1}) == cache_key(
            target="h", endpoint="/a", params={"a": 1, "b": 2})

    def test_each_component_changes_key(self):
        base = dict(target="h", endpoint="/a", method="GET", params="",
                    auth_context="", test_strategy="", strategy_version="1",
                    fingerprint_state="")
        ref = cache_key(**base)
        assert cache_key(**{**base, "endpoint": "/b"}) != ref
        assert cache_key(**{**base, "method": "POST"}) != ref
        assert cache_key(**{**base, "params": "id=1"}) != ref
        assert cache_key(**{**base, "auth_context": "admin"}) != ref
        assert cache_key(**{**base, "test_strategy": "s2"}) != ref
        assert cache_key(**{**base, "fingerprint_state": "fp"}) != ref
        assert cache_key(**{**base, "strategy_version": "2"}) != ref


# ------------------------------------------------- trailing/leading lookup/store
class TestLookupStore:
    def test_miss_then_hit(self):
        c = CacheManager()
        assert c.lookup(target="h", endpoint="/a") is None
        c.store(target="h", endpoint="/a", status=200,
                headers={"Content-Type": "text/html"}, body="hello")
        entry = c.lookup(target="h", endpoint="/a")
        assert entry is not None
        assert entry.status == 200
        assert c.stats()["hits"] == 1
        assert c.stats()["misses"] == 1

    def test_only_metadata_and_body_head_stored(self):
        c = CacheManager(body_head=10)
        entry = c.store(target="h", endpoint="/a", status=200,
                        headers={"Content-Type": "text/html"}, body="A" * 5000)
        assert entry.size == 5000                      # tam ölçü
        assert len(entry.body_head) == 10              # YALNIZ ilk N bayt
        assert entry.truncated is True
        assert entry.content_type == "text/html"
        assert DEFAULT_BODY_HEAD >= 10

    def test_store_from_response_object(self):
        from qbh.http_policy import HttpResponse
        c = CacheManager()
        resp = HttpResponse(200, {"Content-Type": "text/plain"}, "body!", "u", 0.1)
        entry = c.store(target="h", endpoint="/a", response=resp)
        assert entry.status == 200
        assert entry.body_head == "body!"
        assert entry.content_type == "text/plain"

    def test_ttl_expiry_miss_and_metadata_removed(self):
        now, clock = fake_clock(0.0)
        c = CacheManager(ttl=5, clock=clock)
        c.store(target="h", endpoint="/a", status=200, headers={}, body="x")
        assert c.lookup(target="h", endpoint="/a") is not None
        now[0] = 10.0                                   # TTL bitdi
        assert c.lookup(target="h", endpoint="/a") is None
        assert c.stats()["entries"] == 0
        assert c.expirations == 1

    def test_explicit_ttl_override(self):
        now, clock = fake_clock(0.0)
        c = CacheManager(ttl=999, clock=clock)
        c.store(target="h", endpoint="/a", status=200, headers={}, body="x", ttl=1)
        now[0] = 2.0
        assert c.lookup(target="h", endpoint="/a") is None


# --------------------------------------------------------------- invalidation
class TestInvalidation:
    def test_fingerprint_change_causes_miss(self):
        c = CacheManager()
        c.store(target="h", endpoint="/a", fingerprint_state="fp1",
                status=200, headers={}, body="x")
        assert c.lookup(target="h", endpoint="/a",
                        fingerprint_state="fp1") is not None
        assert c.lookup(target="h", endpoint="/a",
                        fingerprint_state="fp2") is None

    def test_invalidate_fingerprint_removes_old(self):
        c = CacheManager()
        c.store(target="h", endpoint="/a", fingerprint_state="fp1",
                status=200, headers={}, body="x")
        removed = c.invalidate_fingerprint("h", "fp2")
        assert removed == 1
        assert c.stats()["entries"] == 0

    def test_strategy_version_change_invalidates(self):
        c = CacheManager()
        c.store(target="h", endpoint="/a", status=200, headers={}, body="x")
        assert c.stats()["entries"] == 1
        removed = c.set_strategy_version("2")
        assert removed == 1
        assert c.stats()["entries"] == 0
        assert c.lookup(target="h", endpoint="/a") is None

    def test_auth_context_change_causes_miss(self):
        c = CacheManager()
        c.store(target="h", endpoint="/a", auth_context="anon",
                status=200, headers={}, body="x")
        assert c.lookup(target="h", endpoint="/a",
                        auth_context="anon") is not None
        assert c.lookup(target="h", endpoint="/a",
                        auth_context="admin") is None

    def test_invalidate_auth_removes_matching_only(self):
        c = CacheManager()
        c.store(target="h", endpoint="/a", auth_context="anon",
                status=200, headers={}, body="x")
        c.store(target="h", endpoint="/b", auth_context="admin",
                status=200, headers={}, body="y")
        removed = c.invalidate_auth("anon")
        assert removed == 1
        assert c.stats()["entries"] == 1
        assert c.lookup(target="h", endpoint="/b",
                        auth_context="admin") is not None

    def test_invalidate_by_target_and_endpoint(self):
        c = CacheManager()
        c.store(target="h1", endpoint="/a", status=200, headers={}, body="x")
        c.store(target="h2", endpoint="/a", status=200, headers={}, body="y")
        assert c.invalidate(target="h1") == 1
        assert c.invalidate(endpoint="/a") == 1
        assert c.stats()["entries"] == 0


# ------------------------------------------------- TAPINTILAR HEÇ VAXT SİLİNMİR
class TestFindingsPreserved:
    def test_findings_survive_prune_on_expiry(self):
        now, clock = fake_clock(0.0)
        c = CacheManager(ttl=10, clock=clock)
        c.record_finding({"title": "IDOR", "severity": "high"})
        c.store(target="h", endpoint="/a", status=200, headers={}, body="x")
        now[0] = 100.0                                  # keş müddəti bitdi
        assert c.prune() == 1
        assert c.stats()["entries"] == 0
        assert c.stats()["findings"] == 1               # TAPINTI QALIR
        assert c.findings[0]["title"] == "IDOR"

    def test_findings_survive_invalidate(self):
        c = CacheManager()
        c.record_finding("f1")
        c.store(target="h", endpoint="/a", status=200, headers={}, body="x")
        c.invalidate(endpoint="/a")
        c.invalidate_strategy("999")
        assert c.stats()["entries"] == 0
        assert c.stats()["findings"] == 1

    def test_findings_survive_expiry_lookup(self):
        now, clock = fake_clock(0.0)
        c = CacheManager(ttl=1, clock=clock)
        c.record_finding("evidence-1")
        c.store(target="h", endpoint="/a", status=200, headers={}, body="x")
        now[0] = 5.0
        assert c.lookup(target="h", endpoint="/a") is None   # TTL miss
        assert c.stats()["findings"] == 1


# ------------------------------------------------------------- HttpPolicy (§3.5)
async def test_second_get_served_from_cache(local_server):
    cache = CacheManager()
    policy = HttpPolicy(scope_loopback(), rate=1000, cache=cache)
    meta = {"target": "127.0.0.1", "endpoint": "/count"}
    async with aiohttp.ClientSession() as s:
        first = await policy.get(s, f"{local_server['base']}/count", cache_meta=meta)
        second = await policy.get(s, f"{local_server['base']}/count", cache_meta=meta)
    assert first.text == "1"
    assert second.text == "1"                        # keşdən qaytarıldı
    assert local_server["state"]["hits"] == 1        # ikinci sorğu şəbəkəyə GETMƏDİ
    assert cache.hits == 1


async def test_cache_never_returns_out_of_scope(local_server):
    cache = CacheManager()
    cache.store(target="evil.example.com", endpoint="/", status=200,
                headers={}, body="hacked")
    policy = HttpPolicy(scope_loopback(), rate=1000, cache=cache)
    async with aiohttp.ClientSession() as s:
        with pytest.raises(ScopeError):
            await policy.get(
                s, "http://evil.example.com/",
                cache_meta={"target": "evil.example.com", "endpoint": "/"})
    assert cache.hits == 0                            # scope keşdən ÜSTÜNDÜR


async def test_post_is_not_cached(local_server):
    cache = CacheManager()
    policy = HttpPolicy(scope_loopback(), rate=1000, cache=cache)
    meta = {"target": "127.0.0.1", "endpoint": "/count"}
    async with aiohttp.ClientSession() as s:
        await policy.post(s, f"{local_server['base']}/count", cache_meta=meta)
    assert cache.stores == 0                          # yalnız GET keşlənir


async def test_no_cache_meta_means_previous_behavior(local_server):
    cache = CacheManager()
    policy = HttpPolicy(scope_loopback(), rate=1000, cache=cache)
    async with aiohttp.ClientSession() as s:
        await policy.get(s, f"{local_server['base']}/count")
        await policy.get(s, f"{local_server['base']}/count")
    assert local_server["state"]["hits"] == 2         # keş işə düşmədi
    assert cache.stores == 0


async def test_policy_without_cache_is_backward_compatible(local_server):
    policy = HttpPolicy(scope_loopback(), rate=1000)
    assert policy.cache is None
    async with aiohttp.ClientSession() as s:
        first = await policy.get(s, f"{local_server['base']}/count")
        second = await policy.get(s, f"{local_server['base']}/count")
    assert first.text == "1"
    assert second.text == "2"                         # hər çağırış canlı sorğu
    assert local_server["state"]["hits"] == 2


def test_strategy_version_default_matches_module():
    c = CacheManager()
    assert c.strategy_version == STRATEGY_VERSION == "1"
