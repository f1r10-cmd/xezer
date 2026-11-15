"""Faza 1, §3.4 — Adaptiv planlaşdırma (host-üzrə dinamik concurrency).

Yoxlanılan prinsiplər (şəbəkəsiz, deterministik):

  * 429 → YALNIZ həmin host-un paralellik limiti AZALIR (digər hostlar təsir
    görmür).
  * Sağlam (2xx/3xx) cavablar → limit BƏRPA olunur (tavanla məhdud).
  * `Retry-After` HÖRMƏT olunur: cooldown bitməmiş BƏRPA EDİLMİR; planlaşdırıcı
    heç vaxt gözləmir (gözləmə `HttpPolicy`-dədir) → onu OVERRIDE ETMİR.
  * Guardian cooldown-u REUSE olunur (təkrar saxlanmır).
  * Retry qasırğası YOXDUR: `TaskLedger.max_attempts` tətbiq olunur.
  * Sabit `per_host_limit` davranışı qorunur (geriyə uyğunluq).
"""
from __future__ import annotations

import asyncio

from qbh.scheduler import HostLimit, SchedTask, Scheduler
from qbh.tasks import STATE_FAILED, TaskLedger


async def _noop():
    return None


# --------------------------------------------------------------------------- #
# HostLimit — dinamik limit primitivi
# --------------------------------------------------------------------------- #
class TestHostLimitPrimitive:
    def test_throttle_halves_and_never_below_one(self):
        hl = HostLimit(8)
        assert hl.throttle() == 4
        assert hl.throttle() == 2
        assert hl.throttle() == 1
        assert hl.throttle() == 1          # 1-dən aşağı düşmür

    def test_recover_increments_up_to_ceiling(self):
        hl = HostLimit(3)
        hl.set_limit(1)
        assert hl.recover() == 2
        assert hl.recover() == 3
        assert hl.recover() == 3           # tavanı aşmır

    async def test_acquire_respects_current_limit(self):
        hl = HostLimit(2)
        await hl.acquire()
        await hl.acquire()
        assert hl.active == 2
        # Limit azaldılsa da yeni giriş bloklanır.
        hl.set_limit(1)
        blocked = asyncio.create_task(hl.acquire())
        await asyncio.sleep(0.01)
        assert not blocked.done()          # active(2) >= limit(1) → gözləyir
        await hl.release()
        await asyncio.sleep(0.01)
        assert not blocked.done()          # active(1) >= limit(1) → hələ gözləyir
        await hl.release()
        await asyncio.sleep(0.01)
        assert blocked.done()              # active(0) < limit(1) → keçir
        await blocked


# --------------------------------------------------------------------------- #
# Scheduler.observe — 429 azaldır, sağlam bərpa edir
# --------------------------------------------------------------------------- #
class TestAdaptiveObserve:
    async def test_429_reduces_only_that_host(self):
        s = Scheduler(workers=4, per_host_limit=4)
        async with s:
            await s.submit(SchedTask(identity="a", engine="e", host="h1",
                                     run=_noop))
            await s.submit(SchedTask(identity="b", engine="e", host="h2",
                                     run=_noop))
            await s.drain()
        assert s.host_limit("h1") == 4
        assert s.host_limit("h2") == 4
        s.observe("h1", 429)
        assert s.host_limit("h1") == 2
        assert s.host_limit("h2") == 4     # digər host TƏSİR GÖRMÜR
        assert s.host_throttles == 1

    async def test_healthy_response_recovers(self):
        s = Scheduler(workers=2, per_host_limit=4)
        async with s:
            await s.submit(SchedTask(identity="a", engine="e", host="h",
                                     run=_noop))
            await s.drain()
        s.observe("h", 429)
        s.observe("h", 429)
        assert s.host_limit("h") == 1
        s.observe("h", 200)
        assert s.host_limit("h") == 2
        s.observe("h", 200)
        assert s.host_limit("h") == 3

    async def test_recovery_capped_at_ceiling(self):
        s = Scheduler(workers=2, per_host_limit=2)
        async with s:
            await s.submit(SchedTask(identity="a", engine="e", host="h",
                                     run=_noop))
            await s.drain()
        for _ in range(5):
            s.observe("h", 200)
        assert s.host_limit("h") == 2      # tavanı aşmır

    async def test_429_does_not_overstep_floor(self):
        s = Scheduler(workers=2, per_host_limit=8)
        async with s:
            await s.submit(SchedTask(identity="a", engine="e", host="h",
                                     run=_noop))
            await s.drain()
        for _ in range(10):
            s.observe("h", 429)
        assert s.host_limit("h") == 1

    async def test_observe_unknown_host_is_noop(self):
        s = Scheduler(workers=1, per_host_limit=2)
        # host üçün qapı yaradılmayıbsa → 0 (HTTP trafik YARADILMIR).
        assert s.observe("nope", 429) == 0


# --------------------------------------------------------------------------- #
# Retry-After hörməti (planlaşdırıcı onu OVERRIDE ETMİR)
# --------------------------------------------------------------------------- #
class TestRetryAfterRespected:
    async def test_retry_after_blocks_recovery(self):
        s = Scheduler(workers=2, per_host_limit=4)
        async with s:
            await s.submit(SchedTask(identity="a", engine="e", host="h",
                                     run=_noop))
            await s.drain()
        s.observe("h", 429, retry_after=60)      # uzun cooldown
        assert s.host_limit("h") == 2
        s.observe("h", 200)
        # Cooldown bitməyib → bərpa YOX (hörmət).
        assert s.host_limit("h") == 2
        assert s.host_recoveries == 0

    async def test_observe_never_sleeps(self):
        # Planlaşdırıcı gözləmir — Retry-After yalnız qeyd olunur.
        s = Scheduler(workers=1, per_host_limit=4)
        async with s:
            await s.submit(SchedTask(identity="a", engine="e", host="h",
                                     run=_noop))
            await s.drain()
        started = asyncio.get_running_loop().time()
        s.observe("h", 429, retry_after=3600)
        elapsed = asyncio.get_running_loop().time() - started
        assert elapsed < 0.05              # dərhal qayıtdı


# --------------------------------------------------------------------------- #
# Guardian cooldown REUSE (təkrar saxlanmır)
# --------------------------------------------------------------------------- #
class _FakeGuardian:
    def __init__(self, halted_hosts=()):
        self.halted_hosts = set(halted_hosts)

    def halted(self, host: str) -> bool:
        return host in self.halted_hosts


class TestGuardianReuse:
    async def test_guardian_halt_forces_limit_one(self):
        g = _FakeGuardian({"h"})
        s = Scheduler(workers=2, per_host_limit=8, guardian=g)
        async with s:
            await s.submit(SchedTask(identity="a", engine="e", host="h",
                                     run=_noop))
            await s.drain()
        assert s.host_limit("h") == 1      # Guardian cooldown-u oxunur
        s.observe("h", 200)
        assert s.host_limit("h") == 1      # hələ halted → bərpa yox

    async def test_guardian_not_halted_host_uses_limit(self):
        g = _FakeGuardian()
        s = Scheduler(workers=2, per_host_limit=4, guardian=g)
        async with s:
            await s.submit(SchedTask(identity="a", engine="e", host="h",
                                     run=_noop))
            await s.drain()
        assert s.host_limit("h") == 4

    async def test_without_guardian_uses_limit(self):
        s = Scheduler(workers=1, per_host_limit=3)
        async with s:
            await s.submit(SchedTask(identity="a", engine="e", host="h",
                                     run=_noop))
            await s.drain()
        assert s.host_limit("h") == 3


# --------------------------------------------------------------------------- #
# Retry qasırğası YOX + geriyə uyğunluq
# --------------------------------------------------------------------------- #
class TestNoRetryStormAndBackwardCompat:
    def test_task_ledger_enforces_max_attempts(self):
        led = TaskLedger(max_attempts=3)
        ident = "task-1"
        assert led.consider(ident).create is True
        for _ in range(3):
            led.mark(ident, STATE_FAILED, "xəta")
            assert led.consider(ident).create is True     # bounded retry
        led.mark(ident, STATE_FAILED, "xəta")
        d = led.consider(ident)
        assert d.create is False                          # limit aşıldı
        assert "limit" in d.reason

    async def test_static_per_host_limit_still_respected(self):
        # Geriyə uyğunluq: host limiti DEFAULT olaraq dəyişmir.
        s = Scheduler(workers=10, per_host_limit=2)
        active: dict[str, int] = {}
        peak: dict[str, int] = {}

        async def work(host):
            active[host] = active.get(host, 0) + 1
            peak[host] = max(peak.get(host, 0), active[host])
            await asyncio.sleep(0.02)
            active[host] -= 1

        async with s:
            for i in range(12):
                host = "h1" if i % 2 == 0 else "h2"
                await s.submit(SchedTask(identity=f"t{i}", engine="e",
                                         host=host,
                                         run=lambda h=host: work(h)))
            await s.drain()
        assert peak.get("h1", 0) <= 2
        assert peak.get("h2", 0) <= 2

    async def test_snapshot_includes_adaptive_fields(self):
        s = Scheduler(workers=1, per_host_limit=2)
        async with s:
            await s.submit(SchedTask(identity="a", engine="e", host="h",
                                     run=_noop))
            await s.drain()
        snap = s.snapshot()
        assert "host_limits" in snap
        assert "host_throttles" in snap
        assert "host_recoveries" in snap
        assert snap["host_limits"]["h"] == 2
