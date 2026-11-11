"""Mərkəzləşdirilmiş HTTP Request Policy.

Bütün modullar HTTP sorğularını BURADAN keçirir. Təmin edir:
  * scope yoxlaması (hər sorğu və hər redirect addımı)
  * host başına rate limit + qlobal concurrency limiti
  * bağlantı və ümumi timeout
  * məhdud eksponensial backoff ilə retry
  * Retry-After hörməti (429)
  * 403/429 → target üçün cooldown + circuit breaker (EVASION YOXDUR)
  * blok hadisələrinin audit qeydi
  * graceful cancellation (CancelledError udulmur)

Bu modul heç vaxt identiklik dəyişmir, MAC/IP/proxy rotasiyası etmir.
"""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import aiohttp

from .scope import ScopeEnforcer, ScopeError, extract_host


class TargetBlocked(RuntimeError):
    """Hədəf blok/cooldown altındadır — sorğu göndərilmir."""


def parse_retry_after(value) -> float:
    """`Retry-After` başlığını saniyəyə çevirir (rəqəm və ya HTTP-date)."""
    if value is None:
        return 0.0
    text = str(value).strip()
    if not text:
        return 0.0
    try:
        return max(0.0, float(text))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return 0.0
    if when is None:
        return 0.0
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


@dataclass
class BlockEvent:
    host: str
    status: int
    at: str
    reason: str


@dataclass
class HttpResponse:
    status: int
    headers: dict
    text: str
    url: str
    elapsed: float
    truncated: bool = False


@dataclass
class _HostState:
    tokens: float = 0.0
    last: float = field(default_factory=time.monotonic)
    blocks: int = 0
    halted_until: float = 0.0


class HttpPolicy:
    DEFAULT_UA = "QBH/2.1 (+authorized-bug-bounty-scanner)"

    def __init__(
        self,
        scope: ScopeEnforcer,
        *,
        rate: float = 5.0,
        max_concurrency: int = 10,
        connect_timeout: float = 10.0,
        total_timeout: float = 30.0,
        max_retries: int = 2,
        backoff_base: float = 0.5,
        max_redirects: int = 5,
        cooldown: float = 60.0,
        max_cooldown: float = 600.0,
        max_body: int = 2_000_000,
    ):
        self.scope = scope
        self.rate = float(rate)
        self.max_concurrency = max_concurrency
        self._sem = asyncio.Semaphore(max_concurrency)
        self.connect_timeout = connect_timeout
        self.total_timeout = total_timeout
        self.max_retries = max(0, int(max_retries))
        self.backoff_base = backoff_base
        self.max_redirects = max_redirects
        self.cooldown = cooldown
        self.max_cooldown = max_cooldown
        self.max_body = max_body
        self._state: dict[str, _HostState] = defaultdict(_HostState)
        self.block_events: list[BlockEvent] = []

    # ---------------- rate limiting + cooldown ----------------
    async def _wait_rate(self, host: str) -> None:
        st = self._state[host]
        while True:
            now = time.monotonic()
            st.tokens = min(self.rate, st.tokens + (now - st.last) * self.rate)
            st.last = now
            if st.tokens >= 1:
                st.tokens -= 1
                return
            await asyncio.sleep(max(0.01, (1 - st.tokens) / self.rate))

    def is_halted(self, host: str) -> bool:
        st = self._state[host]
        if st.halted_until and time.monotonic() < st.halted_until:
            return True
        return False

    def halt_remaining(self, host: str) -> float:
        st = self._state[host]
        return max(0.0, st.halted_until - time.monotonic())

    async def acquire(self, host: str) -> None:
        """Sorğudan əvvəl çağırılır: cooldown + rate limit."""
        if self.is_halted(host):
            raise TargetBlocked(
                f"{host} cooldown altındadır "
                f"({self.halt_remaining(host):.0f}s qalıb) — sorğu göndərilmir")
        await self._wait_rate(host)

    def record(self, host: str, status: int, headers: dict | None = None) -> None:
        """HTTP cavabını qeyd edir. 403/429 → target dayandırılır (evasion YOX).

        429 üçün `Retry-After` başlığı hörmətlə qarşılanır.
        """
        st = self._state[host]
        if status in (403, 429):
            st.blocks += 1
            wait = min(self.cooldown * (2 ** (st.blocks - 1)), self.max_cooldown)
            note = ""
            if status == 429 and headers:
                retry_after = parse_retry_after(
                    headers.get("Retry-After") or headers.get("retry-after"))
                if retry_after > 0:
                    wait = min(max(wait, retry_after), self.max_cooldown)
                    note = f"; Retry-After={retry_after:.0f}s hörmət edildi"
            st.halted_until = time.monotonic() + wait
            reason = ("rate-limit (429) alındı" if status == 429
                      else "qadağa (403) alındı")
            ev = BlockEvent(host, status, datetime.now(timezone.utc).isoformat(),
                            f"{reason}; hədəf {wait:.0f}s dayandırıldı{note}")
            self.block_events.append(ev)
            print(f"   [⛔] {host}: HTTP {status} → {wait:.0f}s cooldown "
                  f"(evasion tətbiq edilmir, skan bu hədəfdə dayandı)")
        elif 200 <= status < 400:
            st.blocks = 0
            st.halted_until = 0.0

    def audit(self) -> list[dict]:
        return [e.__dict__ for e in self.block_events]

    # ---------------- requests ----------------
    async def request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        allow_redirects: bool = False,
        retries: int | None = None,
        **kwargs,
    ) -> HttpResponse:
        try:
            host = extract_host(url)
            host = self.scope.authorize(host)
        except ScopeError as exc:
            raise ScopeError(f"sorğu scope xaricində bloklandı: {url} ({exc})")

        await self.acquire(host)

        max_tries = self.max_retries if retries is None else max(0, int(retries))
        attempt = 0
        current = url
        redirects = 0

        while True:
            try:
                async with self._sem:
                    started = time.monotonic()
                    timeout = aiohttp.ClientTimeout(
                        total=self.total_timeout, connect=self.connect_timeout)
                    async with session.request(
                            method, current, headers=headers, timeout=timeout,
                            allow_redirects=False, **kwargs) as resp:
                        status = resp.status
                        head = dict(resp.headers)
                        text, truncated = await self._read_body(resp)
                        elapsed = time.monotonic() - started
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                attempt += 1
                if attempt > max_tries:
                    raise
                await asyncio.sleep(self.backoff_base * (2 ** (attempt - 1)))
                continue

            # Redirect-ləri ÖZÜMÜZ idarə edirik — scope yoxlaması ilə
            if allow_redirects and status in (301, 302, 303, 307, 308):
                location = head.get("Location")
                if location and redirects < self.max_redirects:
                    redirects += 1
                    current = self.scope.resolve_redirect(current, location)
                    if status == 303:
                        method = "GET"
                    continue

            self.record(host, status, head)
            if self.is_halted(host):
                raise TargetBlocked(f"{host}: HTTP {status} → cooldown aktivdir")
            return HttpResponse(status, head, text, current, elapsed, truncated)

    async def _read_body(self, resp: aiohttp.ClientResponse):
        try:
            raw = await resp.content.read(self.max_body + 1)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return "", False
        truncated = len(raw) > self.max_body
        raw = raw[: self.max_body]
        try:
            encoding = resp.get_encoding()
        except (RuntimeError, LookupError, ValueError):
            # aiohttp 3.14: gövdə `stream.read` ilə oxunduqda `_body` None qalır
            # və fallback encoding hesablanmır → UTF-8 istifadə edilir.
            encoding = "utf-8"
        return raw.decode(encoding, errors="ignore"), truncated

    async def get(self, session, url, **kwargs) -> HttpResponse:
        return await self.request(session, "GET", url, **kwargs)

    async def post(self, session, url, **kwargs) -> HttpResponse:
        return await self.request(session, "POST", url, **kwargs)

    def summary(self) -> dict:
        return {
            "blocks": len(self.block_events),
            "blocked_hosts": sorted({e.host for e in self.block_events}),
            "rate": self.rate,
            "max_concurrency": self.max_concurrency,
        }
