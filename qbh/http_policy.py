"""Mərkəzləşdirilmiş HTTP Request Policy.

Bütün modullar HTTP sorğularını BURADAN keçirir. Təmin edir:
  * scope yoxlaması (hər sorğu və hər redirect addımı) — yeganə toxunulmaz qayda
  * host başına rate limit + qlobal concurrency limiti
  * bağlantı və ümumi timeout
  * məhdud eksponensial backoff ilə retry
  * `Retry-After` hörməti (429)
  * **adaptiv blok strategiyası** (`block_429`/`block_403`):
      - `respect`            → Retry-After/cooldown gözləyir,
      - `backoff`            → eksponensial cooldown,
      - `rotate`             → identikliyi dəyişir və yenidən yoxlayır,
      - `backoff_then_rotate`→ əvvəl gözləyir, sonra identikliyi dəyişir,
      - `escalate_bypass`    → `TargetBlocked(suggest_bypass=True)` qaldırır ki
                              zəncirləmə bypass matrisini işə salsın.
  * identiklik rotasiyası (`identity_provider`) — UA/başlıq/proxy (OPSEC)
  * blok və rotasiya hadisələrinin audit qeydi
  * graceful cancellation (CancelledError udulmur)

Scope qapısı burada heç vaxt keçilə bilməz — yalnız İCAZƏLİ hədəflərə trafik.
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

    def __init__(self, *args, suggest_bypass: bool = False):
        super().__init__(*args)
        self.suggest_bypass = suggest_bypass


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
        max_redirects: int = 20,
        cooldown: float = 60.0,
        max_cooldown: float = 600.0,
        max_body: int = 2_000_000,
        block_429: str = "respect",
        block_403: str = "backoff",
        identity_provider=None,
        max_rotate_attempts: int = 2,
        transport=None,
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
        self.block_429 = block_429
        self.block_403 = block_403
        self.identity_provider = identity_provider
        self.max_rotate_attempts = max(0, int(max_rotate_attempts))
        #: Faza 2.1: TLS/HTTP2 barmaq izi təqlid edən transport (opsional).
        #: `available` False olduqda şəffaf şəkildə aiohttp istifadə olunur.
        self.transport = transport
        self.transport_requests = 0
        self._state: dict[str, _HostState] = defaultdict(_HostState)
        self.block_events: list[BlockEvent] = []
        self.rotation_events: list[dict] = []

    def _block_strategy(self, status: int) -> str:
        if status == 429:
            return self.block_429
        if status == 403:
            return self.block_403
        return "respect"

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
                  f"(strategiya: {self._block_strategy(status)})")
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
        observe_block: bool = True,
        **kwargs,
    ) -> HttpResponse:
        try:
            host = extract_host(url)
            host = self.scope.authorize(host)
        except ScopeError as exc:
            raise ScopeError(
                f"sorğu scope xaricində bloklandı: {url} ({exc})") from exc

        await self.acquire(host)

        max_tries = self.max_retries if retries is None else max(0, int(retries))
        attempt = 0
        rotate_attempts = 0
        current = url
        redirects = 0

        while True:
            attempt_headers = headers
            call_kwargs = dict(kwargs)
            if self.identity_provider is not None:
                if attempt_headers is None:
                    attempt_headers = self.identity_provider.headers_for(host)
                if "proxy" not in call_kwargs:
                    px = self.identity_provider.proxy_for(host)
                    if px:
                        call_kwargs["proxy"] = px
            try:
                status, head, text, truncated, elapsed = await self._fetch_once(
                    session, method, current, attempt_headers, call_kwargs)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                attempt += 1
                if attempt > max_tries:
                    raise
                await asyncio.sleep(self.backoff_base * (2 ** (attempt - 1)))
                continue

            # Redirect-ləri ÖZÜMÜZ idarə edirik — hər addım scope yoxlanılır
            if allow_redirects and status in (301, 302, 303, 307, 308):
                location = head.get("Location")
                if location and redirects < self.max_redirects:
                    redirects += 1
                    current = self.scope.resolve_redirect(current, location)
                    if status == 303:
                        method = "GET"
                    continue

            # ---- blok (403/429) → adaptiv strategiya ----
            # `observe_block=False` (məs. bypass probe): xam status qaytarılır və
            # host cooldown-a salınmır → eyni yol üzrə bypass matrisi sınana bilər.
            if status in (403, 429) and observe_block:
                strategy = self._block_strategy(status)
                if strategy in ("rotate", "backoff_then_rotate", "escalate_bypass"):
                    if strategy == "backoff_then_rotate":
                        ra = parse_retry_after(
                            head.get("Retry-After") or head.get("retry-after")
                        ) if status == 429 else 0.0
                        await asyncio.sleep(min(max(ra, self.backoff_base), 5.0))
                    if (rotate_attempts < self.max_rotate_attempts
                            and self.identity_provider is not None):
                        if self.identity_provider.rotate(
                                host, reason=f"HTTP {status} ({strategy})"):
                            rotate_attempts += 1
                            self.rotation_events.append(
                                {"host": host, "status": status,
                                 "strategy": strategy})
                            print(f"   [↻] {host}: HTTP {status} → identiklik "
                                  f"dəyişdirildi ({strategy}), təkrar yoxlanılır")
                            await self.acquire(host)
                            continue
                    # rotasiya mümkün olmadı → cooldown + (lazımdırsa) bypass işarəsi
                    self.record(host, status, head)
                    raise TargetBlocked(
                        f"{host}: HTTP {status} → "
                        + ("bypass matrisi tələb olunur" if strategy == "escalate_bypass"
                           else "cooldown aktivdir"),
                        suggest_bypass=(strategy == "escalate_bypass"))
                # respect / backoff → klassik cooldown
                self.record(host, status, head)
                if self.is_halted(host):
                    raise TargetBlocked(f"{host}: HTTP {status} → cooldown aktivdir")

            if observe_block or status not in (403, 429):
                self.record(host, status, head)
            return HttpResponse(status, head, text, current, elapsed, truncated)

    def _use_transport(self) -> bool:
        """Təqlid edən transport hazırdırmı? (yoxsa aiohttp-a düşülür)."""
        t = self.transport
        return t is not None and bool(getattr(t, "available", False))

    async def _fetch_once(self, session, method: str, url: str, headers,
                          call_kwargs) -> tuple:
        """Bir HTTP cəhdi — transport varsa onunla, yoxsa aiohttp ilə.

        Faza 2.1: hədəfə gedən BÜTÜN native HTTP trafiki (mümkün olduqda)
        təqlid edən TLS/HTTP2 transportundan keçir; əks halda şəffaf şəkildə
        aiohttp istifadə olunur (heç bir səssiz davranış dəyişikliyi yoxdur).
        """
        async with self._sem:
            started = time.monotonic()
            if self._use_transport():
                tr = await self.transport.request(
                    method, url, headers=headers, allow_redirects=False,
                    proxy=call_kwargs.get("proxy"),
                    timeout=self.total_timeout)
                self.transport_requests += 1
                return (tr.status, dict(tr.headers), tr.text, tr.truncated,
                        time.monotonic() - started)
            timeout = aiohttp.ClientTimeout(
                total=self.total_timeout, connect=self.connect_timeout)
            async with session.request(
                    method, url, headers=headers, timeout=timeout,
                    allow_redirects=False, **call_kwargs) as resp:
                status = resp.status
                head = dict(resp.headers)
                text, truncated = await self._read_body(resp)
                return (status, head, text, truncated,
                        time.monotonic() - started)

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
            "rotations": len(self.rotation_events),
            "block_429": self.block_429,
            "block_403": self.block_403,
            "impersonated_requests": self.transport_requests,
        }
