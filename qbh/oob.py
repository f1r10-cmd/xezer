"""Out-of-Band (OOB) təsdiq infrastrukturu (Faza 1.4).

Blind zəifliklər (SSRF, XXE, blind RCE, blind SSTI, blind SQLi) yalnız
xarici geri-zəng (callback) ilə təsdiqlənə bilər. Bu modul sistem üzrə
**YEGANƏ** OOB dinləyicisini idarə edir:

  * `OOBCallbackServer` — aiohttp ilə sadə HTTP geri-zəng dinləyicisi.
    Ona gələn HƏR sorğu correlation token-i ilə qeyd olunur.
  * `OOBManager` — unikal correlation ID-lər qeydiyyatdan keçirir,
    `url_for(token)` qurur, daxil olan callback-ləri toplayır və finding-i
    `candidate → confirmed` çevirmək üçün sübut verir.

Dürüstlük / məhdudiyyət:
  * Xarici hədəfdən geri-zəng yalnız domain İNTERNETDƏN ƏLÇATAN olduqda
    mümkündür. `oob.domain` konfiqurasiya olunmayıbsa OOB HONEST şəkildə
    `disabled` olur və blind təsdiq edən mühərriklər bunu açıq bildirir —
    heç bir "təsdiqləndi" iddiası sübutsuz verilmir.
  * ProjectDiscovery `interactsh-server` xarici backend kimi DƏSTƏKLƏNİR
    (`interactsh` konfiqurasiyası), lakin avtomatik başladılmır; istifadəçi
    onu ayrıca işə salır. Yerli `OOBCallbackServer` "compatible" backend-dir.
"""
from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field

from aiohttp import web

#: Token → callback üçün default gözləmə müddəti (saniyə).
DEFAULT_WAIT = 20.0
DEFAULT_POLL = 1.0


@dataclass
class OOBHit:
    token: str
    remote: str
    method: str
    path: str
    at: float
    detail: str = ""

    def to_evidence(self) -> str:
        return (f"OOB callback alındı: {self.method} {self.path} "
                f"mənbə={self.remote} ({time.strftime('%H:%M:%S', time.gmtime(self.at))})")


def new_token() -> str:
    """Kriptoqrafik təsadüfi correlation token (DNS-uyğun, a-z0-9)."""
    return secrets.token_hex(8)


class OOBCallbackServer:
    """Yerli HTTP geri-zəng dinləyicisi (loopback / konfiqurasiya edilə bilən).

    Hər daxil olan sorğunun hostundan ilk label-ı correlation token kimi
    götürür və `OOBManager`-ə ötürür.
    """

    def __init__(self, manager: "OOBManager", *, host: str = "127.0.0.1",
                 port: int = 0):
        self.manager = manager
        self.host = host
        self.port = port
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self.bound_port: int = 0

    async def start(self) -> int:
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", self._handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self.host, self.port)
        await self._site.start()
        # Faktiki portu götür (port=0 → OS tərəfindən seçilir).
        for sock in getattr(self._site, "_server", None).sockets \
                if getattr(self._site, "_server", None) else []:
            self.bound_port = sock.getsockname()[1]
        if not self.bound_port:
            self.bound_port = self.port
        return self.bound_port

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
            self._site = None

    async def _handle(self, request: web.Request) -> web.Response:
        host = (request.host or "").split(":")[0]
        token = host.split(".")[0] if host else ""
        remote = request.remote or ""
        self.manager.record_hit(token, remote, request.method,
                                request.path, detail=host)
        return web.Response(text="ok")


@dataclass
class OOBManager:
    """Sistem üzrə tək OOB idarəçisi.

    `domain` boşdursa → `enabled=False` (disabled, dürüst şəkildə bildirilir).
    """

    domain: str = ""
    enabled: bool = True
    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    backend: str = "local"            # "local" | "interactsh"
    audit: list = field(default_factory=list)
    _server: OOBCallbackServer | None = None
    _hits: dict[str, list[OOBHit]] = field(default_factory=dict)
    _tokens: set[str] = field(default_factory=set)
    started: bool = False

    @property
    def active(self) -> bool:
        """Blind təsdiq mümkündürmü? (domain + enabled)."""
        return bool(self.enabled and self.domain)

    def register(self) -> str:
        """Yeni unikal correlation token qeydiyyatdan keçirir."""
        token = new_token()
        self._tokens.add(token)
        self._hits.setdefault(token, [])
        self.audit.append({"event": "oob_register", "token": token})
        return token

    def url_for(self, token: str, path: str = "/") -> str:
        """Token üçün xarici geri-zəng URL-i."""
        if not self.domain:
            return ""
        host = f"{token}.{self.domain}"
        return f"http://{host}{path if path.startswith('/') else '/' + path}"

    def record_hit(self, token: str, remote: str = "", method: str = "GET",
                   path: str = "/", detail: str = "") -> OOBHit | None:
        """Callback qeyd edir. Yalnız qeydiyyatdan keçmiş tokenlər qəbul olunur."""
        if not token or token not in self._tokens:
            return None
        hit = OOBHit(token=token, remote=remote, method=method, path=path,
                     at=time.time(), detail=detail)
        self._hits.setdefault(token, []).append(hit)
        self.audit.append({"event": "oob_hit", "token": token,
                           "remote": remote, "path": path})
        return hit

    def hits(self, token: str) -> list[OOBHit]:
        return list(self._hits.get(token, []))

    def confirmed(self, token: str) -> bool:
        return bool(self._hits.get(token))

    def poll(self) -> dict[str, list[OOBHit]]:
        return {t: list(h) for t, h in self._hits.items() if h}

    async def start(self) -> None:
        """Dinləyicini başladır (yalnız `active` olduqda mənalıdır)."""
        if not self.active or self.backend != "local":
            self.started = False
            return
        self._server = OOBCallbackServer(
            self, host=self.listen_host, port=self.listen_port)
        await self._server.start()
        self.started = True
        # Dinləyicinin faktiki portunu domain-ə əlavə etmək lazım deyil;
        # `domain` xarici ünvandır, port yalnız yerli bind üçündür.
        self.audit.append({"event": "oob_start", "host": self.listen_host,
                           "port": self._server.bound_port})

    async def stop(self) -> None:
        if self._server is not None:
            await self._server.stop()
            self._server = None
        self.started = False

    async def wait_for(self, token: str, *, timeout: float = DEFAULT_WAIT,
                       interval: float = DEFAULT_POLL) -> bool:
        """Token üçün callback-i gözləyir (loopback testləri üçün faydalı)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.confirmed(token):
                return True
            await asyncio.sleep(interval)
        return self.confirmed(token)

    def summary(self) -> dict:
        return {
            "enabled": self.enabled,
            "active": self.active,
            "domain": self.domain,
            "backend": self.backend,
            "tokens": len(self._tokens),
            "hits": sum(len(v) for v in self._hits.values()),
        }
