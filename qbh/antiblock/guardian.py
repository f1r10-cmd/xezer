"""Guardian — blok/cooldown nəzarətçisi və audit qeydiyyatçısı.

ARTIQ EVASION YOXDUR: MAC/IP/UA rotasiyası, credit sistemi və
"blokdan sonra davam et" davranışı tamamilə silinmişdir.

Guardian indi yalnız:
  * scope yoxlamalı HTTP policy-ni təqdim edir,
  * hər sorğuya sabit identiklik başlıqlarını (UA) və sabit proxy-ni qoşur,
  * 403/429 aldıqda hədəfi cooldown/circuit-breaker altına salır,
  * blok hadisələrini audit üçün qeyd edir.
"""
from __future__ import annotations

from ..http_policy import HttpPolicy, HttpResponse, TargetBlocked
from ..scope import extract_host
from .identity import IdentityManager


class Guardian:
    def __init__(self, identity_mgr: IdentityManager, policy: HttpPolicy):
        self.ids = identity_mgr
        self.policy = policy

    # ---- HTTP policy ilə eyni interfeys ----
    async def acquire(self, host: str) -> None:
        """Sorğudan əvvəl: cooldown + rate limit. Blokdadırsa TargetBlocked."""
        await self.policy.acquire(host)

    def identity(self, host: str):
        return self.ids.identity_for(host)

    def observe(self, host: str, status: int) -> None:
        """HTTP cavabını qeyd edir. 403/429 → hədəf dayandırılır, evasion YOX."""
        self.policy.record(host, status)

    async def request(self, session, method: str, url: str, **kwargs) -> HttpResponse:
        ident = self.ids.identity_for(extract_host(url))
        headers = dict(ident.headers())
        headers.update(kwargs.pop("headers", None) or {})
        kwargs.setdefault("proxy", ident.proxy)
        return await self.policy.request(session, method, url,
                                         headers=headers, **kwargs)

    async def get(self, session, url: str, **kwargs) -> HttpResponse:
        return await self.request(session, "GET", url, **kwargs)

    async def post(self, session, url: str, **kwargs) -> HttpResponse:
        return await self.request(session, "POST", url, **kwargs)

    def halted(self, host: str) -> bool:
        return self.policy.is_halted(host)

    def audit(self) -> list[dict]:
        return self.policy.audit()

    def summary(self) -> dict:
        return self.policy.summary()
