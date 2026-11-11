"""Guardian — adaptiv blok idarəetməsi və audit.

v2.2-də Guardian "əyləc pedalı" deyil, **adaptiv engine**-dir:
  * 403/429 → `block_strategy`-yə görə qərar verir:
      - `respect`            → `Retry-After`/cooldown gözləyir,
      - `rotate`             → identikliyi dəyişir və yenidən yoxlayır,
      - `backoff_then_rotate`→ əvvəl gözləyir, sonra identikliyi dəyişir,
      - `escalate_bypass`    → bypass matrisi üçün işarə qaldırır.
  * Hər blok və rotasiya audit üçün qeyd olunur.
  * Scope qapısı `HttpPolicy`-də hər sorğu və hər redirect addımında işləyir.
"""
from __future__ import annotations

from ..http_policy import HttpPolicy, HttpResponse
from ..scope import extract_host
from .identity import IdentityManager


class Guardian:
    def __init__(self, identity_mgr: IdentityManager, policy: HttpPolicy):
        self.ids = identity_mgr
        self.policy = policy
        # Policy identiklik provayderini Guardian-dən alsın (rotasiya üçün).
        if policy.identity_provider is None:
            policy.identity_provider = identity_mgr

    # ---- HTTP policy ilə eyni interfeys ----
    async def acquire(self, host: str) -> None:
        """Sorğudan əvvəl: cooldown + rate limit. Blokdadırsa TargetBlocked."""
        await self.policy.acquire(host)

    def identity(self, host: str):
        return self.ids.identity_for(host)

    def observe(self, host: str, status: int) -> None:
        """HTTP cavabını qeyd edir (adaptiv strategiya HttpPolicy-də tətbiq olunur)."""
        self.policy.record(host, status)

    async def request(self, session, method: str, url: str, **kwargs) -> HttpResponse:
        extra = kwargs.pop("headers", None)
        if extra:
            host = extract_host(url)
            merged = dict(self.ids.headers_for(host))
            merged.update(extra)
            kwargs["headers"] = merged
        return await self.policy.request(session, method, url, **kwargs)

    async def get(self, session, url: str, **kwargs) -> HttpResponse:
        return await self.request(session, "GET", url, **kwargs)

    async def post(self, session, url: str, **kwargs) -> HttpResponse:
        return await self.request(session, "POST", url, **kwargs)

    def halted(self, host: str) -> bool:
        return self.policy.is_halted(host)

    def rotate(self, host: str, reason: str = "") -> bool:
        """İdentikliyi əl ilə dəyişir (məs. bypass addımı üçün)."""
        return self.ids.rotate(host, reason=reason)

    def audit(self) -> list[dict]:
        return self.policy.audit()

    def rotation_audit(self) -> list[dict]:
        return self.ids.audit_log()

    def summary(self) -> dict:
        s = self.policy.summary()
        s["rotations_identity"] = len(self.ids.audit_log())
        return s
