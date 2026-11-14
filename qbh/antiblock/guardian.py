"""Guardian — adaptiv blok idarəetməsi və audit.

v2.2-də Guardian "əyləc pedalı" deyil, **adaptiv engine**-dir:
  * 403/429 → `block_strategy`-yə görə qərar verir:
      - `respect`            → `Retry-After`/cooldown gözləyir,
      - `rotate`             → identikliyi dəyişir və yenidən yoxlayır,
      - `backoff_then_rotate`→ əvvəl gözləyir, sonra identikliyi dəyişir,
      - `escalate_bypass`    → bypass matrisi üçün işarə qaldırır.
  * Hər blok və rotasiya audit üçün qeyd olunur.
  * Scope qapısı `HttpPolicy`-də hər sorğu və hər redirect addımında işləyir.

v3.0 (Faza 2.5): Guardian `HttpPolicy`-nin üstünə **eskalasiya nərdivanı**
əlavə edir (`qbh.stealth.ladder`). Ardıcıl bloklar boyu:

  1. 429 + Retry-After → hörmət,
  2. israrlı blok → identiklik rotasiyası,
  3. davam edərsə → WAF-şüurlu backoff + rate azaldılması,
  4. davam edərsə → `stealth_mode` (rate ciddi düşür),
  5. davam edərsə → intrusiv fazalar (SQLi/PoC) TƏXİRƏ SALINIR.

Rol: Guardian **tətbiq mexanizmidir**, sadəcə logger deyil — `halt` zamanı
alt-proses qrupları SIGKILL edilir (Faza 0.2, `qbh/egress.py` + `adapters`).
"""
from __future__ import annotations

from ..http_policy import HttpPolicy, HttpResponse, TargetBlocked
from ..scope import extract_host
from ..stealth.ladder import EscalationLadder
from .identity import IdentityManager


class Guardian:
    def __init__(self, identity_mgr: IdentityManager, policy: HttpPolicy,
                 ladder: EscalationLadder | None = None):
        self.ids = identity_mgr
        self.policy = policy
        #: Skan-üzrə TƏHLÜKƏSİZLİK qapısı (intrusiv fazaların təxirə salınması).
        #: QƏSDƏN qlobaldır: bir hostda ciddi blok bütün skan üzrə intrusiv
        #: fazaları ehtiyatlı şəkildə saxlayır (§6.2).
        self.ladder = ladder or EscalationLadder()
        #: Host-a xas eskalasiya (YALNIZ həmin hostun rate-ini azaldır).
        #: Beləcə Host A-nın bloku Host B-nin rate-inə təsir ETMİR (§6.1).
        self._host_ladders: dict[str, EscalationLadder] = {}
        self.ladder_audit: list[dict] = []
        #: Aşkarlanmış WAF adı (Faza 2.2) — nərdivan qərarlarını zənginləşdirir.
        self.waf_name = ""
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

    # ---- host-a xas eskalasiya (rate izolyasiyası) ----
    def _host_ladder(self, host: str) -> EscalationLadder:
        hl = self._host_ladders.get(host)
        if hl is None:
            hl = EscalationLadder()
            self._host_ladders[host] = hl
        return hl

    def _note_events(self, events) -> None:
        """MƏHZ bu sorğuya aid BLOK hadisələrini nərdivanlara ötürür (§6.3).

        Hadisələr `TargetBlocked.block_events`-dən gəlir (paylaşılan
        `policy.block_events` dilimindən DEYİL) → konkurentlikdə hər hadisə
        öz hostuna dəqiq aid edilir. İki təsir:
          1. Skan-üzrə təhlükəsizlik qapısı (`self.ladder`) — intrusiv təxirə,
          2. Host-a xas rate eskalasiyası — YALNIZ `ev.host`-un rate-i azalır.
        """
        for ev in events:
            gdec = self.ladder.on_block(ev.status, waf=self.waf_name)
            hl = self._host_ladder(ev.host)
            hdec = hl.on_block(ev.status, waf=self.waf_name)
            self.policy.set_host_rate_factor(ev.host, hdec.rate_factor)
            self.ladder_audit.append(hdec.to_dict())
            if gdec.defer_intrusive:
                print("   [⛔] Guardian: intrusiv fazalar görünürlük düzələnə "
                      "qədər təxirə salınır (stealth_mode)")

    def _on_host_success(self, host: str) -> None:
        """Uğurlu cavab → YALNIZ bu hostun nərdivanı bir pillə aşağı (§6.2).

        Host B-nin uğuru Host A-nın blok/eskalasiya vəziyyətini və ya
        cooldown-unu TƏMİZLƏMİR.
        """
        hl = self._host_ladders.get(host)
        if hl is None or hl.blocks == 0:
            return
        hl.on_success()
        self.policy.set_host_rate_factor(host, hl.rate_factor)

    async def request(self, session, method: str, url: str, **kwargs) -> HttpResponse:
        extra = kwargs.pop("headers", None)
        try:
            host = extract_host(url)
        except Exception:  # noqa: BLE001 - etibarsız URL → policy öz xətasını atır
            host = ""
        if extra:
            merged = dict(self.ids.headers_for(host))
            merged.update(extra)
            kwargs["headers"] = merged
        try:
            resp = await self.policy.request(session, method, url, **kwargs)
        except TargetBlocked as exc:
            # Konkurentlik-təhlükəsiz atribusiya: yalnız BU sorğunun hadisələri.
            self._note_events(getattr(exc, "block_events", ()))
            raise
        self._on_host_success(host)
        if not self.ladder.blocked:
            self.ladder.on_success()
        return resp

    async def get(self, session, url: str, **kwargs) -> HttpResponse:
        return await self.request(session, "GET", url, **kwargs)

    async def post(self, session, url: str, **kwargs) -> HttpResponse:
        return await self.request(session, "POST", url, **kwargs)

    def halted(self, host: str) -> bool:
        return self.policy.is_halted(host)

    def allows_intrusive(self) -> bool:
        """İntrusiv fazalar (SQLi/PoC) hazırda icazəlidirmi?"""
        return self.ladder.allows_intrusive()

    def rotate(self, host: str, reason: str = "") -> bool:
        """İdentikliyi əl ilə dəyişir (məs. bypass addımı üçün)."""
        return self.ids.rotate(host, reason=reason)

    def audit(self) -> list[dict]:
        return self.policy.audit()

    def rotation_audit(self) -> list[dict]:
        return self.ids.audit_log()

    def ladder_state(self) -> dict:
        return self.ladder.state()

    def summary(self) -> dict:
        s = self.policy.summary()
        s["rotations_identity"] = len(self.ids.audit_log())
        s["ladder"] = self.ladder.state()
        return s
