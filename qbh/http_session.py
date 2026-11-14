"""Skan-scoped HTTP sessiya meneceri (Faza 1, §4).

Məqsəd: hər mühərrikin öz `aiohttp.ClientSession`-unu yaratmasının qarşısını
almaq → bir skan boyu TƏK uyğun sessiya (və beləcə TCP bağlantısı təkrar
istifadə olunur). Bu, hədəfə gedən trafiki ARTIRMIR: rate/cooldown/scope
qapıları `HttpPolicy`-də olduğu kimi işləməyə davam edir.

Qaydalar:
  * Sessiya **aktiv event loop daxilində LAZY** yaradılır — modul import
    zamanı və ya modul-qlobal sessiya YOXDUR.
  * Sessiyalar skanlar arasında PAYLAŞILMIR (`Conductor` hər skan üçün təzə
    `Context` yaradır; `Context.aclose()` sonunda bağlayır).
  * `inject()` testlər üçün mock sessiya/transport yeridir (sahiblənən deyil →
    bağlanmır).
  * TLS yoxlaması AKTİVDİR: `TCPConnector` üçün `ssl` parametri verilmir →
    aiohttp default-u (`True`, sistem CA-ları ilə doğrulama) işləyir.
    `ssl=False` HEÇ VAXT istifadə olunmur.

**DNS qeydi (mütləq oxu).** `ttl_dns_cache` yalnız aiohttp-ın daxili DNS
keşidir; bu, `EgressController`-in subprocess DNS pinning-ini ƏVƏZ ETMİR və
zəiflətmir. Native HTTP yolu üçün DNS həlli əvvəlki kimi OS resolver-dən keçir.
"""
from __future__ import annotations

import aiohttp

#: `keepalive_timeout` — bağlantının təkrar istifadəsi üçün mühafizəkar dəyər.
#: Çox böyük dəyər yarı-açıq bağlantı riskini artırır; 15s balanslı seçimdir.
DEFAULT_KEEPALIVE_TIMEOUT = 15.0

#: aiohttp DNS keşinin TTL-i (saniyə) — bounded, qısa ömürlü.
DEFAULT_DNS_TTL = 30.0


class _SharedSessionCM:
    """`async with` interfeysini PAYLAŞILAN sessiyaya verir (sessiyanı BAĞLAMIR).

    Mühərriklər əvvəllər `async with aiohttp.ClientSession() as session:`
    işlədirdi (hər mühərrik/host üçün təzə bağlantı hovuzu). Bu şim həmin
    `async with` quruluşunu KORUYARAQ skan-scoped paylaşılan sessiyanı verir →
    TCP bağlantıları skan boyu təkrar istifadə olunur. Çıxışda sessiya
    bağlanmır (sahib `Context`-dir).
    """

    __slots__ = ("_session",)

    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, *exc) -> bool:
        return False


class ScanSession:
    """Bir skan üçün tək, təkrar istifadə olunan `aiohttp.ClientSession`."""

    def __init__(self, *, total_limit: int = 10, per_host_limit: int = 3,
                 connect_timeout: float = 10.0, total_timeout: float = 30.0,
                 keepalive_timeout: float = DEFAULT_KEEPALIVE_TIMEOUT,
                 dns_ttl: float = DEFAULT_DNS_TTL, metrics=None):
        self.total_limit = max(1, int(total_limit))
        self.per_host_limit = max(1, int(per_host_limit))
        self.connect_timeout = float(connect_timeout)
        self.total_timeout = float(total_timeout)
        self.keepalive_timeout = float(keepalive_timeout)
        self.dns_ttl = float(dns_ttl)
        self.metrics = metrics
        self._session = None
        self._owned = True

    @property
    def created(self) -> bool:
        """Sessiya faktiki yaradılıbmı?"""
        return self._session is not None

    @property
    def session(self):
        """Sessiyanı lazım gəldikdə (aktiv loop daxilində) yaradır."""
        if self._session is None:
            self._session = self._build()
        return self._session

    def _build(self):
        connector = aiohttp.TCPConnector(
            limit=self.total_limit,
            limit_per_host=self.per_host_limit,
            keepalive_timeout=self.keepalive_timeout,
            ttl_dns_cache=int(self.dns_ttl),
        )
        timeout = aiohttp.ClientTimeout(total=self.total_timeout,
                                        connect=self.connect_timeout)
        if self.metrics is not None:
            self.metrics.record_session_created()
        return aiohttp.ClientSession(connector=connector, timeout=timeout)

    def inject(self, session) -> None:
        """Testlər üçün xarici (mock) sessiya yeridir — bağlanmır."""
        self._session = session
        self._owned = False

    async def aclose(self) -> None:
        """Sessiyanı bağlayır (uğur, xəta, exception və ləğv halında çağırılır)."""
        session = self._session
        self._session = None
        if session is None or not self._owned:
            return
        try:
            await session.close()
        finally:
            if self.metrics is not None:
                self.metrics.record_session_closed()
