"""TLS/HTTP2 barmaq izi təqlidi — Faza 2.1 (ən yüksək prioritet).

Müasir stack-lərdə **Python-un öz TLS barmaq izi skaner imzasıdır**. `aiohttp`
və ya `requests` ilə edilən sorğu JA3/JA4 səviyyəsində dərhal seçilir. Bu modul
`curl_cffi` ilə Chrome/Safari/Firefox/Edge təqlidi təmin edir: düzgün JA3/JA4,
HTTP/2 SETTINGS, başlıq sırası.

**Dürüstlük (mütləq oxu).**
`curl_cffi` quraşdırılmayıbsa `impersonation_available()` → `False` olur və
`ImpersonatingTransport.available` False qaytarır. Bu halda:
  * heç bir "təqlid edirik" iddiası verilmir —
  * `HttpPolicy` şəffaf şəkildə aiohttp-a düşür,
  * `docs/STEALTH.md`-də bu məhdudiyyət açıq yazılır.

`off` seçilərsə təqlid TAMAMİLƏ söndürülür (proxy yoxdur, saxta başlıq yoxdur).
"""
from __future__ import annotations

import importlib.util
import time
from dataclasses import dataclass, field

import aiohttp

#: İstifadəçi adı → curl_cffi hədəfləri (ilkin uyğun versiya əvvəldə).
BROWSER_TARGETS: dict[str, tuple[str, ...]] = {
    "chrome": ("chrome131", "chrome124", "chrome120", "chrome116", "chrome110"),
    "safari": ("safari17_2", "safari17_0", "safari15_5"),
    "firefox": ("firefox133", "firefox120", "firefox110"),
    "edge": ("edge101", "edge99"),
}

#: curl_cffi olmadıqda hansı brauzerin təqlid olunacağını bildirən adlar.
KNOWN = frozenset(BROWSER_TARGETS) | {"off"}


def impersonation_available() -> bool:
    """`curl_cffi` hazırdırmı? (quraşdırılmayıbsa dürüst `False`)."""
    try:
        return importlib.util.find_spec("curl_cffi") is not None
    except (ImportError, ValueError):  # pragma: no cover - müdafiə
        return False


def _supported_targets() -> frozenset[str]:
    """Runtim-də curl_cffi-nin dəstəklədiyi hədəflər (yoxdursa boş)."""
    if not impersonation_available():
        return frozenset()
    try:  # pragma: no cover - yalnız curl_cffi quraşdırıldıqda işləyir
        from curl_cffi.const import CurlOpt  # noqa: F401
        from curl_cffi.requests import BrowserType  # type: ignore

        return frozenset(str(x) for x in BrowserType)
    except Exception:  # noqa: BLE001
        return frozenset()


def resolve_target(name: str) -> str | None:
    """Brauzer adını konkret curl_cffi hədəfinə çevirir.

    `off` və ya naməlum ad → `None`. curl_cffi yoxdursa ilk ehtimal qaytarılır
    (çağıran `impersonation_available()`-i ayrıca yoxlamalıdır).
    """
    key = str(name or "").strip().lower()
    if key not in BROWSER_TARGETS:
        return None
    candidates = BROWSER_TARGETS[key]
    supported = _supported_targets()
    if supported:
        for cand in candidates:
            if cand in supported:
                return cand
        return candidates[0]
    return candidates[0]


@dataclass
class TransportResponse:
    """Təqlid edən transport-un nəticəsi (`HttpResponse`-a çevrilir)."""

    status: int
    headers: dict = field(default_factory=dict)
    text: str = ""
    url: str = ""
    elapsed: float = 0.0
    truncated: bool = False


class ImpersonatingTransport:
    """`curl_cffi.requests.AsyncSession` üzərində nazik, təhlükəsiz sarğı.

    `available=False` olduqda `request()` **xəta qaldırır** — çağıran tərəf
    (`HttpPolicy`) aiohttp-a düşür. Bu, səssiz saxta nəticəni qadağan edir.
    """

    name = "impersonate"

    def __init__(self, browser: str = "chrome", *, timeout: float = 30.0,
                 proxy: str | None = None, max_body: int = 2_000_000):
        self.browser = str(browser or "off").strip().lower()
        self.target = resolve_target(self.browser)
        self.timeout = float(timeout)
        self.proxy = proxy
        self.max_body = int(max_body)
        self._session = None

    @property
    def enabled(self) -> bool:
        return self.browser != "off" and self.target is not None

    @property
    def available(self) -> bool:
        return self.enabled and impersonation_available()

    def summary(self) -> dict:
        return {
            "browser": self.browser,
            "target": self.target,
            "available": self.available,
            "reason": ("hazır" if self.available else
                       ("curl_cffi quraşdırılmayıb" if self.enabled
                        else "təqlid söndürülüb")),
        }

    async def _ensure_session(self):
        if self._session is None:  # pragma: no cover - curl_cffi tələb edir
            from curl_cffi.requests import AsyncSession

            self._session = AsyncSession()
        return self._session

    async def close(self) -> None:  # pragma: no cover - curl_cffi tələb edir
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def request(self, method: str, url: str, *, headers=None,
                      allow_redirects: bool = False, proxy=None,
                      timeout: float | None = None, **kwargs) -> TransportResponse:
        """Təqlid edən HTTP sorğu. Mövcud deyilsə `RuntimeError` qaldırır."""
        if not self.available:
            raise RuntimeError(
                "impersonation mövcud deyil (curl_cffi yoxdur və ya off)")
        session = await self._ensure_session()
        started = time.monotonic()
        try:  # pragma: no cover - curl_cffi tələb edir
            resp = await session.request(
                method, url, headers=headers, allow_redirects=allow_redirects,
                proxy=proxy or self.proxy,
                timeout=timeout or self.timeout, impersonate=self.target,
                **kwargs)
        except Exception as exc:  # noqa: BLE001 - vahid xəta tipinə çevrilir
            # curl_cffi öz xəta tipini qaldırır; `HttpPolicy` isə yalnız
            # aiohttp/OS xətalarını tutur → burada normallaşdırılır ki,
            # retry məntiqi hər iki transport üçün eyni olsun.
            raise aiohttp.ClientError(str(exc)) from exc
        content = resp.content or b""
        truncated = len(content) > self.max_body
        encoding = "utf-8"
        try:
            encoding = resp.encoding or "utf-8"
        except (LookupError, AttributeError):
            pass
        return TransportResponse(
            status=int(resp.status_code),
            headers=dict(resp.headers or {}),
            text=content[: self.max_body].decode(encoding, errors="ignore"),
            url=str(getattr(resp, "url", url)),
            elapsed=time.monotonic() - started,
            truncated=truncated,
        )
