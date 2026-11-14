"""Paylaşılan "xidmət URL-i" həlledicisi (HTTP/HTTPS protokol seçimi).

Fingerprint və WAF aşkarlama mühərrikləri əvvəllər `https://{host}` fərz
edirdilər. Yalnız HTTP-də xidmət göstərən host-larda bu, səhvən uğursuzluğa
səbəb olurdu. Bu modul həmin fərziyyəni TƏHLÜKƏSİZ şəkildə əvəz edir:

  * Saxlanmış recon URL-lərindən ( `db.scheme_hint` ) ipucu götürülür.
  * İpucu yoxdursa, MƏHDUD sayda (maksimum 2) HTTP/HTTPS yoxlaması aparılır.
  * Uğurlu protokol host başına keşlənir → təkrar sorğular üçün YENİDƏN
    zondlanmır.
  * Əlaqə xətaları növlərə ayrılır (timeout / refused / DNS / TLS / digər).

Təhlükəsizlik:
  * BÜTÜN sorğular Guardian/HttpPolicy-dən keçir (scope + rate + cooldown).
  * Birbaşa idarə olunmayan `aiohttp` sorğusu YOXDUR.
  * Uğursuzluq halında "uydurma" nəticə istehsal olunmur.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import aiohttp

from .http_policy import TargetBlocked
from .scope import ScopeError

#: Əlaqə uğursuzluğunun növləri — dürüst raportlaşdırma üçün.
KIND_OK = "ok"
KIND_TIMEOUT = "timeout"
KIND_REFUSED = "refused"
KIND_DNS = "dns"
KIND_TLS = "tls"
KIND_OTHER = "other"

_FAILURE_LABEL = {
    KIND_TIMEOUT: "timeout",
    KIND_REFUSED: "əlaqə rədd edildi",
    KIND_DNS: "DNS həll olunmadı",
    KIND_TLS: "TLS əl sıxışması uğursuz",
    KIND_OTHER: "əlaqə qurula bilmədi",
}


def failure_label(kind: str) -> str:
    """Uğursuzluq növünü insan-oxunaqlı etiketə çevirir."""
    return _FAILURE_LABEL.get(kind, kind)


def classify_error(exc: BaseException) -> str:
    """`aiohttp`/`OSError` istisnasını əlaqə uğursuzluğu növünə çevirir.

    Aiohttp-un bükmə (wrap) etdiyi xətalar (`ClientConnectorError`) üçün
    `os_error` sahəsi açılır, beləcə real səbəb (məs. `ConnectionRefusedError`,
    `socket.gaierror`) düzgün təsnif olunur.
    """
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return KIND_TIMEOUT

    cause = getattr(exc, "os_error", None) or exc
    if (isinstance(exc, (aiohttp.ClientSSLError,
                         aiohttp.ClientConnectorCertificateError))
            or isinstance(cause, ssl.SSLError)):
        return KIND_TLS
    if isinstance(cause, socket.gaierror) or type(exc).__name__ == \
            "ClientConnectorDNSError":
        return KIND_DNS
    if isinstance(cause, ConnectionRefusedError):
        return KIND_REFUSED
    if isinstance(exc, aiohttp.ServerDisconnectedError):
        return KIND_OTHER
    return KIND_OTHER


@dataclass
class ServiceEndpoint:
    """Bir host üçün həll olunmuş xidmət nöqtəsi (protokol + ilk cavab)."""

    host: str
    scheme: str
    ok: bool
    kind: str = KIND_OK
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""

    @property
    def base(self) -> str:
        return f"{self.scheme}://{self.host}"

    def url(self, path: str = "/") -> str:
        if not path.startswith("/"):
            path = "/" + path
        return self.base + path


class ServiceResolver:
    """Host başına işləyən protokolu müəyyən edir və keşləyir."""

    def __init__(self, guardian, *, schemes: tuple[str, ...] = ("https", "http")):
        self.guardian = guardian
        self.schemes = tuple(schemes)
        self._cache: dict[str, ServiceEndpoint] = {}

    def cached(self, host: str) -> ServiceEndpoint | None:
        ep = self._cache.get(host)
        return ep if ep is not None and ep.ok else None

    async def resolve(self, session, host: str, *, hint: str | None = None,
                      allow_redirects: bool = True) -> ServiceEndpoint:
        """Host üçün işləyən protokolu qaytarır (maksimum 2 zond).

        `hint` (məs. saxlanmış recon URL-dən) verilərsə əvvəlcə o sınanır;
        uğursuz olarsa digər protokol sınanır. Nəticə keşlənir.
        """
        cached = self._cache.get(host)
        if cached is not None and cached.ok:
            return cached

        order = list(self.schemes)
        if hint in order:
            order.remove(hint)
            order.insert(0, hint)

        if self.guardian is None:  # pragma: no cover - guardian həmişə verilir
            ep = ServiceEndpoint(host=host, scheme=order[0], ok=False,
                                 kind=KIND_OTHER)
            self._cache[host] = ep
            return ep

        last = ServiceEndpoint(host=host, scheme=order[0], ok=False,
                               kind=KIND_OTHER)
        for scheme in order:
            ep = ServiceEndpoint(host=host, scheme=scheme, ok=False)
            try:
                r = await self.guardian.get(
                    session, f"{scheme}://{host}/",
                    allow_redirects=allow_redirects)
            except (TargetBlocked, ScopeError):
                raise
            except Exception as exc:  # noqa: BLE001 - növə çevrilir, udulur
                ep.kind = classify_error(exc)
                last = ep
                continue
            ep.ok = True
            ep.kind = KIND_OK
            ep.status = int(getattr(r, "status", 0) or 0)
            ep.headers = dict(getattr(r, "headers", {}) or {})
            ep.body = (getattr(r, "text", "") or "")[:400_000]
            final = urlsplit(str(getattr(r, "url", "") or ""))
            if (final.hostname or "").lower() == host and \
                    final.scheme in ("http", "https"):
                ep.scheme = final.scheme
            self._cache[host] = ep
            return ep

        self._cache[host] = last
        return last
