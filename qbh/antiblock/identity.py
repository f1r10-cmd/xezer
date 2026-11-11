"""İdentiklik meneceri — configurable OPSEC rotasiyası.

v2.2-də identiklik rotasiyası **legitim OPSEC** kimi qaytarıldı: UA, başlıq və
(açıq şəkildə konfiqurasiya olunubsa) proxy rotasiyası. Bu, yalnız İCAZƏLİ
scope daxilində, `rotation` konfiqurasiyası ilə idarə olunur və hər rotasiya
audit üçün loqda saxlanılır.

Rotasiya qapalı olduqda (passive profil) davranış deterministik və sabitdir
(hosta görə).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .proxymanager import ProxyManager

#: Rotasiya üçün UA hovuzu.
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) "
    "Gecko/20100101 Firefox/124.0",
]

#: Başlıq rotasiyası üçün variantlar (Accept-Language).
LANG_POOL = ["en-US,en;q=0.9", "en-GB,en;q=0.8", "de-DE,de;q=0.9,en;q=0.8",
             "fr-FR,fr;q=0.9,en;q=0.8", "tr-TR,tr;q=0.9,en;q=0.8"]

#: Rotasiya zamanı əlavə olunan benign başlıqlar.
EXTRA_HEADER_POOL = [
    ("Cache-Control", "no-cache"),
    ("Pragma", "no-cache"),
    ("X-Requested-With", "XMLHttpRequest"),
    ("Sec-Fetch-Mode", "navigate"),
    ("Sec-Fetch-Site", "same-origin"),
]


@dataclass(frozen=True)
class Identity:
    index: int
    ua: str
    lang: str
    proxy: str | None

    def headers(self, extra: bool = False) -> dict:
        h = {
            "User-Agent": self.ua,
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "*/*;q=0.8"),
            "Accept-Language": self.lang,
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if extra:
            for k, v in EXTRA_HEADER_POOL[self.index % len(EXTRA_HEADER_POOL):]:
                h.setdefault(k, v)
        return h


class IdentityManager:
    """Host başına identiklik; rotasiya konfiqurasiya olunubsa dəyişir."""

    def __init__(self, proxy_file: str = "", interface: str = "eth0",
                 rotation=None, proxy_mode: str = "off"):
        self.interface = interface
        self.rotation = rotation
        self._rot_ua = bool(getattr(rotation, "enabled", False)
                            and getattr(rotation, "ua", False))
        self._rot_headers = bool(getattr(rotation, "enabled", False)
                                 and getattr(rotation, "headers", False))
        self._rot_proxy = bool(getattr(rotation, "enabled", False)
                               and getattr(rotation, "proxy", False))
        self._on_block = bool(getattr(rotation, "on_block", True))
        mode = "rotate" if self._rot_proxy else (
            "single" if proxy_mode == "single" else "off")
        self._proxies = ProxyManager(mode, proxy_file)
        self._n = 0
        self._cache: dict[str, Identity] = {}
        self.events: list[dict] = []

    # ---------------- köməkçilər ----------------
    @staticmethod
    def _base_index(host: str) -> int:
        return int(hashlib.sha256(host.encode()).hexdigest(), 16)

    def _build(self, host: str, index: int) -> Identity:
        proxies = self._proxies.proxies
        proxy = proxies[index % len(proxies)] if proxies else None
        return Identity(
            index=index,
            ua=UA_POOL[index % len(UA_POOL)],
            lang=LANG_POOL[index % len(LANG_POOL)],
            proxy=proxy,
        )

    def identity_for(self, host: str) -> Identity:
        ident = self._cache.get(host)
        if ident is None:
            ident = self._build(host, self._base_index(host))
            self._cache[host] = ident
        return ident

    def headers_for(self, host: str) -> dict:
        return self.identity_for(host).headers(extra=self._rot_headers)

    def proxy_for(self, host: str) -> str | None:
        return self.identity_for(host).proxy

    # ---------------- rotasiya ----------------
    @property
    def can_rotate(self) -> bool:
        return self._rot_ua or self._rot_headers or self._rot_proxy

    def rotate(self, host: str, reason: str = "") -> bool:
        """İdentikliyi dəyişir. Uğurlu olduqda True qaytarır."""
        if not (self._on_block and self.can_rotate):
            return False
        self._n += 1
        new_index = self._base_index(host) + self._n
        self._cache[host] = self._build(host, new_index)
        self.events.append({
            "host": host, "reason": reason, "n": self._n,
            "ua_changed": self._rot_ua,
            "headers_changed": self._rot_headers,
            "proxy_changed": self._rot_proxy and bool(self._proxies.proxies),
        })
        return True

    def audit_log(self) -> list[dict]:
        return list(self.events)
