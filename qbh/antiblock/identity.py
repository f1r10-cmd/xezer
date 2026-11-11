"""Sabit identiklik — ROTASİYA YOXDUR.

IdentityManager artıq UA/proxy/MAC/IP dəyişmir. Yalnız host üçün sabit
identiklik (UA + başlıqlar + istəyə bağlı sabit proxy marşrutu) təqdim edir.
Blok aşma məqsədilə heç bir dəyişiklik edilmir.
"""
from __future__ import annotations

from dataclasses import dataclass

from .ua_rotator import ua_for


@dataclass(frozen=True)
class Identity:
    mode: str                 # "direct" | "proxy"
    ua: str
    proxy: str | None = None

    def headers(self) -> dict:
        return {
            "User-Agent": self.ua,
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "*/*;q=0.8"),
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }


class IdentityManager:
    """Host başına SABİT identiklik. Rotasiya metodu yoxdur (bilərəkdən)."""

    def __init__(self, proxy: str | None = None, interface: str = "eth0"):
        self.proxy = proxy or None
        self.interface = interface
        self._cache: dict[str, Identity] = {}

    def identity_for(self, host: str) -> Identity:
        ident = self._cache.get(host)
        if ident is None:
            ident = Identity(
                mode="proxy" if self.proxy else "direct",
                ua=ua_for(host),
                proxy=self.proxy,
            )
            self._cache[host] = ident
        return ident
