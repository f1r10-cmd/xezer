"""Proxy marşrutu — yalnız AÇIQ şəkildə konfiqurasiya olunmuş istifadə üçün.

QADAĞANDIR: blokdan yayınmaq üçün proxy rotasiyası. Bu modul artıq
təsadüfi rotasiya etmir və `rotate` rejimi dəstəklənmir. Proxy yalnız
istifadəçinin şəbəkə marşrutu tələb etdiyi hallarda istifadə olunur.
"""
from __future__ import annotations


class ProxyManager:
    SUPPORTED_MODES = ("off", "single")

    def __init__(self, mode: str, proxy_file: str):
        self.mode = mode if mode in self.SUPPORTED_MODES else "off"
        self.proxies: list[str] = []
        if self.mode == "single" and proxy_file:
            self.proxies = self._load(proxy_file)
            if not self.proxies:
                print(f"[!] Proxy faylı boşdur/tapılmadı: {proxy_file} "
                      f"— birbaşa bağlantı istifadə olunur")
                self.mode = "off"

    @staticmethod
    def _load(path: str) -> list[str]:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return [ln.strip() for ln in fh
                        if ln.strip() and not ln.strip().startswith("#")]
        except FileNotFoundError:
            return []

    def for_host(self, host: str) -> str | None:  # noqa: ARG002 - interfeys
        """Sabit marşrut: rotasiya YOX. Konfiqurasiya olunmuşsa ilk proxy."""
        if self.mode == "single" and self.proxies:
            return self.proxies[0]
        return None
