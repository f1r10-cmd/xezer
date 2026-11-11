"""Proxy marşrutu və (konfiqurasiya olunubsa) rotasiya — legitim OPSEC.

v2.2-də proxy rotasiyası **yalnız İCAZƏLİ scope daxilində** və **yalnız açıq
şəkildə konfiqurasiya olunduqda** icazəlidir (`rotation.proxy: true`). Bu,
`IdentityManager` tərəfindən idarə olunur və hər rotasiya audit qeydinə düşür.

Rejimlər:
  * `off`    → proxy yoxdur,
  * `single` → sabit proxy (ilk sətir),
  * `rotate` → host başına rotasiya üçün siyahı (IdentityManager istifadə edir).
"""
from __future__ import annotations


class ProxyManager:
    SUPPORTED_MODES = ("off", "single", "rotate")

    def __init__(self, mode: str, proxy_file: str):
        self.mode = mode if mode in self.SUPPORTED_MODES else "off"
        self.proxies: list[str] = []
        if self.mode in ("single", "rotate") and proxy_file:
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
        """Sabit marşrut: ilk proxy (rotasiya IdentityManager-də olur)."""
        if self.mode in ("single", "rotate") and self.proxies:
            return self.proxies[0]
        return None
