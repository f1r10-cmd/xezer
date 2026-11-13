"""İnsan-təqlidi başlıq / UA / fasilə — Faza 3.6 (stealth workflow).

Skanerin ikinci ən asan imzası: SABİT `User-Agent` və SABİT başlıq dəsti.
Real brauzer hər sorğuda `Sec-Fetch-*`, `Accept-Language`, `Accept` kimi
başlıqları göndərir; skaner göndərmirsə dərhal seçilir.

Bu modul:
  * mobil + masaüstü qarışıq real UA hovuzu təqdim edir,
  * brauzer ailəsinə uyğun başlıq dəstlərini qurur,
  * sorğular arasında dəyişkən "düşünmə" fasiləsi (jitter) verir.

**Dürüstlük.** Bu, barmaq izini AZALDIR — bot idarəsini YOX ETMİR və CAPTCHA
həll etmir. Rotasiya deterministik `rng` ilə aparılır ki, testlər təkrarlana
bilsin (flaky olmasın).
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

#: Sorğular arası təsadüfi fasilə aralığı (saniyə) — real insan tempi.
JITTER_MIN = 0.5
JITTER_MAX = 3.0

#: Real masaüstü + mobil UA hovuzu (sabit deyil → korrelyasiya azalır).
UA_POOL: tuple[str, ...] = (
    # Masaüstü
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) "
    "Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Mobil
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 "
    "Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
)

#: Brauzer ailəsi → sabit başlıq dəsti (UA ayrıca əlavə olunur).
HEADER_SETS: dict[str, dict[str, str]] = {
    "chrome": {
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                   "image/avif,image/webp,*/*;q=0.8"),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
    },
    "firefox": {
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                   "image/avif,image/webp,*/*;q=0.8"),
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
    },
    "safari": {
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                   "*/*;q=0.8"),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
    },
    "edge": {
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                   "image/avif,image/webp,*/*;q=0.8"),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
    },
}

FAMILIES = tuple(HEADER_SETS)


@dataclass
class Humanizer:
    """Rotasiya edən UA + brauzer başlıqları + insan-təqlidi jitter.

    `rng` inyeksiya edilə bilər → testlər deterministik olur.
    """

    rng: random.Random = field(default_factory=random.Random)
    _index: int = field(default=0, init=False)

    def ua(self) -> str:
        """Növbəti UA (hovuzu dövrəli rotasiya edir)."""
        value = UA_POOL[self._index % len(UA_POOL)]
        self._index += 1
        return value

    def browser(self) -> str:
        """Növbəti brauzer ailəsi (rotasiya)."""
        return FAMILIES[(self._index // max(1, len(UA_POOL))) % len(FAMILIES)]

    def headers(self, browser: str | None = None) -> dict[str, str]:
        """Tam brauzer başlıq dəsti (UA daxil, rotasiya edilmiş)."""
        family = (browser or self.browser()).lower()
        base = dict(HEADER_SETS.get(family, HEADER_SETS["chrome"]))
        base["User-Agent"] = self.ua()
        return base

    def jitter(self) -> float:
        """Sorğular arası təsadüfi fasilə: 0.5–3.0 saniyə."""
        return self.rng.uniform(JITTER_MIN, JITTER_MAX)

    def state(self) -> dict:
        return {"index": self._index, "ua_pool": len(UA_POOL),
                "families": list(FAMILIES),
                "jitter": [JITTER_MIN, JITTER_MAX]}
