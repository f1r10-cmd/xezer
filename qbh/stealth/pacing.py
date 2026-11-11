"""İnsan-təqlidi temp (pacing) — Faza 2.4.

Skanerin ən sadə imzası: **mexaniki** sorğu tempidir (bərabər fasilələr,
qırılmaz partlayışlar). Bu modul sorğular arasında dəyişkən "düşünmə vaxtı"
və sessiya-partlayış modeli tətbiq edir.

**Sürət müqaviləsi (müqavilə kodla tətbiq olunur).**
`Pacer.delay()` heç vaxt `(max_overhead - 1.0) / rate` saniyədən böyük dəyər
qaytarmır. Beləliklə bulk fazalarda ümumi yavaşlama `stealth.pacing_max_overhead`
faktorunu (default 1.15x) AŞA BİLMƏZ — stealth sürəti məhv etmir.
"""
from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field

#: Profil → tempo parametrləri (saniyə).
#:   think_*  — partlayışlar ARASINDAKI uzun fasilə aralığı,
#:   burst_*  — partlayış DAXİLİNDƏKI qısa fasilə aralığı,
#:   burst_len— bir partlayışdakı sorğu sayı aralığı.
PACING_PARAMS: dict[str, dict[str, float]] = {
    "passive": {
        "think_min": 0.8, "think_max": 2.6,
        "burst_min": 0.05, "burst_max": 0.35,
        "burst_len_min": 3, "burst_len_max": 7,
    },
    "normal": {
        "think_min": 0.25, "think_max": 0.9,
        "burst_min": 0.0, "burst_max": 0.12,
        "burst_len_min": 4, "burst_len_max": 9,
    },
    "aggressive": {
        "think_min": 0.0, "think_max": 0.08,
        "burst_min": 0.0, "burst_max": 0.02,
        "burst_len_min": 8, "burst_len_max": 16,
    },
}


@dataclass
class Pacer:
    """Dəyişkən, insan-təqlidi sorğu tempi (sürət həddi ilə məhdudlaşdırılmış).

    `rng` inyeksiya edilə bilər → testlər deterministik olur (flaky deyil).
    """

    profile: str = "aggressive"
    rate: float = 5.0
    max_overhead: float = 1.15
    rng: random.Random = field(default_factory=random.Random)

    _in_burst: int = field(default=0, init=False)
    _burst_len: int = field(default=0, init=False)
    _count: int = field(default=0, init=False)
    _total: float = field(default=0.0, init=False)

    def __post_init__(self) -> None:
        if self.profile not in PACING_PARAMS:
            self.profile = "aggressive"
        self._params = PACING_PARAMS[self.profile]
        self._new_burst()

    # ---------------------------------------------------------------- model
    def _new_burst(self) -> None:
        lo = int(self._params["burst_len_min"])
        hi = int(self._params["burst_len_max"])
        self._burst_len = self.rng.randint(lo, max(lo, hi))
        self._in_burst = 0

    @property
    def budget(self) -> float:
        """İcazəli maksimal orta fasilə (saniyə). `max_overhead <= 1` → 0."""
        if self.max_overhead <= 1.0 or self.rate <= 0:
            return 0.0
        return (self.max_overhead - 1.0) / float(self.rate)

    def sample(self) -> float:
        """Bir xam fasilə seçir (hədd tətbiq edilməmiş)."""
        p = self._params
        if self._in_burst < self._burst_len:
            self._in_burst += 1
            lo, hi = p["burst_min"], p["burst_max"]
        else:
            self._new_burst()
            self._in_burst = 1
            lo, hi = p["think_min"], p["think_max"]
        if hi <= lo:
            return max(0.0, lo)
        return self.rng.uniform(lo, hi)

    def delay(self) -> float:
        """Növbəti sorğudan ƏVVƏL gözləniləcək saniyə (sürət həddi ilə)."""
        value = self.sample()
        capped = min(value, self.budget)
        self._count += 1
        self._total += capped
        return capped

    async def wait(self) -> float:
        """Fasiləni faktiki gözləyir və gözlənilən müddəti qaytarır."""
        value = self.delay()
        if value > 0:
            await asyncio.sleep(value)
        return value

    # ---------------------------------------------------------------- stats
    def stats(self) -> dict:
        avg = (self._total / self._count) if self._count else 0.0
        return {
            "profile": self.profile,
            "rate": self.rate,
            "max_overhead": self.max_overhead,
            "budget": round(self.budget, 6),
            "count": self._count,
            "avg_delay": round(avg, 6),
            "within_budget": avg <= self.budget + 1e-9,
        }
