"""Proxy strategiyası seçimi — Faza 2.3 (sürət şüurlu).

`proxy.strategy` variantları: `off | single | rotate | residential | tor`.

**Deliberate dizayn məhdudiyyəti.** Tor (SOCKS5) GECİKMƏLİDİR. Ona görə Tor
YALNIZ yavaş, həssas fazalarda (PoC replay, yüksək-dəyərli endpoint-in dərin
crawl-u) istifadə olunur — bulk fuzzinqdə ASLA, çünki Tor sürəti məhv edərdi.
Bu, konfiqurasiya ilə tətbiq olunur (`stealth.tor_for_sensitive_only`), sadəcə
sənəd deyil.

Residential rotasiya dəstəklənir (ən yaxşı stealth/sürət balansı), lakin
credential-lar YALNIZ lokal konfiqurasiyada saxlanılır — heç bir secret
commit olunmur.
"""
from __future__ import annotations

from dataclasses import dataclass

#: Bulk (sürət kritik) fazalar — Tor burada İSTİFADƏ OLUNMUR.
BULK_PHASES = frozenset({
    "recon", "discovery", "content", "ferox", "api_fuzz", "fuzz",
    "deep_enum", "crawl", "param_enum",
})

#: Həssas fazalar — yavaş olsa da Tor qəbul edilir.
SENSITIVE_PHASES = frozenset({
    "poc", "replay", "confirm", "auth", "deep_crawl", "sensitive",
})

STRATEGIES = frozenset({"off", "single", "rotate", "residential", "tor"})


def is_sensitive_phase(phase: str) -> bool:
    """Faza həssasdırmı? (bilinməyən fazalar → həssas sayılmır = təhlükəsiz default)"""
    return str(phase or "").strip().lower() in SENSITIVE_PHASES


@dataclass(frozen=True)
class ProxyPlan:
    """Seçilmiş proxy planı və onun SƏBƏBİ (audit üçün)."""

    strategy: str
    effective: str
    use_tor: bool
    rotate: bool
    residential: bool
    phase: str
    reason: str

    def to_dict(self) -> dict:
        return {
            "strategy": self.strategy, "effective": self.effective,
            "use_tor": self.use_tor, "rotate": self.rotate,
            "residential": self.residential, "phase": self.phase,
            "reason": self.reason,
        }


def plan_proxy(strategy: str, phase: str, *,
               tor_for_sensitive_only: bool = True) -> ProxyPlan:
    """Strategiya + fazaya görə effektiv proxy planını qurur.

    Qaydalar:
      * `off` → heç bir proxy.
      * `tor` + bulk faza + `tor_for_sensitive_only` → **direct-ə düşür**
        (sürət qorunur) və səbəb audit üçün qeyd olunur.
      * `tor` + həssas faza → Tor aktiv.
      * `single|rotate|residential` → bütün fazalarda aktiv.
    """
    strat = str(strategy or "off").strip().lower()
    if strat not in STRATEGIES:
        strat = "off"
    ph = str(phase or "").strip().lower()
    sensitive = is_sensitive_phase(ph)

    if strat == "off":
        return ProxyPlan("off", "direct", False, False, False, ph,
                         "proxy strategiyası söndürülüb")
    if strat == "tor":
        if tor_for_sensitive_only and not sensitive:
            return ProxyPlan("tor", "direct", False, False, False, ph,
                             "Tor yalnız həssas fazalarda — bulk fazada "
                             "sürəti qorumaq üçün direct istifadə olunur")
        return ProxyPlan("tor", "tor", True, True, False, ph,
                         f"Tor aktiv (həssas faza: {ph or 'naməlum'})")
    if strat == "single":
        return ProxyPlan("single", "single", False, False, False, ph,
                         "tək datacenter proxy (TLS təqlidi ilə)")
    if strat == "rotate":
        return ProxyPlan("rotate", "rotate", False, True, False, ph,
                         "rotasiya edilən datacenter proxy")
    return ProxyPlan("residential", "residential", False, True, True, ph,
                     "residential rotasiya (stealth/sürət balansı)")
