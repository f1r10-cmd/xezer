"""Adaptiv stealth qərarı — WAF nəticəsini REAL alət parametrlərinə çevirir.

Faza 2-də `rate_factor_for`/`tamper_for`/`encodings_for` funksiyaları var idi,
lakin onlar TƏK BİR QƏRARA birləşdirilmirdi və alət parametrlərinə
(`nuclei -rl/-c`, `ffuf -rate/-t`, `feroxbuster --rate-limit`,
`naabu -rate`) tətbiq OLUNMURDU. Bu modul həmin boşluğu bağlayır.

Qaydalar (Faza 3.6, adaptive):
  * **WAF aşkarlandı** → `rate = min(base * faktor, WAF_MAX_RPS=3.0)`,
    `concurrency = min(base, WAF_MAX_CONCURRENCY=5)`, UA rotasiyası ON,
    əlavə mühafizəkar template istisnası (`fuzz/intrusive`).
  * **WAF yox** → `rate = min(base, NO_WAF_MAX_RPS=10.0)`,
    `concurrency = base` (sürət qorunur).
  * `waf_adapt=False` → heç bir uyğunlaşdırma (faktor 1.0, tam sürət).

**Dürüstlük.** Bu, deteksiyanı AZALDIR — "görünməzlik" vəd ETMİR. Qərar
audit üçün `to_dict()` ilə tam əsaslandırılır (`reason`).
"""
from __future__ import annotations

from dataclasses import dataclass

from .humanize import JITTER_MAX, JITTER_MIN
from .waf import encodings_for, rate_factor_for, tamper_for

#: WAF aşkarlandıqda tətbiq olunan üst hədlər (təmkinli rejim).
WAF_MAX_RPS = 3.0
WAF_MAX_CONCURRENCY = 5

#: WAF yoxdursa da aşılmaması tövsiyə olunan HTTP üst həddi.
NO_WAF_MAX_RPS = 10.0

#: WAF aşkarlandıqda əlavə istisna olunan nuclei tag-ları (WAF tetikləyən).
WAF_EXTRA_EXCLUDE: tuple[str, ...] = ("fuzz", "fuzzing", "intrusive")


@dataclass(frozen=True)
class StealthPlan:
    """WAF → konkret alət parametrləri (audit oluna bilən qərar)."""

    waf: str = ""
    detected: bool = False
    rate_factor: float = 1.0
    base_rate: float = 0.0
    effective_rate: float = 0.0
    concurrency: int = 0
    ua_rotation: bool = False
    jitter: tuple[float, float] = (JITTER_MIN, JITTER_MAX)
    tamper: tuple[str, ...] = ()
    encodings: tuple[str, ...] = ()
    extra_exclude_tags: tuple[str, ...] = ()
    reason: str = ""

    def rate_arg(self) -> int:
        """Alət `-rate`/`-rl` arqumenti üçün tam ədəd (≥1)."""
        return max(1, int(round(self.effective_rate)))

    def to_dict(self) -> dict:
        return {
            "waf": self.waf, "detected": self.detected,
            "rate_factor": round(self.rate_factor, 2),
            "base_rate": round(self.base_rate, 2),
            "effective_rate": round(self.effective_rate, 2),
            "concurrency": self.concurrency,
            "ua_rotation": self.ua_rotation,
            "jitter": [self.jitter[0], self.jitter[1]],
            "tamper": list(self.tamper), "encodings": list(self.encodings),
            "extra_exclude_tags": list(self.extra_exclude_tags),
            "reason": self.reason,
        }


def build_plan(*, waf_name: str = "", base_rate: float = 5.0,
               base_concurrency: int = 25, waf_adapt: bool = True) -> StealthPlan:
    """WAF identikliyindən konkret stealth planı qurur.

    `base_rate` alətin WAF-sız istifadə edəcəyi sürətdir; nəticə heç vaxt
    `base_rate`-ı AŞMIR və WAF halında `WAF_MAX_RPS`-i keçmir.
    """
    name = str(waf_name or "").strip().lower()
    detected = bool(name) and name != "none"
    base = max(0.1, float(base_rate))
    conc_base = max(1, int(base_concurrency))

    if detected and waf_adapt:
        factor = rate_factor_for(name)
        effective = min(base * factor, WAF_MAX_RPS)
        concurrency = min(conc_base, WAF_MAX_CONCURRENCY)
        reason = (f"WAF={name} aşkarlandı → sürət {factor:.2f}x azaldıldı, "
                  f"üst hədd {WAF_MAX_RPS:g} rps, UA rotasiyası ON")
        return StealthPlan(
            waf=name, detected=True, rate_factor=factor, base_rate=base,
            effective_rate=max(1.0, effective), concurrency=concurrency,
            ua_rotation=True, jitter=(JITTER_MIN, JITTER_MAX),
            tamper=tuple(tamper_for(name)), encodings=tuple(encodings_for(name)),
            extra_exclude_tags=WAF_EXTRA_EXCLUDE, reason=reason)

    effective = min(base, NO_WAF_MAX_RPS)
    reason = ("WAF aşkarlanmadı → normal sürət (təmkinli üst hədd "
              f"{NO_WAF_MAX_RPS:g} rps)")
    if detected and not waf_adapt:
        reason = (f"WAF={name} aşkarlandı, lakin waf_adapt söndürülüb → "
                  "uyğunlaşdırma tətbiq olunmur")
    return StealthPlan(
        waf=name if detected else "", detected=detected,
        rate_factor=1.0, base_rate=base,
        effective_rate=max(1.0, effective), concurrency=conc_base,
        ua_rotation=False, jitter=(JITTER_MIN, JITTER_MAX),
        tamper=tuple(tamper_for(name)) if detected else (),
        encodings=tuple(encodings_for(name)) if detected else (),
        extra_exclude_tags=(), reason=reason)
