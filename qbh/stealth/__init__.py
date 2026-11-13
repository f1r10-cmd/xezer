"""Faza 2 — Stealth qatı (deteksiya azaltma).

Bu paket profil-əsaslı və **audit oluna bilən** deteksiya-azaltma nəzarətlərini
bir yerə toplayır:

  * `waf`         — WAF barmaq izi + adaptiv bypass/tamper/rate qərarları.
  * `impersonate` — curl_cffi ilə TLS/HTTP2 barmaq izi təqlidi (yoxdursa dürüst
                    şəkildə "mövcud deyil" bildirir, heç vaxt uydurmur).
  * `pacing`      — insan-təqlidi fasilələr; bulk fazalarda `pacing_max_overhead`
                    həddini AŞMIR (sürət qorunur).
  * `proxy`       — proxy strategiyası seçimi; Tor YALNIZ həssas fazalarda
                    (bulk fuzzinqdə Tor-un gecikməsi sürəti məhv edərdi).
  * `ladder`      — Guardian eskalasiya nərdivanı (əyləc deyil, adaptiv qərar).

**Dürüstlük.** Bu qat deteksiyanı AZALDIR, "görünməzlik" VƏD ETMİR. Xüsusilə:
subprocess alətləri üçün tam egress nəzarəti OS səviyyəli sandbox tələb edir
(`docs/STEALTH.md`); CAPTCHA avtomatik həll OLUNMUR.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .humanize import Humanizer
from .impersonate import (
    ImpersonatingTransport,
    impersonation_available,
    resolve_target,
)
from .ladder import EscalationLadder, LadderDecision
from .pacing import Pacer
from .policy import StealthPlan, build_plan
from .proxy import ProxyPlan, is_sensitive_phase, plan_proxy
from .waf import WafProfile, detect_waf, encodings_for, rate_factor_for, tamper_for


@dataclass
class StealthStack:
    """Bir skan üçün stealth vəziyyəti (konfiq + transport + tempo + WAF).

    `waf` sahəsi `WafDetectEngine` tərəfindən doldurulur; `ctx.waf_name` da
    ondan oxunur ki, SQLi/SSTI kimi mühərriklər uyğun tamper/payload seçə bilsin.
    """

    cfg: Any = None
    transport: ImpersonatingTransport | None = None
    pacer: Pacer | None = None
    waf: WafProfile = field(default_factory=WafProfile)
    audit: list = field(default_factory=list)
    humanizer: Humanizer = field(default_factory=Humanizer)

    @property
    def waf_name(self) -> str:
        return self.waf.name if self.waf.detected else ""

    def note_waf(self, profile: WafProfile) -> None:
        """WAF aşkarlamasını qeyd edir (yalnız daha güclü nəticə üstün gəlir)."""
        if profile is None or not profile.detected:
            return
        if profile.confidence >= self.waf.confidence:
            self.waf = profile
        self.audit.append({"event": "waf_detected", **profile.to_dict()})

    def proxy_plan(self, phase: str) -> ProxyPlan:
        cfg = self.cfg
        return plan_proxy(
            getattr(cfg, "proxy_strategy", "off"), phase,
            tor_for_sensitive_only=getattr(cfg, "tor_for_sensitive_only", True))

    def plan(self, base_rate: float, *, base_concurrency: int = 25,
             phase: str = "") -> StealthPlan:
        """Aşkarlanmış WAF-a görə konkret alət parametrlərini hesablayır.

        Qərar audit olunur (`waf_detected` kimi) → hansı sürətin və
        template seçiminin nə üçün dəyişdiyi sonradan izlənə bilər.
        """
        cfg = self.cfg
        p = build_plan(
            waf_name=self.waf_name, base_rate=base_rate,
            base_concurrency=base_concurrency,
            waf_adapt=bool(getattr(cfg, "waf_adapt", True)))
        self.audit.append({"event": "stealth_plan", "phase": phase,
                           **p.to_dict()})
        return p

    def summary(self) -> dict:
        return {
            "impersonate": (self.transport.summary() if self.transport
                            else {"available": False, "reason": "yoxdur"}),
            "pacing": (self.pacer.stats() if self.pacer else {}),
            "waf": self.waf.to_dict(),
        }


__all__ = [
    "EscalationLadder",
    "Humanizer",
    "ImpersonatingTransport",
    "LadderDecision",
    "Pacer",
    "ProxyPlan",
    "StealthPlan",
    "StealthStack",
    "WafProfile",
    "build_plan",
    "detect_waf",
    "encodings_for",
    "impersonation_available",
    "is_sensitive_phase",
    "plan_proxy",
    "rate_factor_for",
    "resolve_target",
    "tamper_for",
]
