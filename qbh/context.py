"""Pipeline konteksti — bütün mühərriklər bunu alır.

Dövrəli import-un qarşısını almaq üçün ayrı modulda saxlanılır.
`authorization` skan boyu YEGANƏ scope/RoE qərar mərkəzidir.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Context:
    cfg: Any                 # qbh.config.Config
    args: Any                # argparse.Namespace
    guardian: Any            # qbh.antiblock.guardian.Guardian
    scan_id: int | None = None
    authorization: Any = None  # qbh.authorization.Authorization
    #: DNS pinning audit (Faza 0.2): host → (IP-lər, həll vaxtı).
    resolved_ips: dict = field(default_factory=dict)
    #: Egress audit jurnalı (rədd edilən hədəflər, pin edilmiş IP-lər).
    egress_audit: list = field(default_factory=list)
    #: Aşkarlanmış WAF adı (Faza 2.2) — SQLi/SSTI tamper seçimi üçün.
    waf_name: str = ""
    _egress: Any = None
    _oob: Any = None
    _stealth: Any = None

    def _auth(self):
        """Authorization yoxdursa konfiqdən təmin edir (fail-closed)."""
        if self.authorization is None:
            from .authorization import from_config

            self.authorization = from_config(self.cfg, self.scan_id)
        return self.authorization

    @property
    def egress(self):
        """Subprocess hədəf validasiyası üçün tək giriş nöqtəsi (Faza 0.2)."""
        if self._egress is None:
            from .egress import EgressController

            self._egress = EgressController(
                self._auth(),
                resolved_store=self.resolved_ips,
                audit=self.egress_audit)
        return self._egress

    @property
    def oob(self):
        """Sistem üzrə tək OOB geri-zəng idarəçisi (Faza 1.4)."""
        if self._oob is None:
            from .oob import OOBManager

            cfg = getattr(self.cfg, "oob", None)
            self._oob = OOBManager(
                domain=getattr(cfg, "domain", "") or "",
                enabled=getattr(cfg, "enabled", False),
                listen_host=getattr(cfg, "listen_host", "127.0.0.1"),
                listen_port=getattr(cfg, "listen_port", 0),
                backend=getattr(cfg, "backend", "local"),
                audit=self.egress_audit)
        return self._oob

    @property
    def stealth(self):
        """Stealth vəziyyəti: TLS təqlidi + tempo + WAF (Faza 2)."""
        if self._stealth is None:
            from .stealth import ImpersonatingTransport, Pacer, StealthStack

            scfg = getattr(self.cfg, "stealth", None)
            transport = ImpersonatingTransport(
                getattr(scfg, "impersonate", "off"),
                timeout=float(self.limits.total_timeout))
            pacer = Pacer(
                getattr(scfg, "pacing", "aggressive"), rate=self.rate,
                max_overhead=float(getattr(scfg, "pacing_max_overhead", 1.15)))
            self._stealth = StealthStack(cfg=scfg, transport=transport,
                                         pacer=pacer,
                                         audit=self.egress_audit)
        return self._stealth

    def note_waf(self, profile) -> None:
        """WAF aşkarlamasını qeyd edir və `waf_name`-i sinxronlaşdırır."""
        self.stealth.note_waf(profile)
        self.waf_name = self.stealth.waf_name

    @property
    def rate(self) -> float:
        cli = getattr(self.args, "rate", None)
        base = float(self.cfg.effective_rate)
        if cli is None:
            return base
        return max(0.1, min(float(cli), base))

    @property
    def limits(self):
        return self.cfg.limits

    @property
    def scope(self):
        return self.cfg.scope

    @property
    def active_fuzz(self) -> bool:
        """Aktiv fuzzinq: profil default-u ON, proqram qadağası və CLI override.

        Qayda: proqram qadağan edərsə → həmişə False.
        Əks halda CLI eksplisit seçim edərsə o tətbiq olunur, yoxsa profil
        (passive|normal|aggressive) default-u işləyir.
        """
        auth = self._auth()
        if not auth.allows("active_fuzz"):
            return False
        override = getattr(self.args, "active_fuzz", None)
        if override is None:
            return True
        return bool(override)

    @property
    def race_fixture(self) -> str | None:
        """Yalnız açıq göstərilən lokal fixture üzərində race testi."""
        return getattr(self.args, "race_fixture", None)

    def in_scope(self, host: str) -> bool:
        return self.cfg.in_scope(host)

    def authorize_url(self, url: str) -> str:
        return self._auth().authorize_url(url)

    def allows(self, action: str) -> bool:
        return self._auth().allows(action)
