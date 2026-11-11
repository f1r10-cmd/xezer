"""Pipeline konteksti — bütün mühərriklər bunu alır.

Dövrəli import-un qarşısını almaq üçün ayrı modulda saxlanılır.
`authorization` skan boyu YEGANƏ scope/RoE qərar mərkəzidir.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Context:
    cfg: Any                 # qbh.config.Config
    args: Any                # argparse.Namespace
    guardian: Any            # qbh.antiblock.guardian.Guardian
    scan_id: int | None = None
    authorization: Any = None  # qbh.authorization.Authorization

    def _auth(self):
        """Authorization yoxdursa konfiqdən təmin edir (fail-closed)."""
        if self.authorization is None:
            from .authorization import from_config

            self.authorization = from_config(self.cfg, self.scan_id)
        return self.authorization

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
