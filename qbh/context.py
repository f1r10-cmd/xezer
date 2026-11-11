"""Pipeline konteksti — bütün mühərriklər bunu alır.

Dövrəli import-un qarşısını almaq üçün ayrı modulda saxlanılır.
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

    @property
    def rate(self) -> float:
        return float(getattr(self.args, "rate", 5) or 5)

    @property
    def limits(self):
        return self.cfg.limits

    @property
    def scope(self):
        return self.cfg.scope

    @property
    def active_fuzz(self) -> bool:
        """Aktiv/state-dəyişən fuzzinq yalnız açıq icazə ilə."""
        return bool(getattr(self.args, "active_fuzz", False))

    @property
    def race_fixture(self) -> str | None:
        """Yalnız açıq göstərilən lokal fixture üzərində race testi."""
        return getattr(self.args, "race_fixture", None)

    def in_scope(self, host: str) -> bool:
        return self.cfg.in_scope(host)
