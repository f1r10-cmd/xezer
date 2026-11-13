"""Faza 3.5 — Hunter orkestratoru ('avtomatik zəncir').

Tək `hunt` rejimində bütün hunter dövrünü ardıcıl və AÇIQ şəkildə icra edir:

    subdomain → canlı → fingerprint → JS → secret/param → fuzz → CVE →
    confirm → PoC → hesabat

Əlavə olaraq **dərin mərhələ** (`hunter_deep`) işlədilir:
  * `admin/login/upload/...` kimi **yüksək-dəyərli endpoint-lər** seçilir;
  * onlardan 401/403 qaytaranlar üçün **bypass matrisi** sınanır.

Prinsiplər:
  * Heç bir yeni şəbəkə yolu yaradılmır — mövcud mühərriklər (Recon, Vuln,
    ChainPipeline, BypassEngine) `Conductor` vasitəsilə çağırılır və onlar
    `HttpPolicy`/`Guardian` (scope + rate + cooldown) qapılarından keçir.
  * Gedişat RoE (`program_rules.forbidden`) və skan büdcəsi ilə bağlıdır;
    qadağan olunan addımlar sadəcə atlanır və audit olunur.
"""
from __future__ import annotations

import re

from . import db
from .engines.bypass import BypassEngine

#: Yüksək-dəyərli endpoint işarələri (dərin zəncir prioriteti).
HIGH_VALUE_RE = re.compile(
    r"(?i)(admin|login|signin|sign-in|upload|portal|manage|dashboard|"
    r"console|webhook|/api/|actuator|graphql|internal|private)")
MAX_DEEP = 20


class Hunter:
    """Conductor üzərində qurulmuş ardıcıl (avtomatik) hunter orkestratoru."""

    name = "hunter"

    def __init__(self, conductor):
        self.conductor = conductor
        self.ctx = conductor.ctx
        self.auth = conductor.authorization

    async def hunt(self) -> None:
        """Tam hunter dövrünü skan həyat dövrü içində icra edir."""
        c = self.conductor
        c.resolve_targets()

        async def body():
            await c.run_recon()        # subdomain → canlı
            await c.run_vuln()         # fingerprint → JS → secret/param → fuzz
                                       # → CVE → confirm → chain(PoC) → hesabat
            await self._deep_pass()    # 401/403 → bypass + yüksək-dəyər dərin zəncir

        await c._pipeline("hunt", body)

    # ------------------------------------------------------------- deep pass
    def _high_value_urls(self) -> list[str]:
        """Cari skanın yüksək-dəyərli endpoint-lərini qaytarır (limitli)."""
        rows = db.get_db().execute(
            "SELECT DISTINCT u.url FROM urls u JOIN hosts h ON h.id=u.host_id "
            "WHERE h.scan_id=? AND (h.halted IS NULL OR h.halted=0) "
            "LIMIT 800",
            (db.effective_scan_id(self.ctx.scan_id),)).fetchall()
        out: list[str] = []
        for r in rows:
            if HIGH_VALUE_RE.search(r["url"]) and r["url"] not in out:
                out.append(r["url"])
            if len(out) >= MAX_DEEP:
                break
        return out

    async def _deep_pass(self) -> None:
        """Yüksək-dəyərli endpoint-lər üzərində bypass matrisini sınayır.

        `BypassEngine` yalnız baseline 401/403 olan yollarda matrisi işə salır;
        yəni bu, əlavə və hədəfli (noise-aşağı) bir dərinləşdirmədir.
        """
        urls = self._high_value_urls()
        if not urls:
            return
        await self.conductor._run_stage(
            "hunter_deep", "",
            lambda: BypassEngine(self.ctx).run(urls))
