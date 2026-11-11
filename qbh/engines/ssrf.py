"""SSRF Engine — server-side request forgery (blind təsdiq OOB ilə).

Trigger: URL-formalı parametr, fetch/import/proxy funksionallığı.

Təsdiq:
  * Parametrə unikal OOB correlation URL yerləşdirilir →
    `ctx.oob` ünvanına geri-zəng gələrsə finding `confirmed` olur
    (zaman möhürlü sübut).
  * OOB konfiqurasiya olunmayıbsa (`domain` yoxdur) blind təsdiq MÜMKÜN
    DEYİL — bu hal DÜRÜST şəkildə bildirilir və heç bir uydurma təsdiq
    verilmir.
"""
from __future__ import annotations

import asyncio
import re

import aiohttp
from yarl import URL

from ..antiblock.ua_rotator import ua_for
from ..results import EngineResult
from ..scope import ScopeError
from .offensive import OffensiveEngine

SSRF_PARAM_NAMES = re.compile(
    r"(?i)^(url|uri|link|src|source|dest|destination|redirect|next|return|"
    r"continue|callback|webhook|fetch|import|proxy|image|img|file|path|host|"
    r"domain|target|feed|rss|remote|load|open|resource|page|view|to|out|"
    r"u|q|address|site|href|goto|domain_url|api)$")
URLISH = re.compile(r"^https?://", re.I)


class SSRFEngine(OffensiveEngine):
    name = "ssrf"
    tool = ""            # OOB-əsaslı; xarici binary tələb olunmur
    timeout = 300
    max_targets = 20

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        if not self.ctx.allows("active_fuzz"):
            return res.skip("aktiv fuzz qadağandır — SSRF atlandı")
        rows = self.candidate_urls(only_params=True, limit=self.max_targets)
        if not rows:
            return res.skip("parametrli URL yoxdur — SSRF atlandı")
        if self.ctx.guardian is None:
            res.fail("guardian yoxdur — SSRF təhlükəsiz icra oluna bilməz")
            return res

        oob = self.ctx.oob
        if not oob.active:
            res.warn("OOB geri-zəng konfiqurasiya olunmayıb (oob.domain yoxdur) "
                     "— blind SSRF təsdiqi mümkün deyil (dürüst məhdudiyyət)")
            return res.skip("OOB aktiv deyil")
        print(f"[═══ SSRF (OOB) ═══] {len(rows)} hədəf")

        for row in rows:
            if not await self.gate(row["url"], res, host=row["subdomain"]):
                continue
            await self._probe_row(row, oob, res)
        return res

    def _ssrf_params(self, url: str) -> list[str]:
        try:
            q = URL(url).query
        except (ValueError, TypeError):
            return []
        out = []
        for name, val in q.items():
            if SSRF_PARAM_NAMES.match(name) or URLISH.match(val or ""):
                out.append(name)
        return out

    async def _probe_row(self, row, oob, res: EngineResult) -> None:
        params = self._ssrf_params(row["url"])
        if not params:
            return
        try:
            target = URL(row["url"])
        except (ValueError, TypeError):
            return
        if not self.cfg.in_scope(target.host or ""):
            return

        async with aiohttp.ClientSession() as session:
            for name in params:
                token = oob.register()
                callback = oob.url_for(token)
                p = dict(target.query)
                p[name] = callback
                probe = str(target.with_query(p))
                await self._send(session, probe, row["subdomain"])

                delivered = await oob.wait_for(token, timeout=float(
                    getattr(self.cfg.oob, "wait", 20.0)))
                if not delivered:
                    continue
                hits = oob.hits(token)
                ev = hits[0].to_evidence() if hits else f"callback {callback}"
                fid = self.record(
                    row["host_id"], "high", "SSRF (OOB ilə təsdiq)",
                    f"{probe} — parametr '{name}' server tərəfindən "
                    f"götürülüb və geri-zəng gəlib.",
                    evidence=ev, confidence=0.8, status="candidate",
                    source="oob")
                self.confirm(fid, "callback",
                             f"SSRF OOB təsdiq: {ev}", confidence=0.95)
                res.findings += 1
                print(f"[🔴] {row['subdomain']}: SSRF TƏSDİQLƏNDİ ('{name}')")
                break

    async def _send(self, session, url: str, host: str) -> None:
        try:
            await self.ctx.guardian.get(
                session, url, allow_redirects=False,
                headers={"User-Agent": ua_for(host)})
        except (aiohttp.ClientError, asyncio.TimeoutError, ScopeError):
            pass
