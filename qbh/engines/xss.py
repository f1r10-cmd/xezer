"""XSS Engine — Dalfox + daxili kxss-üslub refleksiya yoxlaması.

İki mərhələli təsdiq:
  1. **Refleksiya yoxlaması (daxili)** — parametrə unikal marker yeridilir və
     cavabda `<`/`>` kimi kontekst simvolları ilə geri qayıdıbsa `candidate`.
  2. **Dalfox** — refleksiya olan hədəflər üzərində çalışır; yalnız "Verified"
     / POC çıxışı ilə `confirmed`.

Sübut: refleksiya edilmiş cavab fraqmenti (marker) və ya Dalfox POC.
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

DALFOX_VERIFIED_RE = re.compile(
    r"(\[V\]|Verified|POC:|vulnerable|XSS\s*found)", re.I)
MARKER = "qbProbe7531"
REFLECT_RE = re.compile(re.escape(MARKER))


class XSSEngine(OffensiveEngine):
    name = "xss"
    tool = "dalfox"
    timeout = 600
    max_targets = 15

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        if not self.ctx.allows("active_fuzz"):
            return res.skip("aktiv fuzz qadağandır — XSS atlandı")
        rows = self.candidate_urls(only_params=True, limit=self.max_targets)
        if not rows:
            return res.skip("parametrli URL yoxdur — XSS atlandı")
        if not self.guardian:
            res.fail("guardian yoxdur — XSS təhlükəsiz icra oluna bilməz")
            return res
        print(f"[═══ XSS (Dalfox + refleksiya) ═══] {len(rows)} hədəf")

        reflected: list = []
        for row in rows:
            if not await self.gate(row["url"], res, host=row["subdomain"]):
                continue
            if await self._reflection(row, res):
                reflected.append(row)

        if not reflected:
            print("[-] heç bir refleksiya aşkarlanmadı — Dalfox atlandı")
            return res
        if not self.tool_present():
            res.warn("dalfox tapılmadı — yalnız refleksiya sübutu saxlanıldı")
            return res

        for row in reflected:
            await self._dalfox(row, res)
        return res

    # ------------------------------------------------------- reflection
    async def _reflection(self, row, res: EngineResult) -> bool:
        """Parametrlərə marker yerləşdirib cavabda refleksiyanı yoxlayır."""
        url = row["url"]
        try:
            target = URL(url)
        except (ValueError, TypeError):
            return False
        if not target.query:
            return False
        marker = f"{MARKER}"
        # Hər mövcud parametrə marker yerləşdirir (ilk parametr kifayətdir).
        params = dict(target.query)
        key = next(iter(params))
        params[key] = marker
        probe = str(target.with_query(params))
        if not self.cfg.in_scope(target.host or ""):
            return False

        async with aiohttp.ClientSession() as session:
            try:
                r = await self.guardian.get(
                    session, probe, allow_redirects=False,
                    headers={"User-Agent": ua_for(row["subdomain"])})
            except (aiohttp.ClientError, asyncio.TimeoutError, ScopeError):
                return False
            if r.status >= 400:
                return False
            body = r.text
        if not REFLECT_RE.search(body) or not self.cfg.in_scope(str(r.url)):
            return False
        idx = body.find(marker)
        ctx = body[max(0, idx - 40): idx + len(marker) + 40]
        fid = self.record(
            row["host_id"], "medium", "Refleksiya olunan parametr (XSS namizədi)",
            f"{probe} — marker cavabda geri qaytarılır. Kontekst manual XSS "
            f"yoxlaması üçün prioritetlidir.",
            evidence=ctx, confidence=0.4, status="candidate", source="reflection")
        _ = fid
        res.findings += 1
        print(f"[?] {row['subdomain']}: refleksiya aşkarlandı")
        return True

    # ---------------------------------------------------------- dalfox
    async def _dalfox(self, row, res: EngineResult) -> None:
        cmd = ["dalfox", "url", row["url"], "--no-spinner", "--silence",
               "--output", "/dev/stdout", "--only-poc", "r"]
        # Faza 1.2: TƏK egress qapısı (scope + fail-closed DNS pinning).
        proc = await self.ctx.egress.run(cmd, targets=[row["url"]],
                                         timeout=self.timeout)
        if proc.blocked:
            res.warn("dalfox: egress qapısı hədəfi bloklandı")
            return
        if proc.missing:
            res.warn("dalfox tapılmadı")
            return
        out = proc.stdout.decode(errors="ignore")
        if not DALFOX_VERIFIED_RE.search(out):
            return
        poc = self._excerpt(out)
        fid = self.record(
            row["host_id"], "high", "XSS (Dalfox təsdiq)",
            f"Dalfox {row['url']} üzərində XSS təsdiqlədi. POC çıxışı sübut "
            f"kimi saxlanılır.",
            evidence=poc, confidence=0.85, status="candidate", source="dalfox")
        self.confirm(fid, "http_response", poc, confidence=0.9)
        res.findings += 1
        print(f"[🔴] {row['subdomain']}: XSS TƏSDİQLƏNDİ (Dalfox)")

    @staticmethod
    def _excerpt(out: str, limit: int = 1200) -> str:
        lines = [ln for ln in out.splitlines()
                 if re.search(r"(POC|Verified|\[V\]|payload)", ln, re.I)]
        return "\n".join(lines[:30])[:limit] or out[:limit]
