"""SSTI Engine — server-side template injection.

Təsdiq metodu (ələtlərdən ASILI OLMAYAN riyazi marker):
  * `{{7*7}}` → `49`, `{{8*8}}` → `64` (Jinja2/Twig/Freemarker ...)
  * `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}` variantları.
  İki fərqli markerin gözlənilən nəticəsi də cavabda görünürsə → `confirmed`
  (təsadüf ehtimalını azaldır). Əlavə olaraq `sstimap` işləyirsə genişləndirir.

Refleksiya olmayan / gözlənilən nəticə çıxmayan hallarda heç bir iddia
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

#: payload → gözlənilən nəticə (template engine sinfi).
MATH_PROBES: tuple[tuple[str, str], ...] = (
    ("{{7*7}}", "49"),
    ("{{8*8}}", "64"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("*{7*7}", "49"),
    ("{{7*'7'}}", "7777777"),
)

ENGINE_HINTS = ("jinja", "twig", "freemarker", "mako", "velocity", "handlebars",
                "mustache", "django", "smarty", "thymeleaf", "nunjucks", "liquid")


class SSTIEngine(OffensiveEngine):
    name = "ssti"
    tool = "sstimap"
    timeout = 600
    max_targets = 12

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        if not self.ctx.allows("active_fuzz"):
            return res.skip("aktiv fuzz qadağandır — SSTI atlandı")
        rows = self.candidate_urls(only_params=True, limit=self.max_targets)
        if not rows:
            return res.skip("parametrli URL yoxdur — SSTI atlandı")
        if not self.guardian:
            res.fail("guardian yoxdur — SSTI təhlükəsiz icra oluna bilməz")
            return res
        print(f"[═══ SSTI (riyazi marker + sstimap) ═══] {len(rows)} hədəf")

        for row in rows:
            if not await self.gate(row["url"], res, host=row["subdomain"]):
                continue
            if await self._math_marker(row, res):
                continue
            if self.tool_present():
                await self._sstimap(row, res)
        return res

    async def _math_marker(self, row, res: EngineResult) -> bool:
        try:
            target = URL(row["url"])
        except (ValueError, TypeError):
            return False
        if not target.query or not self.cfg.in_scope(target.host or ""):
            return False
        params = dict(target.query)
        key = next(iter(params))

        async with aiohttp.ClientSession() as session:
            hits: list[tuple[str, str]] = []
            for payload, expect in MATH_PROBES:
                p = dict(params)
                p[key] = payload
                probe = str(target.with_query(p))
                body = await self._fetch(session, probe, row["subdomain"])
                if body is not None and expect in body:
                    hits.append((payload, expect))
            # İki FƏRQLİ marker də təsdiqlənirsə → güclü sübut.
            if len({h[1] for h in hits}) < 2:
                return False

        evidence = "; ".join(f"{pl}→{ex}" for pl, ex in hits)
        fid = self.record(
            row["host_id"], "high", "Server-Side Template Injection",
            f"{row['url']} — riyazi marker payload-ları serverdə "
            f"hesablanaraq cavabda qaytarılır ({evidence}).",
            evidence=evidence, confidence=0.85, status="candidate",
            source="math-marker")
        self.confirm(fid, "marker", f"SSTI riyazi marker: {evidence}",
                     confidence=0.95)
        res.findings += 1
        print(f"[🔴] {row['subdomain']}: SSTI TƏSDİQLƏNDİ ({evidence})")
        return True

    async def _fetch(self, session, url: str, host: str) -> str | None:
        try:
            r = await self.guardian.get(
                session, url, allow_redirects=False,
                headers={"User-Agent": ua_for(host)})
        except (aiohttp.ClientError, asyncio.TimeoutError, ScopeError):
            return None
        if r.status >= 500:
            return None
        return r.text

    async def _sstimap(self, row, res: EngineResult) -> None:
        cmd = ["sstimap", "-u", row["url"], "--level", "2", "--no-color"]
        # Faza 1.2: TƏK egress qapısı (scope + fail-closed DNS pinning).
        proc = await self.ctx.egress.run(cmd, targets=[row["url"]],
                                         timeout=self.timeout)
        if proc.blocked:
            res.warn("sstimap: egress qapısı hədəfi bloklandı")
            return
        if proc.missing:
            return
        out = proc.stdout.decode(errors="ignore")
        if not re.search(r"(vulnerable|SSTI|inject)", out, re.I):
            return
        excerpt = "\n".join(out.splitlines()[:30])[:1200]
        fid = self.record(
            row["host_id"], "high", "SSTI (sstimap təsdiq)",
            f"sstimap {row['url']} üzərində şablon mühərriki inyeksiyası bildirdi.",
            evidence=excerpt, confidence=0.7, status="candidate", source="sstimap")
        self.confirm(fid, "marker", excerpt, confidence=0.85)
        res.findings += 1
        print(f"[🟠] {row['subdomain']}: SSTI siqnalı (sstimap)")
