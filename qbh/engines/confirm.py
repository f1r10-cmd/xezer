"""Confirm Engine — kandidat tapıntıların qəti (decisive) yoxlanması.

Prinsip: **yalnız real siqnal olduqda `confirmed`** — uydurma təsdiq yoxdur.

Yoxlanan siniflər:
  * CVE: canlı banner/başlıqdan aşkarlanan versiya `cve_matches`-dəki
    versiya ilə üst-üstə düşürsə → `confirmed`; üst-üstə düşmürsə → toxunulmur.
  * Exposure (js/secret/.git/config ...): cavab gövdəsində gözlənilən imza
    (signature) varsa → `confirmed` + sübut; 404/xəta → `rejected`.

Bütün sorğular Guardian/HttpPolicy → scope + rate + adaptiv blok.
"""
from __future__ import annotations

import asyncio
import re

import aiohttp

from .. import db
from ..http_policy import TargetBlocked
from ..results import EngineResult
from ..scope import ScopeError

MAX_ITEMS = 40
CONCURRENCY = 4
URL_RE = re.compile(r"https?://[^\s'\"`]+")

#: Modul → gözlənilən imza (regex). Uyğunluq "confirmed", 404 isə "rejected".
SIGNATURES = {
    "js": r"(?i)(function|var |const |=>|apikey|token|secret)",
    "content": r"(?i)(index of /|directory listing|\.git/|\.env)",
    "ferox": r"(?i)(<html|doctype|\.git/config|backup)",
    "api_enum": r"(?i)(swagger|openapi|\"paths\"|graphql)",
    "cve-intel": r"(?i)(server|nginx|apache|tomcat|php)",
}
CONFIRM_CONF = 0.85


class ConfirmEngine:
    name = "confirm"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian

    async def run(self, finding_ids: list[int] | None = None) -> EngineResult:
        res = EngineResult(stage=self.name)
        if self.guardian is None:
            res.fail("guardian yoxdur — confirm icra oluna bilməz")
            return res
        rows = self._candidates(finding_ids)
        if not rows:
            return res.skip("təsdiq üçün kandidat tapıntı yoxdur")
        print(f"[═══ CONFIRM ENGINE ═══] {len(rows)} kandidat")

        sem = asyncio.Semaphore(CONCURRENCY)
        async with aiohttp.ClientSession() as session:

            async def one(f):
                async with sem:
                    await self._check(session, f, res)

            await asyncio.gather(*[one(f) for f in rows])
        return res

    def _candidates(self, ids):
        conn = db.get_db()
        if ids:
            marks = ",".join("?" * len(ids))
            return conn.execute(
                f"SELECT f.*, h.subdomain FROM findings f "
                f"JOIN hosts h ON h.id=f.host_id "
                f"WHERE f.id IN ({marks}) AND f.status='candidate'",
                tuple(ids)).fetchall()
        return conn.execute(
            "SELECT f.*, h.subdomain FROM findings f "
            "JOIN hosts h ON h.id=f.host_id "
            "WHERE f.status='candidate' AND f.severity IN ('high','critical') "
            "ORDER BY CASE f.severity WHEN 'critical' THEN 1 ELSE 2 END "
            "LIMIT ?", (MAX_ITEMS,)).fetchall()

    async def _check(self, session, finding, res: EngineResult) -> None:
        url = self._extract_url(finding)
        if not url or not self.cfg.in_scope(url):
            return
        try:
            self.ctx.authorization.ensure_active()
            r = await self.guardian.get(session, url, allow_redirects=True)
        except (TargetBlocked, ScopeError, aiohttp.ClientError, OSError):
            return

        module = finding["module"]
        pattern = SIGNATURES.get(module)
        if module == "cve-intel":
            await self._confirm_cve(session, finding, url, r, res)
            return
        if r.status == 404:
            db.set_finding_status(finding["id"], "rejected", confidence=0.1)
            res.warnings.append(f"{url}: 404 → rejected")
            return
        if pattern and 200 <= r.status < 400 and re.search(pattern, r.text or ""):
            excerpt = (r.text or "")[:300].replace("\n", " ")
            db.set_finding_status(finding["id"], "confirmed",
                                  confidence=max(float(finding["confidence"] or 0),
                                                 CONFIRM_CONF))
            db.add_evidence(finding["id"], "http_response",
                            f"HTTP {r.status} · imza uyğundur · {excerpt}",
                            scan_id=self.ctx.scan_id)
            res.findings += 1
            print(f"   [✅] {finding['subdomain']}: '{finding['title'][:50]}' "
                  f"→ confirmed ({module})")

    async def _confirm_cve(self, session, finding, url, r, res: EngineResult) -> None:
        """Banner-də görünən versiya CVE versiyası ilə uyğun gəlirsə təsdiqlə."""
        header_blob = " ".join(f"{k}: {v}" for k, v in (r.headers or {}).items())
        row = db.get_db().execute(
            "SELECT product, version_detected FROM cve_matches "
            "WHERE host_id=? ORDER BY epss DESC LIMIT 1",
            (finding["host_id"],)).fetchone()
        if not row or not row["version_detected"]:
            return
        ver = row["version_detected"]
        if ver and ver.lower() in (header_blob + " " + (r.text or "")).lower():
            db.set_finding_status(finding["id"], "confirmed", confidence=CONFIRM_CONF)
            db.add_evidence(finding["id"], "marker",
                            f"versiya '{ver}' canlı cavabda müşahidə olundu",
                            scan_id=self.ctx.scan_id)
            res.findings += 1
            print(f"   [✅] {finding['subdomain']}: CVE versiya '{ver}' "
                  f"canlı cavabda təsdiqləndi")

    @staticmethod
    def _extract_url(finding) -> str | None:
        for source in (finding["curl_repro"], finding["evidence"]):
            if not source:
                continue
            m = URL_RE.search(str(source))
            if m:
                return m.group(0).strip("'\"`),")
        return None
