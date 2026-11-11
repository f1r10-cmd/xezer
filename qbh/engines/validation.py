"""Validation Engine — sübut yoxlaması və false-positive süzgəci.

Məqsəd: `high`/`critical` tapıntıların təkrar HTTP yoxlaması ilə
sübutunun mövcudluğunu qiymətləndirmək və AYDIQ şəkildə hansı tapıntının
yalnız HEURISTIK olduğunu qeyd etmək.

Prinsiplər:
  * Yalnız heuristic siqnal varsa "confirmed" İDDİA EDİLMİR — tapıntı
    `potential` statusunda qalır, `validated` cədvəlində nəticə saxlanır.
  * Yenidən yoxlama sorğusu Guardian/HttpPolicy-dən keçir (scope + rate +
    cooldown). Scope xaricindədirsə sorğu GÖNDƏRİLMİR.
  * URL əlçatmazdırsa/yoxdursa → `passed=NULL` (yoxlanıla bilmədi).
  * Yenidən yoxlama uğursuz olduqda tapıntı `false-positive` kimi işarələnir.
"""
from __future__ import annotations

import asyncio
import re

import aiohttp

from .. import db
from ..http_policy import TargetBlocked
from ..results import EngineResult
from ..scope import ScopeError

FP_PATTERNS = [
    (r"(?i)lorem ipsum|example\.com|placeholder", "placeholder məzmun"),
    (r"(?i)jquery|bootstrap|font-?awesome", "framework qalıntısı"),
]

MAX_CHECKS = 100
CONCURRENCY = 5
RECHECK_TIMEOUT = 15
URL_RE = re.compile(r"https?://[^\s'\"`]+")


class ValidationEngine:
    name = "validation"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        conn = db.get_db()
        pending = conn.execute(
            "SELECT f.*, h.subdomain FROM findings f "
            "JOIN hosts h ON h.id = f.host_id "
            "WHERE f.severity IN ('high','critical') "
            "AND f.status != 'rejected' "
            "AND f.id NOT IN (SELECT finding_id FROM validated) "
            "LIMIT ?", (MAX_CHECKS,)).fetchall()
        if not pending:
            return res.skip("yoxlanılacaq high/critical tapıntı yoxdur")
        if not self.guardian:
            res.fail("guardian yoxdur — validation təhlükəsiz icra oluna bilməz")
            return res
        print(f"[═══ VALIDATION ENGINE ═══] {len(pending)} tapıntı")

        sem = asyncio.Semaphore(CONCURRENCY)
        async with aiohttp.ClientSession() as session:

            async def check(f):
                async with sem:
                    await self._check(session, f, res)

            await asyncio.gather(*[check(f) for f in pending])
        return res

    async def _check(self, session, finding, res: EngineResult) -> None:
        host = finding["subdomain"]
        url = self._extract_url(finding)
        if not url:
            db.upsert_validated(finding["id"], None,
                                "yenidən yoxlama mümkün deyil: URL yoxdur")
            res.warn(f"{host}: '{finding['title'][:40]}' üçün URL yoxdur")
            return
        if not self.cfg.in_scope(url):
            db.upsert_validated(finding["id"], None,
                                "URL scope xaricindədir — sorğu göndərilmədi")
            res.warn(f"scope xaricində URL yoxlanılmadı: {url}")
            return

        try:
            r = await self.guardian.get(session, url, allow_redirects=True)
        except TargetBlocked as exc:
            db.upsert_validated(finding["id"], None, f"cooldown: {exc}")
            res.warn(f"{host}: {exc}")
            return
        except (ScopeError, aiohttp.ClientError, OSError) as exc:
            db.upsert_validated(finding["id"], None,
                                f"sorğu alınmadı: {type(exc).__name__}")
            res.warn(f"{host}: yenidən yoxlama alınmadı ({type(exc).__name__})")
            return

        passed, note = self._classify(r)
        db.upsert_validated(finding["id"], passed, note)
        if passed is False:
            db.set_finding_status(finding["id"], "rejected")
        mark = {True: "✅", False: "❌", None: "❓"}[passed]
        print(f"  {mark} {host}: {finding['title'][:60]} ({note})")

    @staticmethod
    def _extract_url(finding) -> str | None:
        for source in (finding["curl_repro"], finding["evidence"]):
            if not source:
                continue
            m = URL_RE.search(str(source))
            if m:
                return m.group(0).strip("'\"`),")
        return None

    @staticmethod
    def _classify(resp) -> tuple[bool | None, str]:
        if resp.status in (404, 410):
            return False, "resurs artıq mövcud deyil (404/410)"
        if resp.status >= 500:
            return None, f"server xətası ({resp.status}) — qiymətləndirilə bilməz"
        body = resp.text or ""
        for pat, label in FP_PATTERNS:
            if re.search(pat, body):
                return False, f"false-positive: {label}"
        if resp.status in (200, 301, 302, 401, 403):
            return True, f"resurs əlçatandır (status {resp.status})"
        return None, f"qeyri-müəyyən status ({resp.status})"
