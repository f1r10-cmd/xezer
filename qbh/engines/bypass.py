"""Bypass Engine — 401/403 cavablarını aşma cəhdi (Faza 2/3).

Məntiq:
  1. `urls` cədvəlindən "maraqlı" yollar götürülür (admin/api/login/upload ...).
  2. Hər yol üçün baseline GET edilir.
  3. Cavab **401/403**-dürsə, `payloads.build_matrix` ilə bypass texnikaları
     (path normalizasiya, encoding, header tricks, verb tampering) sınanır.
  4. İlk uğurlu cəhd (2xx/3xx, lakin bypass-dan sonra fərqli status) →
     tapıntı `confirmed` edilir və sübut (request/response markeri) saxlanılır.

Bütün sorğular Guardian/HttpPolicy-dən keçir → scope + rate + adaptiv blok.
Proqram `bypass` hərəkətini qadağan edibsə, mühərrik atlanır.
"""
from __future__ import annotations

import asyncio
import re

import aiohttp

from .. import db
from ..http_policy import TargetBlocked
from ..payloads import build_matrix
from ..results import EngineResult
from ..scope import ScopeError

INTERESTING_RE = re.compile(
    r"(?i)(admin|api|internal|private|login|upload|debug|config|"
    r"backup|\.git|swagger|actuator|manage|dashboard|/v\d+/|graphql)")

MAX_URLS = 25
MAX_HTML = 400
CONCURRENCY = 4
BYPASS_OK = 0.8
GUARD_CODES = {401, 403, 405, 404}


class BypassEngine:
    name = "bypass"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian

    async def run(self, urls: list[str] | None = None) -> EngineResult:
        res = EngineResult(stage=self.name)
        if not self.ctx.allows("bypass"):
            return res.skip("proqram qaydaları bypass'ı qadağan edir")
        if self.guardian is None:
            res.fail("guardian yoxdur — bypass icra oluna bilməz")
            return res

        candidates = urls if urls is not None else self._db_candidates()
        if not candidates:
            return res.skip("bypass üçün maraqlı endpoint tapılmadı")
        # Faza 4.4: artıq təsdiqlənmiş (confirmed/reported) endpoint YENİDƏN
        # sınanmır — 'təsdiqlənmiş tapıntı heç vaxt yenidən skan edilmir'.
        settled = db.settled_targets(self.name, self.ctx.scan_id)
        if settled:
            fresh = [u for u in candidates if u not in settled]
            if len(fresh) != len(candidates):
                print(f"   [♻] {len(candidates) - len(fresh)} endpoint artıq "
                      f"təsdiqlənib — yenidən sınanmır (reuse)")
            candidates = fresh
        if not candidates:
            return res.skip("bütün namizədlər artıq təsdiqlənib — yenidən skan yoxdur")
        print(f"[═══ BYPASS ENGINE ═══] {len(candidates)} endpoint")

        sem = asyncio.Semaphore(CONCURRENCY)
        async with aiohttp.ClientSession() as session:

            async def one(u):
                async with sem:
                    await self._probe(session, u, res)

            await asyncio.gather(*[one(u) for u in candidates])
        return res

    def _db_candidates(self) -> list[str]:
        rows = db.get_db().execute(
            "SELECT u.url, h.id AS host_id, h.subdomain FROM urls u "
            "JOIN hosts h ON h.id=u.host_id "
            "WHERE h.status_code IS NOT NULL "
            "AND (h.halted IS NULL OR h.halted=0) AND h.scan_id=? "
            "LIMIT 500", (db.effective_scan_id(self.ctx.scan_id),)).fetchall()
        picked: list[str] = []
        for r in rows:
            if INTERESTING_RE.search(r["url"]):
                picked.append(r["url"])
            if len(picked) >= MAX_URLS:
                break
        return picked

    async def _probe(self, session, url: str, res: EngineResult) -> None:
        if not self.cfg.in_scope(url):
            return
        try:
            # `observe_block=False` → 403/429 xam qaytarılır, host cooldown-a
            # düşmür; beləliklə matris eyni yol üzrə sınana bilir.
            base = await self.guardian.get(session, url, allow_redirects=False,
                                           observe_block=False)
        except (TargetBlocked, ScopeError, aiohttp.ClientError, OSError):
            return
        if base.status not in (401, 403):
            return
        res.warnings.append(f"{url}: HTTP {base.status} → bypass matrisi sınanır")
        print(f"   [↻] {url}: HTTP {base.status} → bypass matrisi sınanır")

        for attempt in build_matrix(url):
            self.ctx.authorization.ensure_active()
            if not self.cfg.in_scope(attempt.url):
                continue
            try:
                r = await self.guardian.request(
                    session, attempt.method, attempt.url, headers=attempt.headers,
                    allow_redirects=False, observe_block=False)
            except (TargetBlocked, ScopeError, aiohttp.ClientError, OSError):
                continue
            if r.status not in GUARD_CODES and 200 <= r.status < 400:
                self._record(url, attempt, base.status, r, res)
                return

    def _record(self, url, attempt, base_status, resp, res: EngineResult) -> None:
        row = db.get_db().execute(
            "SELECT h.id AS host_id, h.subdomain FROM urls u "
            "JOIN hosts h ON h.id=u.host_id WHERE u.url=? AND h.scan_id=?",
            (url, db.effective_scan_id(self.ctx.scan_id))).fetchone()
        if not row:
            return
        excerpt = (resp.text or "")[:MAX_HTML].replace("\n", " ")
        title = (f"Authorization bypass: HTTP {base_status} → {resp.status} "
                 f"({attempt.label})")
        desc = (
            f"`{url}` baseline cavabı HTTP {base_status} idi. "
            f"`{attempt.label}` texnikası ilə HTTP {resp.status} alındı — "
            f"resurs icazəsiz əlçatan görünür. Yenidən manual təsdiq tövsiyə olunur.")
        curl = (f"curl -sk -X {attempt.method} '{attempt.url}' "
                + " ".join(f"-H '{k}: {v}'" for k, v in attempt.headers.items()))
        fid = db.insert_finding(
            row["host_id"], "bypass", "high", title, desc,
            evidence=f"{attempt.url} → {resp.status}", curl_repro=curl,
            confidence=BYPASS_OK, status="confirmed",
            source=f"bypass:{attempt.label}", scan_id=self.ctx.scan_id)
        if fid > 0:
            db.add_evidence(fid, "http_response",
                            f"baseline={base_status} bypass={resp.status} "
                            f"method={attempt.method} {excerpt}",
                            scan_id=self.ctx.scan_id)
            # Faza 4.4: hədəfi sübutda qeyd et → sonrakı mərhələ bu endpoint-i
            # yenidən skan etməsin (`db.settled_targets`).
            db.add_evidence(fid, "data", f"target={url}",
                            scan_id=self.ctx.scan_id)
        res.findings += 1
        print(f"   [🔓] {row['subdomain']}: {attempt.label} → "
              f"HTTP {resp.status} (confirmed)")
