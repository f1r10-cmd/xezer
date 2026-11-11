"""Library CVE — JS kitabxana versiyalarının OSV/KEV/EPSS ilə uyğunluğu.

Axın (Faza 1.3):
  1. Skan-daxili JS faylları yüklənir və kitabxana versiyaları çıxarılır
     (jQuery, React, Vue, Angular, Bootstrap, Lodash, Moment, Axios ...).
  2. Hər (paket, versiya) OSV API-yə (npm ekosistemi) sorğulanır.
  3. Uyğunluq varsa CVE/OSV id-ləri KEV + EPSS ilə qiymətləndirilir və
     `cve_matches`-ə yazılır.
  4. Yalnız OSV **dəqiq** versiya uyğunluğunda finding yaradılır —
     `match_type=confirmed`. Banner/versiya tək başına "zəiflik" DEYİL və
     bu, təsvirdə açıq göstərilir.

Bu mənbələr (OSV/KEV/EPSS) SKAN HƏDƏFİ DEYİL → onlara scope tətbiq olunmur.
"""
from __future__ import annotations

import asyncio
import re

import aiohttp

from .. import db
from ..redact import redact
from ..results import EngineResult
from .cve_intel import get_kev, rank_batch

OSV_URL = "https://api.osv.dev/v1/query"
MAX_JS = 60
MAX_SIZE = 400_000

#: (paket adı, versiyanı tutan regex)
LIB_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("jquery", re.compile(r"jQuery\s+v?([0-9]+\.[0-9]+\.[0-9]+)")),
    ("react", re.compile(r"React\s+v?([0-9]+\.[0-9]+\.[0-9]+)")),
    ("vue", re.compile(r"Vue\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)")),
    ("angular", re.compile(r"[Aa]ngular(?:\.js)?\s+v?([0-9]+\.[0-9]+\.[0-9]+)")),
    ("bootstrap", re.compile(r"Bootstrap\s+v?([0-9]+\.[0-9]+\.[0-9]+)")),
    ("lodash", re.compile(r"lodash[^0-9]{0,20}([0-9]+\.[0-9]+\.[0-9]+)")),
    ("moment", re.compile(r"moment(?:\.js)?\s+v?([0-9]+\.[0-9]+\.[0-9]+)")),
    ("axios", re.compile(r"axios/([0-9]+\.[0-9]+\.[0-9]+)")),
    ("underscore", re.compile(r"Underscore\.js\s+([0-9]+\.[0-9]+\.[0-9]+)")),
    ("handlebars", re.compile(r"Handlebars\s+v?([0-9]+\.[0-9]+\.[0-9]+)")),
    ("dompurify", re.compile(r"DOMPurify\s+([0-9]+\.[0-9]+\.[0-9]+)")),
)


def extract_libraries(text: str) -> dict[str, str]:
    """JS mətnindən {paket: versiya} çıxarır."""
    found: dict[str, str] = {}
    for name, pat in LIB_PATTERNS:
        m = pat.search(text or "")
        if m:
            found[name] = m.group(1)
    return found


async def osv_npm(session, package: str, version: str) -> list[dict]:
    """OSV-də npm paketi/versiyası üçün zəifliklər."""
    try:
        async with session.post(
                OSV_URL, json={"package": {"name": package, "ecosystem": "npm"},
                               "version": version},
                timeout=aiohttp.ClientTimeout(total=30)) as r:
            if r.status != 200:
                return []
            data = await r.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        return []
    return list((data or {}).get("vulns", []) or [])


class LibraryCVEEngine:
    name = "library_cve"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        rows = db.get_db().execute(
            "SELECT u.url, u.host_id, h.subdomain FROM urls u "
            "JOIN hosts h ON h.id=u.host_id WHERE u.is_js=1 AND h.scan_id=? "
            "LIMIT ?", (db.effective_scan_id(self.ctx.scan_id), MAX_JS)
        ).fetchall()
        if not rows:
            return res.skip("JS faylı yoxdur — library CVE atlandı")

        # 1) kitabxanaları topla
        libs: dict[tuple[int, str], dict[str, str]] = {}
        import aiohttp
        async with aiohttp.ClientSession() as session:
            for row in rows:
                if not self.cfg.in_scope(row["url"]) or not self.guardian:
                    continue
                text = await self._fetch(session, row["url"], row["subdomain"])
                if not text:
                    continue
                found = extract_libraries(text)
                if found:
                    libs[(row["host_id"], row["subdomain"])] = found

            if not libs:
                return res.skip("kitabxana versiyası aşkarlanmadı")

            print(f"[═══ LIBRARY CVE (OSV/KEV/EPSS) ═══] {len(libs)} host")
            kev = await get_kev(session)
            for (host_id, sub), found in libs.items():
                for package, version in found.items():
                    await self._match(session, host_id, sub, package, version,
                                      kev, res)
        return res

    async def _fetch(self, session, url: str, host: str) -> str | None:
        try:
            r = await self.guardian.get(session, url, allow_redirects=True)
        except Exception:  # noqa: BLE001 — guardian blok/scope xətası
            return None
        if r.status != 200:
            return None
        return (r.text or "")[:MAX_SIZE]

    async def _match(self, session, host_id: int, sub: str, package: str,
                     version: str, kev: set, res: EngineResult) -> None:
        vulns = await osv_npm(session, package, version)
        if not vulns:
            return
        ids = [v.get("id") for v in vulns if v.get("id")][:20]
        cve_ids = [i for i in ids if i.startswith("CVE-")]
        ranked = await rank_batch(session, cve_ids, kev) if cve_ids else {}

        for v in vulns[:20]:
            vid = v.get("id") or ""
            if not vid:
                continue
            info = ranked.get(vid, {"kev": vid in kev, "epss": 0.0})
            prio = self._priority(info.get("kev"), info.get("epss", 0.0),
                                  v.get("database_specific", {}).get("severity"))
            db.insert_cve(host_id, vid, package, version, bool(info.get("kev")),
                          float(info.get("epss", 0.0)), prio,
                          match_type="confirmed", source="osv-npm")
            db.insert_finding(
                host_id, "library-cve", prio,
                f"Kitabxana zəifliyi: {package} {version} → {vid}",
                f"OSV npm ekosistemində {package}@{version} üçün bu zəifliyi "
                f"təsdiqləyir (dəqiq versiya uyğunluğu). "
                f"KEV={'bəli' if info.get('kev') else 'xeyr'}, "
                f"EPSS={float(info.get('epss', 0.0)):.2f}. "
                f"Manual reproduksiya tələb olunur — versiya banner-i tək "
                f"başına zəiflik sübutu DEYİL.",
                evidence=redact(f"{package}@{version} → {vid}"),
                confidence=0.7, status="candidate", source="library-cve")
            res.findings += 1
            print(f"[🟠] {sub}: {package} {version} → {vid} "
                  f"(KEV={'✓' if info.get('kev') else '✗'})")

    @staticmethod
    def _priority(kev: bool, epss: float, severity: str | None) -> str:
        if kev or (severity or "").upper() == "CRITICAL":
            return "critical"
        if epss > 0.5 or (severity or "").upper() == "HIGH":
            return "high"
        if epss > 0.1:
            return "medium"
        return "low"
