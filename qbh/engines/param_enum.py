"""Param Enum: Arjun + x8 — gizli parametrlərin kəşfi (yalnız GET, non-destructive).

Təhlükəsizlik prinsipləri:
  * Yalnız scope-daxili URL-lər; hər URL yoxlanır.
  * Yalnız GET metodundan istifadə olunur (state dəyişən sorğu yoxdur).
  * Rate/cooldown Guardian vasitəsilə tətbiq olunur.
  * Nəticələr "info"/"low" severity və "potential" statusu ilə qeyd olunur.
"""
from __future__ import annotations

import re

from .. import db
from ..adapters.base import run_process
from ..redact import redact
from ..results import EngineResult

MAX_URLS = 50
MAX_PARAMS = 15
TIMEOUT = 300

HUNTER_PARAMS = (
    "debug test admin dev staging internal verbose access role user auth "
    "token redirect url next return callback api_key secret filter query "
    "file path template render page lang email is_admin enable activate"
).replace(" ", ",")


class ParamEnumEngine:
    name = "param_enum"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        rows = db.get_db().execute(
            "SELECT DISTINCT u.url, u.host_id, h.subdomain FROM urls u "
            "JOIN hosts h ON h.id = u.host_id "
            "WHERE u.is_js = 0 AND u.source IN "
            "('katana','gau','ffuf','ferox','api-enum','kiterunner') "
            "AND u.url NOT LIKE '%##%' AND h.scan_id=? LIMIT ?",
            (db.effective_scan_id(self.ctx.scan_id), MAX_URLS)).fetchall()
        if not rows:
            return res.skip("uyğun URL yoxdur — param enum atlandı")
        print(f"[═══ PARAM ENUM (Arjun + x8) ═══] {len(rows)} URL")

        for row in rows:
            if not self.cfg.in_scope(row["url"]):
                res.warn(f"scope xaricində URL atlandı: {row['url']}")
                continue
            # Faza 0.2: alt-prosesə verilən URL egress validasiyasından keçir.
            tset = await self.ctx.egress.authorize_process_targets([row["url"]])
            if row["url"] not in tset.urls:
                res.warn(f"egress: {row['url']} scope xaricindədir — atlandı")
                continue
            if self.guardian:
                if self.guardian.halted(row["subdomain"]):
                    res.warn(f"{row['subdomain']} cooldown altındadır — atlandı")
                    continue
                await self.guardian.acquire(row["subdomain"])
            await self._arjun(row, res)
            await self._x8(row, res)
        return res

    async def _arjun(self, row, res: EngineResult) -> None:
        proc = await run_process([
            "arjun", "-u", row["url"], "-m", "GET", "-t", "10",
            "--stable", "-o", "/dev/stdout",
        ], timeout=TIMEOUT)
        if proc.missing:
            res.warn("arjun tapılmadı")
            return
        if proc.timed_out:
            res.warn(f"arjun {row['url']}: timeout")
            return
        params = self._parse_arjun(proc.stdout.decode(errors="ignore"))
        if not params:
            return
        db.insert_finding(
            row["host_id"], "paramenum", "info",
            f"Gizli parametrlər: {', '.join(params)}",
            f"{row['url']} üzərində {len(params)} gizli GET parametri tapıldı "
            f"(sonrakı manual testlər üçün prioritet siyahı).",
            evidence=row["url"], confidence=0.5, status="potential",
            source="arjun", scan_id=self.ctx.scan_id)
        db.insert_url(row["host_id"],
                      f"{row['url']}##params:{','.join(params)}",
                      "priority-param", False, scan_id=self.ctx.scan_id)
        res.findings += 1
        print(f"[+] {row['subdomain']}: parametrlər → {params}")

    @staticmethod
    def _parse_arjun(out: str) -> list:
        params, in_params = [], False
        stop = {"parameter", "parameters", "found", "get", "post", "value"}
        for line in out.splitlines():
            if "parameter" in line.lower() or in_params:
                in_params = True
                for tok in re.split(r"[\s│|:]+", line):
                    tok = tok.strip("│|:-`'\"")
                    if (re.match(r"^[a-z_][a-z0-9_\-]{2,25}$", tok or "")
                            and tok.lower() not in stop):
                        params.append(tok)
        return list(dict.fromkeys(params))[:MAX_PARAMS]

    async def _x8(self, row, res: EngineResult) -> None:
        proc = await run_process(
            ["x8", "-u", row["url"], "-w", "-", "-X", "GET"],
            stdin=HUNTER_PARAMS.encode(), timeout=TIMEOUT)
        if proc.missing:
            return
        if proc.timed_out:
            res.warn(f"x8 {row['url']}: timeout")
            return
        text = proc.stdout.decode(errors="ignore")
        lines = [ln for ln in text.splitlines()
                 if ln.strip() and not ln.strip().startswith("[")][:10]
        if not lines:
            return
        db.insert_finding(
            row["host_id"], "paramenum", "low",
            "x8 gizli parametr siqnalı",
            f"{row['url']} — x8 nəticələri manual yoxlanış tələb edir "
            f"(yalnız GET, heuristik).",
            evidence=redact("\n".join(lines)), confidence=0.3,
            status="potential", source="x8", scan_id=self.ctx.scan_id)
        res.findings += 1
        print(f"[?] {row['subdomain']}: x8 siqnal verdi")
