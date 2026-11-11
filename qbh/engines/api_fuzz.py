"""API Fuzz: OpenAPI sxemi üzərində Schemathesis property-testi.

Təhlükəsizlik prinsipləri:
  * YALNIZ `--active-fuzz` açıq şəkildə verildikdə işləyir. Default: atlanır.
  * Yalnız GET metodları yoxlanır (`-M GET`) → state dəyişən sorğu yoxdur.
  * Yalnız scope-daxili və API sxemi olduğu təsdiqlənmiş URL-lərə qarşı işləyir.
  * Nəticələr "potential" kimi qeyd olunur; avtomatik "confirmed" iddiası yoxdur.
  * Credential hücumu, brute force və data extraction YOXDUR.
"""
from __future__ import annotations

import json
import os
import tempfile

from .. import db
from ..adapters.base import run_process
from ..results import EngineResult

MAX_SCHEMAS = 10
MAX_EXAMPLES = 50
TIMEOUT = 900


class APIFuzzEngine:
    name = "api_fuzz"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        if not self.ctx.active_fuzz:
            return res.skip(
                "API fuzzinq deaktivdir — yalnız `--active-fuzz` ilə "
                "icazəli endpoint-lərə qarşı işləyir")

        rows = db.get_db().execute(
            "SELECT u.url, u.host_id, h.subdomain FROM urls u "
            "JOIN hosts h ON h.id=u.host_id "
            "WHERE (u.url LIKE '%openapi%' OR u.url LIKE '%swagger%' "
            "OR u.url LIKE '%api-docs%') LIMIT ?",
            (MAX_SCHEMAS,)).fetchall()
        if not rows:
            return res.skip("OpenAPI sxem tapılmadı — API fuzzinq atlandı")
        print(f"[═══ API FUZZ (Schemathesis, GET-only) ═══] {len(rows)} sxem")

        for row in rows:
            if not self.cfg.in_scope(row["url"]):
                res.warn(f"scope xaricində sxem atlandı: {row['url']}")
                continue
            await self._schemathesis(row, res)
        return res

    async def _schemathesis(self, row, res: EngineResult) -> None:
        fd, result_file = tempfile.mkstemp(prefix="qbh_st_", suffix=".json")
        os.close(fd)
        try:
            proc = await run_process([
                "schemathesis", "run", row["url"],
                "-M", "GET",
                "--checks", "all",
                "--max-examples", str(MAX_EXAMPLES),
                "-o", "json", result_file,
            ], timeout=TIMEOUT)
            if proc.missing:
                res.warn("schemathesis tapılmadı (pip install schemathesis)")
                return
            if proc.timed_out:
                res.warn(f"schemathesis {row['url']}: timeout")
            failures = self._read_failures(result_file)
        finally:
            try:
                os.unlink(result_file)
            except OSError:
                pass

        if failures:
            db.insert_finding(
                row["host_id"], "apifuzz", "medium",
                f"API property-test: {failures} nasazlıq",
                f"Schemathesis {row['url']} sxemində {failures} yoxlama "
                f"uyğunsuzluğu tapdı (yalnız GET). Bu POTENSIAL siqnaldır — "
                f"manual təsdiq tələb olunur.",
                evidence=row["url"], confidence=0.4,
                status="potential", source="schemathesis")
            res.findings += 1
            print(f"[🧪] {row['subdomain']}: {failures} failure (potential)")

    @staticmethod
    def _read_failures(result_file: str) -> int:
        try:
            with open(result_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return 0
        if not isinstance(data, dict):
            return 0
        summary = data.get("stats") or data.get("summary") or {}
        if not isinstance(summary, dict):
            return 0
        failures = (summary.get("failures") or summary.get("failed")
                    or summary.get("checks_failed") or 0)
        if isinstance(failures, dict):
            failures = failures.get("total", 0)
        try:
            return int(failures)
        except (TypeError, ValueError):
            return 0
