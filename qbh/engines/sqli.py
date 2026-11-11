"""SQLi Engine — sqlmap (fallback: Ghauri) ilə avtomatik SQL injection təsdiqi.

Zəncir trigger-i: gizli parametr (x8/arjun) + refleksiya/xəta marker-i.
Təsdiq YALNIZ sübutla: DB xəta imzası, boolean differensialı və ya
çıxarılmış data (banner / current-db). Əks halda tapıntı `candidate` qalır.

Təhlükəsizlik:
  * `ctx.authorize_url` + egress (DNS pinning) + Guardian qapısı.
  * Yalnız `active_fuzz` icazəlidirsə işləyir (RoE qapısı).
  * `--batch` (interaktiv yoxdur), `shell=True` yoxdur.
  * WAF aşkarlandıqda tamper skriptləri seçilir (Faza 2, `qbh.stealth.waf`).
"""
from __future__ import annotations

import re

from ..results import EngineResult
from .offensive import OffensiveEngine

#: sqlmap çıxışında injection-ın təsdiqini göstərən imzalar.
INJECTION_RE = re.compile(
    r"(is vulnerable|injectable|sqlmap identified the following injection"
    r"|Parameter: .*\(GET\)|Type: (boolean-based|time-based|error-based|"
    r"UNION query|stacked queries))", re.I)
DBMS_RE = re.compile(r"back-end DBMS:\s*([^\n]+)", re.I)
DATA_RE = re.compile(r"(current database|current user|banner):\s*'?([^'\n]+)",
                     re.I)

PROFILE_LEVEL = {"passive": ("1", "1"), "normal": ("2", "1"),
                 "aggressive": ("3", "2")}


class SQLiEngine(OffensiveEngine):
    name = "sqli"
    tool = "sqlmap"
    timeout = 900
    max_targets = 8
    fallback = "ghauri"

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        if not self.ctx.allows("active_fuzz"):
            return res.skip("aktiv fuzz qadağandır — SQLi atlandı")
        rows = self.candidate_urls(only_params=True, limit=self.max_targets)
        if not rows:
            return res.skip("parametrli URL yoxdur — SQLi atlandı")
        tool = self.tool if self.tool_present() else (
            self.fallback if self.tool_present_alt() else "")
        if not tool:
            res.warn(f"{self.tool}/{self.fallback} tapılmadı — SQLi atlandı")
            return res.skip("sqlmap/ghauri mövcud deyil")
        print(f"[═══ SQLi ({tool}) ═══] {len(rows)} hədəf")

        for row in rows:
            if not await self.gate(row["url"], res, host=row["subdomain"]):
                continue
            await self._probe(tool, row, res)
        return res

    def tool_present_alt(self) -> bool:
        import shutil
        return shutil.which(self.fallback) is not None

    def _waf_tampers(self) -> list[str]:
        """WAF aşkar olunubsa uyğun tamper skriptlərini seçir (Faza 2)."""
        waf = getattr(self.ctx, "waf_name", None)
        if not waf:
            return []
        try:
            from ..stealth.waf import tamper_for

            return tamper_for(waf)
        except Exception:  # noqa: BLE001 — stealth qatı yoxdursa tamper yoxdur
            return []

    async def _probe(self, tool: str, row, res: EngineResult) -> None:
        level, risk = PROFILE_LEVEL.get(self.cfg.aggressiveness, ("2", "1"))
        if tool == "sqlmap":
            cmd = ["sqlmap", "-u", row["url"], "--batch", "--level", level,
                   "--risk", risk, "--banner", "--current-db", "--no-cast",
                   "--flush-session", "--output-dir", "/tmp/qbh_sqlmap",
                   "--disable-coloring"]
            for tamper in self._waf_tampers():
                cmd += ["--tamper", tamper]
        else:  # ghauri
            cmd = ["ghauri", "-u", row["url"], "--batch", "--level", level,
                   "--confirm", "--dbs"]
        from ..adapters.base import run_process

        proc = await run_process(cmd, timeout=self.timeout)
        if proc.missing:
            res.warn(f"{tool} tapılmadı")
            return
        out = proc.stdout.decode(errors="ignore") + "\n" + \
            proc.stderr.decode(errors="ignore")
        if not INJECTION_RE.search(out):
            return
        host_id = row["host_id"]
        dbms = DBMS_RE.search(out)
        data = DATA_RE.search(out)
        title = "SQL injection (sqlmap təsdiq)"
        desc = (f"sqlmap {row['url']} üzərində injection aşkar etdi"
                + (f" — DBMS: {dbms.group(1).strip()}" if dbms else "")
                + ". Sübut sqlmap çıxışı ilə saxlanılır.")
        fid = self.record(
            host_id, "critical", title, desc,
            evidence=self._excerpt(out), curl_repro=f"sqlmap -u '{row['url']}' --batch",
            confidence=0.8, status="candidate", source=tool)
        excerpt = self._excerpt(out)
        if data:
            # Data çıxarıldı → GÜCLÜ sübut → təsdiq.
            self.confirm(fid, "data",
                         f"sqlmap çıxarılan data: {data.group(0).strip()}",
                         confidence=0.95)
            res.findings += 1
            print(f"[🔴] {row['subdomain']}: SQLi TƏSDİQLƏNDİ (data extraction)")
        else:
            # Marker əsaslı → sübut saxlanır, lakin `candidate` qalır.
            self.confirm(fid, "marker", excerpt, confidence=0.65)
            res.findings += 1
            print(f"[🟠] {row['subdomain']}: SQLi marker aşkarlandı (təsdiq tələb olunur)")

    @staticmethod
    def _excerpt(out: str, limit: int = 1200) -> str:
        lines = [ln for ln in out.splitlines()
                 if re.search(r"(injectable|Parameter|Type:|DBMS|vulnerable)",
                              ln, re.I)]
        return "\n".join(lines[:40])[:limit] or out[:limit]
