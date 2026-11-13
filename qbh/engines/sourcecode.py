"""Source Code Engine — açıq `.git` harvest + Semgrep statik analizi.

Trigger: canlı hostda `.git/` ekspozisiyası.

Axın:
  1. `/.git/HEAD` (+ `/.git/config`) zondlanır → ekspozisiya təsdiqi.
     Uğurlu olarsa **məlumatlandırıcı** finding (source code exposure).
  2. `git-dumper` mövcuddursa repo çıxarılır; sonra Semgrep (qbh xüsusi
     qaydalar dəsti) işlədilir → hər nəticə kod-səviyyəli sübutla finding.

Dürüstlük: `git-dumper`/`semgrep` yoxdursa mühərrik ekspozisiyanı bildirir,
lakin analiz etmədiyini AÇIQ yazır (`skipped`/`warn`) — "analiz edildi"
iddiası verilmir.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile

import aiohttp

from .. import db
from ..antiblock.ua_rotator import ua_for
from ..redact import redact
from ..results import EngineResult
from ..scope import ScopeError
from .offensive import OffensiveEngine

GIT_HEAD_RE = re.compile(rb"^ref:\s+refs/")
SEMGREP_RULES = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                             "rules", "semgrep_qbh.yml")
SEV_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


class SourceCodeEngine(OffensiveEngine):
    name = "sourcecode"
    tool = "semgrep"
    timeout = 600
    max_hosts = 8

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        if not self.ctx.guardian:
            res.fail("guardian yoxdur — source scan təhlükəsiz icra oluna bilməz")
            return res
        hosts = db.alive_hosts(self.ctx.scan_id)[: self.max_hosts]
        if not hosts:
            return res.skip("yaşayan host yoxdur — source scan atlandı")

        dumper = shutil.which("git-dumper")
        semgrep = shutil.which("semgrep")
        print(f"[═══ SOURCE CODE (.git harvest + Semgrep) ═══] {len(hosts)} host")

        async with aiohttp.ClientSession() as session:
            for h in hosts:
                sub = h["subdomain"]
                if self.guardian.halted(sub):
                    res.warn(f"{sub} cooldown altındadır — atlandı")
                    continue
                if not await self._git_exposed(session, h, res):
                    continue
                fid = self.record(
                    h["id"], "high", "Açıq `.git` deposu",
                    f"https://{sub}/.git/ ictimaiyyətə açıqdır — mənbə kodu, "
                    f"secret-lər və commit tarixçəsi sıza bilər.",
                    evidence=f"https://{sub}/.git/HEAD → ref:refs",
                    confidence=0.7, status="candidate", source="git-exposure")
                res.findings += 1
                print(f"[🟠] {sub}: açıq .git aşkarlandı")
                if not dumper:
                    res.warn("git-dumper tapılmadı — repo çıxarılmadı "
                             "(açıq .git bildirildi, analiz edilmədi)")
                    continue
                await self._dump_and_scan(sub, fid, semgrep, res)
        return res

    async def _git_exposed(self, session, host, res: EngineResult) -> bool:
        url = f"https://{host['subdomain']}/.git/HEAD"
        if not self.cfg.in_scope(url):
            return False
        try:
            tset = await self.ctx.egress.authorize_process_targets([url])
        except Exception:  # noqa: BLE001 — egress fail → atla
            return False
        if url not in tset.urls:
            return False
        try:
            r = await self.ctx.guardian.get(
                session, url, allow_redirects=False,
                headers={"User-Agent": ua_for(host["subdomain"])})
        except (aiohttp.ClientError, asyncio.TimeoutError, ScopeError):
            return False
        if r.status != 200:
            return False
        body = r.text.encode("utf-8", errors="ignore")
        return bool(GIT_HEAD_RE.match(body.strip()))

    async def _dump_and_scan(self, sub: str, fid: int, semgrep: str | None,
                             res: EngineResult) -> None:
        url = f"https://{sub}/.git/"
        tmp = tempfile.mkdtemp(prefix="qbh_gitdump_")
        try:
            # Faza 1.2: git-dumper hədəfi TƏK egress qapısından keçir
            # (scope + fail-closed DNS pinning).
            proc = await self.ctx.egress.run(
                ["git-dumper", url, tmp], targets=[url], timeout=self.timeout)
            if proc.blocked:
                res.warn(f"{sub}: egress qapısı git-dumper-ı bloklandı")
                return
            if proc.missing or proc.timed_out:
                res.warn(f"{sub}: git-dumper uğursuz (dump alınmadı)")
                return
            if not semgrep:
                res.warn("semgrep tapılmadı — dump alındı, statik analiz yox")
                return
            await self._semgrep(tmp, fid, res, sub)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    async def _semgrep(self, path: str, fid: int, res: EngineResult,
                       sub: str) -> None:
        from ..adapters.base import run_process

        if not os.path.exists(SEMGREP_RULES):
            res.warn("qbh semgrep qaydaları tapılmadı")
            return
        cmd = ["semgrep", "--config", SEMGREP_RULES, "--json", "--quiet",
               "--timeout", "120", path]
        proc = await run_process(cmd, timeout=self.timeout)
        if proc.missing:
            res.warn("semgrep tapılmadı")
            return
        try:
            data = json.loads(proc.stdout.decode(errors="ignore") or "{}")
        except json.JSONDecodeError:
            res.warn(f"{sub}: semgrep çıxışı oxuna bilmədi")
            return
        results = data.get("results", [])
        for item in results[:40]:
            rule = (item.get("check_id") or "").split(".")[-1]
            sev = SEV_MAP.get(item.get("extra", {}).get("severity", ""), "low")
            loc = f"{item.get('path')}:{item.get('start', {}).get('line')}"
            msg = item.get("extra", {}).get("message", rule)
            self.record(
                self._host_id_for(sub), sev, f"Statik analiz: {rule}",
                f"{msg} — {loc}",
                evidence=redact(loc), confidence=0.5, status="candidate",
                source="semgrep", template=rule)
            res.findings += 1
        if results:
            print(f"[🔍] {sub}: semgrep {len(results)} kod səviyyəli siqnal")

    def _host_id_for(self, sub: str) -> int:
        row = db.get_db().execute(
            "SELECT id FROM hosts WHERE subdomain=? AND scan_id=?",
            (sub, db.effective_scan_id(self.ctx.scan_id))).fetchone()
        return row["id"] if row else -1
