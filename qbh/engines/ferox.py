"""M5+: Feroxbuster — RECURSIVE dərin kəşf (ffuf flat qalır).

Təhlükəsizlik prinsipləri:
  * Yalnız scope-daxili hostlar skan edilir (fail-closed).
  * Rekursiya dərinliyi və vaxt məhduddur → runaway yoxdur.
  * Rate limit və hədəf cooldown-u hörmətlə qarşılanır.
  * Hər tapılmış URL scope yoxlamasından keçir; kənar URL-lər atılır.
  * Subprocess shell-siz işlədilir və timeout/cancel zamanı öldürülür.
"""
from __future__ import annotations

import json
import os
import tempfile

from .. import db
from ..adapters.base import limited_wordlist, run_process
from ..antiblock.ua_rotator import ua_for
from ..results import EngineResult
from ..scope import ScopeError

FEROX_WORDLIST = \
    "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"

MAX_HOSTS = 8
MAX_DEPTH = 2
MAX_WORDS = 20_000
TIMEOUT = 900
INTERESTING_STATUS = (200, 204, 301, 302, 307, 401, 403, 500)


class FeroxEngine:
    name = "ferox"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian
        self.rate = ctx.rate

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        if not os.path.exists(FEROX_WORDLIST):
            return res.skip(
                f"wordlist yoxdur: {FEROX_WORDLIST} (apt install seclists)")

        hosts = db.alive_hosts()[:MAX_HOSTS]
        if not hosts:
            return res.skip("yaşayan host yoxdur — ferox atlandı")
        print(f"[═══ M5+ FEROX (recursive, depth={MAX_DEPTH}) ═══] {len(hosts)} host")

        for row in hosts:
            host = row["subdomain"]
            if self.guardian and self.guardian.halted(host):
                res.warn(f"{host} cooldown altındadır — atlandı")
                continue
            try:
                self.cfg.authorize_target(host)
            except ScopeError as exc:
                res.warn(f"{host}: {exc}")
                continue
            await self._scan(row, res)
        return res

    async def _scan(self, host_row, res: EngineResult) -> None:
        host = host_row["subdomain"]
        wordlist, tmp_words = limited_wordlist(FEROX_WORDLIST, MAX_WORDS)
        if tmp_words:
            res.warn(f"{host}: wordlist {MAX_WORDS} sətrə məhdudlaşdırıldı")
        fd, out_file = tempfile.mkstemp(prefix="qbh_ferox_", suffix=".jsonl")
        os.close(fd)
        try:
            proc = await run_process([
                "feroxbuster",
                "-u", f"https://{host}",
                "-w", wordlist,
                "-H", f"User-Agent: {ua_for(host)}",
                "--rate-limit", str(max(1, int(self.rate * 10))),
                "-t", "10",
                "--depth", str(MAX_DEPTH),
                "--extensions", "json,bak,old,txt,php",
                "--no-state", "--quiet", "--json",
                "-o", out_file,
            ], timeout=TIMEOUT)
            if proc.missing:
                res.warn("feroxbuster tapılmadı — atlandı")
                return
            if proc.timed_out:
                res.warn(f"ferox {host}: timeout ({TIMEOUT}s)")
            self._parse(host_row, out_file, res)
        finally:
            for path in (out_file, tmp_words):
                if path:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass

    def _parse(self, host_row, out_file: str, res: EngineResult) -> None:
        host = host_row["subdomain"]
        n = 0
        try:
            fh = open(out_file, "r", encoding="utf-8", errors="ignore")
        except OSError:
            return
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if r.get("type") and r.get("type") != "response":
                    continue
                url = r.get("url")
                status = r.get("status")
                if not url or status not in INTERESTING_STATUS:
                    continue
                if not self.cfg.in_scope(url):  # scope yoxlaması
                    res.warn(f"scope xaricində URL rədd edildi: {url}")
                    continue
                db.insert_url(host_row["id"], url, "ferox", False)
                res.urls += 1
                n += 1
                length = r.get("content_length") or 0
                if status == 200 and length > 2000:
                    db.insert_finding(
                        host_row["id"], "ferox", "info",
                        f"Recursive tapıntı: {url}",
                        f"Feroxbuster {MAX_DEPTH} səviyyə dərinlikdə tapdı "
                        f"(status: {status}, ölçü: {length})",
                        evidence=url, confidence=0.4, source="ferox")
                    res.findings += 1
        if n:
            print(f"[+] ferox {host}: {n} nəticə")
