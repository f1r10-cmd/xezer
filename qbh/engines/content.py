"""M5: ffuf — flat content discovery (ferox ilə əlaqələndirilir).

Təhlükəsizlik prinsipləri:
  * Yalnız scope-daxili hostlar.
  * Wordlist ölçüsü məhdudlaşdırılır → həddindən artıq sorğu generasiyası yoxdur.
  * Rate limit hörmətlə qarşılanır; cooldown-dakı hədəf atlanır.
  * Tapılan URL-lər scope yoxlamasından keçir.
  * Subprocess shell-siz; timeout/cancel zamanı öldürülür.
"""
from __future__ import annotations

import json
import os
import tempfile

from .. import db
from ..adapters.base import limited_wordlist, run_process
from ..results import EngineResult
from ..scope import ScopeError

WORDLIST = "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"

MAX_HOSTS = 10
MAX_WORDS = 20_000
MAX_RESULTS = 30
TIMEOUT = 600
MATCH_CODES = "200,204,301,302,307,401,403"
INTERESTING_STATUS = (200, 401, 403)


class ContentEngine:
    name = "content"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian
        self.rate = ctx.rate

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        if not os.path.exists(WORDLIST):
            return res.skip(f"wordlist yoxdur: {WORDLIST} (apt install seclists)")

        hosts = db.alive_hosts(self.ctx.scan_id)[:MAX_HOSTS]
        if not hosts:
            return res.skip("yaşayan host yoxdur — content discovery atlandı")
        print(f"[═══ M5 CONTENT (ffuf) ═══] {len(hosts)} host")

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
            await self._ffuf(row, res)
        return res

    async def _ffuf(self, host_row, res: EngineResult) -> None:
        host = host_row["subdomain"]
        # Faza 0.2: alt-proses hədəfi scope yoxlaması + DNS pinning-dən keçir.
        tset = await self.ctx.egress.authorize_process_targets(
            [f"https://{host}"])
        if host not in set(tset.hostnames):
            res.warn(f"egress: {host} scope xaricindədir — ffuf atlandı")
            return
        wordlist, tmp_words = limited_wordlist(WORDLIST, MAX_WORDS)
        if tmp_words:
            res.warn(f"{host}: wordlist {MAX_WORDS} sətrə məhdudlaşdırıldı")
        fd, out_file = tempfile.mkstemp(prefix="qbh_ffuf_", suffix=".json")
        os.close(fd)
        # Faza 3.6: WAF-a görə rate/concurrency + insan-təqlidi başlıqlar.
        plan = self.ctx.stealth.plan(
            self.rate * 8, base_concurrency=10, phase="ffuf")
        ua = self.ctx.stealth.humanizer.ua()
        try:
            args = [
                "ffuf", "-w", wordlist,
                "-u", f"https://{host}/FUZZ",
                "-rate", str(plan.rate_arg()),
                "-H", f"User-Agent: {ua}",
                "-H", "Accept-Language: en-US,en;q=0.9",
                "-t", str(plan.concurrency), "-ac",
                "-of", "json", "-o", out_file,
                "-mc", MATCH_CODES,
            ]
            proc = await run_process(args, timeout=TIMEOUT)
            if proc.missing:
                res.warn("ffuf tapılmadı — atlandı")
                return
            if proc.timed_out:
                res.warn(f"ffuf {host}: timeout ({TIMEOUT}s)")
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
        try:
            with open(out_file, "r", encoding="utf-8", errors="ignore") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return

        interesting = [
            r for r in data.get("results", [])
            if r.get("status") in INTERESTING_STATUS
            and (r.get("length") or 0) > 100]
        shown = 0
        for r in interesting[:MAX_RESULTS]:
            url = r.get("url")
            if not url:
                continue
            if not self.cfg.in_scope(url):  # scope yoxlaması
                res.warn(f"scope xaricində URL rədd edildi: {url}")
                continue
            db.insert_url(host_row["id"], url, "ffuf", False, scan_id=self.ctx.scan_id)
            res.urls += 1
            shown += 1
            if r.get("status") == 200 and (r.get("length") or 0) > 500:
                db.insert_finding(
                    host_row["id"], "content", "info",
                    f"İnteresli path: {url}",
                    f"Status {r.get('status')}, ölçü {r.get('length')} bayt",
                    evidence=url, confidence=0.35, source="ffuf",
                    scan_id=self.ctx.scan_id)
                res.findings += 1
        if shown:
            print(f"[+] ffuf {host}: {shown} nəticə")
