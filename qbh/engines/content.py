"""M5: ffuf — flat content discovery (ferox ilə əlaqələndirilir).

Təhlükəsizlik prinsipləri:
  * Yalnız scope-daxili hostlar.
  * Wordlist ölçüsü məhdudlaşdırılır → həddindən artıq sorğu generasiyası yoxdur.
  * Rate limit hörmətlə qarşılanır; cooldown-dakı hədəf atlanır.
  * Tapılan URL-lər scope yoxlamasından keçir.
  * Subprocess shell-siz; timeout/cancel zamanı öldürülür.

Etibarlılıq:
  * Limitlər (`content.timeout_seconds`, `content.max_words`,
    `content.max_hosts`, `content.max_results`) konfiqurasiya ilə idarə olunur;
    default-lar əvvəlki sabitlərlə eynidir.
  * ffuf timeout və ya sıfırdan fərqli çıxış kodu ilə bitsə də, yazılmış JSON
    çıxışı OXUNUR. Etibarlı qismən nəticələr saxlanılır; zədələnmiş fayl
    yalnız xəbərdarlıqla bildirilir və HEÇ VAXT tapıntı yaradılmır.
  * Timeout olunan mərhələ `partial` kimi raportlanır — "tam uğurlu" DEYİL.
"""
from __future__ import annotations

import json
import os
import tempfile

from .. import db, urlintel
from ..adapters.base import limited_wordlist, run_process
from ..parallel import run_bounded
from ..results import EngineResult
from ..scope import ScopeError

#: Faza 1 (§7): host-lar üzərində paralel ffuf alt-proseslərinin tavanı.
#: Subprocess-lər `HttpPolicy` semaforundan keçmədiyi üçün KİÇİK saxlanılır —
#: hər proses öz `--rate` limitini hörmət edir və hər host müstəqildir.
MAX_PARALLEL = 3

WORDLIST = "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"

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
        conf = self.cfg.content
        if not os.path.exists(WORDLIST):
            return res.skip(f"wordlist yoxdur: {WORDLIST} (apt install seclists)")

        alive = db.alive_hosts(self.ctx.scan_id)
        hosts = alive[:conf.max_hosts]
        if not hosts:
            return res.skip("yaşayan host yoxdur — content discovery atlandı")
        if len(alive) > len(hosts):
            # Limit FAKTİKİ olaraq əhatəni kəsir → mərhələ natamamdır.
            res.mark_partial(
                f"{len(alive)} yaşayan host var, lakin content.max_hosts="
                f"{conf.max_hosts} — yalnız {len(hosts)} host skan olunur "
                "(əhatə məhdudlaşdırıldı)")
        print(f"[═══ M5 CONTENT (ffuf) ═══] {len(hosts)} host")

        # Faza 1 (§7): host-lar MÜSTƏQİLDİR (hər biri öz ffuf alt-prosesi ilə) →
        # MƏHDUD paralel icra. Cooldown/scope yoxlaması hər host üçün edilir;
        # bir host-un xətası digərlərini dayandırmır.
        limit = max(1, min(MAX_PARALLEL, len(hosts)))

        async def _one(row):
            host = row["subdomain"]
            if self.guardian and self.guardian.halted(host):
                return f"{host} cooldown altındadır — atlandı"
            try:
                self.cfg.authorize_target(host)
            except ScopeError as exc:
                return f"{host}: {exc}"
            await self._ffuf(row, res)
            return None

        outcomes = await run_bounded(hosts, _one, limit=limit)
        for outcome in outcomes:
            if isinstance(outcome, BaseException):
                res.warn(f"content: gözlənilməz xəta — {outcome}")
            elif outcome:
                res.warn(outcome)
        return res

    async def _ffuf(self, host_row, res: EngineResult) -> None:
        host = host_row["subdomain"]
        conf = self.cfg.content
        # Faza 0.2: alt-proses hədəfi scope yoxlaması + DNS pinning-dən keçir.
        tset = await self.ctx.egress.authorize_process_targets(
            [f"https://{host}"])
        if host not in set(tset.hostnames):
            res.warn(f"egress: {host} scope xaricindədir — ffuf atlandı")
            return
        wordlist, tmp_words = limited_wordlist(WORDLIST, conf.max_words)
        if tmp_words:
            # Wordlist FAKTİKİ olaraq kəsildi → əhatə tam deyil.
            res.mark_partial(
                f"{host}: wordlist {conf.max_words} sətrə məhdudlaşdırıldı — "
                "əhatə tam skan olunmur")
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
            proc = await run_process(args, timeout=conf.timeout_seconds)
            if proc.missing:
                res.warn("ffuf tapılmadı — atlandı")
                return
            incomplete = False
            if proc.timed_out:
                incomplete = True
                res.warn(f"ffuf {host}: timeout ({conf.timeout_seconds}s) — "
                         "qismən nəticələr yoxlanılır")
            elif proc.returncode != 0:
                incomplete = True
                res.warn(f"ffuf {host}: çıxış kodu {proc.returncode} — "
                         "qismən nəticələr yoxlanılır")
            parsed, found = self._parse(host_row, out_file, res)
            if incomplete:
                if parsed:
                    res.mark_partial(
                        f"ffuf {host}: natamam nəticə ({found} nəticə) — "
                        "mərhələ tam uğurlu sayılmır")
                else:
                    res.mark_partial(
                        f"ffuf {host}: natamam/etibarsız çıxış — "
                        "mərhələ tam uğurlu sayılmır")
            elif not parsed:
                res.warn(f"ffuf {host}: JSON nəticəsi oxuna bilmədi")
        finally:
            for path in (out_file, tmp_words):
                if path:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass

    def _parse(self, host_row, out_file: str, res: EngineResult) -> tuple[bool, int]:
        """ffuf JSON çıxışını oxuyur. `(uyğun_oxundu, qeyd_olunan_nəticə)`.

        Zədələnmiş/natamam fayl halında `(False, 0)` qaytarır və xəbərdarlıq
        verir — HEÇ VAXT yarımçıq datadan tapıntı yaradılmır.
        """
        host = host_row["subdomain"]
        try:
            with open(out_file, "r", encoding="utf-8", errors="ignore") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            res.warn(f"ffuf {host}: JSON çıxışı oxuna bilmədi "
                     f"({type(exc).__name__}) — natamam/zədələnmiş nəticə "
                     "nəzərə alınmır")
            return False, 0
        if not isinstance(data, dict):
            res.warn(f"ffuf {host}: JSON çıxışı gözlənilən formatda deyil")
            return False, 0

        interesting = [
            r for r in data.get("results", []) or []
            if isinstance(r, dict)
            and r.get("status") in INTERESTING_STATUS
            and (r.get("length") or 0) > 100]
        shown = 0
        for r in interesting[:self.cfg.content.max_results]:
            url = r.get("url")
            if not url:
                continue
            if not self.cfg.in_scope(url):  # scope yoxlaması
                res.warn(f"scope xaricində URL rədd edildi: {url}")
                continue
            db.insert_url(host_row["id"], url, "ffuf", False, scan_id=self.ctx.scan_id)
            # Faza 2: ffuf-in ARTİQ çəkdiyi cavabın `content-type`-ı ilə
            # təsnifatı dəqiqləşdir (əlavə HTTP sorğusu YOX). Yalnız uyğunluğu
            # dəyişməyən dəqiqləşdirmə tətbiq olunur; əks halda rədd + səbəb.
            ctype = r.get("content-type")
            if ctype:
                urlintel.get_url_intelligence(self.ctx).refine_from_response(
                    url, content_type=str(ctype), source="ffuf")
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
        return True, shown
