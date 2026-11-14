"""M1 Recon: httpx → naabu → katana → gau.

Cloudflare/CDN origin-IP bypass MEXANİZMİ SİLİNMİŞDİR. Yalnız
ictimai recon: HTTP xidmət aşkarlama, port taraması, URL toplama,
texnologiya aşkarlama və DNS. Bütün nəticələr scope yoxlamasından keçir.
Hədəf sessiyası `-follow-redirects` İSTİFADƏ ETMİR → redirect escape yoxdur.
"""
from __future__ import annotations

import json
import urllib.parse

from .. import db
from ..adapters.base import run_process
from ..antiblock.ua_rotator import ua_for
from ..installer import resolve_httpx
from ..redact import redact
from ..results import EngineResult
from ..scope import ScopeError, normalize_host

#: Uğursuz alt-prosesin stderr-indən loglara yazılan maksimum simvol sayı.
_STDERR_LIMIT = 400


def _stderr_excerpt(raw: bytes, limit: int = _STDERR_LIMIT) -> str:
    """stderr-i təhlükəsiz, MƏHDUD uzunluqda qaytarır (secret-lər maskalanır).

    Çox uzun stderr logları şişirməsin deyə kəsilir; `redact` ilə mümkün
    secret-lər maskalanır (heç bir həssas dəyər açıq yazılmır).
    """
    text = redact(raw.decode(errors="ignore")).strip()
    if not text:
        return "(stderr boşdur)"
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


class ReconEngine:
    name = "recon"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian
        self.max_subs = int(ctx.limits.max_subdomains_per_target)
        self.max_alive = 200
        self.rate = ctx.rate
        #: Dürüst raport: hansı alətin yoxluğu barədə artıq xəbərdarlıq verilib.
        self._warned: set[str] = set()

    def _warn_missing(self, res: EngineResult, tool: str, note: str = "") -> None:
        """Alət binari-si yoxdursa BİR DƏFƏ dürüst `res.warn` verir.

        Uydurma nəticə istehsal OLUNMUR; sadəcə mərhələnin məhdud qaldığı
        açıq şəkildə bildirilir (`docs/SECURITY_VERIFICATION.md`).
        """
        if tool in self._warned:
            return
        self._warned.add(tool)
        res.warn(f"{tool} tapılmadı — recon məhdud"
                 + (f" ({note})" if note else ""))

    async def run(self, domain: str, subdomains=None) -> EngineResult:
        res = EngineResult(stage=self.name)
        try:
            domain = self.ctx.scope.authorize(domain)
        except ScopeError as exc:
            res.fail(f"scope xaricində hədəf rədd edildi: {exc}")
            return res
        print(f"[═══ M1 RECON ═══] {domain}")

        subs: list[str] = []
        seen: set[str] = set()
        for s in (subdomains if subdomains is not None else {domain}):
            try:
                host = normalize_host(s)
            except ScopeError:
                continue
            if not self.cfg.in_scope(host) or host in seen:
                continue
            seen.add(host)
            subs.append(host)
        subs = subs[: self.max_subs]
        if not subs:
            res.fail("scope-daxili heç bir host yoxdur")
            return res
        # Faza 0.2: alt-proseslərə (httpx/naabu/katana/gau) verilən hostlar
        # egress validasiyasından keçir + DNS pinning audit-i aparılır.
        tset = await self.ctx.egress.authorize_process_targets(subs)
        allowed = set(tset.hostnames)
        subs = [h for h in subs if h in allowed]
        if not subs:
            res.fail("egress: heç bir icazəli host qalmadı")
            return res
        print(f"[+] {len(subs)} host recon boru xəttinə daxil oldu")

        alive = await self._httpx(subs, res)
        res.hosts = len(alive)
        await self._naabu(alive, res)
        await self._crawl(alive, res)
        await self._gau(domain, res)
        return res

    def _skip(self, host: str, res: EngineResult) -> bool:
        """Blok/cooldown altındakı hostları atla (evasion YOX — atlamaq)."""
        if self.guardian and self.guardian.halted(host):
            res.warn(f"{host} blok cooldown-undadır — atlandı")
            return True
        return False

    async def _httpx(self, subdomains: list[str], res: EngineResult) -> list[dict]:
        inp = "\n".join(subdomains)
        # Faza 3.6: ilk təmas — random UA + təmkinli rate (WAF hələ bilinmir).
        plan = self.ctx.stealth.plan(
            self.rate * 10, base_concurrency=50, phase="httpx")
        alive: list[dict] = []
        # ProjectDiscovery httpx-in YOXLANILMIŞ yolu (PATH-dəki əlaqəsiz
        # "httpx" adlı proqram deyil). Tapılmasa uyğunsuz binari icra olunmur.
        exe = await resolve_httpx()
        if not exe:
            self._warn_missing(res, "httpx", "canlı host aşkarlanmadı")
            return alive
        res_proc = await run_process(
            [exe, "-json", "-silent", "-tech-detect", "-title",
             "-cdn", "-status-code", "-no-color", "-random-agent",
             "-rate-limit", str(plan.rate_arg())],
            stdin=inp.encode(), timeout=600)
        # Hər ProcResult vəziyyəti AÇIQ şəkildə idarə olunur — uğursuz
        # alt-proses HEÇ VAXT "0 canlı host" kimi uğurlu təqdim edilmir.
        if res_proc.missing:
            self._warn_missing(res, "httpx", "canlı host aşkarlanmadı")
            return alive
        if res_proc.blocked:
            res.fail("httpx: egress/scope qapısı alt-prosesi BLOKLADI — "
                     "skan başladılmadı (canlı host nəticəsi yoxdur)")
            return alive
        if res_proc.timed_out:
            res.fail("httpx: timeout — nəticələr natamamdır "
                     "(canlı host nəticəsi etibarsız)")
            return alive
        if res_proc.returncode != 0:
            res.fail(f"httpx: proses uğursuz oldu (çıxış kodu "
                     f"{res_proc.returncode}): {_stderr_excerpt(res_proc.stderr)}")
            return alive

        malformed = 0
        for line in res_proc.stdout.decode(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            host = urllib.parse.urlparse(r.get("url", "")).hostname or ""
            try:
                host = normalize_host(host)
            except ScopeError:
                continue
            if not self.cfg.in_scope(host):
                continue
            tech_list = r.get("tech") if isinstance(r.get("tech"), list) \
                else ([r.get("tech")] if r.get("tech") else [])
            a = r.get("a") or []
            cdn = r.get("cdn")
            host_id = db.upsert_host(
                host,
                self.ctx.scan_id,
                ip=a[0] if a else None,
                cdn=(cdn[0] if isinstance(cdn, list) and cdn else cdn) or None,
                status_code=r.get("status_code"),
                title=str(r.get("title") or "")[:200],
                tech_raw=",".join(str(t) for t in tech_list))
            if self.guardian:
                self.guardian.observe(host, int(r.get("status_code") or 200))
            alive.append({"id": host_id, "url": r.get("url"), "host": host,
                          "status": r.get("status_code")})
            if len(alive) >= self.max_alive:
                break
        if malformed:
            res.warn(f"httpx: {malformed} xətalı JSON sətri atlandı "
                     "(nəticələr natamam ola bilər)")
        if not alive:
            if res_proc.stdout.strip():
                res.warn("httpx: scope-daxili etibarlı nəticə tapılmadı")
            else:
                res.warn("httpx: nəticə qaytarılmadı (boş çıxış) — hədəf "
                         "əlçatmaz sayılmır")
        print(f"[+] {len(alive)} yaşayan host")
        return alive

    async def _naabu(self, alive: list[dict], res: EngineResult):
        # Faza 3.6: port taraması tempi WAF qərarına uyğunlaşdırılır.
        plan = self.ctx.stealth.plan(
            self.rate * 10, base_concurrency=30, phase="ports")
        rate = plan.rate_arg()
        for h in alive[:30]:
            if self._skip(h["host"], res):
                continue
            row = db.get_db().execute(
                "SELECT real_ip, ip FROM hosts WHERE id=?", (h["id"],)).fetchone()
            target = (row and (row["real_ip"] or row["ip"])) or h["host"]
            # IP scope-da deyilsə (yalnız host icazəlidirsə) DNS adı ilə davam et
            if not self.cfg.in_scope(target):
                target = h["host"]
            ports = await self._naabu_scan(target, rate)
            if ports is None:            # naabu yoxdur → dürüst xəbərdarlıq
                self._warn_missing(res, "naabu", "port taraması atlandı")
                break
            if ports:
                db.insert_finding(
                    h["id"], "recon", "info",
                    f"Açıq portlar: {','.join(ports)}",
                    f"{h['host']} üzərində {len(ports)} port açıqdır "
                    f"(yalnız -top-ports 100)",
                    evidence=", ".join(ports), confidence=0.6,
                    source="naabu", scan_id=self.ctx.scan_id)
                res.findings += 1

    @staticmethod
    async def _naabu_scan(target: str, rate: int = 30) -> list[str] | None:
        """Açıq portları qaytarır; alət yoxdursa `None` (boş siyahıdan fərqli)."""
        r = await run_process(
            ["naabu", "-host", target, "-top-ports", "100",
             "-rate", str(max(1, int(rate))), "-silent",
             "-json", "-no-color"], timeout=180)
        if r.missing:
            return None
        if r.timed_out:
            return []
        ports: set[str] = set()
        for line in r.stdout.decode(errors="ignore").splitlines():
            try:
                ports.add(str(json.loads(line).get("port")))
            except (json.JSONDecodeError, TypeError):
                continue
        return sorted(p for p in ports if p and p != "None")

    async def _crawl(self, alive: list[dict], res: EngineResult):
        for h in alive[:20]:
            if self._skip(h["host"], res):
                continue
            url = h.get("url")
            if not url:
                continue
            r = await run_process(
                ["katana", "-u", url, "-d", "3", "-js-crawl", "-silent",
                 "-no-color", "-fs", "rdn",
                 "-H", f"User-Agent: {ua_for(h['host'])}"], timeout=300)
            if r.missing:
                self._warn_missing(res, "katana", "crawl atlandı")
                continue
            if r.timed_out:
                continue
            n = 0
            for line in r.stdout.decode(errors="ignore").splitlines():
                u = line.strip().strip('"')
                if not u.startswith("http"):
                    continue
                try:
                    host = normalize_host(u)
                except ScopeError:
                    continue
                if not self.cfg.in_scope(host):
                    continue
                db.insert_url(h["id"], u, "katana", u.endswith(".js"), scan_id=self.ctx.scan_id)
                res.urls += 1
                n += 1
            if n:
                print(f"[+] katana {h['host']}: {n} URL")

    async def _gau(self, domain: str, res: EngineResult):
        r = await run_process(["gau", domain, "--threads", "5"], timeout=180)
        if r.missing:
            self._warn_missing(res, "gau", "arxiv toplama atlandı")
            return
        if r.timed_out:
            return
        host_map = {h["subdomain"]: h["id"] for h in db.alive_hosts(self.ctx.scan_id)}
        n = 0
        for url in r.stdout.decode(errors="ignore").splitlines()[:2000]:
            url = url.strip()
            if not url:
                continue
            try:
                host = normalize_host(url)
            except ScopeError:
                continue
            if host in host_map and self.cfg.in_scope(host):
                db.insert_url(host_map[host], url, "gau", url.endswith(".js"), scan_id=self.ctx.scan_id)
                res.urls += 1
                n += 1
        print(f"[+] gau: {n} arxiv URL")
