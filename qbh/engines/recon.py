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
from ..results import EngineResult
from ..scope import ScopeError, normalize_host


class ReconEngine:
    name = "recon"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian
        self.max_subs = int(ctx.limits.max_subdomains_per_target)
        self.max_alive = 200

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
        print(f"[+] {len(subs)} host recon boru xəttinə daxil oldu")

        alive = await self._httpx(subs)
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

    async def _httpx(self, subdomains: list[str]) -> list[dict]:
        inp = "\n".join(subdomains)
        res = await run_process(
            ["httpx", "-json", "-silent", "-tech-detect", "-title",
             "-cdn", "-status-code", "-no-color"],
            stdin=inp.encode(), timeout=600)
        alive: list[dict] = []
        if res.missing:
            print("[-] httpx tapılmadı")
            return alive
        if res.timed_out:
            print("[-] httpx timeout")
            return alive

        for line in res.stdout.decode(errors="ignore").splitlines():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
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
        print(f"[+] {len(alive)} yaşayan host")
        return alive

    async def _naabu(self, alive: list[dict], res: EngineResult):
        for h in alive[:30]:
            if self._skip(h["host"], res):
                continue
            row = db.get_db().execute(
                "SELECT real_ip, ip FROM hosts WHERE id=?", (h["id"],)).fetchone()
            target = (row and (row["real_ip"] or row["ip"])) or h["host"]
            # IP scope-da deyilsə (yalnız host icazəlidirsə) DNS adı ilə davam et
            if not self.cfg.in_scope(target):
                target = h["host"]
            ports = await self._naabu_scan(target)
            if ports:
                db.insert_finding(
                    h["id"], "recon", "info",
                    f"Açıq portlar: {','.join(ports)}",
                    f"{h['host']} üzərində {len(ports)} port açıqdır "
                    f"(yalnız -top-ports 100)",
                    evidence=", ".join(ports), confidence=0.6,
                    source="naabu")
                res.findings += 1

    @staticmethod
    async def _naabu_scan(target: str) -> list[str]:
        r = await run_process(
            ["naabu", "-host", target, "-top-ports", "100", "-silent",
             "-json", "-no-color"], timeout=180)
        if r.missing or r.timed_out:
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
            if r.missing or r.timed_out:
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
                db.insert_url(h["id"], u, "katana", u.endswith(".js"))
                res.urls += 1
                n += 1
            if n:
                print(f"[+] katana {h['host']}: {n} URL")

    async def _gau(self, domain: str, res: EngineResult):
        r = await run_process(["gau", domain, "--threads", "5"], timeout=180)
        if r.missing or r.timed_out:
            return
        host_map = {h["subdomain"]: h["id"] for h in db.alive_hosts()}
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
                db.insert_url(host_map[host], url, "gau", url.endswith(".js"))
                res.urls += 1
                n += 1
        print(f"[+] gau: {n} arxiv URL")
