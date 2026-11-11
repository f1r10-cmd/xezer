"""Recon dərinləşdirmə mühərrikləri (Faza 1.2).

  * `BBOTEngine`      — BBOT ilə alternativ/əlavə dərin kəşf (host + URL).
  * `WaymoreEngine`   — waymore: tarixi URL-lər + cavab gövdələri (gau yanında).
  * `GowitnessEngine` — canlı hostların ekran görüntüsü inventarı.
  * `DnstwistEngine`  — typosquat/lookalike domenlər → `candidate` tapıntılar.

Dürüstlük: hər mühərrik alət binary-si yoxdursa `skipped (tool unavailable)`
qaytarır — "işlədi" iddiası verilmir. Bütün nəticələr scope yoxlamasından və
egress (DNS pinning) qapısından keçir.
"""
from __future__ import annotations

import json
import os
import urllib.parse

from .. import db
from ..adapters.base import run_process
from ..results import EngineResult
from ..scope import ScopeError, normalize_host

TIMEOUT = 900


class BBOTEngine:
    """BBOT — çoxmərhələli dərin kəşf (subdomain-enum + URL)."""

    name = "bbot"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.max_subs = int(ctx.limits.max_subdomains_per_target)

    async def run(self, domain: str) -> EngineResult:
        res = EngineResult(stage=self.name)
        try:
            domain = self.ctx.scope.authorize(domain)
        except ScopeError as exc:
            res.fail(f"scope xaricində hədəf rədd edildi: {exc}")
            return res
        tset = await self.ctx.egress.authorize_process_targets([domain])
        if domain not in set(tset.hostnames):
            res.fail(f"egress: {domain} icazəli deyil")
            return res
        proc = await run_process(
            ["bbot", "-t", domain, "-f", "subdomain-enum", "-om", "json",
             "-o", "/dev/stdout", "-y", "--no-color"],
            timeout=TIMEOUT)
        if proc.missing:
            res.warn("bbot tapılmadı — dərin kəşf atlandı")
            return res.skip("bbot mövcud deyil")
        if proc.timed_out:
            res.warn("bbot timeout — qismən nəticə")
        hosts = self._parse_hosts(proc.stdout.decode(errors="ignore"))
        added = 0
        for host in hosts:
            try:
                host = normalize_host(host)
            except ScopeError:
                continue
            if not self.cfg.in_scope(host):
                continue
            db.upsert_host(host, self.ctx.scan_id, source="bbot")
            added += 1
            if added >= self.max_subs:
                break
        res.hosts = added
        res.data["subdomains"] = {domain}
        print(f"[+] bbot: {added} scope-daxili host")
        return res

    @staticmethod
    def _parse_hosts(out: str) -> set[str]:
        found: set[str] = set()
        for line in out.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            data = obj.get("data") if isinstance(obj, dict) else None
            if isinstance(data, str):
                found.add(data)
            elif isinstance(data, dict):
                for key in ("host", "name", "url"):
                    if data.get(key):
                        found.add(urllib.parse.urlparse(
                            str(data[key])).hostname or str(data[key]))
        return {h for h in found if h}


class WaymoreEngine:
    """waymore — tarixi URL-lər və cavab gövdələri (gau-dan dərin)."""

    name = "waymore"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.max_urls = 400

    async def run(self, domain: str) -> EngineResult:
        res = EngineResult(stage=self.name)
        try:
            domain = self.ctx.scope.authorize(domain)
        except ScopeError as exc:
            res.fail(f"scope xaricində hədəf rədd edildi: {exc}")
            return res
        tset = await self.ctx.egress.authorize_process_targets([domain])
        if domain not in set(tset.hostnames):
            res.fail(f"egress: {domain} icazəli deyil")
            return res
        proc = await run_process(
            ["waymore", "-i", domain, "-mode", "U", "-n", "0"],
            timeout=TIMEOUT)
        if proc.missing:
            res.warn("waymore tapılmadı — atlandı")
            return res.skip("waymore mövcut deyil")
        added = 0
        for line in proc.stdout.decode(errors="ignore").splitlines():
            url = line.strip()
            if not url.startswith("http") or not self.cfg.in_scope(url):
                continue
            host = urllib.parse.urlparse(url).hostname or ""
            try:
                host = normalize_host(host)
            except ScopeError:
                continue
            host_id = db.upsert_host(host, self.ctx.scan_id, source="waymore")
            db.insert_url(host_id, url, "waymore", url.endswith(".js"), scan_id=self.ctx.scan_id)
            added += 1
            if added >= self.max_urls:
                break
        res.urls = added
        print(f"[+] waymore: {added} URL")
        return res


class GowitnessEngine:
    """gowitness — canlı hostların ekran görüntüsü inventarı."""

    name = "gowitness"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        hosts = db.alive_hosts(self.ctx.scan_id)[:50]
        if not hosts:
            return res.skip("yaşayan host yoxdur — skrinşot atlandı")
        outdir = os.path.join("reports", "screenshots",
                              str(db.effective_scan_id(self.ctx.scan_id)))
        os.makedirs(outdir, exist_ok=True)
        targets = "\n".join(f"https://{h['subdomain']}" for h in hosts)
        proc = await run_process(
            ["gowitness", "scan", "file", "-", "--screenshot-path", outdir,
             "--write-db", "--no-http"], stdin=targets.encode(), timeout=TIMEOUT)
        if proc.missing:
            res.warn("gowitness tapılmadı — skrinşot atlandı")
            return res.skip("gowitness mövcud deyil")
        shots = {}
        for name in os.listdir(outdir):
            for h in hosts:
                if h["subdomain"] in name:
                    shots[h["subdomain"]] = os.path.join(outdir, name)
        res.data["screenshots"] = shots
        res.hosts = len(shots)
        print(f"[+] gowitness: {len(shots)} skrinşot")
        return res


class DnstwistEngine:
    """dnstwist — typosquat/lookalike domenlər (candidate tapıntılar)."""

    name = "dnstwist"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.max_items = 30

    async def run(self, domain: str) -> EngineResult:
        res = EngineResult(stage=self.name)
        try:
            domain = self.ctx.scope.authorize(domain)
        except ScopeError as exc:
            res.fail(f"scope xaricində hədəf rədd edildi: {exc}")
            return res
        proc = await run_process(
            ["dnstwist", "--registered", "--format", "json", domain],
            timeout=TIMEOUT)
        if proc.missing:
            res.warn("dnstwist tapılmadı — atlandı")
            return res.skip("dnstwist mövcud deyil")
        try:
            data = json.loads(proc.stdout.decode(errors="ignore") or "[]")
        except json.JSONDecodeError:
            res.warn("dnstwist JSON oxuna bilmədi")
            return res
        host_id = db.upsert_host(domain, self.ctx.scan_id)
        count = 0
        for item in (data or [])[: self.max_items]:
            dom = item.get("domain")
            if not dom:
                continue
            # Qeyd: lookalike domenlər scope XARİCİDİR — onlara trafik
            # göndərilmir, yalnız məlumatlandırıcı tapıntı kimi qeyd olunur.
            db.insert_finding(
                host_id, "dnstwist", "low",
                f"Lookalike domen: {dom}",
                f"{domain} üçün oxşar domen aşkarlandı (typosquat/impersonation "
                f"riski). QEYD: bu domen scope xaricindədir — ona trafik "
                f"göndərilmir.",
                evidence=dom, confidence=0.3, status="candidate",
                source="dnstwist", scan_id=self.ctx.scan_id)
            count += 1
        res.findings = count
        print(f"[+] dnstwist: {count} lookalike domen")
        return res
