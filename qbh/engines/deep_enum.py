"""M1+ Deep Enum: Subfinder + Amass + crt.sh + Alterx permutation + DNS.

Qeyd: crt.sh və digər kəşf mənbələri HƏDƏF DEYİL — onlar üçün scope
tətbiq olunmur. Scope yoxlaması yalnız tapılan hostlara tətbiq edilir.
"""
from __future__ import annotations

import asyncio
import json

import aiohttp

from .. import db
from ..adapters.base import run_process
from ..antiblock.ua_rotator import ua_for
from ..redact import redact
from ..results import EngineResult
from ..scope import ScopeError, normalize_host


class DeepEnumEngine:
    name = "deep_enum"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian
        self.max_subs = int(ctx.limits.max_subdomains_per_target)

    async def run(self, domain: str) -> EngineResult:
        res = EngineResult(stage=self.name)
        try:
            domain = self.ctx.scope.authorize(domain)
        except ScopeError as exc:
            res.fail(f"scope xaricində hədəf rədd edildi: {exc}")
            return res
        print(f"[═══ M1+ DEEP ENUM ═══] {domain}")

        labels = ("subfinder", "amass", "crt.sh", "alterx")
        gathered = await asyncio.gather(
            self._subfinder(domain), self._amass(domain),
            self._crtsh(domain), self._permutation(domain),
            return_exceptions=True)

        provenance: dict[str, set] = {}
        for label, item in zip(labels, gathered, strict=False):
            if isinstance(item, BaseException):
                res.warn(f"{label} mənbəyi xətası: {redact(str(item))}")
                continue
            for s in item:
                provenance.setdefault(s, set()).add(label)

        valid: dict[str, set] = {}
        rejected = 0
        for s, srcs in provenance.items():
            try:
                host = normalize_host(s)
            except ScopeError:
                rejected += 1
                continue
            if not self.cfg.in_scope(host):
                rejected += 1
                continue
            valid[host] = srcs
        if rejected:
            res.warn(f"{rejected} nəticə scope/format yoxlamasından keçmədi")

        if len(valid) > self.max_subs:
            res.warn(f"subdomain limiti tətbiq edildi: "
                     f"{len(valid)} → {self.max_subs}")
            valid = dict(sorted(valid.items())[: self.max_subs])

        await self._dns_resolve(sorted(valid))

        for host, srcs in valid.items():
            db.upsert_host(host, source=",".join(sorted(srcs)))
        res.hosts = len(valid)
        res.data["subdomains"] = set(valid) | {domain}
        print(f"[+] Ümumi unikal, scope-daxili subdomain: {len(valid)}")
        return res

    # ---------------- mənbələr ----------------
    async def _subfinder(self, domain: str) -> set[str]:
        res = await run_process(
            ["subfinder", "-d", domain, "-all", "-silent"], timeout=600)
        if res.missing:
            raise RuntimeError("subfinder tapılmadı")
        if res.timed_out:
            raise RuntimeError("subfinder timeout")
        subs = {ln.strip() for ln in res.stdout.decode(errors="ignore").splitlines()
                if ln.strip()}
        print(f"[+] subfinder: {len(subs)}")
        return subs

    async def _amass(self, domain: str) -> set[str]:
        res = await run_process(
            ["amass", "enum", "-passive", "-d", domain, "-timeout", "5"],
            timeout=900)
        if res.missing:
            print("[-] amass yoxdur — subfinder kifayət edir")
            return set()
        if res.timed_out:
            print("[-] amass timeout")
            return set()
        subs = set()
        for ln in res.stdout.decode(errors="ignore").splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("["):
                subs.add(ln.split()[0])
        print(f"[+] amass: {len(subs)}")
        return subs

    async def _crtsh(self, domain: str) -> set[str]:
        subs: set[str] = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            timeout = aiohttp.ClientTimeout(total=60)
            async with aiohttp.ClientSession() as s:
                async with s.get(url, timeout=timeout,
                                 headers={"User-Agent": ua_for("crt.sh")}) as r:
                    if r.status == 200:
                        for entry in await r.json(content_type=None):
                            for name in str(entry.get("name_value", "")).split("\n"):
                                name = name.strip().lstrip("*.")
                                if name:
                                    subs.add(name)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            raise RuntimeError(f"crt.sh xətası: {redact(str(exc))}") from exc
        print(f"[+] crt.sh: {len(subs)}")
        return subs

    async def _permutation(self, domain: str) -> set[str]:
        alt = await run_process(["alterx", "-l", domain], timeout=120)
        if alt.missing:
            print("[-] alterx yoxdur — permutation atlandı")
            return set()
        if alt.timed_out or not alt.stdout.strip():
            return set()
        dns = await run_process(
            ["dnsx", "-silent", "-a", "-resp"], stdin=alt.stdout, timeout=600)
        if dns.missing or dns.timed_out:
            return set()
        live: set[str] = set()
        for line in dns.stdout.decode(errors="ignore").splitlines():
            host = line.split(" ")[0].strip("[].")
            if host and self.cfg.in_scope(host):
                live.add(host)
        print(f"[+] permutation: {len(live)} canlı variant")
        return live

    async def _dns_resolve(self, hosts: list[str]):
        if not hosts:
            return
        res = await run_process(
            ["dnsx", "-silent", "-json", "-a", "-cname", "-resp"],
            stdin="\n".join(hosts).encode(), timeout=600)
        if res.missing or res.timed_out:
            return
        for line in res.stdout.decode(errors="ignore").splitlines():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = r.get("host", "")
            try:
                host = normalize_host(host)
            except ScopeError:
                continue
            if not self.cfg.in_scope(host):
                continue
            a = r.get("a") or []
            cname = str(r.get("cname") or "").lower()
            db.upsert_host(
                host,
                ip=a[0] if a else None,
                cdn="cloudflare" if "cloudflare" in cname else None)
