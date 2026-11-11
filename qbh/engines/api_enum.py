"""API Enum: Kiterunner (yalnız GET) + OpenAPI/Swagger sənəd kəşfi.

Təhlükəsizlik prinsipləri:
  * Yalnız GET sorğuları qeyd olunur və hesabata düşür — POST/PUT/PATCH/DELETE
    nəticələri atılır (state dəyişən əməliyyat yoxdur).
  * OpenAPI/Swagger fallback zondları yalnız GET-dir.
  * Bütün sorğular Guardian/HttpPolicy-dən keçir (scope + rate + cooldown).
  * Tapılan route-lar scope yoxlamasından keçir.
"""
from __future__ import annotations

import os
import re

import aiohttp

from .. import db
from ..adapters.base import run_process
from ..antiblock.ua_rotator import ua_for
from ..http_policy import TargetBlocked
from ..results import EngineResult
from ..scope import ScopeError

KR_FILES = [
    "/opt/kiterunner/routes/WordPress/routes-WordPress.kite",
    "/opt/kiterunner/routes/Generic/generic-api.kite",
]

COMMON_API = ["v1", "v2", "v3", "users", "auth", "login", "admin",
              "graphql", "docs", "swagger", "openapi.json", "health",
              "api-docs", "redoc"]

MAX_HOSTS = 15
MAX_PROBES = 24
TARGET_TIMEOUT = 300

_KR_LINE = re.compile(r"\b(200|201|204|401|403)\b.*?\b(GET)\s+(\S+)")


class APIEnumEngine:
    name = "api_enum"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        hosts = db.alive_hosts()[:MAX_HOSTS]
        if not hosts:
            return res.skip("yaşayan host yoxdur — API enum atlandı")

        kr_files = [f for f in KR_FILES if os.path.exists(f)]
        if kr_files:
            print(f"[═══ API ENUM (Kiterunner) ═══] {len(kr_files)} route faylı")
            preferred = [h for h in hosts
                         if "api" in (h["tech_raw"] or "").lower()]
            for row in (preferred or hosts):
                host = row["subdomain"]
                if self.guardian and self.guardian.halted(host):
                    res.warn(f"{host} cooldown altındadır — atlandı")
                    continue
                for wordlist in kr_files:
                    await self._kr(row, wordlist, res)
        else:
            res.warn("kiterunner route faylları tapılmadı — yalnız OpenAPI zondları")

        await self._fallback(hosts, res)
        return res

    async def _kr(self, row, wordlist: str, res: EngineResult) -> None:
        host = row["subdomain"]
        try:
            self.cfg.authorize_target(host)
        except ScopeError as exc:
            res.warn(f"{host}: {exc}")
            return
        proc = await run_process(
            ["kr", "scan", f"https://{host}", "-w", wordlist],
            timeout=TARGET_TIMEOUT)
        if proc.missing:
            res.warn("kiterunner (kr) tapılmadı")
            return
        if proc.timed_out:
            res.warn(f"kiterunner {host}: timeout")
        self._parse_kr(row, proc.stdout.decode(errors="ignore"), res)

    def _parse_kr(self, row, text: str, res: EngineResult) -> None:
        host = row["subdomain"]
        for line in text.splitlines():
            m = _KR_LINE.search(line)
            if not m:
                continue
            status, method, route = m.groups()
            url = f"https://{host}{route}"
            if not self.cfg.in_scope(url):
                res.warn(f"scope xaricində route rədd edildi: {url}")
                continue
            db.insert_url(row["id"], url, "kiterunner", False)
            res.urls += 1
            if int(status) in (200, 201, 204):
                db.insert_finding(
                    row["id"], "apienum", "medium",
                    f"API route: {route}",
                    f"Kiterunner tapdı — {method} {route} → {status}. "
                    f"Yalnız GET təsdiqlənir; digər metodlar tətbiq edilmir.",
                    evidence=url,
                    curl_repro=(f"curl -X GET '{url}' -H "
                                f"'User-Agent: {ua_for(host)}'"),
                    confidence=0.6, status="potential", source="kiterunner")
                res.findings += 1
                print(f"[⚡] {host}: GET {route} ({status})")

    async def _fallback(self, hosts: list, res: EngineResult) -> None:
        """Kiterunner yoxdursa: yalnız GET ilə OpenAPI/Swagger zondları."""
        if not self.guardian:
            res.fail("guardian yoxdur — API zondları təhlükəsiz icra oluna bilməz")
            return
        async with aiohttp.ClientSession() as session:
            for h in hosts:
                host = h["subdomain"]
                if self.guardian.halted(host):
                    res.warn(f"{host} cooldown altındadır — atlandı")
                    continue
                candidates = [f"https://{host}/openapi.json",
                              f"https://{host}/swagger.json",
                              f"https://{host}/api-docs"]
                for seg in ("api", "api/v1", "rest"):
                    candidates += [f"https://{host}/{seg}/{w}"
                                   for w in COMMON_API[:6]]
                for url in candidates[:MAX_PROBES]:
                    try:
                        r = await self.guardian.get(
                            session, url, allow_redirects=False)
                    except TargetBlocked as exc:
                        res.warn(str(exc))
                        break
                    except ScopeError as exc:
                        res.warn(f"{url}: {exc}")
                        continue
                    except (aiohttp.ClientError, OSError):
                        continue
                    if r.status != 200:
                        continue
                    if not self.cfg.in_scope(r.url):
                        continue
                    db.insert_url(h["id"], r.url, "api-enum", False)
                    res.urls += 1
                    if "openapi" in url or "swagger" in url:
                        db.insert_finding(
                            h["id"], "apienum", "medium",
                            f"API sənədi açıqdır: {url}",
                            "OpenAPI/Swagger sxemi əlçatandır — sxem ictimai "
                            "olduqda həssas endpoint siyahısı sıza bilər.",
                            evidence=url, confidence=0.6,
                            status="potential", source="api-enum")
                        res.findings += 1
                        print(f"[⚡] {url} → 200 (API sxemi!)")
