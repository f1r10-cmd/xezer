"""API Enum: Kiterunner (yalnız GET) + OpenAPI/Swagger sənəd kəşfi.

Təhlükəsizlik prinsipləri:
  * Yalnız GET sorğuları göndərilir: Kiterunner `--force-method GET` ilə İCRA
    səviyyəsində məcbur edilir (yalnız çıxışı süzməklə DEYİL). POST/PUT/PATCH/
    DELETE HEÇ VAXT göndərilmir.
  * OpenAPI/Swagger fallback zondları yalnız GET-dir.
  * Bütün sorğular Guardian/HttpPolicy-dən keçir (scope + rate + cooldown).
  * Tapılan route-lar scope yoxlamasından keçir.

Etibarlılıq:
  * Kiterunner binari-sinin mövcudluğu route fayllarının mövcudluğundan AYRI
    yoxlanılır və AYRI bildirilir.
  * Route faylları konfiqurasiya ilə verilə bilər (`api_enum.route_paths`);
    köhnə sabit yollar fallback kimi qorunur. Rekursiv filesystem axtarışı,
    avtomatik yükləmə və quraşdırma APARILMIR.
  * Kiterunner uğursuz olsa belə OpenAPI fallback davam edir.
  * Protokol (HTTP/HTTPS) paylaşılan `ServiceResolver` ilə seçilir → yalnız
    HTTP-də xidmət göstərən host da yoxlanılır.
"""
from __future__ import annotations

import os
import re
import shutil

import aiohttp

from .. import db
from ..adapters.base import run_process
from ..antiblock.ua_rotator import ua_for
from ..http_policy import TargetBlocked
from ..results import EngineResult
from ..scope import ScopeError
from ..service_url import ServiceResolver, failure_label

#: Kiterunner binari adı (PATH-dən axtarılır).
KR_BIN = "kr"

#: Köhnə sabit yollar — konfiq verilmədikdə fallback kimi yoxlanılır.
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


def _is_kite(path: str) -> bool:
    return path.endswith(".kite") and os.path.isfile(path) \
        and os.access(path, os.R_OK)


def collect_route_files(configured: list[str]) -> tuple[list[str], list[str]]:
    """`(tapılan .kite faylları, yoxlanılan yerlər)`.

    Konfiqurasiya yolları ƏVVƏL, sonra daxili fallback yolları yoxlanılır.
    Kataloq verilərsə YALNIZ bir səviyyə (rekursiv deyil) `*.kite` faylları
    oxunur. Eyni fayl (realpath) BİR dəfədən çox əlavə olunmur.
    """
    found: list[str] = []
    checked: list[str] = []
    seen_files: set[str] = set()
    seen_checked: set[str] = set()

    for entry in [*configured, *KR_FILES]:
        if entry in seen_checked:
            continue
        seen_checked.add(entry)
        checked.append(entry)
        if os.path.isdir(entry):
            try:
                names = sorted(os.listdir(entry))
            except OSError:
                continue
            for name in names:
                cand = os.path.join(entry, name)
                if not _is_kite(cand):
                    continue
                real = os.path.realpath(cand)
                if real in seen_files:
                    continue
                seen_files.add(real)
                found.append(cand)
        elif _is_kite(entry):
            real = os.path.realpath(entry)
            if real in seen_files:
                continue
            seen_files.add(real)
            found.append(entry)
    return found, checked


class APIEnumEngine:
    name = "api_enum"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        hosts = db.alive_hosts(self.ctx.scan_id)[:MAX_HOSTS]
        if not hosts:
            return res.skip("yaşayan host yoxdur — API enum atlandı")

        kr_available = shutil.which(KR_BIN) is not None
        route_files, checked = collect_route_files(
            self.cfg.api_enum.route_paths)

        if not kr_available:
            res.warn("kiterunner (kr) tapılmadı — yalnız OpenAPI fallback "
                     "icra olunur")
        if not route_files:
            res.warn("kiterunner route faylı (.kite) tapılmadı — yoxlanılan "
                     "yerlər: " + ", ".join(checked))
        elif not kr_available:
            res.warn(f"{len(route_files)} route faylı mövcuddur, lakin 'kr' "
                     "binari yoxdur — Kiterunner skanı icra olunmur")

        if kr_available and route_files:
            print(f"[═══ API ENUM (Kiterunner) ═══] {len(route_files)} route faylı")
            resolver = ServiceResolver(self.guardian)
            preferred = [h for h in hosts
                         if "api" in (h["tech_raw"] or "").lower()]
            async with aiohttp.ClientSession() as session:
                for row in (preferred or hosts):
                    host = row["subdomain"]
                    if self.guardian and self.guardian.halted(host):
                        res.warn(f"{host} cooldown altındadır — atlandı")
                        continue
                    for wordlist in route_files:
                        await self._kr(session, resolver, row, wordlist, res)

        # Kiterunner uğursuz/mövcud olmasa belə fallback HƏMİŞƏ icra olunur.
        await self._fallback(hosts, res)
        return res

    async def _kr(self, session, resolver: ServiceResolver, row,
                  wordlist: str, res: EngineResult) -> None:
        host = row["subdomain"]
        try:
            self.cfg.authorize_target(host)
        except ScopeError as exc:
            res.warn(f"{host}: {exc}")
            return
        try:
            hint = db.scheme_hint(row["id"], self.ctx.scan_id)
            ep = await resolver.resolve(session, host, hint=hint)
        except TargetBlocked as exc:
            res.warn(str(exc))
            return
        except ScopeError as exc:
            res.warn(f"{host}: {exc}")
            return
        if not ep.ok:
            res.warn(f"{host}: {failure_label(ep.kind)} — kiterunner atlandı")
            return
        base = ep.base
        # Faza 0.2: kiterunner hədəfi egress validasiyasından keçir.
        tset = await self.ctx.egress.authorize_process_targets([base])
        if host not in set(tset.hostnames):
            res.warn(f"egress: {host} scope xaricindədir — kiterunner atlandı")
            return
        # `--force-method GET` → .kite faylındakı metodlar TAMAMİLƏ əvəz olunur;
        # GET-dən başqa heç bir state dəyişən metod GÖNDƏRİLMİR.
        proc = await run_process(
            ["kr", "scan", base, "-w", wordlist, "--force-method", "GET"],
            timeout=TARGET_TIMEOUT)
        if proc.missing:
            res.warn("kiterunner (kr) tapılmadı")
            return
        if proc.timed_out:
            res.warn(f"kiterunner {host}: timeout — qismən nəticələr yoxlanılır")
        self._parse_kr(row, proc.stdout.decode(errors="ignore"), ep, res)

    def _parse_kr(self, row, text: str, ep, res: EngineResult) -> None:
        host = row["subdomain"]
        for line in text.splitlines():
            m = _KR_LINE.search(line)
            if not m:
                continue
            status, method, route = m.groups()
            if method != "GET":  # müdafiə qatı (icra səviyyəsində onsuz da GET)
                continue
            url = ep.url(route)
            if not self.cfg.in_scope(url):
                res.warn(f"scope xaricində route rədd edildi: {url}")
                continue
            db.insert_url(row["id"], url, "kiterunner", False, scan_id=self.ctx.scan_id)
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
                    confidence=0.6, status="potential", source="kiterunner",
                    scan_id=self.ctx.scan_id)
                res.findings += 1
                print(f"[⚡] {host}: GET {route} ({status})")

    async def _fallback(self, hosts: list, res: EngineResult) -> None:
        """Kiterunner yoxdursa: yalnız GET ilə OpenAPI/Swagger zondları."""
        if not self.guardian:
            res.fail("guardian yoxdur — API zondları təhlükəsiz icra oluna bilməz")
            return
        resolver = ServiceResolver(self.guardian)
        async with aiohttp.ClientSession() as session:
            for h in hosts:
                host = h["subdomain"]
                if self.guardian.halted(host):
                    res.warn(f"{host} cooldown altındadır — atlandı")
                    continue
                try:
                    hint = db.scheme_hint(h["id"], self.ctx.scan_id)
                    ep = await resolver.resolve(session, host, hint=hint)
                except TargetBlocked as exc:
                    res.warn(str(exc))
                    break
                except ScopeError as exc:
                    res.warn(f"{host}: {exc}")
                    continue
                if not ep.ok:
                    res.warn(f"{host}: {failure_label(ep.kind)} — API zondları "
                             "atlandı")
                    continue
                candidates = [ep.url("/openapi.json"),
                              ep.url("/swagger.json"),
                              ep.url("/api-docs")]
                for seg in ("api", "api/v1", "rest"):
                    candidates += [ep.url(f"/{seg}/{w}")
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
                    db.insert_url(h["id"], r.url, "api-enum", False, scan_id=self.ctx.scan_id)
                    res.urls += 1
                    if "openapi" in url or "swagger" in url:
                        db.insert_finding(
                            h["id"], "apienum", "medium",
                            f"API sənədi açıqdır: {url}",
                            "OpenAPI/Swagger sxemi əlçatandır — sxem ictimai "
                            "olduqda həssas endpoint siyahısı sıza bilər.",
                            evidence=url, confidence=0.6,
                            status="potential", source="api-enum",
                            scan_id=self.ctx.scan_id)
                        res.findings += 1
                        print(f"[⚡] {url} → 200 (API sxemi!)")
