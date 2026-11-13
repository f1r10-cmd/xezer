"""Faza 3.3 — CNAME takeover (subdomain itkisi) detektoru.

Məntiq (yalnız scope-daxili trafik):
  1. Hər canlı host üçün **CNAME** qeydi oxunur (in-scope DNS sorğusu).
  2. CNAME hədəfi tanınmış zəif provayder siyahısı ilə uyğunlaşdırılır
     (məs. `*.s3.amazonaws.com`, `*.github.io`).
  3. Uyğunluq varsa hostun ünvan qeydləri (A/AAAA) yoxlanılır:
       * ünvan YOXDUR → zəncir qırıqdır (NXDOMAIN) → `candidate` (high);
       * ünvan VAR → host özü HTTP ilə sorğulanır (in-scope) və provayderin
         "sahibsiz/donmuş" imzası (məs. `NoSuchBucket`) axtarılır → uyğun
         olarsa `confirmed`.

Scope təminatı: YALNIZ in-scope host adları həll olunur və YALNIZ in-scope
hosta HTTP sorğusu gedir. CNAME hədəfinə (out-of-scope ola bilər) HEÇ VAXT
sorğu göndərilmir — yalnız sətir müqayisəsi aparılır.
"""
from __future__ import annotations

import asyncio

import aiohttp

from .. import db
from ..http_policy import TargetBlocked
from ..results import EngineResult
from ..scope import ScopeError

MAX_HOSTS = 300
CONFIRM_CONF = 0.85
CANDIDATE_CONF = 0.6

#: (provayder adı, CNAME sonluğu, "sahibsiz" cavab imzaları).
VULNERABLE_PROVIDERS: list[tuple[str, str, tuple[str, ...]]] = [
    ("AWS S3", "s3.amazonaws.com",
     ("NoSuchBucket", "The specified bucket does not exist")),
    ("AWS CloudFront", "cloudfront.net",
     ("ERROR: The request could not be satisfied", "Bad request")),
    ("GitHub Pages", "github.io",
     ("There isn't a GitHub Pages site here",)),
    ("Heroku", "herokuapp.com", ("No such app", "heroku | no such app")),
    ("Azure Web Apps", "azurewebsites.net",
     ("Error 404 - Web app not found",)),
    ("Netlify", "netlify.app", ("Not Found", "DEPLOYMENT_NOT_FOUND")),
    ("Read the Docs", "readthedocs.io", ("unknown to Read the Docs",)),
    ("Fastly", "fastly.net", ("Fastly error: unknown domain",)),
    ("Shopify", "myshopify.com",
     ("Sorry, this shop is currently unavailable",)),
    ("Surge.sh", "surge.sh", ("project not found",)),
    ("Bitbucket", "bitbucket.io", ("Repository not found",)),
    ("Pantheon", "pantheonsite.io",
     ("The gods are wise, but do not know of the site",)),
    ("Zendesk", "zendesk.com", ("Help Center Closed",)),
    ("Tumblr", "domains.tumblr.com",
     ("Whatever you were looking for doesn't currently exist",)),
    ("WordPress.com", "wordpress.com", ("Do you want to register",)),
    ("Vercel", "vercel.app", ("DEPLOYMENT_NOT_FOUND",)),
]


def match_provider(cnames: list[str]) -> tuple[str, str, tuple[str, ...]] | None:
    """CNAME hədəflərini zəif provayder siyahısı ilə uyğunlaşdırır."""
    for target in cnames:
        t = (target or "").lower().rstrip(".")
        for name, suffix, fps in VULNERABLE_PROVIDERS:
            if t == suffix or t.endswith("." + suffix):
                return name, suffix, fps
    return None


def default_cname_resolver(host: str) -> list[str]:
    """dnspython ilə hostun CNAME qeydlərini oxuyur (yoxdursa boş)."""
    try:
        import dns.resolver
    except Exception:  # noqa: BLE001 - paket yoxdursa dürüst boş
        return []
    try:
        answer = dns.resolver.resolve(host, "CNAME", lifetime=5.0)
    except Exception:  # noqa: BLE001 - NXDOMAIN/NoAnswer/timeout
        return []
    out: list[str] = []
    for rr in answer:
        target = str(getattr(rr, "target", rr)).rstrip(".")
        if target and target not in out:
            out.append(target)
    return out


class TakeoverEngine:
    name = "takeover"

    def __init__(self, ctx, *, cname_resolver=None, address_resolver=None,
                 url_builder=None, max_hosts: int = MAX_HOSTS):
        from ..egress import system_resolver

        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian
        self._cname = cname_resolver or default_cname_resolver
        self._addr = address_resolver or system_resolver
        self._url = url_builder or (lambda h: f"https://{h}/")
        self.max_hosts = max_hosts

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        hosts = db.alive_hosts(self.ctx.scan_id)
        if not hosts:
            return res.skip("yaşayan host yoxdur — takeover yoxlaması atlandı")
        print(f"[═══ CNAME TAKEOVER ═══] {len(hosts)} host")

        async with aiohttp.ClientSession() as session:
            for row in hosts[:self.max_hosts]:
                host = row["subdomain"]
                if not self.cfg.in_scope(host):
                    continue
                if self.guardian and self.guardian.halted(host):
                    res.warn(f"{host} cooldown altındadır — atlandı")
                    continue
                try:
                    await self._check(session, row, res)
                except (TargetBlocked, ScopeError) as exc:
                    res.warn(f"{host}: {exc}")
        res.data = {"checked": min(len(hosts), self.max_hosts)}
        return res

    async def _check(self, session, row, res: EngineResult) -> None:
        host = row["subdomain"]
        cnames = await self._resolve(self._cname, host)
        if not cnames:
            return
        provider = match_provider(cnames)
        if provider is None:
            return
        name, _suffix, fingerprints = provider
        cname = cnames[0]

        addrs = await self._resolve(self._addr, host)
        if not addrs:
            # Zəncir qırıqdır (NXDOMAIN) → takeover namizədi (təsdiq tələb edir).
            self._record(row, "candidate", CANDIDATE_CONF, name, cname,
                         evidence=f"CNAME → {cname} · ünvan (A/AAAA) YOXDUR "
                                  f"(qırıq zəncir)", res=res)
            return
        await self._confirm(session, row, name, cname, fingerprints, res)

    async def _confirm(self, session, row, name, cname, fingerprints, res):
        """Host özü HTTP ilə sorğulanır; provayder imzası varsa → confirmed."""
        if self.guardian is None:
            res.warn("guardian yoxdur — takeover təsdiqi aparıla bilməz")
            return
        url = self._url(row["subdomain"])
        try:
            self.ctx.authorize_url(url)
        except Exception as exc:  # noqa: BLE001 - scope/RoE
            res.warn(f"{url}: {exc}")
            return
        try:
            self.ctx.authorization.ensure_active()
            r = await self.guardian.get(session, url, allow_redirects=False)
        except (TargetBlocked, ScopeError, aiohttp.ClientError, OSError):
            return
        body = r.text or ""
        hit = next((fp for fp in fingerprints if fp and fp in body), None)
        if hit:
            self._record(row, "confirmed", CONFIRM_CONF, name, cname,
                         evidence=f"CNAME → {cname} · provayder imzası "
                                  f"'{hit}' (HTTP {r.status})", res=res)

    def _record(self, row, status: str, confidence: float, name: str,
                cname: str, *, evidence: str, res: EngineResult) -> None:
        host = row["subdomain"]
        title = f"CNAME takeover: {name} ({host})"
        description = (f"{host} domeni {name} provayderinə CNAME ilə yönləndirilir "
                       f"({cname}) və provayder səhifəsi sahibsiz görünür. "
                       f"Bu, subdomain ələ keçirməsinə (takeover) imkan verə bilər.")
        db.insert_finding(row["id"], self.name,
                          "high" if status == "confirmed" else "medium",
                          title, description,
                          evidence=evidence, confidence=confidence,
                          status=status, source=self.name,
                          scan_id=self.ctx.scan_id)
        res.findings += 1
        mark = "✅" if status == "confirmed" else "⚠"
        print(f"   [{mark}] {host}: {name} ({status})")

    @staticmethod
    async def _resolve(func, host: str) -> list[str]:
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, func, host)
        except Exception:  # noqa: BLE001 - resolver xətası skanı dayandırmasın
            return []
