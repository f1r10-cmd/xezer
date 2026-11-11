"""M2: Texnologiya aşkarlama + versiya çıxarma + strategiya yoxlamaları.

Prinsiplər:
  * Yalnız HTTP başlıqları, HTML göstəriciləri və tanınmış imzalar.
  * Versiya yalnız MÜTLƏQ dəstəklənən mənbədən çıxarılır (Server başlığı,
    meta generator, readme) — uydurma versiya iddiası yoxdur.
  * Hər versiya üçün `confidence` saxlanılır.
  * Bütün sorğular Guardian/HttpPolicy-dən keçir (scope + rate + cooldown).
"""
from __future__ import annotations

import os
import re

import yaml

from .. import db
from ..http_policy import TargetBlocked
from ..results import EngineResult
from ..scope import ScopeError

STRATEGY_DIR = "config/strategies"

# (ad, başlıq/body regex, strategiya)
SIGNATURES = [
    ("wordpress", re.compile(r"wp-content|wp-includes|/wp-json/", re.I), "wordpress"),
    ("drupal", re.compile(r"Drupal\.settings|/sites/default/files", re.I), "generic"),
    ("joomla", re.compile(r"/media/jui/|option=com_", re.I), "generic"),
    ("nginx", re.compile(r"^nginx", re.I), "nginx"),
    ("apache", re.compile(r"^Apache", re.I), "apache"),
    ("php", re.compile(r"X-Powered-By:\s*PHP|\.php", re.I), "php"),
    ("express", re.compile(r"X-Powered-By:\s*Express", re.I), "nodejs"),
    ("nodejs", re.compile(r"X-Powered-By:\s*Node", re.I), "nodejs"),
]

_VERSION_CONF = {"header": 0.8, "generator": 0.6, "readme": 0.5}


class FingerprintEngine:
    name = "fingerprint"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        hosts = db.alive_hosts()
        if not hosts:
            return res.skip("yaşayan host yoxdur — fingerprint atlandı")
        print(f"[═══ M2 FINGERPRINT ═══] {len(hosts)} host")

        for row in hosts:
            host = row["subdomain"]
            if self.guardian and self.guardian.halted(host):
                res.warn(f"{host} cooldown altındadır — atlandı")
                continue
            try:
                await self._fingerprint(host, row, res)
            except TargetBlocked as exc:
                res.warn(str(exc))
            except ScopeError as exc:
                res.warn(f"{host}: {exc}")
        return res

    async def _fingerprint(self, host: str, row, res: EngineResult) -> None:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            status, headers, body = await self._fetch(
                session, f"https://{host}/")
            if status is None:
                res.warn(f"{host}: cavab alınmadı")
                return

            techs = self._detect(host, headers, body)
            strategy = techs[0][1] if techs else "generic"
            if strategy == "generic":
                code, _, _ = await self._fetch(
                    session, f"https://{host}/wp-login.php")
                if code == 200:
                    strategy = "wordpress"
                    techs.append(("wordpress", "wordpress", 0.5))

            product, version, conf = await self._version(
                session, host, strategy, headers, body)
            tech_raw = self._tech_raw(row["tech_raw"], techs, product, version)
            db.upsert_host(host, strategy=strategy, tech_raw=tech_raw[:500])
            if version:
                res.data.setdefault("technologies", []).append({
                    "host": host, "product": product, "version": version,
                    "confidence": conf})

            await self._strategy_checks(session, row, host, strategy, res)

    # ---------------- HTTP ----------------
    async def _fetch(self, session, url: str):
        """Guardian varsa ondan, yoxsa da birbaşa — hər zaman scope-daxili."""
        try:
            if self.guardian:
                r = await self.guardian.get(session, url, allow_redirects=True)
            else:  # pragma: no cover - guardian həmişə verilir
                import aiohttp
                async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    return resp.status, dict(resp.headers), \
                        (await resp.text(errors="ignore"))[:400_000]
            return r.status, r.headers, r.text[:400_000]
        except TargetBlocked:
            raise
        except Exception:
            return None, {}, ""

    # ---------------- aşkarlama ----------------
    @staticmethod
    def _detect(host: str, headers: dict, body: str) -> list[tuple]:
        haystack = "\n".join(
            [f"{k}: {v}" for k, v in headers.items()] + [body[:20000]])
        out: list[tuple] = []
        server = headers.get("Server", "") or headers.get("server", "")
        for name, pat, strategy in SIGNATURES:
            if pat.search(haystack) or (name == "nginx" and server.lower()
                                        .startswith("nginx")):
                out.append((name, strategy, 0.7))
        return out

    @staticmethod
    def _tech_raw(prev: str, techs: list, product, version) -> str:
        names = [t[0] for t in techs]
        base = ",".join(dict.fromkeys(names))
        if prev and base and prev not in base:
            base = (base + "," + prev)[:500]
        elif not base:
            base = prev or ""
        if version and product:
            base = f"{base}|{product}:{version}"
        return base.strip("|,")

    async def _version(self, session, host: str, strategy: str, headers, body):
        """(product, version, confidence) — yalnız MÜTLƏQ mənbədən."""
        server = headers.get("Server", "") or headers.get("server", "")
        m = re.match(r"(nginx|Apache|gunicorn|Microsoft-IIS)/([0-9][0-9.]*)",
                     server, re.I)
        if m:
            return m.group(1).lower(), m.group(2), _VERSION_CONF["header"]

        if strategy == "wordpress":
            code, _, rd = await self._fetch(session, f"https://{host}/readme.html")
            if code == 200:
                mm = re.search(r"[Vv]ersion\s+([0-9]+\.[0-9.]+)", rd)
                if mm:
                    return "wordpress", mm.group(1), _VERSION_CONF["readme"]

        if body:
            m = re.search(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']'
                r'([^"\']+?)(?:\s+v?([0-9][0-9.a-z-]*))?["\']', body, re.I)
            if m:
                product = (m.group(1) or "cms").strip().lower().replace(" ", "-")
                return product, m.group(2), _VERSION_CONF["generator"]
        return None, None, 0.0

    # ---------------- strategiya yoxlamaları ----------------
    async def _strategy_checks(self, session, row, host, strategy, res) -> None:
        path = os.path.join(STRATEGY_DIR, f"{strategy}.yaml")
        try:
            with open(path, "r", encoding="utf-8") as fh:
                strat = yaml.safe_load(fh) or {}
        except (FileNotFoundError, yaml.YAMLError):
            return

        for check in strat.get("checks", []) or []:
            if not isinstance(check, dict):
                continue
            cpath = check.get("path")
            if not cpath or not str(cpath).startswith("/"):
                continue
            code, _, body = await self._fetch(
                session, f"https://{host}{cpath}")
            if not code:
                continue
            expected = [str(s) for s in check.get("expect_status", [200])]
            if str(code) not in expected:
                continue
            expect = check.get("expect_contains")
            if expect is not None and (not body or expect not in body):
                continue
            finding = check.get("finding") or {}
            db.insert_finding(
                row["id"], "fingerprint",
                str(finding.get("severity", "medium")).lower(),
                str(finding.get("title", check.get("name", cpath))),
                str(finding.get("description", f"{cpath} əlçatandır")),
                evidence=f"GET {cpath} → {code}", confidence=0.7,
                source="fingerprint")
            res.findings += 1
            print(f"   [⚠] {host}: {check.get('name', cpath)}")
