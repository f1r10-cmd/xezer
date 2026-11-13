"""API Fuzz: OpenAPI sxemi üzərində Schemathesis property-testi.

Təhlükəsizlik prinsipləri:
  * YALNIZ `--active-fuzz` açıq şəkildə verildikdə işləyir. Default: atlanır.
  * Yalnız GET metodları yoxlanır (`-M GET`) → state dəyişən sorğu yoxdur.
  * YALNIZ cari skanın (`scan_id`) hostlarına aid sxemlər emal olunur.
  * **Sənədin `servers:` bölməsi də validasiya olunur** — dəyişənlər əvəz
    edildikdən və nisbi URL-lər sənədin əsasına görə həll olunduqdan SONRA
    hər server `authorize_url()` ilə yoxlanılır. Scope xarici serverlər RƏDD
    edilir və loglanır (səssizcə əvəzlənmir). Schemathesis yalnız təsdiqlənmiş
    baza URL-lərini (`--base-url`) alır.
  * **Sxem sənədi HttpPolicy-dən keçir** (Faza 1.3): `aiohttp` birbaşa
    çağırışı yerinə `ctx.guardian.get()` istifadə olunur → hər sorğu və hər
    redirect addımı scope yoxlamasından + rate limitdən keçir.
  * Nəticələr "candidate" kimi qeyd olunur; avtomatik "confirmed" iddiası yoxdur.
  * Credential hücumu, brute force və data extraction YOXDUR.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
from urllib.parse import urljoin, urlsplit

import aiohttp

from .. import db
from ..http_policy import TargetBlocked
from ..results import EngineResult
from ..scope import ScopeError

MAX_SCHEMAS = 10
MAX_EXAMPLES = 50
TIMEOUT = 900
MAX_SERVERS = 20


class APIFuzzEngine:
    name = "api_fuzz"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        if not self.ctx.active_fuzz:
            return res.skip(
                "API fuzzinq deaktivdir — yalnız `--active-fuzz` ilə "
                "icazəli endpoint-lərə qarşı işləyir")

        rows = db.get_db().execute(
            "SELECT u.url, u.host_id, h.subdomain FROM urls u "
            "JOIN hosts h ON h.id=u.host_id "
            "WHERE (u.url LIKE '%openapi%' OR u.url LIKE '%swagger%' "
            "OR u.url LIKE '%api-docs%') AND h.scan_id=? LIMIT ?",
            (db.effective_scan_id(self.ctx.scan_id), MAX_SCHEMAS)).fetchall()
        if not rows:
            return res.skip("OpenAPI sxem tapılmadı — API fuzzinq atlandı")
        print(f"[═══ API FUZZ (Schemathesis, GET-only) ═══] {len(rows)} sxem")

        for row in rows:
            if not self.cfg.in_scope(row["url"]):
                res.warn(f"scope xaricində sxem atlandı: {row['url']}")
                continue
            await self._schemathesis(row, res)
        return res

    # ----------------------------------------------------- server validasiyası
    @staticmethod
    def effective_servers(doc, doc_url: str) -> list[str]:
        """Sənədin `servers:` siyahısını ABSOLYUT URL-lərə çevirir.

        Dəyişənlər `variables[*].default` ilə əvəz olunur; nisbi URL-lər
        sənədin öz ünvanına (`doc_url`) görə həll olunur. Həll olunmamış
        dəyişən qalan server etibarsız sayılır və atılır. `servers` boşdursa
        OpenAPI default-u (sənədin öz hostu, kök yol) istifadə olunur.
        """
        raw = doc.get("servers") if isinstance(doc, dict) else None
        servers: list[str] = []
        if isinstance(raw, list):
            for s in raw[:MAX_SERVERS]:
                if not isinstance(s, dict):
                    continue
                url = str(s.get("url") or "").strip()
                if not url:
                    continue
                variables = s.get("variables")
                if isinstance(variables, dict):
                    for name, spec in variables.items():
                        default = ""
                        if isinstance(spec, dict):
                            default = str(spec.get("default") or "")
                        url = url.replace("{" + str(name) + "}", default)
                if "{" in url or "}" in url:
                    continue  # həll olunmamış dəyişən → etibarsız
                servers.append(urljoin(doc_url, url))
        if not servers:
            servers.append(urljoin(doc_url, "/"))
        out: list[str] = []
        for s in servers:
            if urlsplit(s).scheme in ("http", "https"):
                out.append(s)
        return out

    @classmethod
    def validate_servers(cls, doc, doc_url: str, authorize) -> tuple[list, list]:
        """Server URL-lərini `authorize(url)` ilə süzür.

        `authorize` — `ctx.authorize_url` (scope xaricində `ScopeError` atır).
        Qaytarır: (icazəli_url-lər, rədd_edilmişlər[(url, səbəb)]).
        """
        good: list[str] = []
        bad: list[tuple[str, str]] = []
        for s in cls.effective_servers(doc, doc_url):
            try:
                authorize(s)
                good.append(s)
            except ScopeError as exc:
                bad.append((s, str(exc)))
        return good, bad

    async def _schemathesis(self, row, res: EngineResult) -> None:
        async with aiohttp.ClientSession() as session:
            doc = await self._fetch_document(session, row["url"])
        if doc is None:
            res.warn(f"sxem oxuna bilmədi: {row['url']}")
            return
        good, bad = self.validate_servers(doc, row["url"], self.ctx.authorize_url)
        if bad:
            res.warn(f"{row['subdomain']}: {len(bad)} scope-xarici server "
                     f"rədd edildi ({', '.join(u for u, _ in bad[:3])})")
        if not good:
            res.warn(f"{row['subdomain']}: heç bir scope-daxili server yoxdur "
                     f"— sxem atlandı")
            return
        for base in good:
            await self._run_one(row, base, res)

    async def _run_one(self, row, base_url: str, res: EngineResult) -> None:
        # Faza 0.2: schemathesis hədəfləri (sənəd + baza URL) egress
        # validasiyasından keçir (scope + fail-closed DNS pinning).
        tset = await self.ctx.egress.authorize_process_targets(
            [row["url"], base_url])
        if base_url not in tset.urls:
            res.warn(f"egress: {base_url} scope xaricindədir — atlandı")
            return
        fd, result_file = tempfile.mkstemp(prefix="qbh_st_", suffix=".json")
        os.close(fd)
        try:
            proc = await self.ctx.egress.run([
                "schemathesis", "run", row["url"],
                "--base-url", base_url,
                "-M", "GET",
                "--checks", "all",
                "--max-examples", str(MAX_EXAMPLES),
                "-o", "json", result_file,
            ], targets=[row["url"], base_url], timeout=TIMEOUT)
            if proc.blocked:
                res.warn(f"schemathesis {base_url}: egress qapısı bloklandı")
                return
            if proc.missing:
                res.warn("schemathesis tapılmadı (pip install schemathesis)")
                return
            if proc.timed_out:
                res.warn(f"schemathesis {base_url}: timeout")
            failures = self._read_failures(result_file)
        finally:
            try:
                os.unlink(result_file)
            except OSError:
                pass

        if failures:
            db.insert_finding(
                row["host_id"], "apifuzz", "medium",
                f"API property-test: {failures} nasazlıq",
                f"Schemathesis {base_url} (sxem: {row['url']}) üzərində "
                f"{failures} yoxlama uyğunsuzluğu tapdı (yalnız GET). Bu "
                f"POTENSIAL siqnaldır — manual təsdiq tələb olunur.",
                evidence=base_url, confidence=0.4,
                status="candidate", source="schemathesis", scan_id=self.ctx.scan_id)
            res.findings += 1
            print(f"[🧪] {row['subdomain']}: {failures} failure (candidate)")

    async def _fetch_document(self, session, url: str):
        """Sxem sənədini HttpPolicy (Guardian) vasitəsilə yükləyir (Faza 1.3).

        Əvvəllər birbaşa `aiohttp.ClientSession().get()` istifadə olunurdu →
        `HttpPolicy`-dən kənar idi (scope/redirect/rate yoxlaması yox). İndi
        `ctx.guardian.get()` çağırılır: hər sorğu və hər redirect addımı vahid
        siyasətdən (scope + rate limit + cooldown) keçir.
        """
        guardian = getattr(self.ctx, "guardian", None)
        try:
            if guardian is not None:
                r = await guardian.get(
                    session, url, allow_redirects=True,
                    headers={"Accept": "application/json, */*"})
                status, text = r.status, r.text
            elif hasattr(self.ctx, "authorize_url"):
                self.ctx.authorize_url(url)          # scope qapısı (fail-closed)
                async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    status = resp.status
                    text = await resp.text()
            else:  # pragma: no cover - qoruyucu: heç bir icazəli yol yoxdur
                return None
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError,
                ScopeError, TargetBlocked):
            return None
        if status != 200:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _read_failures(result_file: str) -> int:
        try:
            with open(result_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return 0
        if not isinstance(data, dict):
            return 0
        summary = data.get("stats") or data.get("summary") or {}
        if not isinstance(summary, dict):
            return 0
        failures = (summary.get("failures") or summary.get("failed")
                    or summary.get("checks_failed") or 0)
        if isinstance(failures, dict):
            failures = failures.get("total", 0)
        try:
            return int(failures)
        except (TypeError, ValueError):
            return 0
