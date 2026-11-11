"""M4: JS fayllarında endpoint və secret aşkarlanması.

Təhlükəsizlik prinsipləri:
  * Bütün yükləmələr Guardian/HttpPolicy-dən keçir (scope + rate + cooldown).
  * Tapılan secret-lər HƏSSASDIR: bazaya yalnız MASKALANMIŞ önizləmə yazılır,
    loglarda və hesabatlarda tam dəyər heç vaxt göstərilmir.
  * Aşkarlanan credential-lar HEÇ VAXT istifadə olunmur.
  * Güclü pattern-lər (AWS/Google/JWT/private key) ilə ümumi pattern-lər
    (entropiya yoxlaması ilə) fərqləndirilir → false-positive azaldılır.
"""
from __future__ import annotations

import math
import re

from .. import db
from ..http_policy import TargetBlocked
from ..redact import mask_value
from ..results import EngineResult
from ..scope import ScopeError

MAX_JS = 200
MAX_SIZE = 500_000
HTTP_TIMEOUT = 15

# (ad, pattern, baza güvən, "güclü"?)
SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), 0.85, True),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), 0.85, True),
    ("JWT token", re.compile(
        r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}"),
     0.7, True),
    ("Slack webhook", re.compile(
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/"
        r"B[A-Za-z0-9]+/[A-Za-z0-9]+"), 0.8, True),
    ("Private key", re.compile(
        r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"), 0.9, True),
    ("Generic secret", re.compile(
        r"(?:api[_-]?key|token|secret|passwd|password)['\"]?\s*[:=]\s*"
        r"['\"]([A-Za-z0-9_\-]{16,})['\"]"), 0.3, False),
]

# Bunlar real secret deyil, nümunə/placeholder-dir
PLACEHOLDERS = re.compile(
    r"(?i)example|placeholder|your[_-]?(api|key|token)|change[_-]?me|"
    r"xxxxxxxx|aaaa+|abcd1234|dummy|sample|test[_-]?key")

_ENDPOINT_RE = re.compile(
    r"['\"]((?:/api|/v[0-9]|/admin|/graphql|/rest)/[A-Za-z0-9_\-/]{2,60})['\"]")


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class JSAnalysisEngine:
    name = "js"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        rows = db.get_db().execute(
            "SELECT u.url, u.host_id, h.subdomain FROM urls u "
            "JOIN hosts h ON h.id=u.host_id WHERE u.is_js=1 LIMIT ?",
            (MAX_JS,)).fetchall()
        if not rows:
            return res.skip("JS faylı tapılmadı — JS analizi atlandı")
        print(f"[═══ M4 JS ANALİZ ═══] {len(rows)} fayl")

        import aiohttp
        async with aiohttp.ClientSession() as session:
            for row in rows:
                host = row["subdomain"]
                if not self.cfg.in_scope(row["url"]):
                    res.warn(f"scope xaricində JS URL atlandı: {row['url']}")
                    continue
                if self.guardian and self.guardian.halted(host):
                    res.warn(f"{host} cooldown altındadır — atlandı")
                    continue
                if not self.guardian:
                    res.fail("guardian yoxdur — JS analizi təhlükəsiz icra oluna bilməz")
                    return res
                try:
                    content = await self._download_js(session, row["url"], host)
                except TargetBlocked as exc:
                    res.warn(str(exc))
                    continue
                except ScopeError as exc:
                    res.warn(f"{row['url']}: {exc}")
                    continue
                if not content:
                    continue
                self._find_secrets(row, content, res)
                self._find_endpoints(row, content, res)
        return res

    async def _download_js(self, session, url: str, host: str) -> str | None:
        r = await self.guardian.get(session, url, allow_redirects=True)
        if r.status != 200:
            return None
        if r.truncated or len(r.text) > MAX_SIZE:
            return r.text[:MAX_SIZE]
        return r.text

    def _find_secrets(self, row, content: str, res: EngineResult) -> None:
        for name, pat, base_conf, strong in SECRET_PATTERNS:
            for match in pat.finditer(content):
                value = match.group(1) if match.groups() else match.group(0)
                if not value or PLACEHOLDERS.search(value):
                    continue
                if not strong:
                    # ümumi pattern: entropiya + uzunluq yoxlaması
                    if len(value) < 20 or _entropy(value) < 3.0:
                        continue
                masked = mask_value(value)
                # Bazaya YALNIZ maskalanmış önizləmə yazılır.
                db.insert_secret(row["host_id"], row["url"], name, masked)
                severity = "high" if strong else "low"
                db.insert_finding(
                    row["host_id"], "jsanalysis", severity,
                    f"{name} potensial olaraq açıq qalıb",
                    f"{row['url']} faylında aşkarlandı. Dəyər maskalanmışdır "
                    f"({masked}). Yalnız manual, icazəli yoxlama tələb olunur — "
                    f"aşkarlanan credential İSTİFADƏ EDİLMİR.",
                    evidence=mask_value(row["url"]),
                    confidence=base_conf, status="potential",
                    source="jsanalysis")
                res.findings += 1
                print(f"[🔑] {row['subdomain']}: {name} (maskalanmış: {masked})")

    def _find_endpoints(self, row, content: str, res: EngineResult) -> None:
        eps = set(_ENDPOINT_RE.findall(content))
        added = 0
        for ep in list(eps)[:20]:
            url = f"https://{row['subdomain']}{ep}"
            if not self.cfg.in_scope(url):
                continue
            db.insert_url(row["host_id"], url, "jsanalysis", False)
            res.urls += 1
            added += 1
        if added:
            print(f"[+] {row['subdomain']}: {added} endpoint JS-dən çıxarıldı")
