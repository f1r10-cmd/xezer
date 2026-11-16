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

from .. import db, urlintel
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
            "SELECT u.id, u.url, u.host_id, u.is_js, u.source, h.subdomain "
            "FROM urls u JOIN hosts h ON h.id=u.host_id "
            "WHERE u.is_js=1 AND h.scan_id=? LIMIT ?",
            (db.effective_scan_id(self.ctx.scan_id), MAX_JS)).fetchall()
        if not rows:
            return res.skip("JS faylı tapılmadı — JS analizi atlandı")
        # F-03: URL Intelligence uyğunluq qaydası ('js' → yalnız JavaScript
        # resursları). Sətirlər prioritet sırasına salınır, dublikatlar
        # çıxarılır; uyğun olmayan/naməlum resurslar SƏBƏBLƏ qeyd olunur
        # (səssizcə atılmır). Orijinal URL və host_id TOXUNULMAZ qalır.
        rows, plan = urlintel.get_url_intelligence(self.ctx).plan_rows(
            rows, engine=self.name, limit=MAX_JS)
        if not rows:
            return res.skip("uyğun JS resursu qalmadı — JS analizi atlandı")
        print(f"[═══ M4 JS ANALİZ ═══] {len(rows)} fayl"
              f" (uyğun={plan.eligible}, xaric={plan.excluded})")

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
                from ..brain.js_intelligence import analyze, persist
                observations = analyze(content, row["url"])
                await self._source_maps(session, row, observations, res)
                status = persist(self.ctx, row["url"], content, observations)
                res.data.setdefault("js_intelligence", []).append({"source_id": row["id"], "status": status,
                                                                  **observations.summary()})
                for limitation in observations.limitations:
                    res.warn("JS intelligence: " + limitation)
        return res

    async def _source_maps(self, session, row, observations, res):
        from ..brain.js_intelligence import analyze, source_map_sources
        from urllib.parse import urlsplit, unquote
        import base64
        processed = 0
        for item in list(observations.observations):
            if item['kind'] != 'source_map':
                continue
            if processed >= 5:
                item['map_status'] = 'deferred_source_map_budget'
                continue
            processed += 1
            try:
                url = item['value']
                if url.startswith('data:'):
                    prefix, data = url.split(',', 1)
                    if len(data) > MAX_SIZE:
                        raise ValueError('source_map_size_limit')
                    content = base64.b64decode(data, validate=True).decode() if ';base64' in prefix else unquote(data)
                else:
                    self.ctx._auth().authorize_request('GET', url, 'jsanalysis')
                    parts = urlsplit(url)
                    if parts.query or parts.username or parts.password:
                        item['map_status'] = 'deferred_credential_review'
                        continue
                    response = await self.guardian.get(session, url, allow_redirects=False)
                    if response.status != 200 or response.truncated or len(response.text) > MAX_SIZE:
                        item['map_status'] = 'deferred_source_map_response'
                        continue
                    content = response.text
                sources = source_map_sources(content)
                item['embedded_sources'] = sources
                for index, source in enumerate(sources):
                    if index >= 20:
                        source['analysis_status'] = 'deferred_source_budget'
                        continue
                    if not isinstance(source['content'], str):
                        continue
                    child = analyze(source['content'], row['url'])
                    self._find_secrets(row, source['content'], res)
                    observations.observations.extend(child.observations)
                    observations.limitations.extend(child.limitations)
                    source['analysis_status'] = 'analyzed'
                item['map_status'] = 'analyzed'
            except Exception as exc:
                item['map_status'] = 'deferred:' + type(exc).__name__
                observations.limitations.append('source_map_unavailable:' + type(exc).__name__)

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
                # Bazaya YALNIZ maskalanmış önizləmə yazılır. Xam dəyər, əgər
                # şifrəli vault əlçatandırsa, Fernet ilə şifrələnib saxlanılır
                # (Faza 3.2) — düz mətn HEÇ VAXT yazılmır.
                enc = self.ctx.vault.encrypt(value)
                db.insert_secret(row["host_id"], row["url"], name, masked,
                                 value_enc=enc)
                severity = "high" if strong else "low"
                db.insert_finding(
                    row["host_id"], "jsanalysis", severity,
                    f"{name} potensial olaraq açıq qalıb",
                    f"{row['url']} faylında aşkarlandı. Dəyər maskalanmışdır "
                    f"({masked}). Yalnız manual, icazəli yoxlama tələb olunur — "
                    f"aşkarlanan credential İSTİFADƏ EDİLMİR.",
                    evidence=mask_value(row["url"]),
                    confidence=base_conf, status="potential",
                    source="jsanalysis", scan_id=self.ctx.scan_id)
                res.findings += 1
                print(f"[🔑] {row['subdomain']}: {name} (maskalanmış: {masked})")

    def _find_endpoints(self, row, content: str, res: EngineResult) -> None:
        eps = set(_ENDPOINT_RE.findall(content))
        added = 0
        from urllib.parse import urljoin
        for ep in sorted(eps):
            url = urljoin(row["url"], ep)
            if not self.cfg.in_scope(url):
                continue
            db.insert_url(row["host_id"], url, "jsanalysis", False, scan_id=self.ctx.scan_id)
            res.urls += 1
            added += 1
        if added:
            print(f"[+] {row['subdomain']}: {added} endpoint JS-dən çıxarıldı")
