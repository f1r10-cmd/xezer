"""Faza 3.2 — `secret_replay` mühərriki.

JS təhlilində tapılan (vault-da şifrəli saxlanılan) credential-ları hədəfə
qarşı **yalnız oxuma (GET)** sorğusu ilə yoxlayır — secret-in həqiqətən
qüvvədə olub-olmadığını təsdiqləyir.

Təhlükəsizlik prinsipləri:
  * RoE `secret_replay` ilə QAPILIDIR. Qadağandırsa addım atlanır və audit
    yazılır (uydurma icra yoxdur).
  * Yalnız GET — state dəyişən metodlar və Slack webhook kimi replay-lər
    İSTİFADƏ OLUNMUR (DoS/state-changing qadağası).
  * Hər sorğu Guardian/HttpPolicy-dən keçir (scope + rate + cooldown).
  * Xam secret HEÇ VAXT loglanmır/hesabata yazılmır — yalnız maskalanmış
    önizləmə. Bazadan oxunan xam dəyər yalnız başlıqda istifadə olunur.

Təsdiq məntiqi (uydurma yoxdur): eyni URL-ə əvvəl secret-siz (baza), sonra
secret-li sorğu göndərilir. Cavab fərqlənirsə və 2xx-dirsə → `confirmed`;
401/403 → `rejected`; fərq yoxdursa → qeyri-müəyyən (toxunulmur).
"""
from __future__ import annotations

import hashlib

import aiohttp

from .. import db
from ..http_policy import TargetBlocked
from ..redact import mask_value
from ..results import EngineResult
from ..scope import ScopeError
from urllib.parse import urlsplit

MAX_ITEMS = 50

#: Replay edilməyəcək kind-lər (state dəyişən — qadağan).
NON_REPLAYABLE = ("slack", "webhook")


def headers_for(kind: str, secret: str) -> dict[str, str]:
    """`kind`-ə uyğun təhlükəsiz (yalnız oxuma) auth başlıqları qurur."""
    k = (kind or "").lower()
    if "jwt" in k or "token" in k or "bearer" in k:
        return {"Authorization": f"Bearer {secret}"}
    if "google" in k or "aws" in k or "api" in k:
        return {"X-Api-Key": secret,
                "Authorization": f"Bearer {secret}"}
    return {"Authorization": f"Bearer {secret}", "X-Api-Key": secret}


class SecretReplayEngine:
    name = "secret_replay"

    def __init__(self, ctx, probe_path: str = "/"):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian
        self.vault = ctx.vault
        self.probe_path = probe_path or "/"

    def _audit(self, event: str, **kw) -> None:
        try:
            self.ctx.egress_audit.append({"event": event, **kw})
        except Exception:  # noqa: BLE001 - audit sadəcə jurnaldır
            pass

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)

        if not self.ctx.allows("secret_replay"):
            self._audit("secret_replay_skipped", reason="RoE qadağan edir")
            return res.skip("secret replay proqram qaydaları ilə qadağandır")
        if self.guardian is None:
            return res.fail("guardian yoxdur — secret replay icra oluna bilməz")
        if not self.vault.available:
            return res.skip(
                f"vault əlçatan deyil ({self.vault.reason}) — replay atlandı")

        rows = db.secrets_with_cipher(self.ctx.scan_id)
        if not rows:
            return res.skip("şifrəli secret tapılmadı — replay üçün namizəd yoxdur")
        print(f"[═══ SECRET REPLAY ═══] {min(len(rows), MAX_ITEMS)} namizəd")

        async with aiohttp.ClientSession() as session:
            for row in rows[:MAX_ITEMS]:
                await self._replay_one(session, row, res)
        return res

    async def _replay_one(self, session, row, res: EngineResult) -> None:
        kind = row["kind"] or ""
        if any(tag in kind.lower() for tag in NON_REPLAYABLE):
            res.warn(f"{row['subdomain']}: '{kind}' replay edilə bilməz "
                     f"(state dəyişən) — atlandı")
            return

        secret = self.vault.decrypt(row["value_enc"])
        if not secret:
            res.warn(f"{row['subdomain']}: secret şifrəsi açıla bilmədi — atlandı")
            return

        url = self._probe_url(row["js_url"], row["subdomain"])
        try:
            self.ctx.authorize_url(url)
        except Exception as exc:  # noqa: BLE001 - scope/RoE
            res.warn(f"{url}: {exc}")
            return

        baseline = await self._probe(session, url, {})
        if baseline is None:
            res.warn(f"{url}: baza sorğusu alınmadı — atlandı")
            return
        authed = await self._probe(session, url, headers_for(kind, secret))
        if authed is None:
            res.warn(f"{url}: replay sorğusu alınmadı — atlandı")
            return

        b_status, _, b_hash = baseline
        a_status, _, a_hash = authed
        masked = row["value_preview"] or mask_value(secret)

        if a_status in (401, 403):
            self._record(row, "rejected", 0.1,
                         f"Secret replay rədd edildi ({a_status})",
                         f"'{kind}' secret-i {url} üzərində qüvvədə deyil "
                         f"({masked}).", res)
            return
        if 200 <= a_status < 300 and (a_status != b_status or a_hash != b_hash):
            self._record(row, "confirmed", 0.8,
                         f"Secret replay təsdiqləndi: {kind} qüvvədədir",
                         f"'{kind}' secret-i {url} üzərində qəbul olundu "
                         f"(HTTP {a_status} vs baza {b_status}; {masked}). "
                         f"Dəyər maskalanmışdır.", res)
            return
        res.warn(f"{url}: '{kind}' üçün qeyri-müəyyən nəticə "
                 f"(HTTP {a_status} ≈ {b_status})")

    async def _probe(self, session, url, headers):
        """Bir GET sorğusu edir → (status, body_len, body_hash) və ya `None`."""
        try:
            self.ctx.authorization.ensure_active()
            r = await self.guardian.get(session, url, allow_redirects=False,
                                        headers=headers)
        except (TargetBlocked, ScopeError, aiohttp.ClientError, OSError):
            return None
        body = r.text or ""
        return (int(r.status), len(body),
                hashlib.sha256(body.encode()).hexdigest()[:16])

    def _record(self, row, status: str, confidence: float, title: str,
                description: str, res: EngineResult) -> None:
        try:
            db.insert_finding(
                row["host_id"], self.name,
                "high" if status == "confirmed" else "info",
                title, description, evidence=mask_value(row["js_url"]),
                confidence=confidence, status=status, source=self.name,
                scan_id=self.ctx.scan_id)
            res.findings += 1 if status == "confirmed" else 0
        except Exception as exc:  # noqa: BLE001
            res.warn(f"tapıntı yazıla bilmədi: {exc}")
            return
        mark = "✅" if status == "confirmed" else "❌"
        print(f"   [{mark}] {row['subdomain']}: {title}")

    def _probe_url(self, js_url: str, subdomain: str) -> str:
        """JS URL-dən sxem+host çıxarıb probe URL-i qurur."""
        parts = urlsplit(js_url or "")
        if parts.scheme and parts.netloc:
            return f"{parts.scheme}://{parts.netloc}{self.probe_path}"
        return f"https://{subdomain}{self.probe_path}"
