"""M-WAF: WAF barmaq izi aşkarlaması (Faza 2.2).

Məqsəd: hədəfin qarşısında hansı WAF/CDN olduğunu müəyyən etmək və bunu
SİSTEMƏ ötürmək (`ctx.waf_name` + `ctx.stealth.waf`). Bu identiklik sonra:

  * `SQLiEngine` → sqlmap `--tamper` seçimi,
  * `payloads.waf_matrix` → bypass texnikalarının sıralanması,
  * subprocess alətləri → rate/concurrency azaldılması (`rate_factor_for`)

üçün istifadə olunur.

Metodologiya (dürüst və yumşaq):
  1. **Passiv** — canlı hostun normal cavabının başlıq/gövdə imzaları.
  2. **Yarım-aktiv** — mövcud olmayan təsadüfi yol (`404` səhifəsi tez-tez WAF
     blok səhifəsidir).
  3. **Aktiv** — YALNIZ `active_fuzz` icazəlidirsə: bir dəyişən + bir dırnaq
     simvolu ilə `4xx/5xx` blok səhifəsi tetiklənir.

Yalnız Guardian/HttpPolicy-dən keçən sorğular; scope qapısı hər addımda işləyir.
"""
from __future__ import annotations

import secrets

from .. import db
from ..http_policy import TargetBlocked
from ..results import EngineResult
from ..scope import ScopeError
from ..stealth.waf import detect_waf

MAX_HOSTS = 20


class WafDetectEngine:
    name = "wafdetect"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        hosts = db.alive_hosts(self.ctx.scan_id)[:MAX_HOSTS]
        if not hosts:
            return res.skip("yaşayan host yoxdur — WAF aşkarlaması atlandı")
        print(f"[═══ M-WAF AŞKARLAMA ═══] {len(hosts)} host")

        import aiohttp
        active = self.ctx.allows("active_fuzz")
        profiles: dict[str, dict] = {}
        async with aiohttp.ClientSession() as session:
            for row in hosts:
                host = row["subdomain"]
                if self.guardian and self.guardian.halted(host):
                    res.warn(f"{host} cooldown altındadır — atlandı")
                    continue
                if not self.guardian:
                    res.fail("guardian yoxdur — WAF aşkarlaması icra oluna bilməz")
                    return res
                try:
                    profile = await self._probe(session, host, active)
                except TargetBlocked as exc:
                    res.warn(str(exc))
                    continue
                except ScopeError as exc:
                    res.warn(f"{host}: {exc}")
                    continue
                if profile.detected:
                    self.ctx.note_waf(profile)
                    profiles[host] = profile.to_dict()
                    print(f"   [🛡] {host}: {profile.name} "
                          f"(güvən {profile.confidence:.2f})")
        if self.ctx.waf_name:
            self.guardian.waf_name = self.ctx.waf_name
        res.data = {"waf": self.ctx.stealth.waf.to_dict(), "hosts": profiles,
                    "active_probe": active}
        return res

    async def _probe(self, session, host: str, active: bool):
        """Passiv → yarım-aktiv → (icazə varsa) aktiv sorğular."""
        base = f"https://{host}"
        best = detect_waf()
        for url in (f"{base}/", f"{base}/{secrets.token_hex(6)}"):
            r = await self.guardian.get(session, url, allow_redirects=False)
            cand = detect_waf(status=r.status, headers=r.headers, body=r.text)
            if cand.confidence >= best.confidence:
                best = cand
            if best.confidence >= 0.8:
                return best
        if not active:
            return best
        for payload in ("qbhprobe1", "qbhprobe'", "qbhprobe\u003c"):
            url = f"{base}/?qbh={payload}"
            r = await self.guardian.get(session, url, allow_redirects=False)
            cand = detect_waf(status=r.status, headers=r.headers, body=r.text)
            if cand.confidence >= best.confidence:
                best = cand
            if best.confidence >= 0.8:
                break
        return best
