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

Protokol (HTTP/HTTPS) host başına paylaşılan `ServiceResolver` ilə seçilir.
Timeout-lar AÇIQ şəkildə host başına raportlanır və BİR host-un timeout-u
bütün mərhələni dayandırmır. Cooldown/scope-dakı hostlar ATLANIR (heç bir
gizli yan keçmə yoxdur).

Yalnız Guardian/HttpPolicy-dən keçən sorğular; scope qapısı hər addımda işləyir.
"""
from __future__ import annotations

import secrets

from .. import db
from ..http_policy import TargetBlocked
from ..results import EngineResult
from ..scope import ScopeError
from ..service_url import (KIND_TIMEOUT, ServiceResolver, failure_label)
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
        checked = skipped = timed_out = 0
        resolver = ServiceResolver(self.guardian)
        async with aiohttp.ClientSession() as session:
            for row in hosts:
                host = row["subdomain"]
                if self.guardian and self.guardian.halted(host):
                    res.warn(f"{host} cooldown altındadır — atlandı")
                    skipped += 1
                    continue
                if not self.guardian:
                    res.fail("guardian yoxdur — WAF aşkarlaması icra oluna bilməz")
                    return res
                try:
                    hint = db.scheme_hint(row["id"], self.ctx.scan_id)
                    ep = await resolver.resolve(session, host, hint=hint)
                except TargetBlocked as exc:
                    res.warn(str(exc))
                    skipped += 1
                    continue
                except ScopeError as exc:
                    res.warn(f"{host}: {exc}")
                    skipped += 1
                    continue
                if not ep.ok:
                    if ep.kind == KIND_TIMEOUT:
                        timed_out += 1
                    else:
                        skipped += 1
                    res.warn(f"{host}: {failure_label(ep.kind)} — WAF "
                             "aşkarlaması atlandı")
                    continue

                try:
                    profile, err = await self._probe(session, ep, active)
                except TargetBlocked as exc:
                    res.warn(str(exc))
                    skipped += 1
                    continue
                except ScopeError as exc:
                    res.warn(f"{host}: {exc}")
                    skipped += 1
                    continue
                if err is not None:
                    if err == KIND_TIMEOUT:
                        timed_out += 1
                        res.warn(f"{host}: timeout — WAF aşkarlaması "
                                 f"natamam (təyin: {profile.name})")
                    else:
                        skipped += 1
                        res.warn(f"{host}: {failure_label(err)} — WAF "
                                 f"aşkarlaması natamam (təyin: {profile.name})")
                else:
                    checked += 1
                if profile.detected:
                    self.ctx.note_waf(profile)
                    profiles[host] = profile.to_dict()
                    print(f"   [🛡] {host}: {profile.name} "
                          f"(güvən {profile.confidence:.2f})")
        if self.ctx.waf_name:
            self.guardian.waf_name = self.ctx.waf_name
        res.hosts = checked
        res.data = {"waf": self.ctx.stealth.waf.to_dict(), "hosts": profiles,
                    "active_probe": active, "checked": checked,
                    "timed_out": timed_out, "skipped": skipped,
                    "detected": len(profiles)}
        print(f"[+] WAF: yoxlanıldı {checked} · timeout {timed_out} · "
              f"atlandı {skipped} · aşkarlandı {len(profiles)}")
        return res

    async def _probe(self, session, ep, active: bool):
        """Passiv → yarım-aktiv → (icazə varsa) aktiv sorğular.

        `(profile, error_kind)` qaytarır — `error_kind` None olarsa probe tam
        tamamlandı; əks halda nəticə NATAMAMDIR və səbəb (məs. timeout)
        açıq bildirilir. Heç vaxt uydurma "WAF var" iddiası verilmir.
        """
        best = detect_waf()
        for url in (ep.url("/"), ep.url("/" + secrets.token_hex(6))):
            try:
                r = await self.guardian.get(
                    session, url, allow_redirects=False)
            except (TargetBlocked, ScopeError):
                raise
            except Exception as exc:  # noqa: BLE001 - növə çevrilir
                from ..service_url import classify_error
                return best, classify_error(exc)
            cand = detect_waf(status=r.status, headers=r.headers, body=r.text)
            if cand.confidence >= best.confidence:
                best = cand
            if best.confidence >= 0.8:
                return best, None
        if not active:
            return best, None
        for payload in ("qbhprobe1", "qbhprobe'", "qbhprobe\u003c"):
            url = f"{ep.base}/?qbh={payload}"
            try:
                r = await self.guardian.get(
                    session, url, allow_redirects=False)
            except (TargetBlocked, ScopeError):
                raise
            except Exception as exc:  # noqa: BLE001 - növə çevrilir
                from ..service_url import classify_error
                return best, classify_error(exc)
            cand = detect_waf(status=r.status, headers=r.headers, body=r.text)
            if cand.confidence >= best.confidence:
                best = cand
            if best.confidence >= 0.8:
                break
        return best, None
