"""M3: Nuclei — profilə uyğun template dəsti ilə.

Təhlükəsizlik/offensive qaydaları:
  * `intrusive_templates` (aggressive profil) aktiv olduqda intrusiv/exploit
    template-ləri də işlədilir; yalnız ZƏRƏRLİ kateqoriyalar (DoS, brute
    force) həmişə istisna edilir.
  * profil/pasiv rejimdə geniş istisna siyahısı tətbiq olunur.
  * Template-lər AVTOMATİK yenilənmir (`-update-templates` işlədilmir).
  * Uzaqdan yüklənmiş ixtiyari template icra olunmur.
  * Yalnız scope-daxili və cooldown-da olmayan hostlar skan edilir.
  * Out-of-band (interactsh) sorğuları söndürülür.
"""
from __future__ import annotations

import json
import os
import tempfile

from .. import db
from ..adapters.base import run_process
from ..results import EngineResult
from ..scope import ScopeError, normalize_host

STRATEGY_TAGS = {
    "wordpress": ["wordpress", "wp-plugin", "wp-theme"],
    "nginx": ["nginx"],
    "apache": ["apache", "httpd"],
    "php": ["php"],
    "nodejs": ["nodejs"],
    "generic": [],
}
GENERIC_TAGS = ["misconfig", "exposure", "takeover", "panel"]

# Heç bir halda işlədilməyən dağıdıcı/intrusiv kateqoriyalar
EXCLUDE_TAGS = [
    "dos", "fuzz", "fuzzing", "intrusive", "brute-force", "bruteforce",
    "creds-stuffing", "default-login", "file-upload", "rce-oob",
]

#: `intrusive_templates` profil açarı aktiv olduqda (aggressive) yalnız bunlar
#: istisna edilir — DoS/brute-force adətən proqram qaydalarınca da qadağandır;
#: qalan intrusiv/exploit template-ləri işlədilir.
DESTRUCTIVE_ONLY = [
    "dos", "fuzz", "fuzzing", "brute-force", "bruteforce", "creds-stuffing",
]

SAFE_SEVERITIES = "medium,high,critical"


class VulnEngine:
    name = "vuln"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian
        self.rate = ctx.rate

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        hosts = db.alive_hosts(self.ctx.scan_id)
        if not hosts:
            return res.skip("yaşayan host yoxdur — nuclei atlandı")
        print(f"[═══ M3 VULN ENGINE ═══] {len(hosts)} host")

        by_strategy: dict[str, list] = {}
        for h in hosts:
            if self.guardian and self.guardian.halted(h["subdomain"]):
                res.warn(f"{h['subdomain']} cooldown altındadır — atlandı")
                continue
            by_strategy.setdefault(h["strategy"] or "generic", []).append(h)

        for strategy, hlist in by_strategy.items():
            await self._scan(hlist, strategy, res)
        return res

    def _exclude_tags(self) -> list[str]:
        """Profil/RoE-ə uyğun istisna olunan nuclei tag-ları.

        `intrusive_templates` (aggressive) aktivdirsə → yalnız zərərli
        kateqoriyalar; əks halda geniş istisna siyahısı.
        """
        if self.ctx.allows("intrusive_templates"):
            return list(DESTRUCTIVE_ONLY)
        return list(EXCLUDE_TAGS)

    async def _scan(self, hosts: list, strategy: str, res: EngineResult):
        tags = STRATEGY_TAGS.get(strategy, []) or GENERIC_TAGS
        # Faza 0.2: alt-prosesə verilən BÜTÜN hədəflər əvvəlcə egress
        # validasiyasından (scope + DNS pinning) keçir. Scope xarici hostlar
        # hədəf faylına DÜŞMÜR.
        tset = await self.ctx.egress.authorize_process_targets(
            [f"https://{h['subdomain']}" for h in hosts])
        if tset.rejected:
            res.warn(f"egress: {len(tset.rejected)} scope-xarici hədəf "
                     f"rədd edildi (nuclei-yə verilmir)")
        authorized = set(tset.hostnames)
        hosts = [h for h in hosts if h["subdomain"] in authorized]
        if not hosts:
            res.warn(f"egress: strategy={strategy} üçün icazəli hədəf yoxdur")
            return
        targets = [f"https://{h['subdomain']}" for h in hosts]
        host_map = {h["subdomain"]: h["id"] for h in hosts}

        fd, target_file = tempfile.mkstemp(prefix="qbh_targets_", suffix=".txt")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(targets))

            # Faza 3.6: WAF aşkarlanması → sürət/concurrency/template uyğunlaşması.
            plan = self.ctx.stealth.plan(
                self.rate * 3, base_concurrency=25, phase="nuclei")
            exclude = list(self._exclude_tags())
            # WAF varsa → profil nə olursa olsun mühafizəkar (geniş) siyahı.
            extra = (list(EXCLUDE_TAGS) if plan.detected
                     else list(plan.extra_exclude_tags))
            for tag in extra:
                if tag not in exclude:
                    exclude.append(tag)
            args = ["nuclei", "-l", target_file,
                    "-severity", SAFE_SEVERITIES,
                    "-tags", ",".join(tags),
                    "-exclude-tags", ",".join(exclude),
                    "-rl", str(plan.rate_arg()), "-c", str(plan.concurrency),
                    "-timeout", "10", "-retries", "1",
                    "-no-interactsh", "-jsonl", "-silent", "-no-color",
                    "-stats=false"]
            if plan.ua_rotation:
                for key, value in self.ctx.stealth.humanizer.headers().items():
                    args += ["-H", f"{key}: {value}"]
            proc = await run_process(args, timeout=3600)
        finally:
            try:
                os.unlink(target_file)
            except OSError:
                pass

        if proc.missing:
            res.warn("nuclei tapılmadı")
            return
        if proc.timed_out:
            res.warn(f"nuclei timeout (strategy={strategy})")
            return

        n = 0
        for line in proc.stdout.decode(errors="ignore").splitlines():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            matched = str(r.get("matched-at") or r.get("host") or "")
            host_id = next((hid for sub, hid in host_map.items()
                            if sub in matched), None)
            if host_id is None:
                continue
            try:
                normalize_host(matched)
            except ScopeError:
                continue

            info = r.get("info", {}) or {}
            severity = str(info.get("severity") or "medium").lower()
            tags_found = {str(t).lower() for t in (info.get("tags") or [])}
            if tags_found & set(EXCLUDE_TAGS):
                res.warn(f"dağıdıcı template nəticəsi rədd edildi: "
                         f"{r.get('template-id')}")
                continue

            db.insert_finding(
                host_id, "nuclei", severity,
                str(info.get("name") or r.get("template-id", "nəticə")),
                str(info.get("description") or "")[:500],
                evidence=matched,
                curl_repro=str(r.get("curl-command") or ""),
                template=str(r.get("template-id") or ""),
                confidence=0.7, source="nuclei", scan_id=self.ctx.scan_id)
            n += 1
            res.findings += 1
            mark = "🔴" if severity in ("high", "critical") else "🟡"
            print(f"   [{mark}] {matched}: {info.get('name')}")
        print(f"[+] nuclei ({strategy}): {n} tapıntı")
