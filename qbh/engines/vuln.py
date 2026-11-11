"""M3: Nuclei — YALNIZ təhlükəsiz, seçilmiş template-lərlə.

Təhlükəsizlik qaydaları:
  * Dağıdıcı/intrusiv template-lər DEFAULT olaraq istisna edilir.
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
        hosts = db.alive_hosts()
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

    async def _scan(self, hosts: list, strategy: str, res: EngineResult):
        tags = STRATEGY_TAGS.get(strategy, []) or GENERIC_TAGS
        targets = [f"https://{h['subdomain']}" for h in hosts]
        host_map = {h["subdomain"]: h["id"] for h in hosts}

        fd, target_file = tempfile.mkstemp(prefix="qbh_targets_", suffix=".txt")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(targets))

            args = ["nuclei", "-l", target_file,
                    "-severity", SAFE_SEVERITIES,
                    "-tags", ",".join(tags),
                    "-exclude-tags", ",".join(EXCLUDE_TAGS),
                    "-rl", str(max(5, int(self.rate * 3))), "-c", "25",
                    "-timeout", "10", "-retries", "1",
                    "-no-interactsh", "-jsonl", "-silent", "-no-color",
                    "-stats=false"]
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
                confidence=0.7, source="nuclei")
            n += 1
            res.findings += 1
            mark = "🔴" if severity in ("high", "critical") else "🟡"
            print(f"   [{mark}] {matched}: {info.get('name')}")
        print(f"[+] nuclei ({strategy}): {n} tapıntı")
