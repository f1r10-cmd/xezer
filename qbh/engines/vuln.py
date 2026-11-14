"""M3: Nuclei — profilə uyğun template dəsti ilə.

Təhlükəsizlik/offensive qaydaları:
  * `intrusive_templates` (aggressive profil) aktiv olduqda intrusiv/exploit
    template-ləri də işlədilir; yalnız ZƏRƏRLİ kateqoriyalar (DoS, brute
    force) həmişə istisna edilir.
  * `vuln.allow_destructive=true` + RoE icazəsi → yalnız QEYRİ-zərərli intrusiv
    kateqoriyalar (`intrusive`, `default-login`, `file-upload`, `rce-oob`)
    açılır; DoS/brute-force/creds-stuffing HƏMİŞƏ istisna qalır.
  * `vuln.allow_all_templates=true` → `-tags` filtri buraxılır (bütün
    template-lər), `-exclude-tags` isə scope/RoE məhdudiyyətini qoruyur.
  * Template-lər YALNIZ `vuln.update_templates=true` olduqda yenilənir
    (opt-in); default olaraq `-update-templates` işlədilmir.
  * Uzaqdan yüklənmiş ixtiyari template icra olunmur.
  * Yalnız scope-daxili və cooldown-da olmayan hostlar skan edilir.
  * Out-of-band (interactsh) sorğuları söndürülür.
  * İcra uğursuz olsa belə ƏLDƏ EDİLƏN etibarlı JSONL tapıntıları SAXLANILIR;
    natamam icra "tam uğurlu skan" kimi təqdim EDİLMİR.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass

from .. import db
from ..adapters.base import run_process
from ..redact import redact
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

#: `vuln.allow_destructive=true` (və RoE icazəsi) olduqda AÇILAN, lakin
#: QEYRİ-zərərli intrusiv kateqoriyalar. DoS/brute-force/creds-stuffing
#: bunlara DAXİL DEYİL və heç vaxt açılmır.
NON_DESTRUCTIVE_INTRUSIVE = [
    "intrusive", "default-login", "file-upload", "rce-oob",
]

SAFE_SEVERITIES = "medium,high,critical"

#: Uğursuz alt-prosesin stderr-indən loglara yazılan maksimum simvol sayı.
_STDERR_LIMIT = 400

_VERSION_RE = re.compile(r"v?\d+\.\d+\.\d+")


def _stderr_excerpt(raw: bytes, limit: int = _STDERR_LIMIT) -> str:
    """stderr-i təhlükəsiz, MƏHDUD uzunluqda qaytarır (secret-lər maskalanır)."""
    text = redact(raw.decode(errors="ignore")).strip()
    if not text:
        return "(stderr boşdur)"
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


def _result_host(record: dict) -> str:
    """Nuclei nəticəsindən REAL host adını çıxarır (DƏQİQ uyğunlaşdırma üçün).

    `matched-at`/`host` sxemli URL (`https://a.b/p`) və ya sxemsiz
    (`a.b:443/p`) ola bilər. `normalize_host` vasitəsilə host çıxarılır:
    kiçik hərf, sağdakı nöqtələr silinir, port atılır, IDNA tətbiq olunur,
    IPv4/IPv6 dəstəklənir. Boş/etibarsız/hostsuz dəyər `ScopeError` atır.
    """
    raw = record.get("matched-at") or record.get("host") or ""
    if not str(raw).strip():
        raise ScopeError("nəticədə host/matched-at yoxdur")
    return normalize_host(str(raw))


@dataclass
class _ParseStats:
    """JSONL parse diaqnostikası (per-strategy)."""

    lines: int = 0
    valid: int = 0
    malformed: int = 0
    no_host: int = 0
    out_of_scope: int = 0
    excluded: int = 0
    accepted: int = 0

    def diagnostics(self) -> dict:
        return {
            "lines": self.lines,
            "valid": self.valid,
            "malformed": self.malformed,
            "no_host": self.no_host,
            "out_of_scope": self.out_of_scope,
            "excluded": self.excluded,
            "accepted": self.accepted,
        }


class VulnEngine:
    name = "vuln"

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian
        self.rate = ctx.rate

    # -------------------------------------------------------- config helpers
    def _flag(self, name: str) -> bool:
        """`vuln.<name>` boolean açarı (konfiq yoxdursa default False)."""
        vc = getattr(self.cfg, "vuln", None)
        return bool(getattr(vc, name, False))

    def _destructive_opt_in(self) -> bool:
        """`vuln.allow_destructive` + RoE qapısı.

        Yalnız QEYRİ-zərərli intrusiv kateqoriyaları açır. Proqram RoE-si
        (`program_rules.forbidden`) HƏMİŞƏ üstündür — `intrusive_templates`
        qadağandırsa bu seçim heç bir şey açmır.
        """
        if not self._flag("allow_destructive"):
            return False
        return bool(self.cfg.is_allowed("intrusive_templates"))

    def _exclude_tags(self) -> list[str]:
        """Profil/RoE/`allow_destructive`-ə uyğun istisna olunan nuclei tag-ları.

        * `intrusive_templates` (aggressive) aktivdirsə → yalnız ZƏRƏRLİ
          kateqoriyalar (`DESTRUCTIVE_ONLY`).
        * `allow_destructive=true` (və RoE icazəsi) olduqda eyni minimal
          siyahı — yalnız qeyri-zərərli intrusiv kateqoriyalar açılır, DoS/
          brute-force HƏMİŞƏ istisna qalır.
        * Əks halda geniş istisna siyahısı (`EXCLUDE_TAGS`).
        """
        if self.ctx.allows("intrusive_templates") or self._destructive_opt_in():
            return list(DESTRUCTIVE_ONLY)
        return list(EXCLUDE_TAGS)

    def _template_args(self, strategy: str) -> list[str]:
        """Template seçimi arqumentləri.

        `vuln.allow_all_templates=true` olduqda `-tags` filtri BURAXILIR
        (bütün template-lər; `-exclude-tags` scope/RoE məhdudiyyətini qoruyur).
        Boş `-tags ""` göndərilmir — belə filtr nuclei davranışını
        qeyri-müəyyən şəkildə dəyişə bilərdi.
        """
        if self._flag("allow_all_templates"):
            return []
        tags = STRATEGY_TAGS.get(strategy, []) or GENERIC_TAGS
        return ["-tags", ",".join(tags)]

    # ------------------------------------------------------------------- run
    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        hosts = db.alive_hosts(self.ctx.scan_id)
        if not hosts:
            return res.skip("yaşayan host yoxdur — nuclei atlandı")
        print(f"[═══ M3 VULN ENGINE ═══] {len(hosts)} host")

        # Opt-in template yeniləmə (default OFF) — skan başlamazdan ƏVVƏL.
        if self._flag("update_templates"):
            await self._update_templates(res)

        by_strategy: dict[str, list] = {}
        for h in hosts:
            if self.guardian and self.guardian.halted(h["subdomain"]):
                res.warn(f"{h['subdomain']} cooldown altındadır — atlandı")
                continue
            by_strategy.setdefault(h["strategy"] or "generic", []).append(h)

        for strategy, hlist in by_strategy.items():
            await self._scan(hlist, strategy, res)
        return res

    async def _update_templates(self, res: EngineResult) -> None:
        """`nuclei -update-templates` — yalnız opt-in olduqda; nəticə dürüst
        raportlanır (uğursuzluq sükutla udulmur)."""
        upd = await run_process(
            ["nuclei", "-update-templates", "-silent", "-no-color"],
            timeout=600)
        if upd.missing:
            res.fail("nuclei tapılmadı — template yeniləmə mümkün deyil")
            return
        if upd.blocked:
            res.fail("nuclei template yeniləmə egress/scope qapısı tərəfindən "
                     "BLOKLANDI — yeniləmə icra olunmadı")
            return
        if upd.timed_out:
            res.fail("nuclei template yeniləmə timeout — template-lər "
                     "yenilənməmiş ola bilər")
            return
        if upd.returncode != 0:
            res.fail("nuclei template yeniləmə uğursuz oldu (çıxış kodu "
                     f"{upd.returncode}): {_stderr_excerpt(upd.stderr)}")
            return
        res.data["templates_updated"] = True
        version = self._template_version(upd)
        if version:
            res.data["templates_version"] = version
        print("[+] nuclei template-ləri yeniləndi"
              + (f" ({version})" if version else ""))

    @staticmethod
    def _template_version(proc) -> str:
        blob = (proc.stdout or b"") + b"\n" + (proc.stderr or b"")
        match = _VERSION_RE.search(redact(blob.decode(errors="ignore")))
        return match.group(0) if match else ""

    # ------------------------------------------------------------------ scan
    async def _scan(self, hosts: list, strategy: str, res: EngineResult):
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
                    "-severity", SAFE_SEVERITIES]
            args += self._template_args(strategy)
            args += [
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

        # ---- Hər proses vəziyyəti AÇIQ şəkildə idarə olunur ----
        if proc.missing:
            res.warn("nuclei tapılmadı")
            return
        if proc.blocked:
            res.fail(f"nuclei: egress/scope qapısı prosesi BLOKLADI "
                     f"(strategy={strategy}) — skan HEÇ BAŞLADILMADI")
            return

        problem: str | None = None
        if proc.timed_out:
            problem = (f"nuclei timeout (strategy={strategy}) — icra "
                       f"NATAMAMDIR, nəticələr tam deyil")
        elif proc.returncode != 0:
            problem = (f"nuclei prosesi uğursuz oldu (çıxış kodu "
                       f"{proc.returncode}, strategy={strategy}): "
                       f"{_stderr_excerpt(proc.stderr)}")

        # Prozess xətası etibarlı tapıntıları QORUYUR — stdout hər halda parse
        # olunur (timeout/qeyri-sıfır çıxış bütün nəticələrin yanlış olduğunu
        # SÜBUT ETMİR).
        stats = self._parse_and_store(proc.stdout, host_map, set(exclude), res)

        if stats.malformed:
            res.warn(f"nuclei ({strategy}): {stats.malformed} xətalı JSON sətri "
                     f"atlandı — nəticələr natamam ola bilər")
        if stats.out_of_scope:
            res.warn(f"nuclei ({strategy}): {stats.out_of_scope} nəticə cari "
                     f"skanın hostları ilə DƏQİQ uyğunlaşmadı — rədd edildi")
        if problem is not None:
            # İcra problemi QEYD olunur; natamam icra "tam uğurlu skan" kimi
            # təqdim EDİLMİR, lakin qorunan tapıntılar açıq bildirilir.
            res.fail(f"{problem}; {stats.accepted} etibarlı tapıntı qorundu "
                     f"(nəticələr NATAMAMDIR)")
        res.data.setdefault("nuclei", {})[strategy] = stats.diagnostics()
        print(f"[+] nuclei ({strategy}): {stats.accepted} tapıntı"
              + (" (NATAMAM)" if problem else ""))

    def _parse_and_store(self, raw_stdout: bytes, host_map: dict,
                         excluded: set, res: EngineResult) -> _ParseStats:
        """JSONL sətir-sətir parse edir; etibarlı tapıntıları yazır.

        Bir sətrin xətalı olması DİGƏR etibarlı sətirləri ATMAZ. Yalnız cari
        skanın hostlarına DƏQİQ uyğun gələn nəticələr qəbul olunur.
        """
        stats = _ParseStats()
        for line in (raw_stdout or b"").decode(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            stats.lines += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                stats.malformed += 1
                continue
            if not isinstance(record, dict):
                stats.malformed += 1
                continue
            stats.valid += 1

            try:
                host = _result_host(record)
            except ScopeError:
                stats.no_host += 1
                continue

            # DƏQİQ host uyğunlaşdırması — substring YOX. Cari skana aid
            # olmayan/scope xarici host (məs.: example.com.attacker.test) HEÇ
            # VAXT `example.com` ilə uyğunlaşmır.
            host_id = host_map.get(host)
            if host_id is None:
                stats.out_of_scope += 1
                continue

            info = record.get("info", {}) or {}
            severity = str(info.get("severity") or "medium").lower()
            tags_found = {str(t).lower() for t in (info.get("tags") or [])}
            if tags_found & excluded:
                stats.excluded += 1
                res.warn(f"dağıdıcı/istisna template nəticəsi rədd edildi: "
                         f"{record.get('template-id')}")
                continue

            matched = str(record.get("matched-at") or record.get("host") or "")
            db.insert_finding(
                host_id, "nuclei", severity,
                str(info.get("name") or record.get("template-id", "nəticə")),
                str(info.get("description") or "")[:500],
                evidence=matched,
                curl_repro=str(record.get("curl-command") or ""),
                template=str(record.get("template-id") or ""),
                confidence=0.7, source="nuclei", scan_id=self.ctx.scan_id)
            stats.accepted += 1
            res.findings += 1
            mark = "🔴" if severity in ("high", "critical") else "🟡"
            print(f"   [{mark}] {host}: {info.get('name')}")
        return stats
