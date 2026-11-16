"""Conductor — bütün mühərrikləri idarə edən beyin.

Əsas prinsiplər:
  * Hər mərhələ `EngineResult` qaytarır; Conductor onu `StageResult`-a çevirir.
  * `_run_stage` HEÇ VAXT `None` qaytarmır və xətanı səssizcə udmur —
    uğursuz mərhələ digərlərini korlamır, sadəcə "failed" kimi qeyd olunur.
  * Tool aşkarlanması YALNIZ BİR DƏFƏ aparılır.
  * Hesabat (report) hətta bəzi mərhələlər uğursuz olsa da yaradılır.
  * Hər mərhələ üçün müddət, status, xəta və xəbərdarlıq izlənir.
  * Ctrl+C zamanı yarımçıq nəticələr saxlanılır və hesabat yenə yazılır.
"""
from __future__ import annotations

import asyncio
import logging
import time
import traceback

from . import db
from . import recovery as rcv
from .adaptive import AdaptiveController
from .antiblock.guardian import Guardian
from .antiblock.identity import IdentityManager
from .antiblock.proxymanager import ProxyManager
from .authorization import from_config as build_authorization
from .context import Context
from .engines import cve_intel
from .engines.api_enum import APIEnumEngine
from .engines.content import ContentEngine
from .engines.deep_enum import DeepEnumEngine
from .engines.deepen import (
    BBOTEngine,
    DnstwistEngine,
    GowitnessEngine,
    WaymoreEngine,
)
from .engines.ferox import FeroxEngine
from .engines.fingerprint import FingerprintEngine
from .engines.jsanalysis import JSAnalysisEngine
from .engines.jwt import JWTEngine
from .engines.library_cve import LibraryCVEEngine
from .engines.race import RaceEngine
from .engines.recon import ReconEngine
from .engines.sourcecode import SourceCodeEngine
from .engines.sqli import SQLiEngine
from .engines.ssrf import SSRFEngine
from .engines.ssti import SSTIEngine
from .engines.takeover import TakeoverEngine
from .engines.validation import ValidationEngine
from .engines.vuln import VulnEngine
from .engines.wafdetect import WafDetectEngine
from .engines.xss import XSSEngine
from .http_policy import HttpPolicy
from .installer import check_tools, format_report, install_tools
from .metrics import OrchestrationMetrics, ScanMetrics
from .report import generator
from .results import EngineResult, StageResult, now_iso
from .scheduler import (HOST_GLOBAL, SchedTask, Scheduler,
                        submit_with_backpressure)
from .scope import ScopeError
from .tasks import (EventLedger, STATE_CANCELLED, STATE_COMPLETED,
                    STATE_FAILED, STATE_PARTIAL, STATE_RUNNING, STATE_SKIPPED,
                    TaskLedger, task_identity)

_log = logging.getLogger("qbh.conductor")

#: `StageResult.status` → dəftər həyat dövrü (davamlı saxlama üçün).
_SR_TO_STATE = {
    "ok": STATE_COMPLETED,
    "partial": STATE_PARTIAL,
    "failed": STATE_FAILED,
    "skipped": STATE_SKIPPED,
    "cancelled": STATE_CANCELLED,
}

#: Dəftər həyat dövrü → `StageResult.status` (bərpa/dedup zamanı göstərilir).
#: `queued`/`running` (eyni icrada dublikat) → `skipped` (icra OLUNMADI).
_STATE_TO_SR = {
    STATE_COMPLETED: "ok",
    STATE_PARTIAL: "partial",
    STATE_FAILED: "failed",
    STATE_SKIPPED: "skipped",
    STATE_CANCELLED: "cancelled",
}


# --------------------------------------------------------------------------- #
# F-04: MƏRHƏLƏ ASILILIQ XƏRİTƏSİ (tam pipeline)
# --------------------------------------------------------------------------- #
#: Hər mərhələ üçün asılılıq/xüsusiyyətlər:
#:   prereq     — əvvəlcə bitməli mərhələlər (sıra zəmanəti)
#:   input      — oxunan data
#:   output     — yazılan data
#:   scope      — "host" (host-üzrə) | "url" (URL-üzrə) | "global"
#:   subprocess — xarici alət (binary) işlədir?
#:   network    — şəbəkə sorğusu göndərir?
#:   findings   — əvvəlki tapıntılardan asılıdır?
#:   klass      — 1 müstəqil + paralelləşdirilə bilən |
#:                2 YALNIZ məhdud qrup daxilində paralel |
#:                3 ciddi ardıcıl | 4 şərti/davam mərhələsi
#:
#: Bu xəritə kodla EYNİ mənbədən törəyir (`run_recon`/`run_vuln` sırası) və
#: `test_stage_map.py` onun ardıcıllığını yoxlayır. Məqsəd: hansı işin paralel,
#: hansının ardıcıl olduğunu ƏSASSLI seçmək — hər şeyi bir planlaşdırıcıya
#: yığmamaq (bax: F-04 tələbi).
STAGE_MAP: dict[str, dict] = {
    # --- recon (hər hədəf üzrə budaqlanma) ---
    "deep_enum": {"prereq": (), "input": "target", "output": "subdomains",
                  "scope": "host", "subprocess": True, "network": True,
                  "findings": False, "klass": 3},
    "recon": {"prereq": ("deep_enum",), "input": "subdomains",
              "output": "hosts+urls", "scope": "host", "subprocess": True,
              "network": True, "findings": False, "klass": 3},
    "bbot": {"prereq": ("recon",), "input": "target", "output": "urls",
             "scope": "host", "subprocess": True, "network": True,
             "findings": False, "klass": 3},
    "waymore": {"prereq": ("recon",), "input": "target", "output": "urls",
                "scope": "host", "subprocess": True, "network": True,
                "findings": False, "klass": 3},
    "dnstwist": {"prereq": ("recon",), "input": "target", "output": "domains",
                 "scope": "host", "subprocess": True, "network": True,
                 "findings": False, "klass": 1},
    "gowitness": {"prereq": ("recon",), "input": "alive hosts",
                  "output": "screenshots", "scope": "global",
                  "subprocess": True, "network": True, "findings": False,
                  "klass": 3},
    # --- vuln aşkarlama ---
    "fingerprint": {"prereq": ("recon",), "input": "alive hosts",
                    "output": "tech/title", "scope": "global",
                    "subprocess": False, "network": True, "findings": False,
                    "klass": 3},
    "wafdetect": {"prereq": ("fingerprint",), "input": "alive hosts",
                  "output": "waf signature", "scope": "global",
                  "subprocess": False, "network": True, "findings": False,
                  "klass": 3},
    "takeover": {"prereq": ("recon",), "input": "subdomains",
                 "output": "takeover findings", "scope": "global",
                 "subprocess": False, "network": True, "findings": False,
                 "klass": 3},
    "vuln": {"prereq": ("fingerprint",), "input": "alive hosts",
             "output": "nuclei findings", "scope": "global",
             "subprocess": True, "network": True, "findings": False,
             "klass": 2},
    "js": {"prereq": ("recon",), "input": "JS urls", "output": "endpoints+secrets",
           "scope": "url", "subprocess": False, "network": True,
           "findings": False, "klass": 2},
    "content": {"prereq": ("recon",), "input": "alive hosts",
                "output": "paths", "scope": "host", "subprocess": True,
                "network": True, "findings": False, "klass": 2},
    "ferox": {"prereq": ("recon",), "input": "alive hosts", "output": "paths",
              "scope": "host", "subprocess": True, "network": True,
              "findings": False, "klass": 2},
    "api_enum": {"prereq": ("js", "content", "ferox"), "input": "alive hosts",
                 "output": "api routes", "scope": "host", "subprocess": True,
                 "network": True, "findings": False, "klass": 3},
    # --- offensive (URL-üzrə, RoE + Guardian qapılı) ---
    "sqli": {"prereq": ("api_enum",), "input": "param urls", "output": "sqli findings",
             "scope": "url", "subprocess": False, "network": True,
             "findings": False, "klass": 2},
    "xss": {"prereq": ("api_enum",), "input": "param urls", "output": "xss findings",
            "scope": "url", "subprocess": False, "network": True,
            "findings": False, "klass": 2},
    "ssti": {"prereq": ("api_enum",), "input": "param urls",
             "output": "ssti findings", "scope": "url", "subprocess": False,
             "network": True, "findings": False, "klass": 2},
    "ssrf": {"prereq": ("api_enum",), "input": "param urls",
             "output": "ssrf findings", "scope": "url", "subprocess": False,
             "network": True, "findings": False, "klass": 2},
    "jwt": {"prereq": ("js",), "input": "discovered tokens",
            "output": "jwt findings", "scope": "url", "subprocess": False,
            "network": True, "findings": True, "klass": 2},
    "sourcecode": {"prereq": ("recon",), "input": ".git urls",
                   "output": "source findings", "scope": "url",
                   "subprocess": False, "network": True, "findings": True,
                   "klass": 2},
    # --- post-processing ---
    "race": {"prereq": ("api_enum",), "input": "endpoint urls",
             "output": "race findings", "scope": "url", "subprocess": False,
             "network": True, "findings": False, "klass": 3},
    "cve_intel": {"prereq": ("fingerprint",), "input": "tech",
                  "output": "cve matches", "scope": "global",
                  "subprocess": False, "network": True, "findings": False,
                  "klass": 1},
    "library_cve": {"prereq": ("js",), "input": "JS libs",
                    "output": "lib cve", "scope": "url", "subprocess": False,
                    "network": True, "findings": False, "klass": 1},
    "validation": {"prereq": ("sqli", "xss", "ssti", "ssrf", "vuln"),
                   "input": "candidate findings", "output": "validated findings",
                   "scope": "global", "subprocess": False, "network": True,
                   "findings": True, "klass": 4},
    "chain": {"prereq": ("validation",), "input": "bütün DB vəziyyəti",
              "output": "zəncir davam testləri", "scope": "global",
              "subprocess": False, "network": True, "findings": True,
              "klass": 4},
}


def stage_klass(stage: str) -> int:
    """Mərhələnin paralellik sinfi (xəritədə yoxdursa 3 — ardıcıl)."""
    return int(STAGE_MAP.get(stage, {}).get("klass", 3))


class PipelineAbort(RuntimeError):
    """İcra davam edə bilməz (məsələn: heç bir icazəli hədəf yoxdur)."""


class Conductor:
    def __init__(self, cfg, args):
        self.cfg = cfg
        self.args = args
        db.init_db()

        lim = cfg.limits
        # Effektiv rate/concurrency: profil faktoru tətbiq olunur, CLI isə
        # yalnız aşağı salmağa (daha ehtiyatlı) icazə verir.
        eff_rate = cfg.effective_rate
        cli_rate = getattr(args, "rate", None)
        if cli_rate:
            eff_rate = max(0.1, min(float(cli_rate), eff_rate))
        # Faza 0 (§3): skan-scoped, bounded HTTP metrikaları.
        self.metrics = ScanMetrics()
        policy = HttpPolicy(
            cfg.scope,
            rate=eff_rate,
            max_concurrency=int(cfg.effective_concurrency),
            connect_timeout=float(lim.connect_timeout),
            total_timeout=float(lim.total_timeout),
            cooldown=float(lim.cooldown),
            max_redirects=int(cfg.profile.get("max_redirects", 20)),
            block_429=cfg.block_strategy.http_429,
            block_403=cfg.block_strategy.http_403,
            per_host_concurrency=getattr(lim, "per_host_concurrency", None),
            metrics=self.metrics,
        )
        self.policy = policy
        self.proxies = ProxyManager(getattr(args, "proxy", "off"), cfg.proxy_file)
        self.identity = IdentityManager(
            cfg.proxy_file, cfg.interface, cfg.rotation,
            getattr(args, "proxy", "off"))
        self.guardian = Guardian(self.identity, policy)
        self.authorization = build_authorization(
            cfg, scan_id=None, canceller=asyncio.Event(),
            allow_state_changing=bool(
                getattr(args, "allow_state_changing", False)))

        self.scan_id: int | None = None
        #: Faza 2 (§4.2): davamlı saxlama adapteri (`recovery.DurableStore`) —
        #: skan başlayanda qoşulur. Bərpa planı `--resume` zamanı saxlanılır.
        self.store = None
        self._resume_plan = None
        self.stages: list[StageResult] = []
        self.authorized_targets: list[str] = []
        self.tool_report = None
        self._tools_checked = False
        self.chain = None

        self.ctx = Context(cfg=cfg, args=args, guardian=self.guardian,
                           scan_id=None, authorization=self.authorization,
                           metrics=self.metrics)
        # Faza 3-6 (§7-§10): orkestrasiya komponentləri — skan boyu TƏK nüsxə.
        # Idempotentlik/hadisə dəftərləri, adaptiv nəzarət və orkestrasiya
        # metrikaları bütün mühərriklər tərəfindən `ctx` vasitəsilə paylaşılır.
        self.orchestration = OrchestrationMetrics()
        self.task_ledger = TaskLedger(max_attempts=3)
        #: F-05: skan boyu FAKTİKİ planlaşdırıcı icra saylarının toplanması
        #: (hər `Scheduler` nüsxəsinin snapshot-ı burada birləşir). Beləliklə
        #: hesabatdakı tapşırıq metrikaları niyyəti deyil, REAL icranı göstərir.
        self._sched_totals: dict = {}
        self.event_ledger = EventLedger(
            max_depth=int(getattr(cfg.chain, "max_depth", 3) or 3))
        self.adaptive = AdaptiveController(ledger=self.task_ledger,
                                           metrics=self.orchestration)
        self.ctx.orchestration = self.orchestration
        self.ctx.task_ledger = self.task_ledger
        self.ctx.event_ledger = self.event_ledger
        self.ctx.adaptive = self.adaptive
        # Faza 2.1: hədəfə gedən native HTTP trafiki TLS təqlidi transportundan
        # keçir (curl_cffi yoxdursa transport `available=False` → aiohttp).
        self.policy.transport = self.ctx.stealth.transport

    # ---------------- target + scope ----------------
    def resolve_targets(self) -> list[str]:
        """CLI `--targets` və ya konfiq hədəflərini scope-a görə süzür.

        `--targets` HEÇ VAXT avtorizasiyanı keçmir — hər hədəf
        `Config.authorize_target` ilə yoxlanılır (fail-closed).
        """
        raw = getattr(self.args, "targets", None)
        requested = ([x.strip() for x in raw.split(",") if x.strip()]
                     if raw else list(self.cfg.targets))
        ok: list[str] = []
        seen: set[str] = set()
        for t in requested:
            try:
                host = self.cfg.authorize_target(t)
            except ScopeError as exc:
                print(f"   [⛔] scope xaricində rədd edildi: {t!r} ({exc})")
                continue
            if host not in seen:
                seen.add(host)
                ok.append(host)
        if not ok:
            raise PipelineAbort("heç bir icazəli hədəf yoxdur — dayandırıldı")
        self.authorized_targets = ok
        return ok

    # ---------------- tool yoxlaması (tək dəfə) ----------------
    async def _ensure_tools(self):
        if self._tools_checked:
            return self.tool_report
        self._tools_checked = True
        report = await check_tools()
        self.tool_report = report
        missing = report.missing_required
        if missing:
            print("[!] Çatışmayan məcburi tool-lar: "
                  + ", ".join(t.name for t in missing))
            if getattr(self.args, "auto_install", False):
                await install_tools(report, dry_run=bool(
                    getattr(self.args, "dry_run", False)))
                print(format_report(report))
            else:
                print("    (qurulum üçün: --mode install --auto-install)")
        return report

    async def install_only(self) -> int:
        report = await check_tools()
        dry = bool(getattr(self.args, "dry_run", False))
        do_install = bool(getattr(self.args, "auto_install", False)) and not dry
        await install_tools(report, dry_run=not do_install)
        print(format_report(report))
        return 0 if not report.missing_required else 1

    # ---------------- stage runner ----------------
    def _stage_identity(self, stage: str, target: str) -> str:
        """Mərhələ tapşırığının DETERMİNİSTİK kimliyi.

        Hədəf-üzrə mərhələlər (məs. recon zənciri) `target` ilə AYRILIR ki,
        çox-hədəfli skanda ikinci hədəf BİRİNCİNİN nəticəsi ilə səhvən
        dedup OLUNMASIN (əhatə azalmasın). Qlobal mərhələlərdə `target=""`
        → `stage` açarı işlədilir (mövcud `_submit_stage` sxemi ilə eyni).
        """
        return task_identity(self.scan_id, stage, target or stage,
                             test_type="stage")

    async def _run_stage(self, stage: str, target: str, factory) -> StageResult:
        """Mərhələni icra edir və strukturlaşdırılmış nəticə qaytarır.

        `factory` çağırılandır (callable → coroutine); beləliklə əvvəlki
        mərhələ uğursuz olsa belə lazımsız korutin yaradılmır.

        Faza 2 (§4.3): mərhələ TƏK həqiqət mənbəyindən (`TaskLedger`) keçir —
        artıq `completed`/`skipped` olan tapşırıq TƏKRAR İCRA OLUNMUR (bərpada
        iş təkrarlanmır), nəticə datası (`sr.data`) isə davamlı saxlanır ki,
        aşağı mərhələlər ondan istifadə edə bilsin.

        Sahiblik (ownership) iki yolla müəyyən olunur:
          * **Paralel yol** — `_submit_stage` tapşırığı `Scheduler`-ə verir və
            Scheduler `task.run()`-dan ƏVVƏL dəftərdə `running` işarələyir.
            Bu halda həyat dövrünü Scheduler idarə edir → biz `consider`
            ETMİRİK, yalnız nəticə datasını saxlayırıq.
          * **Birbaşa yol** — mərhələ boru xətləri (`run_recon`/`run_vuln`)
            `_run_stage`-i birbaşa çağırır; burada qərarı BİZ `consider` ilə
            alırıq və həyat dövrünü özümüz yazırıq.
        """
        identity = self._stage_identity(stage, target)
        rec = self.task_ledger.get(identity)
        if rec is not None and rec.state == STATE_RUNNING:
            owned = False
        else:
            decision = self.task_ledger.consider(
                identity, engine=stage, endpoint=target or stage,
                test_type="stage")
            if not decision.create:
                return self._record_dedup(stage, decision.reason, identity)
            owned = True
        sr = StageResult(stage=stage, target=target, status="running",
                         started_at=now_iso())
        label = f"{stage} · {target}" if target else stage
        print(f"\n[▶] {label}")
        t0 = time.monotonic()
        try:
            if self.authorization.allows(stage):
                result = await factory()
            else:
                result = EngineResult(stage=stage).skip("authorization: forbidden engine " + stage)
        except asyncio.CancelledError:
            sr.status = "cancelled"
            sr.completed_at = now_iso()
            sr.duration = round(time.monotonic() - t0, 3)
            _log.warning("stage ləğv edildi: scan_id=%s engine=%s host=%s",
                         self.scan_id, stage, target or "-")
            self._record(sr)
            self._persist_stage(identity, sr, owned)
            raise
        except Exception as exc:  # noqa: BLE001 - sərhəddə tutulur və raportlanır
            sr.status = "failed"
            sr.errors.append(f"{type(exc).__name__}: {exc}")
            # Strukturlaşdırılmış log: yalnız TİP (mesaj/məzmun YOX).
            _log.error("stage uğursuz: scan_id=%s engine=%s host=%s exc=%s",
                       self.scan_id, stage, target or "-", type(exc).__name__)
            print(f"   [✗] {label} xətası: {type(exc).__name__}: {exc}")
            traceback.print_exc()
        else:
            if isinstance(result, EngineResult):
                sr.findings_count = result.findings
                sr.errors.extend(result.errors)
                sr.warnings.extend(result.warnings)
                sr.data = result.data
                if result.skipped:
                    sr.status = "skipped"
                elif result.partial:
                    sr.status = "partial"
                elif result.ok:
                    sr.status = "ok"
                else:
                    sr.status = "failed"
            else:
                sr.status = "ok"
        sr.completed_at = now_iso()
        sr.duration = round(time.monotonic() - t0, 3)
        self._record(sr)
        self._persist_stage(identity, sr, owned)
        marker = {"ok": "✓", "partial": "~", "skipped": "·",
                  "failed": "✗"}.get(sr.status, "?")
        print(f"   [{marker}] {label} — {sr.duration:.2f}s, "
              f"{sr.findings_count} tapıntı")
        return sr

    def _persist_stage(self, identity: str, sr: StageResult,
                       owned: bool) -> None:
        """Mərhələnin nəticə datasını dəftərə yazır və (lazım gələrsə) vəziyyəti işarələyir.

        `owned=False` (paralel mərhələ) halında həyat dövrünü `Scheduler`
        işarələyir — biz yalnız `result_data`-nı qeyd edirik.
        """
        rec = self.task_ledger.get(identity)
        if rec is not None and isinstance(sr.data, dict):
            rec.result_data = dict(sr.data)
        if not owned:
            return
        state = _SR_TO_STATE.get(sr.status)
        if state is None or rec is None:
            return
        reason = "; ".join(sr.errors) if sr.errors else sr.status
        self.task_ledger.mark(identity, state, reason)

    def _record(self, sr: StageResult) -> None:
        self.stages.append(sr)
        # F-01: mərhələnin REAL statusu `ctx`-ə yazılır — `ChainPipeline` davam
        # testlərinin nəticəsini uydurmadan, FAKTİKİ mərhələ statusuna görə yazır.
        try:
            self.ctx.stage_status[sr.stage] = sr.status
        except Exception:  # noqa: BLE001 - ctx sadə obyekt olsa da davam et
            pass
        try:
            db.record_stage(self.scan_id, sr.target, sr.stage, sr.status,
                            sr.duration, "; ".join(sr.errors),
                            "; ".join(sr.warnings))
        except Exception as exc:  # noqa: BLE001
            print(f"   [!] stage qeydə alına bilmədi: {exc}")

    # ---------------- bounded parallel stage runner (Faza 4) ----------------
    async def _run_parallel(self, specs: list[tuple]) -> None:
        """Müstəqil mərhələləri MƏRKƏZLƏŞDİRİLMİŞ məhdud planlaşdırıcı ilə icra edir.

        `Scheduler` worker sayını, qlobal və host-əsaslı concurrency-ni
        məhdudlaşdırır; bir mərhələnin xətası digərlərinə YAYILMIR və `aclose()`
        bütün işçiləri ləğv edib faktiki bitməsini gözləyir (Task sızması yox).
        Nəticələr `_run_stage` daxilində qeyd olunur (sıra = tamamlanma sırası).

        F-02: `submit()` növbə doyduqda `False` qaytarır. Bu nəticə SƏSSİZCƏ
        atılmır — `submit_with_backpressure` MƏHDUD (sonsuz olmayan) gözləmə ilə
        yenidən cəhd edir; yenə alınmasa mərhələ AÇIQ `failed` kimi qeyd olunur
        (səbəb: backpressure). Beləliklə heç bir mərhələ itmir.
        """
        lim = self.cfg.limits
        per_host = getattr(lim, "per_host_concurrency", None) or 0
        global_cap = int(self.cfg.effective_concurrency)
        sched = Scheduler(
            workers=max(1, min(len(specs), global_cap)),
            global_limit=global_cap,
            per_host_limit=int(per_host),
            ledger=self.task_ledger,
            metrics=self.orchestration)
        self.ctx.scheduler = sched
        async with sched:
            for stage, factory in specs:
                await self._submit_stage(sched, stage, factory)
            await sched.drain()
        # F-05: bu planlaşdırıcının FAKTİKİ icra saylarını skan toplusuna birləş.
        self._merge_scheduler_totals(sched.snapshot())

    async def _submit_stage(self, sched, stage: str, factory) -> None:
        """Mərhələni TƏK həqiqət mənbəyi (TaskLedger) vasitəsilə təqdim edir (F-04).

        İdempotentlik müqaviləsi: qərarı İSTİFADƏÇİ (bu metod) `consider()` ilə
        alır; `Scheduler` yalnız lifecycle yazır (`mark`). Yeni kimlik deyilsə
        mərhələ səssizcə ATILMIR — AÇIQ `skipped` kimi qeyd olunur (səbəblə).
        `submit()` rədd edərsə məhdud cəhd edilir; yenə alınmasa AÇIQ `failed`.
        """
        identity = self._stage_identity(stage, "")
        decision = self.task_ledger.consider(
            identity, engine=stage, endpoint=stage, test_type="stage")
        if not decision.create:
            self._record_dedup(stage, decision.reason, identity)
            return
        # F-06: host-üzrə scope-u OLMAYAN mərhələlər üçün SƏNƏDLƏŞDİRİLMİŞ
        # ədalət açarı — real host UYDURULMUR, `family=stage` ayrı vedrə verir.
        task = SchedTask(
            identity=identity, engine=stage, host=HOST_GLOBAL, family=stage,
            run=lambda st=stage, f=factory: self._run_stage(st, "", f))
        accepted = await submit_with_backpressure(sched, task)
        if not accepted:
            self.task_ledger.mark(identity, STATE_FAILED,
                                  "scheduler backpressure: qəbul olunmadı")
            self._record_rejected(stage)

    def _record_dedup(self, stage: str, reason: str,
                      identity: str = "") -> StageResult:
        """İdempotentlik səbəbilə icra OLUNMAYAN mərhələni AÇIQ qeyd edir (F-04).

        Mərhələ HEÇ VAXT səssizcə itmir: strukturlaşdırılmış nəticə və səbəb
        yazılır ki, hesabatda və metrikalarda görünsün. Tapşırıq ƏVVƏLKİ
        icrada artıq TAMAMLANDIBSA (`completed`) status FAKTİKİ nəticəni
        (`ok`) göstərir və davamlı saxlanmış `result_data` bərpa olunur ki,
        aşağı mərhələlər (məs. `recon` üçün subdomain-lər) əhatəni itirməsin.
        `queued`/`running` (eyni icrada dublikat) isə `skipped` qalır.
        """
        rec = self.task_ledger.get(identity) if identity else None
        status = _STATE_TO_SR.get(getattr(rec, "state", ""), "skipped")
        sr = StageResult(stage=stage, target="", status=status,
                         started_at=now_iso(), completed_at=now_iso())
        if rec is not None and isinstance(rec.result_data, dict):
            sr.data = dict(rec.result_data)
        sr.warnings.append(f"idempotentlik: {reason}")
        self._record(sr)
        print(f"\n[▶] {stage}\n   [·] {stage} — idempotentlik: {reason}")
        return sr

    def _merge_scheduler_totals(self, snap: dict) -> None:
        """Bütün planlaşdırıcı nüsxələrinin REAL icra saylarını toplayır (F-05).

        Attributiv saylar (executed/completed/rejected…) cəmlənir; pik dəyərlər
        maksimum götürülür. Bu toplu hesabatda tapşırıq metrikalarının FAKTİKİ
        icra mənbəyi olur (ledger isə niyyəti göstərir).
        """
        for key in ("submitted", "executed", "completed", "failed",
                    "cancelled", "rejected_backpressure"):
            self._sched_totals[key] = (self._sched_totals.get(key, 0)
                                       + int(snap.get(key, 0)))
        for key in ("peak_queue", "peak_concurrency"):
            self._sched_totals[key] = max(self._sched_totals.get(key, 0),
                                          int(snap.get(key, 0)))
        self._sched_totals["workers"] = snap.get("workers", 0)
        self._sched_totals["queue_limit"] = snap.get("queue_limit", 0)

    def _record_rejected(self, stage: str) -> None:
        """Scheduler qəbul etmədiyi mərhələni AÇIQ `failed` kimi qeyd edir (F-02).

        `submit_with_backpressure` məhdud cəhdlərdən sonra da növbəyə qoya
        bilmirsə, mərhələ səssizcə İTİRİLMƏMƏLİDİR: strukturlaşdırılmış `failed`
        nəticə və səbəb yazılır ki, hesabatda və metrikalarda görünsün.
        """
        sr = StageResult(stage=stage, target="", status="failed",
                         started_at=now_iso(), completed_at=now_iso())
        sr.errors.append(
            "scheduler backpressure: növbə doydu, mərhələ qəbul olunmadı")
        self._record(sr)
        print(f"\n[▶] {stage}\n   [✗] {stage} — scheduler backpressure: "
              "növbə doydu, mərhələ qəbul olunmadı")

    # ---------------- mərhələ boru xətləri ----------------
    async def run_recon(self) -> None:
        targets = self.resolve_targets()
        await self._ensure_tools()
        for t in targets:
            deep = DeepEnumEngine(self.ctx)
            sr = await self._run_stage(
                "deep_enum", t, lambda t=t, deep=deep: deep.run(t))
            subs = sr.data.get("subdomains") or {t}
            recon = ReconEngine(self.ctx)
            await self._run_stage(
                "recon", t,
                lambda t=t, subs=subs, recon=recon: recon.run(t, subs))
            # Faza 1.2: recon dərinləşdirmə (alət yoxdursa honest skip).
            await self._run_stage(
                "bbot", t, lambda t=t: BBOTEngine(self.ctx).run(t))
            await self._run_stage(
                "waymore", t, lambda t=t: WaymoreEngine(self.ctx).run(t))
            await self._run_stage(
                "dnstwist", t, lambda t=t: DnstwistEngine(self.ctx).run(t))
        # Skrinşot inventarı canlı hostlar yarandıqdan SONRA (Faza 1.2).
        await self._run_stage("gowitness", "",
                              lambda: GowitnessEngine(self.ctx).run())

    async def run_vuln(self) -> None:
        await self._ensure_tools()

        fp = FingerprintEngine(self.ctx)
        await self._run_stage("fingerprint", "", lambda: fp.run())

        # Faza 2.2: WAF identikliyi — sonrakı stealth qərarlarını idarə edir.
        await self._run_stage("wafdetect", "",
                              lambda: WafDetectEngine(self.ctx).run())

        # Faza 3.3: CNAME takeover (dangling CNAME + provayder imzası).
        await self._run_stage("takeover", "",
                              lambda: TakeoverEngine(self.ctx).run())

        await self._run_parallel([
            ("vuln", lambda: VulnEngine(self.ctx).run()),
            ("js", lambda: JSAnalysisEngine(self.ctx).run()),
            ("content", lambda: ContentEngine(self.ctx).run()),
            ("ferox", lambda: FeroxEngine(self.ctx).run()),
        ])

        await self._run_stage("api_enum", "",
                              lambda: APIEnumEngine(self.ctx).run())
        # Faza 3.4: `param_enum` və `api_fuzz` (Schemathesis) artıq ChainPipeline
        # tərəfindən trigger-əsaslı REAL icra olunur (RoE qapıları ilə) — burada
        # təkrar skan/trafik yaratmamaq üçün ayrı mərhələ kimi işlədilmir.

        # Faza 1.1: offensive mühərriklər (RoE + nərdivan qapısı ilə).
        await self._run_offensive()

        await self._run_stage("race", "", lambda: RaceEngine(self.ctx).run())
        await self._run_stage("cve_intel", "", lambda: cve_intel.run(self.ctx))
        # Faza 1.3: kitabxana CVE uyğunlaşdırması (OSV + KEV/EPSS).
        await self._run_stage("library_cve", "",
                              lambda: LibraryCVEEngine(self.ctx).run())
        await self._run_stage("validation", "",
                              lambda: ValidationEngine(self.ctx).run())
        # Faza 2: zəncirləmə — kəşfləri avtomatik test/təsdiqə bağlayır.
        await self._run_stage("chain", "", lambda: self._run_chain())

    async def _run_offensive(self) -> None:
        """Faza 1.1 offensive mühərrikləri — honest qapı ilə.

        Qapılar: (1) RoE `active_fuzz`, (2) Guardian eskalasiya nərdivanı
        (`defer_intrusive` → intrusiv fazalar təxirə salınır). Atlandıqda bu
        AÇIQ şəkildə bildirilir — heç vaxt səssizcə "işlədi" deyilmir.
        """
        if not self.ctx.allows("active_fuzz"):
            await self._run_stage("sqli", "", lambda: SQLiEngine(self.ctx).run())
            await self._run_stage("xss", "", lambda: XSSEngine(self.ctx).run())
            print("   [·] offensive mühərriklər: aktiv fuzz qadağandır (RoE)")
            return
        if not self.guardian.allows_intrusive():
            print("   [·] offensive mühərriklər: Guardian nərdivanı intrusiv "
                  "fazaları təxirə salıb")
            return
        await self._run_stage("sqli", "", lambda: SQLiEngine(self.ctx).run())
        await self._run_stage("xss", "", lambda: XSSEngine(self.ctx).run())
        await self._run_stage("ssti", "", lambda: SSTIEngine(self.ctx).run())
        await self._run_stage("ssrf", "", lambda: SSRFEngine(self.ctx).run())
        await self._run_stage("jwt", "", lambda: JWTEngine(self.ctx).run())
        await self._run_stage("sourcecode", "",
                              lambda: SourceCodeEngine(self.ctx).run())

    async def _run_chain(self):
        from .chain import ChainPipeline

        pipeline = ChainPipeline(self.ctx)
        self.chain = pipeline
        result = await pipeline.run()
        snapshot = result.data.get("brain", {}).get("scheduler") if isinstance(result, EngineResult) else None
        if snapshot:
            self._merge_scheduler_totals(snapshot)
        return result

    # ---------------- yekun ----------------
    def generate_report(self) -> str | None:
        # Faza 6 (§10): hesabat anındakı URL/tapşırıq/zəncir sayğaclarını sinxronla.
        try:
            from . import urlintel

            urlintel.record_intake(self.ctx)
            self.orchestration.record_task_stats(
                self.task_ledger.snapshot(),
                dict(self._sched_totals) or None)
            self.orchestration.record_chain_stats(self.event_ledger.snapshot())
        except Exception:  # noqa: BLE001 - metrikalar hesabatı bloklamamalıdır
            pass
        try:
            path = generator.generate(
                severity_min=self.args.severity,
                stages=self.stages,
                meta={
                    "program": self.cfg.program,
                    "scan_id": self.scan_id,
                    "mode": getattr(self.args, "mode", "full"),
                    "targets": list(self.authorized_targets),
                    "rate": self.ctx.rate,
                    "aggressiveness": self.cfg.aggressiveness,
                    "config_warnings": list(self.cfg.warnings),
                    "block_audit": self.guardian.audit(),
                    "rotation_audit": self.guardian.rotation_audit(),
                    "ladder": self.guardian.ladder_state(),
                    "stealth": self.ctx.stealth.summary(),
                    "chain_audit": self.chain.audit() if self.chain else {},
                    "metrics": self.metrics.snapshot(),
                    "orchestration": self.orchestration.snapshot(),
                })
        except Exception:  # noqa: BLE001 - hesabat yaradılmasa da pipeline bitməlidir
            print("[!] Hesabat yaradıla bilmədi:")
            traceback.print_exc()
            return None
        # Faza 4.4: hesabat (və H1 ixracı) yazıldıqdan SONRA təsdiqlənmiş
        # tapıntılar `reported` işarələnir. Beləcə eyni tapıntı sonrakı
        # emalda yenidən "yeni/təsdiqlənmiş" kimi təkrarlanmır (terminal status).
        if path and self.scan_id is not None:
            try:
                n = db.mark_reported(self.scan_id)
                if n:
                    print(f"[✓] {n} təsdiqlənmiş tapıntı `reported` işarələndi")
            except Exception as exc:  # noqa: BLE001 - status yenilənməsə hesabat qalır
                print(f"[!] Tapıntı statusu `reported` edilə bilmədi: {exc}")
        return path

    @property
    def failed_stages(self) -> list[StageResult]:
        return [s for s in self.stages if s.status == "failed"]

    @property
    def partial_stages(self) -> list[StageResult]:
        """Natamam (timeout/qismən nəticə) tamamlanmış mərhələlər."""
        return [s for s in self.stages if s.status == "partial"]

    def print_summary(self) -> None:
        print("\n=== İCRA XÜLASƏSİ ===")
        if not self.stages:
            print("  (mərhələ icra olunmadı)")
        for s in self.stages:
            extra = f" · {s.findings_count} tapıntı" if s.findings_count else ""
            err = f" · xəta: {'; '.join(s.errors)}" if s.errors else ""
            warn = f" · xəbərdarlıq: {'; '.join(s.warnings)}" if s.warnings else ""
            print(f"  [{s.status:<9}] {s.stage:<12} {s.duration:7.2f}s"
                  f"{extra}{err}{warn}")
        summary = self.guardian.summary()
        if summary["blocks"]:
            print(f"  [⛔] {summary['blocks']} blok hadisəsi → "
                  f"dayandırılan hostlar: {', '.join(summary['blocked_hosts'])}")
        if summary.get("rotations"):
            print(f"  [↻] {summary['rotations']} identiklik rotasiyası "
                  f"(UA/başlıq/proxy rotasiyası konfiqurasiya ilə idarə olunur)")
        ladder = summary.get("ladder") or {}
        if ladder.get("level"):
            print(f"  [🪜] Guardian nərdivanı: səviyyə {ladder['level']} "
                  f"({ladder.get('action')})")
        waf = self.ctx.stealth.waf
        if waf.detected:
            print(f"  [🛡] WAF: {waf.name} (güvən {waf.confidence:.2f})")
        imp = self.ctx.stealth.summary().get("impersonate", {})
        if not imp.get("available"):
            print(f"  [i] TLS təqlidi əlçatan deyil: {imp.get('reason')}")

    async def _pipeline(self, mode: str, body, *, scan_id: int | None = None,
                        resume: bool = False) -> None:
        """Skan boru xətti. `scan_id` verilərsə MÖVCUD skan davam etdirilir
        (bərpa); əks halda yeni skan yaradılır.

        Faza 2 (§4.2): hər mərhələ `DurableStore` ilə davamlı saxlamaya
        qoşulur ki, proses çöksə belə iş İTİRMƏSİN. Saxlama YALNIZ bərpa
        üçündür — in-memory dəftərlər əsas həqiqət mənbəyi qalır.
        """
        if scan_id is not None:
            self.scan_id = int(scan_id)
        else:
            self.scan_id = db.start_scan(self.cfg.program, mode)
        self.ctx.scan_id = self.scan_id
        self.authorization.scan_id = self.scan_id
        self.store = rcv.DurableStore(self.scan_id)
        self.task_ledger.store = self.store
        self.event_ledger.store = self.store
        self.adaptive.store = self.store
        if resume:
            self._restore_durable()
        status = "completed"
        try:
            await self.ctx.oob.start()
            # Faza 1.2: skan boyu MƏCBURİ subprocess egress qapısı aktivdir.
            # Hər `run_process` çağırışı (hansı mühərrikdən gəlməsindən asılı
            # olmayaraq) scope + fail-closed DNS yoxlamasından keçir.
            with self.ctx.egress.activate():
                await body()
        except asyncio.CancelledError:
            self.authorization.cancel()
            status = "cancelled"
            print("\n[!] İcra ləğv edildi (Ctrl+C) — yarımçıq nəticələr saxlanılır")
            raise
        finally:
            await self.ctx.oob.stop()
            # Faza 1 (§4): skan-scoped sessiya HƏMİŞƏ bağlanır — uğur, xəta,
            # exception və ləğv (CancelledError) halında. `finally` blokunda
            # olduğu üçün heç bir halda açıq qalmır.
            await self.ctx.aclose()
            if status != "cancelled":
                if self.failed_stages:
                    status = "partial" if len(self.failed_stages) < len(self.stages) \
                        else "failed"
                elif self.partial_stages:
                    # Bütün mərhələlər "ok" olsa da bəziləri NATAMAMDIR —
                    # skanı tam uğurlu kimi təqdim etmək olmaz.
                    status = "partial"
            # Faza 4 (dürüstlük): son STATUS hesabatdan ƏVVƏL yazılır ki,
            # hesabat REAL nəticəni (completed/partial/failed/cancelled)
            # göstərsin — DB default-u olan `running`-i saxlayıb skanı
            # tamamlanmış kimi təqdim ETMƏSİN. Çökmə (SIGKILL/power-off)
            # zamanı bu blok HEÇ VAXT işləmir → sətir `running` qalır və bu,
            # KƏSİLMİŞ (interrupted) skanın dürüst göstəricisidir; belə skan
            # üçün hesabat yazılmır.
            db.finish_scan(self.scan_id, status)
            self.generate_report()
            self.print_summary()

    async def run_full(self) -> None:
        await self._pipeline("full", self._mode_body("full"))

    async def run_recon_mode(self) -> None:
        await self._pipeline("recon", self.run_recon)

    async def run_vuln_mode(self) -> None:
        self.resolve_targets()
        await self._pipeline("vuln", self.run_vuln)

    # ---------------- Faza 2 (§4.2/§4.3): bərpa ----------------
    def _mode_body(self, mode: str):
        """Rejim adına uyğun icra gövdəsini qaytarır (yeni skan və bərpa üçün ortaq)."""
        if mode == "recon":
            return self.run_recon
        if mode == "vuln":
            return self.run_vuln
        if mode == "hunt":
            from .hunter import Hunter

            async def hunt_body():
                await Hunter(self).hunt()
            return hunt_body

        async def full_body():
            await self.run_recon()
            await self.run_vuln()
        return full_body

    def _restore_durable(self) -> dict:
        """Davamlı vəziyyətdən dəftərləri BƏRPA edir və scope-u YENİDƏN yoxlayır.

        * `completed`/`skipped` tapşırıqlar olduğu kimi yüklənir → `consider`
          onları TƏKRAR planlaşdırmır (iş təkrarlanmır).
        * `running` (proses çökmüş) tapşırıqlar yenidən növbəyə alınır.
        * Scope-dan kənar hədəflər AÇIQ `skipped` edilir (yenidən icra YOX).
        * `attempts` / `reason` tarixçəsi QORUNUR.
        """
        plan = rcv.build_resume_plan(
            self.scan_id, program=self.cfg.program,
            authorize=self.cfg.authorize_target)
        restored = self.task_ledger.restore(plan.tasks)
        events = self.event_ledger.restore(plan.events)
        followups = self.adaptive.restore_followups(plan.followups)
        print(f"[↻] Bərpa (skan {self.scan_id}): {restored['restored']} tapşırıq "
              f"yükləndi — təkrar növbə: {restored['requeued']}, "
              f"terminal (təkrarlanmayacaq): {restored['terminal']}; "
              f"{events} hadisə; {followups} gözləyən davam testi")
        if plan.out_of_scope:
            print(f"   [⛔] {len(plan.out_of_scope)} tapşırıq artıq scope "
                  f"xaricindədir — icra OLUNMUR")
        self._resume_plan = plan
        return plan.to_dict()

    async def resume(self, scan_id: int | None = None) -> int:
        """Yarımçıq (çökmüş) skanı DAVAM ETDİRİR (Faza 2 §4.3).

        `scan_id=None` → ən son `running` skan seçilir. Rejim davamlı `scans`
        cədvəlindən oxunur; YENİ skan sətri yaradılmır — eyni `scan_id` davam
        edir. Scope/avtorizasiya YENİDƏN yoxlanılır (fail-closed).
        """
        row = db.get_scan(int(scan_id)) if scan_id is not None \
            else rcv.latest_pending_scan()
        if row is None:
            print("[i] Bərpa üçün yarımçıq (running) skan tapılmadı")
            return 1
        sid = int(row["id"])
        mode = row["mode"] or "full"
        print(f"[↻] Skan {sid} bərpa olunur (rejim: {mode})")
        # Scope YENİDƏN yoxlanılır — bərpa avtorizasiyanı KEÇMİR (§4.3).
        self.resolve_targets()
        await self._pipeline(mode, self._mode_body(mode), scan_id=sid,
                            resume=True)
        return 0 if not self.failed_stages else 1
