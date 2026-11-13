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
import time
import traceback

from . import db
from .antiblock.guardian import Guardian
from .antiblock.identity import IdentityManager
from .antiblock.proxymanager import ProxyManager
from .authorization import from_config as build_authorization
from .context import Context
from .engines import cve_intel
from .engines.api_enum import APIEnumEngine
from .engines.api_fuzz import APIFuzzEngine
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
from .engines.param_enum import ParamEnumEngine
from .engines.race import RaceEngine
from .engines.recon import ReconEngine
from .engines.sourcecode import SourceCodeEngine
from .engines.sqli import SQLiEngine
from .engines.ssrf import SSRFEngine
from .engines.ssti import SSTIEngine
from .engines.validation import ValidationEngine
from .engines.vuln import VulnEngine
from .engines.wafdetect import WafDetectEngine
from .engines.xss import XSSEngine
from .http_policy import HttpPolicy
from .installer import check_tools, format_report, install_tools
from .report import generator
from .results import EngineResult, StageResult, now_iso
from .scope import ScopeError


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
        )
        self.policy = policy
        self.proxies = ProxyManager(getattr(args, "proxy", "off"), cfg.proxy_file)
        self.identity = IdentityManager(
            cfg.proxy_file, cfg.interface, cfg.rotation,
            getattr(args, "proxy", "off"))
        self.guardian = Guardian(self.identity, policy)
        self.authorization = build_authorization(
            cfg, scan_id=None, canceller=asyncio.Event())

        self.scan_id: int | None = None
        self.stages: list[StageResult] = []
        self.authorized_targets: list[str] = []
        self.tool_report = None
        self._tools_checked = False
        self.chain = None

        self.ctx = Context(cfg=cfg, args=args, guardian=self.guardian,
                           scan_id=None, authorization=self.authorization)
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
    async def _run_stage(self, stage: str, target: str, factory) -> StageResult:
        """Mərhələni icra edir və strukturlaşdırılmış nəticə qaytarır.

        `factory` çağırılandır (callable → coroutine); beləliklə əvvəlki
        mərhələ uğursuz olsa belə lazımsız korutin yaradılmır.
        """
        sr = StageResult(stage=stage, target=target, status="running",
                         started_at=now_iso())
        label = f"{stage} · {target}" if target else stage
        print(f"\n[▶] {label}")
        t0 = time.monotonic()
        try:
            result = await factory()
        except asyncio.CancelledError:
            sr.status = "cancelled"
            sr.completed_at = now_iso()
            sr.duration = round(time.monotonic() - t0, 3)
            self._record(sr)
            raise
        except Exception as exc:  # noqa: BLE001 - sərhəddə tutulur və raportlanır
            sr.status = "failed"
            sr.errors.append(f"{type(exc).__name__}: {exc}")
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
                elif result.ok:
                    sr.status = "ok"
                else:
                    sr.status = "failed"
            else:
                sr.status = "ok"
        sr.completed_at = now_iso()
        sr.duration = round(time.monotonic() - t0, 3)
        self._record(sr)
        marker = {"ok": "✓", "skipped": "·", "failed": "✗"}.get(sr.status, "?")
        print(f"   [{marker}] {label} — {sr.duration:.2f}s, "
              f"{sr.findings_count} tapıntı")
        return sr

    def _record(self, sr: StageResult) -> None:
        self.stages.append(sr)
        try:
            db.record_stage(self.scan_id, sr.target, sr.stage, sr.status,
                            sr.duration, "; ".join(sr.errors),
                            "; ".join(sr.warnings))
        except Exception as exc:  # noqa: BLE001
            print(f"   [!] stage qeydə alına bilmədi: {exc}")

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

        await asyncio.gather(
            self._run_stage("vuln", "", lambda: VulnEngine(self.ctx).run()),
            self._run_stage("js", "", lambda: JSAnalysisEngine(self.ctx).run()),
            self._run_stage("content", "", lambda: ContentEngine(self.ctx).run()),
            self._run_stage("ferox", "", lambda: FeroxEngine(self.ctx).run()),
        )

        await self._run_stage("api_enum", "",
                              lambda: APIEnumEngine(self.ctx).run())
        await self._run_stage("api_fuzz", "",
                              lambda: APIFuzzEngine(self.ctx).run())
        await self._run_stage("param_enum", "",
                              lambda: ParamEnumEngine(self.ctx).run())

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
        return await pipeline.run()

    # ---------------- yekun ----------------
    def generate_report(self) -> str | None:
        try:
            return generator.generate(
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
                })
        except Exception:  # noqa: BLE001 - hesabat yaradılmasa da pipeline bitməlidir
            print("[!] Hesabat yaradıla bilmədi:")
            traceback.print_exc()
            return None

    @property
    def failed_stages(self) -> list[StageResult]:
        return [s for s in self.stages if s.status == "failed"]

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

    async def _pipeline(self, mode: str, body) -> None:
        self.scan_id = db.start_scan(self.cfg.program, mode)
        self.ctx.scan_id = self.scan_id
        self.authorization.scan_id = self.scan_id
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
            if status != "cancelled" and self.failed_stages:
                status = "partial" if len(self.failed_stages) < len(self.stages) \
                    else "failed"
            self.generate_report()
            db.finish_scan(self.scan_id, status)
            self.print_summary()

    async def run_full(self) -> None:
        async def body():
            await self.run_recon()
            await self.run_vuln()
        await self._pipeline("full", body)

    async def run_recon_mode(self) -> None:
        await self._pipeline("recon", self.run_recon)

    async def run_vuln_mode(self) -> None:
        self.resolve_targets()
        await self._pipeline("vuln", self.run_vuln)
