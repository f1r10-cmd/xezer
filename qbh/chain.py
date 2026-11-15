"""Zəncirləmə pipeline — 'finding maximization' mərkəzi (Faza 2).

`Recon → Discover → Enrich → Test → Confirm → PoC → Report` axınında mərhələlər
arasında **avtomatik keçidləri** qurur:

| Trigger | Avtomatik davam |
|---|---|
| Subdomain kəşfi | canlı-yoxlama; canlıdırsa fingerprint + JS analizi |
| JS faylı | endpoint/secret çıxarışı → eyni hostda yoxlama |
| Yeni parametr | gizli parametr aşkarlanması → fuzz |
| OpenAPI sənədi | server-ləri scope-a yoxla → aktiv Schemathesis |
| Maraqlı endpoint (login/upload/admin) | hədəfli fuzz / SQLi-yönlü yoxlama |
| Fingerprint-dən CVE uyğunluğu | təsdiq template-i / skript PoC |
| 401/403 maraqlı yolda | bypass matrisi (payloads.build_matrix) |
| Nuclei medium+ hit | sübut toplama, hesabata əlavə, confidence artırımı |

**Vacib:** hər zəncir addımı `ctx.authorization.authorize_url`-dən keçir;
proqram qaydası qadağan edərsə addım atlanır və bu, audit-də qeyd olunur.

Bu modul yeni ağıllı işləri (bypass, confirm) BİRBAŞA icra edir; artıq
Conductor tərəfindən planlaşdırılan addımlar (şəbəkə zənciri) isə "delegated"
kimi audit olunur — beləliklə heç bir iş iki dəfə icra edilmir.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import db, urlintel
from .adaptive import (OUTCOME_CANCELLED, OUTCOME_COMPLETED, OUTCOME_FAILED,
                       OUTCOME_INCONCLUSIVE, OUTCOME_PARTIAL,
                       STRENGTH_STRONG, STRENGTH_WEAK, FollowUp, Signal)
from .engines.api_fuzz import APIFuzzEngine
from .engines.bypass import BypassEngine
from .engines.confirm import ConfirmEngine
from .engines.param_enum import ParamEnumEngine
from .engines.secret_replay import SecretReplayEngine
from .results import EngineResult
from .tasks import STATE_COMPLETED, task_identity

#: Trigger → avtomatik davam hərəkətləri.
TRIGGERS: dict[str, list[str]] = {
    "subdomain": ["live_check", "fingerprint", "js_analysis"],
    "js_file": ["extract_endpoints", "extract_secrets", "test_secret_endpoints",
                "secret_replay"],
    "param": ["hidden_param_detect", "param_fuzz"],
    "openapi": ["scope_validate", "schemathesis_fuzz"],
    "interesting_endpoint": ["targeted_fuzz", "sqli_suggestive"],
    "cve": ["confirm_template", "poc"],
    "blocked": ["bypass_matrix"],
    "nuclei": ["capture_evidence", "boost_confidence"],
    # --- Faza 1.5: yeni offensive zəncir tetikleyiciləri ---
    "sqli_signal": ["sqli_probe"],
    "xss_signal": ["xss_probe"],
    "ssti_signal": ["ssti_probe"],
    "ssrf_signal": ["ssrf_probe"],
    "jwt": ["jwt_probe"],
    "git_exposed": ["source_harvest"],
    "vuln_js_lib": ["library_cve_check"],
}

#: Hərəkətlər → icra anatomiyası: "local" (bu modul icra edir) /
#: "delegated" (Conductor-un artıq planlaşdırdığı mərhələ).
ACTION_EXEC = {
    "live_check": "delegated", "fingerprint": "delegated",
    "js_analysis": "delegated", "extract_endpoints": "delegated",
    "extract_secrets": "delegated", "test_secret_endpoints": "local",
    "secret_replay": "local",
    "hidden_param_detect": "local", "param_fuzz": "local",
    "scope_validate": "local", "schemathesis_fuzz": "local",
    "targeted_fuzz": "delegated", "sqli_suggestive": "delegated",
    "confirm_template": "local", "poc": "local",
    "bypass_matrix": "local", "capture_evidence": "delegated",
    "boost_confidence": "local",
    # Faza 1.1 mühərrikləri Conductor tərəfindən mərhələ kimi icra olunur.
    "sqli_probe": "delegated", "xss_probe": "delegated",
    "ssti_probe": "delegated", "ssrf_probe": "delegated",
    "jwt_probe": "delegated", "source_harvest": "delegated",
    "library_cve_check": "delegated",
}

#: Faza 5 (§9): siqnal → sübut gücü. Zəif siqnallar yalnız təsdiq
#: (confirm-only) işini planlaşdırır; güclü siqnallar hədəfli izləməyə icazə verir.
SIGNAL_STRENGTH = {
    "sqli_signal": STRENGTH_WEAK,
    "xss_signal": STRENGTH_WEAK,
    "ssti_signal": STRENGTH_WEAK,
    "ssrf_signal": STRENGTH_WEAK,
    "jwt": STRENGTH_STRONG,
    "git_exposed": STRENGTH_STRONG,
    "vuln_js_lib": STRENGTH_STRONG,
}

#: Delegasiya olunan davam hərəkəti → onu icra edən Conductor mərhələsi.
#: `None`/yoxdursa hərəkət dəstəklənmir və açıq şəkildə qeyd olunur.
ACTION_STAGE = {
    "live_check": "recon",
    "fingerprint": "fingerprint",
    "js_analysis": "js",
    "extract_endpoints": "js",
    "extract_secrets": "js",
    "scope_validate": "api_enum",
    "targeted_fuzz": "ferox",
    "sqli_suggestive": "sqli",
    "capture_evidence": "validation",
    "sqli_probe": "sqli",
    "xss_probe": "xss",
    "ssti_probe": "ssti",
    "ssrf_probe": "ssrf",
    "jwt_probe": "jwt",
    "source_harvest": "sourcecode",
    "library_cve_check": "library_cve",
}

#: Conductor mərhələ statusu → davam testinin REAL nəticəsi.
#: "skipped"/"partial" UĞUR kimi təqdim OLUNMUR (detection ≠ validation).
STAGE_OUTCOME = {
    "ok": OUTCOME_COMPLETED,
    "partial": OUTCOME_PARTIAL,
    "skipped": OUTCOME_INCONCLUSIVE,
    "failed": OUTCOME_FAILED,
    "cancelled": OUTCOME_CANCELLED,
}

#: Fingerprint/səhifə mətnində template engine işarələri → SSTI.
TEMPLATE_ENGINE_RE = re.compile(
    r"(?i)(jinja2?|twig|freemarker|velocity|handlebars|mustache|thymeleaf|"
    r"smarty|mako|erb|razor|pug|nunjucks|django templates?)")

#: URL-də SSRF-yə meyilli parametr adları.
SSRF_PARAM_RE = re.compile(
    r"(?i)[?&](url|uri|link|src|dest|redirect|next|target|callback|return|"
    r"image|fetch|proxy|webhook|feed|host|domain|path)=")

#: Ekspozisiya olunmuş Git metadata yolları.
GIT_RE = re.compile(r"(?i)/\.git(/|$)|/\.svn(/|$)|/\.hg(/|$)")


INTERESTING_RE = re.compile(
    r"(?i)(admin|api|internal|private|login|upload|debug|config|backup|"
    r"\.git|swagger|actuator|manage|dashboard|/v\d+/|graphql)")


@dataclass
class ChainEvent:
    kind: str
    detail: str
    actions: list[str] = field(default_factory=list)


@dataclass
class PendingFollowUp:
    """Planlaşdırılmış (hələ nəticəsi yazılmamış) davam testi.

    `identity` — `AdaptiveController.evaluate()` tərəfindən `TaskLedger`-də
    `queued` vəziyyətinə keçirilmiş tapşırıq kimliyi. İcra/qiymətləndirmə
    BİTDİKDƏN SONRA bu kimlik terminal vəziyyətə keçir — beləcə heç bir davam
    tapşırığı `queued` vəziyyətində ƏBƏDİ qalmır.
    """

    identity: str
    kind: str
    detail: str
    actions: tuple = ()


class FindingStore:
    """Tapıntı həyat dövrü üçün nazik sarğı (candidate→confirmed→reported)."""

    def __init__(self, scan_id: int | None = None):
        self.scan_id = scan_id

    def candidate(self, host_id, module, severity, title, **kw) -> int:
        kw.setdefault("status", "candidate")
        return db.insert_finding(host_id, module, severity, title, scan_id=self.scan_id, **kw)

    def confirm(self, finding_id: int, note: str = "", evidence: str = "",
                confidence: float = 0.85) -> None:
        db.set_finding_status(finding_id, "confirmed", confidence=confidence)
        if evidence:
            db.add_evidence(finding_id, "note",
                            f"{note}: {evidence}".strip(": "), self.scan_id)

    def reject(self, finding_id: int, note: str = "") -> None:
        db.set_finding_status(finding_id, "rejected")
        if note:
            db.add_evidence(finding_id, "note", note, self.scan_id)

    def report(self, finding_id: int) -> None:
        db.set_finding_status(finding_id, "reported")

    def attach(self, finding_id: int, kind: str, content: str) -> int:
        return db.add_evidence(finding_id, kind, content, self.scan_id)


class ChainPipeline:
    """Zəncirləmə orkestratoru."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.cfg_chain = ctx.cfg.chain
        self.auth = ctx.authorization
        self.store = FindingStore(ctx.scan_id)
        self.events: list[ChainEvent] = []
        self.executed: list[str] = []
        self.delegated: list[str] = []
        self.skipped: list[str] = []
        self._tasks = 0
        # Faza 3/5 (§7,§9): hadisə + tapşırıq idempotentliyi və adaptiv nəzarət.
        # `ctx` bunları vermirsə (köhnə testlər) zəncir ƏVVƏLKİ kimi işləyir.
        self.event_ledger = getattr(ctx, "event_ledger", None)
        self.task_ledger = getattr(ctx, "task_ledger", None)
        self.adaptive = getattr(ctx, "adaptive", None)
        self.metrics = getattr(ctx, "orchestration", None)
        self.duplicates = 0            # təkrarlanan hadisə (hadisə səviyyəsi)
        self.suppressed = 0            # təkrar/dövri tetikleme və ya dublikat tapşırıq
        self._noted: set[str] = set()
        #: F-01: planlaşdırılmış, nəticəsi hələ yazılmamış davam testləri.
        self._pending: list[PendingFollowUp] = []
        #: F-01: davam testi audit jurnalı (hər qərar səbəblə görünür).
        self.followups: list[dict] = []
        #: F-07: yeni dəlil əsasında `deferred`-dən `eligible`-a keçənlər.
        self.reconsidered: list[dict] = []

    @property
    def enabled(self) -> bool:
        return bool(self.cfg_chain.enabled)

    # ------------------------------------------------------------------ emit
    def emit(self, kind: str, detail: str = "") -> list[str]:
        """Trigger-i qeyd edir və icazəli davam hərəkətlərini qaytarır.

        Faza 3 (§7.4) nizamı: (1) hadisə səviyyəsində deduplikasiya,
        (2) dövr/təkrar-tetikleme nəzarəti, (3) RoE qapısı. Beləliklə eyni
        trigger-in min dəfə emissiyası eyni davam işini TƏKRAR planlaşdırmır.
        """
        event_id = ""
        if self.event_ledger is not None:
            decision = self.event_ledger.accept(kind, detail)
            if not decision.accept:
                self.duplicates += 1
                self._sync_chain_metrics()
                return []
            event_id = decision.identity
        planned = list(TRIGGERS.get(kind, []))
        allowed: list[str] = []
        for action in planned:
            if self.event_ledger is not None:
                g = self.event_ledger.guard(source=kind, destination=action,
                                            identity=event_id)
                if not g.accept:
                    self.suppressed += 1
                    key = f"{kind}:{action}"
                    if key not in self._noted:      # audit üçün yalnız BİR dəfə
                        self._noted.add(key)
                        self.skipped.append(f"{key} ({g.reason})")
                    continue
            gate = self._gate(action)
            if gate is None:
                allowed.append(action)
            else:
                self.skipped.append(f"{kind}:{action} ({gate})")
        ev = ChainEvent(kind=kind, detail=detail, actions=allowed)
        self.events.append(ev)
        if allowed:
            print(f"   [⛓] zəncir: {kind} → {', '.join(allowed)}")
        self._evaluate_signal(kind, detail, allowed)
        self._sync_chain_metrics()
        return allowed

    def _gate(self, action: str) -> str | None:
        """Hərəkətin icazəsiz olduğu səbəbi (yoxsa None)."""
        if action in ("param_fuzz", "schemathesis_fuzz", "test_secret_endpoints"):
            if not self.auth.allows("active_fuzz"):
                return "aktiv fuzz qadağandır"
        if action in ("secret_replay", "test_secret_endpoints"):
            if not self.auth.allows("secret_replay"):
                return "secret replay qadağandır"
        if action in ("bypass_matrix",):
            if not self.auth.allows("bypass"):
                return "bypass qadağandır"
        if action in ("confirm_template", "poc"):
            if not self.auth.allows("cve_poc"):
                return "CVE PoC qadağandır"
        return None

    def _budget_ok(self) -> bool:
        return self._tasks < self.cfg_chain.max_tasks

    # ------------------------------------------------- idempotentlik / siqnal
    def _begin(self, test_type: str, engine: str, endpoint: str = "") -> str | None:
        """Lokal zəncir addımı üçün idempotentlik qərarı.

        Qaytarır: kimlik sətri (icra et) və ya `None` (artıq edilib → atla).
        `task_ledger` yoxdursa `""` qaytarır — yəni qapı YOXDUR (köhnə davranış).
        """
        if self.task_ledger is None:
            return ""
        identity = task_identity(self.store.scan_id, engine,
                                 endpoint or test_type, test_type=test_type)
        decision = self.task_ledger.consider(
            identity, engine=engine, endpoint=endpoint or test_type,
            test_type=test_type)
        if not decision.create:
            self.suppressed += 1
            self._sync_chain_metrics()
            return None
        return identity

    def _done(self, identity: str) -> None:
        if identity and self.task_ledger is not None:
            self.task_ledger.mark(identity, STATE_COMPLETED)

    def _evaluate_signal(self, kind: str, detail: str,
                         allowed: list[str]) -> None:
        """Siqnalı adaptiv nəzarətçiyə ötürür və davam qərarını QORUYUR.

        F-01: `evaluate()` qaytardığı `FollowUp` ARTIK ATILMIR. `proceed=True`
        olduqda davam testi növbəyə alınır və `run()` sonunda REAL icra
        nəticəsi ilə terminal vəziyyətə keçirilir. `proceed=False` halında
        `evaluate()` özü səbəbi (`skipped_duplicate`/`skipped_no_signal`)
        statistikada qeyd edir — burada heç nə planlaşdırılmır.
        """
        strength = SIGNAL_STRENGTH.get(kind)
        if strength is None or self.adaptive is None:
            return
        try:
            endpoint = urlintel.endpoint_identity(detail) or detail
        except Exception:  # noqa: BLE001 - normalizasiya uğursuz olsa da davam et
            endpoint = detail
        identity = task_identity(self.store.scan_id, "chain", endpoint,
                                 test_type=kind)
        fu: FollowUp = self.adaptive.evaluate(
            Signal(kind=kind, strength=strength, detail=detail),
            identity=identity, actions=tuple(allowed))
        if not fu.proceed:
            return
        # Dublikat qarşısı: eyni kimlik üçün YALNIZ BİR dəfə növbəyə alınır
        # (`evaluate` artıq `TaskLedger` ilə təkrar-tapşırığı rədd edir, bu isə
        # ikinci müdafiə qatıdır — eyni siqnal selində belə).
        if any(p.identity == fu.identity for p in self._pending):
            return
        self._pending.append(PendingFollowUp(
            identity=fu.identity, kind=kind, detail=detail,
            actions=tuple(fu.actions)))

    # ------------------------------------------------------ davam testi icrası
    def _stage_status(self, stage: str) -> str | None:
        """Conductor mərhələsinin REAL statusu (yoxdursa `None`)."""
        statuses = getattr(self.ctx, "stage_status", None)
        if not statuses:
            return None
        return statuses.get(stage)

    def _followup_outcome(self, actions: tuple) -> tuple[str | None, str]:
        """Davam hərəkətləri üçün REAL nəticə və səbəb müəyyən edir.

        Qaytarır `(none_ola_bilər, səbəb)`. Heç bir hərəkət dəstəklənmirsə
        `(None, səbəb)` → çağıran `record_unsupported` istifadə edir.
        """
        unsupported: list[str] = []
        for action in actions:
            exec_kind = ACTION_EXEC.get(action)
            if exec_kind == "local":
                # Lokal hərəkət bu pipeline daxilində REAL icra olunub?
                if action in self.executed:
                    return OUTCOME_COMPLETED, f"local:{action}:icra olundu"
                unsupported.append(f"{action} (lokal icra olunmadı)")
                continue
            if exec_kind == "delegated":
                stage = ACTION_STAGE.get(action)
                status = self._stage_status(stage) if stage else None
                if status is None:
                    unsupported.append(f"{action} (mərhələ icra olunmadı)")
                    continue
                outcome = STAGE_OUTCOME.get(status)
                if outcome is None:
                    unsupported.append(f"{action} (naməlum status {status})")
                    continue
                return outcome, f"delegated:{action}:{stage}:{status}"
            unsupported.append(f"{action} (dəstəklənmir)")
        return None, "; ".join(unsupported) or "davam hərəkəti yoxdur"

    async def _dispatch_followups(self) -> None:
        """Planlaşdırılmış davam testlərini KONTROLLU icra ilə yekunlaşdırır.

        Heç bir davam tapşırığı `queued` vəziyyətində saxlanılmır: hər biri ya
        REAL icra nəticəsi ilə (`record_outcome`), ya da AÇIQ səbəblə
        (`record_unsupported`) terminal vəziyyətə keçir. Bu, MÖVCUD kontrollu
        icra yolundan (Conductor mərhələləri / lokal addımlar) istifadə edir —
        paralel icra mexanizmi YARADILMIR və əlavə HTTP trafiki yaradılmır.
        """
        for pending in list(self._pending):
            await self._dispatch_one(pending)
        self._pending.clear()

    async def _dispatch_one(self, pending: PendingFollowUp) -> None:
        if self.adaptive is None:
            return
        outcome, reason = self._followup_outcome(pending.actions)
        if outcome is None:
            self.adaptive.record_unsupported(pending.identity, reason)
        else:
            self.adaptive.record_outcome(pending.identity, outcome, reason)
        self.followups.append({
            "identity": pending.identity,
            "kind": pending.kind,
            "detail": pending.detail,
            "actions": list(pending.actions),
            "outcome": outcome or "unsupported",
            "reason": reason,
        })

    def _sync_chain_metrics(self) -> None:
        if self.metrics is None:
            return
        if self.event_ledger is not None:
            self.metrics.record_chain_stats(self.event_ledger.snapshot())

    # ------------------------------------------------------------- discovery
    def _discover_triggers(self) -> None:
        """DB-dəki vəziyyətdən trigger-ləri çıxarır (dirty-data-first)."""
        conn = db.get_db()
        hosts = conn.execute(
            "SELECT subdomain FROM hosts WHERE status_code IS NOT NULL "
            "AND (halted IS NULL OR halted=0) LIMIT 200").fetchall()
        for h in hosts:
            self.emit("subdomain", h["subdomain"])

        js = conn.execute(
            "SELECT url FROM urls WHERE is_js=1 LIMIT 100").fetchall()
        for r in js:
            self.emit("js_file", r["url"])

        openapi = conn.execute(
            "SELECT url FROM urls WHERE url LIKE '%openapi%' OR "
            "url LIKE '%swagger%' OR url LIKE '%api-docs%' LIMIT 50").fetchall()
        for r in openapi:
            self.emit("openapi", r["url"])

        # Faza 3.4: parametrli URL-lər → gizli parametr aşkarlanması + fuzz.
        params = conn.execute(
            "SELECT DISTINCT u.url FROM urls u JOIN hosts h ON h.id=u.host_id "
            "WHERE u.is_js=0 AND u.url NOT LIKE '%##%' AND h.scan_id=? "
            "AND u.source IN ('katana','gau','ffuf','ferox','api-enum',"
            "'kiterunner') LIMIT 50",
            (db.effective_scan_id(self.store.scan_id),)).fetchall()
        if params:
            self.emit("param", f"{len(params)} parametrli URL")

        interesting = conn.execute("SELECT url FROM urls LIMIT 800").fetchall()
        for r in interesting:
            if INTERESTING_RE.search(r["url"]):
                self.emit("interesting_endpoint", r["url"])

        cves = conn.execute("SELECT cve_id FROM cve_matches LIMIT 100").fetchall()
        for r in cves:
            self.emit("cve", r["cve_id"])

        policy = getattr(self.ctx.guardian, "policy", None)
        for ev in (getattr(policy, "block_events", []) if policy else []):
            self.emit("blocked", f"{ev.host} HTTP {ev.status}")

    def _discover_offensive_triggers(self) -> None:
        """Faza 1.5: offensive zəncir tetikleyicilərini DB-dən çıxarır.

        Bu, MÜƏYYƏN siqnalları (template engine, SSRF parametri, JWT, .git
        ekspozisiyası, köhnə JS kitabxanası) yeni mühərriklərlə əlaqələndirir.
        Heç bir siqnal uydurulmur — yalnız bazada REAL olan sətirlər oxunur.
        """
        conn = db.get_db()
        sid = db.effective_scan_id(self.store.scan_id)

        for row in conn.execute(
                "SELECT h.subdomain, h.tech_raw, h.title FROM hosts h "
                "WHERE h.scan_id=? AND h.tech_raw IS NOT NULL LIMIT 200",
                (sid,)).fetchall():
            blob = f"{row['tech_raw'] or ''} {row['title'] or ''}"
            if TEMPLATE_ENGINE_RE.search(blob):
                self.emit("ssti_signal", row["subdomain"])

        for row in conn.execute(
                "SELECT u.url FROM urls u JOIN hosts h ON h.id=u.host_id "
                "WHERE h.scan_id=? AND u.url LIKE '%?%=%' LIMIT 400",
                (sid,)).fetchall():
            url = row["url"]
            if SSRF_PARAM_RE.search(url):
                self.emit("ssrf_signal", url)
            if GIT_RE.search(url):
                self.emit("git_exposed", url)
            if "=" in url:
                # Parametrli endpoint → SQLi/XSS namizədi (marker təsdiqi
                # sonra müvafiq mühərrikdə baş verir).
                self.emit("sqli_signal", url)
                self.emit("xss_signal", url)

        for row in conn.execute(
                "SELECT js_url, kind FROM secrets WHERE kind LIKE '%JWT%' "
                "LIMIT 50").fetchall():
            self.emit("jwt", row["js_url"] or "")

        for row in conn.execute(
                "SELECT c.cve_id, h.subdomain FROM cve_matches c "
                "JOIN hosts h ON h.id=c.host_id WHERE h.scan_id=? LIMIT 100",
                (sid,)).fetchall():
            self.emit("vuln_js_lib", f"{row['subdomain']}:{row['cve_id']}")

    # ------------------------------------------------------------------- run
    def _boost_nuclei_confidence(self) -> int:
        """Nuclei medium+ kandidatları üçün sübut əlavə edir, confidence artırır.

        Uydurma yoxdur: yalnız artıq mövcud nuclei siqnalı sübut kimi
        bağlanır və status `candidate` olaraq qalır (təsdiq tələb olunur).
        """
        rows = db.get_db().execute(
            "SELECT f.id, f.severity, f.confidence, f.template FROM findings f "
            "JOIN hosts h ON h.id=f.host_id "
            "WHERE f.module='nuclei' AND f.status='candidate' AND h.scan_id=? "
            "AND f.severity IN ('medium','high','critical') LIMIT 200",
            (db.effective_scan_id(self.store.scan_id),)).fetchall()
        for r in rows:
            db.add_evidence(
                r["id"], "note",
                f"nuclei template '{r['template'] or '?'}' ({r['severity']}) "
                f"— avtomatik zəncir sübutu", self.store.scan_id)
            db.set_finding_status(
                r["id"], "candidate",
                confidence=max(float(r["confidence"] or 0.0), 0.75))
        return len(rows)

    async def _run_param_steps(self, res: EngineResult) -> None:
        """Faza 3.4: gizli parametr aşkarlanması + parametr fuzzinqi.

        `param` tetikleyicisi ilə REAL icra olunur (əvvəllər "delegated" idi).
        RoE qapısı `emit()` zamanı tətbiq olunur: `param_fuzz` aktiv fuzz
        qadağası ilə bağlanır, `hidden_param_detect` isə yalnız oxuma (GET)
        olduğu üçün açıqdır. Engine özü bütün scope/rate qapılarından keçir.
        """
        allowed = {a for e in self.events if e.kind == "param"
                   for a in e.actions}
        if not ({"hidden_param_detect", "param_fuzz"} & allowed):
            return
        if not self._budget_ok():
            return
        ident = self._begin("hidden_param_detect", "param")
        if ident is None:
            return
        self._tasks += 1
        sub = await ParamEnumEngine(self.ctx).run()
        res.findings += sub.findings
        res.warnings += sub.warnings
        for action in ("hidden_param_detect", "param_fuzz"):
            if action in allowed:
                self.executed.append(action)
        self._done(ident)

    async def _run_openapi_steps(self, res: EngineResult) -> None:
        """Faza 3.4: OpenAPI sxemi üzərində Schemathesis (GET-only) icrası."""
        allowed = {a for e in self.events if e.kind == "openapi"
                   for a in e.actions}
        if "schemathesis_fuzz" not in allowed:
            return
        if not self._budget_ok():
            return
        ident = self._begin("schemathesis_fuzz", "api")
        if ident is None:
            return
        self._tasks += 1
        sub = await APIFuzzEngine(self.ctx).run()
        res.findings += sub.findings
        res.warnings += sub.warnings
        self.executed.append("schemathesis_fuzz")
        self._done(ident)

    # ------------------------------------------------------ F-07: yenidən baxış
    def _discover_param_evidence(self) -> dict:
        """Parametr kəşfinin verdiyi YENİ dəlili endpoint kimliyinə görə toplayır.

        `param_enum` tapdığı gizli parametrləri `<url>##params:a,b` markeri ilə
        saxlayır. Bu metod markeri endpoint kimliyinə bağlayır — beləcə əvvəl
        parametrsiz olduğu üçün `deferred` sayılan endpoint YENİ dəlillə
        yenidən qiymətləndirilə bilər. Heç bir yeni URL uydurulmur.
        """
        conn = db.get_db()
        sid = db.effective_scan_id(self.store.scan_id)
        evidence: dict[str, set] = {}
        rows = conn.execute(
            "SELECT url FROM urls WHERE url LIKE '%##params:%' AND scan_id=?",
            (sid,)).fetchall()
        for r in rows:
            url = r["url"] or ""
            base, sep, params = url.partition("##params:")
            if not sep:
                continue
            identity = urlintel.endpoint_identity(base)
            if not identity:
                continue
            evidence.setdefault(identity, set()).update(
                p.strip() for p in params.split(",") if p.strip())
        return {k: tuple(sorted(v)) for k, v in evidence.items()}

    def _reconsider_deferred(self) -> None:
        """F-07: parametr kəşfindən SONRA deferred endpoint-ləri yenidən baxır.

        Dəlil əsaslı və bounded-dır: yalnız dəlili DƏYİŞƏN endpoint-lər
        yenidən qiymətləndirilir, dəyişməyənlər təkrar emal olunmur və sonsuz
        dövr qurulmur. Heç bir əlavə HTTP trafiki yaradılmır — bu, sadəcə
        uyğunluq qərarının yenilənməsidir (icra mövcud yoldan gedir).
        """
        evidence = self._discover_param_evidence()
        if not evidence:
            return
        intel = getattr(self.ctx, "_urlintel", None) or urlintel.get_url_intelligence(self.ctx)
        promoted: list[dict] = []
        for engine in urlintel.INJECT_ENGINES:
            promoted += intel.reconsider(engine, evidence)
        if promoted:
            self.reconsidered = promoted
            print(f"   [♻] {len(promoted)} deferred endpoint yeni parametr "
                  "dəlili ilə yenidən uyğun sayıldı")

    async def run(self) -> EngineResult:
        res = EngineResult(stage="chain")
        if not self.enabled:
            return res.skip("zəncirləmə konfiqurasiya ilə söndürülüb")
        if self.auth is None:
            res.fail("authorization konteksti yoxdur")
            return res

        print("[═══ CHAIN PIPELINE ═══] trigger-lər toplanır")
        self._discover_triggers()
        self._discover_offensive_triggers()

        # --- local hərəkətlər (birbaşa icra) ---
        if self._budget_ok() and self.auth.allows("bypass"):
            ident = self._begin("bypass_matrix", "bypass")
            if ident is not None:
                interesting_urls = [e.detail for e in self.events
                                    if e.kind == "interesting_endpoint"][:25]
                self._tasks += 1
                sub = await BypassEngine(self.ctx).run(interesting_urls or None)
                res.findings += sub.findings
                res.warnings += sub.warnings
                self.executed.append("bypass_matrix")
                self._done(ident)

        if self._budget_ok() and self.auth.allows("cve_poc"):
            ident = self._begin("confirm_template", "confirm")
            if ident is not None:
                self._tasks += 1
                conf = await ConfirmEngine(self.ctx).run()
                res.findings += conf.findings
                self.executed.append("confirm_template")
                self._done(ident)

        # Faza 3.2: şifrəli secret replay (RoE + vault qapısı ilə).
        if self._budget_ok() and self.auth.allows("secret_replay"):
            ident = self._begin("secret_replay", "secret_replay")
            if ident is not None:
                self._tasks += 1
                rep = await SecretReplayEngine(self.ctx).run()
                res.findings += rep.findings
                res.warnings += rep.warnings
                self.executed.append("secret_replay")
                self._done(ident)

        if self._budget_ok():
            boosted = self._boost_nuclei_confidence()
            if boosted:
                res.warnings.append(
                    f"nuclei: {boosted} medium+ tapıntıya sübut + confidence")
                self.executed.append("boost_confidence")

        # Faza 3.4: əvvəllər "delegated" olan addımlar indi REAL icra olunur.
        await self._run_param_steps(res)
        await self._run_openapi_steps(res)
        # F-07: parametr kəşfinin verdiyi YENİ dəlil ilə deferred endpoint-ləri
        # yenidən qiymətləndir (dəlil əsaslı, bounded, dublikatsız).
        self._reconsider_deferred()

        for ev in self.events:
            for action in ev.actions:
                if ACTION_EXEC.get(action) == "delegated":
                    self.delegated.append(action)

        # F-01: davam testlərini REAL nəticə ilə yekunlaşdır (heç biri `queued`
        # vəziyyətində qalmır). Bu, lokal addımlar BİTDİKDƏN sonra çağırılır ki
        # `self.executed` faktiki vəziyyəti əks etdirsin.
        await self._dispatch_followups()

        self._sync_chain_metrics()
        res.data = {
            "events": len(self.events),
            "executed": sorted(set(self.executed)),
            "delegated": sorted(set(self.delegated)),
            "skipped": self.skipped,
            "duplicates": self.duplicates,
            "suppressed": self.suppressed,
            "followups": self.followups,
            "reconsidered": self.reconsidered,
        }
        print(f"   [⛓] zəncir: {len(self.events)} trigger · "
              f"icra: {len(set(self.executed))} · "
              f"delegasiya: {len(set(self.delegated))} · "
              f"atlanan: {len(self.skipped)} · "
              f"dublikat: {self.duplicates}")
        return res

    def audit(self) -> dict:
        return {
            "events": [{"kind": e.kind, "detail": e.detail,
                        "actions": e.actions} for e in self.events],
            "executed": sorted(set(self.executed)),
            "delegated": sorted(set(self.delegated)),
            "skipped": self.skipped,
            "duplicates": self.duplicates,
            "suppressed": self.suppressed,
            "followups": self.followups,
            "reconsidered": self.reconsidered,
        }
