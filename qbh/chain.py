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

from . import db
from .engines.bypass import BypassEngine
from .engines.confirm import ConfirmEngine
from .results import EngineResult

#: Trigger → avtomatik davam hərəkətləri.
TRIGGERS: dict[str, list[str]] = {
    "subdomain": ["live_check", "fingerprint", "js_analysis"],
    "js_file": ["extract_endpoints", "extract_secrets", "test_secret_endpoints"],
    "param": ["hidden_param_detect", "param_fuzz"],
    "openapi": ["scope_validate", "schemathesis_fuzz"],
    "interesting_endpoint": ["targeted_fuzz", "sqli_suggestive"],
    "cve": ["confirm_template", "poc"],
    "blocked": ["bypass_matrix"],
    "nuclei": ["capture_evidence", "boost_confidence"],
}

#: Hərəkətlər → icra anatomiyası: "local" (bu modul icra edir) /
#: "delegated" (Conductor-un artıq planlaşdırdığı mərhələ).
ACTION_EXEC = {
    "live_check": "delegated", "fingerprint": "delegated",
    "js_analysis": "delegated", "extract_endpoints": "delegated",
    "extract_secrets": "delegated", "test_secret_endpoints": "local",
    "hidden_param_detect": "delegated", "param_fuzz": "delegated",
    "scope_validate": "local", "schemathesis_fuzz": "delegated",
    "targeted_fuzz": "delegated", "sqli_suggestive": "delegated",
    "confirm_template": "local", "poc": "local",
    "bypass_matrix": "local", "capture_evidence": "delegated",
    "boost_confidence": "local",
}

INTERESTING_RE = re.compile(
    r"(?i)(admin|api|internal|private|login|upload|debug|config|backup|"
    r"\.git|swagger|actuator|manage|dashboard|/v\d+/|graphql)")


@dataclass
class ChainEvent:
    kind: str
    detail: str
    actions: list[str] = field(default_factory=list)


class FindingStore:
    """Tapıntı həyat dövrü üçün nazik sarğı (candidate→confirmed→reported)."""

    def __init__(self, scan_id: int | None = None):
        self.scan_id = scan_id

    def candidate(self, host_id, module, severity, title, **kw) -> int:
        kw.setdefault("status", "candidate")
        return db.insert_finding(host_id, module, severity, title, **kw)

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

    @property
    def enabled(self) -> bool:
        return bool(self.cfg_chain.enabled)

    # ------------------------------------------------------------------ emit
    def emit(self, kind: str, detail: str = "") -> list[str]:
        """Trigger-i qeyd edir və icazəli davam hərəkətlərini qaytarır."""
        planned = list(TRIGGERS.get(kind, []))
        allowed: list[str] = []
        for action in planned:
            gate = self._gate(action)
            if gate is None:
                allowed.append(action)
            else:
                self.skipped.append(f"{kind}:{action} ({gate})")
        ev = ChainEvent(kind=kind, detail=detail, actions=allowed)
        self.events.append(ev)
        if allowed:
            print(f"   [⛓] zəncir: {kind} → {', '.join(allowed)}")
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

    # ------------------------------------------------------------------- run
    def _boost_nuclei_confidence(self) -> int:
        """Nuclei medium+ kandidatları üçün sübut əlavə edir, confidence artırır.

        Uydurma yoxdur: yalnız artıq mövcud nuclei siqnalı sübut kimi
        bağlanır və status `candidate` olaraq qalır (təsdiq tələb olunur).
        """
        rows = db.get_db().execute(
            "SELECT id, severity, confidence, template FROM findings "
            "WHERE module='nuclei' AND status='candidate' "
            "AND severity IN ('medium','high','critical') LIMIT 200").fetchall()
        for r in rows:
            db.add_evidence(
                r["id"], "note",
                f"nuclei template '{r['template'] or '?'}' ({r['severity']}) "
                f"— avtomatik zəncir sübutu", self.store.scan_id)
            db.set_finding_status(
                r["id"], "candidate",
                confidence=max(float(r["confidence"] or 0.0), 0.75))
        return len(rows)

    async def run(self) -> EngineResult:
        res = EngineResult(stage="chain")
        if not self.enabled:
            return res.skip("zəncirləmə konfiqurasiya ilə söndürülüb")
        if self.auth is None:
            res.fail("authorization konteksti yoxdur")
            return res

        print("[═══ CHAIN PIPELINE ═══] trigger-lər toplanır")
        self._discover_triggers()

        # --- local hərəkətlər (birbaşa icra) ---
        if self._budget_ok() and self.auth.allows("bypass"):
            interesting_urls = [e.detail for e in self.events
                                if e.kind == "interesting_endpoint"][:25]
            self._tasks += 1
            sub = await BypassEngine(self.ctx).run(interesting_urls or None)
            res.findings += sub.findings
            res.warnings += sub.warnings
            self.executed.append("bypass_matrix")

        if self._budget_ok() and self.auth.allows("cve_poc"):
            self._tasks += 1
            conf = await ConfirmEngine(self.ctx).run()
            res.findings += conf.findings
            self.executed.append("confirm_template")

        if self._budget_ok():
            boosted = self._boost_nuclei_confidence()
            if boosted:
                res.warnings.append(
                    f"nuclei: {boosted} medium+ tapıntıya sübut + confidence")
                self.executed.append("boost_confidence")

        for ev in self.events:
            for action in ev.actions:
                if ACTION_EXEC.get(action) == "delegated":
                    self.delegated.append(action)

        res.data = {
            "events": len(self.events),
            "executed": sorted(set(self.executed)),
            "delegated": sorted(set(self.delegated)),
            "skipped": self.skipped,
        }
        print(f"   [⛓] zəncir: {len(self.events)} trigger · "
              f"icra: {len(set(self.executed))} · "
              f"delegasiya: {len(set(self.delegated))} · "
              f"atlanan: {len(self.skipped)}")
        return res

    def audit(self) -> dict:
        return {
            "events": [{"kind": e.kind, "detail": e.detail,
                        "actions": e.actions} for e in self.events],
            "executed": sorted(set(self.executed)),
            "delegated": sorted(set(self.delegated)),
            "skipped": self.skipped,
        }
