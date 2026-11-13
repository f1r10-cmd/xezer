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
from .engines.api_fuzz import APIFuzzEngine
from .engines.bypass import BypassEngine
from .engines.confirm import ConfirmEngine
from .engines.param_enum import ParamEnumEngine
from .engines.secret_replay import SecretReplayEngine
from .results import EngineResult

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
        self._tasks += 1
        sub = await ParamEnumEngine(self.ctx).run()
        res.findings += sub.findings
        res.warnings += sub.warnings
        for action in ("hidden_param_detect", "param_fuzz"):
            if action in allowed:
                self.executed.append(action)

    async def _run_openapi_steps(self, res: EngineResult) -> None:
        """Faza 3.4: OpenAPI sxemi üzərində Schemathesis (GET-only) icrası."""
        allowed = {a for e in self.events if e.kind == "openapi"
                   for a in e.actions}
        if "schemathesis_fuzz" not in allowed:
            return
        if not self._budget_ok():
            return
        self._tasks += 1
        sub = await APIFuzzEngine(self.ctx).run()
        res.findings += sub.findings
        res.warnings += sub.warnings
        self.executed.append("schemathesis_fuzz")

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

        # Faza 3.2: şifrəli secret replay (RoE + vault qapısı ilə).
        if self._budget_ok() and self.auth.allows("secret_replay"):
            self._tasks += 1
            rep = await SecretReplayEngine(self.ctx).run()
            res.findings += rep.findings
            res.warnings += rep.warnings
            self.executed.append("secret_replay")

        if self._budget_ok():
            boosted = self._boost_nuclei_confidence()
            if boosted:
                res.warnings.append(
                    f"nuclei: {boosted} medium+ tapıntıya sübut + confidence")
                self.executed.append("boost_confidence")

        # Faza 3.4: əvvəllər "delegated" olan addımlar indi REAL icra olunur.
        await self._run_param_steps(res)
        await self._run_openapi_steps(res)

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
