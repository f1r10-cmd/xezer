"""Offensive mühərriklər üçün ortaq baza (Faza 1.1).

Bütün yeni offensive mühərriklər (SQLi, XSS, SSTI, SSRF, JWT, SourceCode)
eyni təhlükəsizlik kontraktına əməl edir:

  * Hədəf URL-lər YALNIZ cari `scan_id`-dən götürülür (Faza 0.1 izolyasiyası).
  * Hər hədəf ƏVVƏLCƏ `ctx.egress.authorize_process_targets()` (scope +
    DNS pinning) → sonra Guardian (blok/cooldown) yoxlamasından keçir.
  * Alət binary-si yoxdursa mühərrik HONEST şəkildə `skipped` qaytarır —
    "işlədi" iddiası verilmir.
  * `candidate → confirmed` keçidi YALNIZ sübutla (marker / OOB callback /
    data extraction) baş verir; əks halda tapıntı `candidate` qalır.
"""
from __future__ import annotations

import shutil

from .. import db, urlintel
from ..results import EngineResult
from ..scope import ScopeError


class OffensiveEngine:
    name = "offensive"
    tool = ""                       # aşkarlanacaq əsas binary
    max_targets = 20
    timeout = 300
    sources = ("katana", "gau", "ffuf", "ferox", "api-enum", "kiterunner")

    def __init__(self, ctx):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.guardian = ctx.guardian
        #: Son `candidate_urls` planı (uyğunluq qərarları, metrikalar üçün).
        self.last_plan = None

    @property
    def scan_id(self) -> int:
        return db.effective_scan_id(self.ctx.scan_id)

    # ------------------------------------------------------------- tooling
    def tool_present(self) -> bool:
        return bool(self.tool) and shutil.which(self.tool) is not None

    # ------------------------------------------------------------ targets
    def candidate_urls(self, *, only_params: bool = False,
                       limit: int | None = None,
                       engine: str | None = None) -> list:
        """Cari skanın kandidat URL-ləri (yalnız scope-daxili hostlardan).

        `engine` verildikdə URL Intelligence uyğunluq süzgəci tətbiq olunur:
        uyğun olmayan statik resurslar ATILIR (səbəblə qeyd olunur), naməlum
        endpoint-lər isə `deferred` kimi saxlanılır. Sətirlər həmişə
        prioritet sırasına salınır (ən mənalı endpoint əvvəl).
        """
        max_n = int(limit or self.max_targets)
        q = ("SELECT u.id, u.url, u.host_id, h.subdomain FROM urls u "
             "JOIN hosts h ON h.id=u.host_id "
             "WHERE h.scan_id=? AND u.is_js=0 "
             "AND u.url NOT LIKE '%##%' "
             "AND (h.halted IS NULL OR h.halted=0)")
        if only_params:
            q += " AND u.url LIKE '%?%=%'"
        q += " LIMIT ?"
        fetch_n = urlintel.fetch_limit(max_n, self.max_targets,
                                       filtering=bool(engine))
        rows = db.get_db().execute(q, (self.scan_id, fetch_n)).fetchall()
        if not rows:
            return []
        intel = urlintel.get_url_intelligence(self.ctx)
        selected, plan = intel.plan_rows(rows, engine=engine, limit=max_n)
        self.last_plan = plan
        if engine and self.ctx.orchestration is not None:
            self.ctx.orchestration.record_engine(
                engine, input_urls=plan.raw, eligible_urls=plan.eligible,
                skipped_urls=plan.excluded, deferred_urls=plan.deferred)
        return selected

    # ------------------------------------------------------------ gating
    async def gate(self, url: str, res: EngineResult, *,
                   host: str | None = None) -> bool:
        """Scope + egress + Guardian qapısı. `False` → hədəf atılmalıdır."""
        try:
            url = self.ctx.authorize_url(url)
        except ScopeError as exc:
            res.warn(f"scope xaricində hədəf rədd edildi: {exc}")
            return False
        tset = await self.ctx.egress.authorize_process_targets([url])
        if url not in tset.urls:
            res.warn(f"egress: {url} icazəli deyil — atlandı")
            return False
        if host and self.guardian and self.guardian.halted(host):
            res.warn(f"{host} blok cooldown-undadır — atlandı")
            return False
        if host and self.guardian:
            await self.guardian.acquire(host)
        return True

    # ------------------------------------------------------------ findings
    def record(self, host_id: int, severity: str, title: str, description: str,
               *, evidence: str = "", curl_repro: str = "", confidence: float = 0.5,
               status: str = "candidate", source: str = "",
               template: str = "") -> int:
        return db.insert_finding(
            host_id, self.name, severity, title, description,
            evidence=evidence, curl_repro=curl_repro, template=template,
            confidence=confidence, status=status, source=source or self.name,
            scan_id=self.ctx.scan_id)

    def confirm(self, finding_id: int, kind: str, content: str,
                confidence: float = 0.9) -> None:
        """Sübut əsaslı təsdiq: finding `confirmed` olur + sübut saxlanılır."""
        db.add_evidence(finding_id, kind, content, self.ctx.scan_id)
        db.set_finding_status(finding_id, "confirmed", confidence=confidence)
