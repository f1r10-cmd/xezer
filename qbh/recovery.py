"""Faza 2 (§4.2/§4.3) — davamlı vəziyyət adapteri və çökmədən bərpa.

Bu modul üç əsas işi görür:

1. **`DurableStore`** — `TaskLedger`, `EventLedger` və `AdaptiveController`
   üçün SQLite-ə YAZAN nazik adapter. Heç bir qərar vermir; yalnız in-memory
   vəziyyəti `task_state` / `event_state` / `followup_queue` cədvəllərinə
   köçürür (bərpa üçün). Yeganə həqiqət mənbəyi dəftərlərin ÖZÜ olaraq qalır.
2. **`build_resume_plan`** — çökmüş (`running`) skanın davamlı vəziyyətini
   oxuyur, scope/avtorizasiya yoxlamasını YENİDƏN tətbiq edir və nəyin
   təkrar planlaşdırılacağını / nəyin TOXUNULMAYACAĞINI müəyyən edir.
3. **`pending_scans` / `resume_candidates`** — bərpa namizədlərini tapır.

Prinsiplər (§4.3):
  * `completed`/`skipped` tapşırıqlar TƏKRAR İCRA OLUNMUR (kimlik dedup-ı).
  * `running` (yarımçıq) tapşırıqlar yenidən növbəyə alınır.
  * `attempts`/`last_error` tarixçəsi QORUNUR.
  * Bərpa scope yoxlamasını KEÇMİR — hədəfi artıq icazəli olmayan tapşırıq
    AÇIQ `skipped` kimi işarələnir (səbəblə), icra edilmir.
  * Skan izolyasiyası QORUNUR — hər sorğu `scan_id` ilə süzülür.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import db
from .tasks import (
    STATE_CANCELLED,
    STATE_SKIPPED,
    TaskRecord,
    TERMINAL_STATES,
)

_log = logging.getLogger("qbh.recovery")

#: Bərpadan sonra TƏKRAR növbəyə alına bilən hallar.
REQUEUE_STATES = frozenset({STATE_CANCELLED}) | {
    "queued", "partial", "failed", "timed_out"}


# --------------------------------------------------------------------------- #
# Davamlı saxlama adapteri
# --------------------------------------------------------------------------- #
class DurableStore:
    """`scan_id`-ə bağlı davamlı saxlama adapteri.

    Bütün metodlar `db`-yə yazır; xəta halında İSTİSNA qaldırmır (davamlı
    saxlama uğursuz olsa belə skan DAVAM EDİR) — bunun əvəzinə xəbərdarlıq
    loqlaşdırılır. Beləliklə saxlama heç vaxt əsas işi BLOKLAMIR.
    """

    def __init__(self, scan_id: int):
        self.scan_id = int(scan_id)
        #: Yazılmış kimliklər (audit/bərpa statistikası üçün).
        self.persisted_tasks: set[str] = set()
        self.persisted_events: set[str] = set()
        self.persisted_followups: int = 0

    # ------------------------------------------------------------------ tasks
    def persist_task(self, rec: TaskRecord, *, last_error: str = "",
                     result_data=None) -> None:
        db.upsert_task_state(
            rec.identity, self.scan_id, identity_hash=rec.identity,
            status=rec.state, engine=rec.engine or "", endpoint=rec.endpoint or "",
            method=rec.method or "GET", params=rec.param or "",
            attempts=int(rec.attempts), last_error=last_error or "",
            result_data=result_data, created_at=rec.first_seen)
        self.persisted_tasks.add(rec.identity)

    # ----------------------------------------------------------------- events
    def persist_event(self, event_id: str, *, event_type: str = "",
                      count: int = 1, detail: str = "") -> None:
        payload = json.dumps({"count": int(count), "detail": detail or ""},
                             sort_keys=True)
        db.upsert_event_state(event_id, self.scan_id, event_type=event_type or "",
                              payload=payload)
        self.persisted_events.add(event_id)

    # -------------------------------------------------------------- followups
    def persist_followup(self, identity: str, action: str, *,
                         status: str = "pending",
                         trigger_finding_id: int | None = None) -> int:
        fid = db.insert_followup(self.scan_id, action or identity,
                                 trigger_finding_id=trigger_finding_id,
                                 prerequisite_hash=identity, status=status)
        self.persisted_followups += 1
        return fid

    def mark_followup(self, identity: str, status: str) -> int:
        return db.set_followup_status(self.scan_id, identity, status)


# --------------------------------------------------------------------------- #
# Davamlı vəziyyətin oxunması
# --------------------------------------------------------------------------- #
def _row_get(row, key, default=None):
    try:
        value = row[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if value is None else value


def task_records(scan_id: int) -> list[TaskRecord]:
    """`scan_id` üçün davamlı tapşırıq sətirlərini `TaskRecord`-a çevirir.

    `TaskRecord`-un `test_type`/`profile` sahələri DB-də saxlanmır (sxem
    spesifikasiyasına uyğun) — kimlik (`identity`) artıq onları ehtiva edir.
    """
    out: list[TaskRecord] = []
    for r in db.load_task_state(scan_id):
        out.append(TaskRecord(
            identity=_row_get(r, "task_id", ""),
            engine=_row_get(r, "engine", "") or "",
            endpoint=_row_get(r, "endpoint", "") or "",
            method=_row_get(r, "method", "") or "GET",
            param=_row_get(r, "params", "") or "",
            state=_row_get(r, "status", "queued") or "queued",
            attempts=int(_row_get(r, "attempts", 0) or 0),
            reason=_row_get(r, "last_error", "") or "",
            first_seen=_row_get(r, "created_at", "") or "",
            updated_at=_row_get(r, "updated_at", "") or "",
            result_data=_result_data(_row_get(r, "result_data", "")),
        ))
    return out


def _result_data(raw) -> dict:
    """`task_state.result_data` sətrini dict-ə çevirir (xətalı/boş → `{}`)."""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def event_records(scan_id: int) -> list[tuple]:
    """`(event_id, event_type, count)` üçlükləri (`EventLedger.restore` üçün)."""
    out: list[tuple] = []
    for r in db.load_event_state(scan_id):
        payload = _row_get(r, "payload", "")
        count = 1
        if payload:
            try:
                count = int(json.loads(payload).get("count", 1))
            except (TypeError, ValueError, AttributeError):
                count = 1
        out.append((_row_get(r, "event_id", ""),
                    _row_get(r, "event_type", "") or "", count))
    return out


def followup_records(scan_id: int, *, status: str = "pending"):
    """`followup_queue` sətirləri (default: yalnız gözləyənlər)."""
    return db.load_followups(scan_id, status=status)


# --------------------------------------------------------------------------- #
# Bərpa planı
# --------------------------------------------------------------------------- #
def _endpoint_host(endpoint: str) -> str:
    """Endpoint sətrindən host çıxarır (URL deyilsə boş sətir)."""
    if not endpoint or "://" not in endpoint:
        return ""
    try:
        return urlsplit(endpoint).hostname or ""
    except (ValueError, TypeError):
        return ""


@dataclass
class ResumePlan:
    """Çökmüş skanın bərpa planı (nə təkrar icra olunacaq, nə yox)."""

    scan_id: int
    program: str = ""
    mode: str = ""
    tasks: list[TaskRecord] = field(default_factory=list)
    events: list[tuple] = field(default_factory=list)
    followups: list = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    counts: dict = field(default_factory=dict)

    @property
    def requeue(self) -> list[TaskRecord]:
        """Yenidən növbəyə alınacaq tapşırıqlar (terminal olmayanlar)."""
        return [t for t in self.tasks if t.state not in TERMINAL_STATES]

    @property
    def terminal(self) -> list[TaskRecord]:
        """Artıq bitmiş → TƏKRAR İCRA OLUNMAYACAQ tapşırıqlar."""
        return [t for t in self.tasks if t.state in TERMINAL_STATES]

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "program": self.program,
            "mode": self.mode,
            "tasks": len(self.tasks),
            "requeue": len(self.requeue),
            "terminal": len(self.terminal),
            "events": len(self.events),
            "pending_followups": len(self.followups),
            "out_of_scope": len(self.out_of_scope),
            "counts": dict(self.counts),
        }


def build_resume_plan(scan_id: int, *, program: str = "",
                      mode: str = "", authorize=None) -> ResumePlan:
    """Davamlı vəziyyətdən bərpa planı qurur və scope-u YENİDƏN yoxlayır.

    `authorize` — `(host) -> str` (uğur) və ya `ScopeError` (icazəsiz). `None`
    verilərsə scope yenidən yoxlanmır (yalnız test/audit üçün). Scope-dan
    kənar hədəfi olan tapşırıq AÇIQ `skipped` edilir → icra OLUNMUR.
    """
    plan = ResumePlan(scan_id=int(scan_id), program=program, mode=mode)
    plan.tasks = task_records(scan_id)
    plan.events = event_records(scan_id)
    plan.followups = list(followup_records(scan_id, status="pending"))

    counts = {"queued": 0, "running": 0, "completed": 0, "skipped": 0,
              "requeued": 0, "terminal": 0, "out_of_scope": 0}
    for rec in plan.tasks:
        counts[rec.state] = counts.get(rec.state, 0) + 1

    if authorize is not None:
        for rec in plan.tasks:
            host = _endpoint_host(rec.endpoint)
            if not host:
                continue
            try:
                authorize(host)
            except Exception as exc:  # noqa: BLE001 - ScopeError və s.
                # Scope-dan kənar → TƏKRAR İCRA OLUNMUR (fail-closed).
                rec.state = STATE_SKIPPED
                rec.reason = f"bərpa: hədəf artıq icazəli deyil ({host}): {exc}"
                plan.out_of_scope.append(rec.identity)
                counts["out_of_scope"] += 1
                counts["skipped"] = counts.get("skipped", 0) + 1

    plan.counts = counts
    return plan


def pending_scans():
    """Bərpa namizədi olan (çökmüş `running`) skanlar — ən yenidən köhnəyə."""
    return db.running_scans()


def latest_pending_scan():
    """Ən son yarımçıq skan və ya `None`."""
    return db.latest_running_scan()


def resume_mode(scan_id: int) -> str:
    """`scan_id`-ə uyğun yenidən işlədiləcək rejimi qaytarır.

    Skan rejimi davamlı `scans` cədvəlindən oxunur (CLI arqumenti deyil) —
    bərpa MƏHZ yarımçıq işi davam etdirməlidir, yeni rejim seçməməlidir.
    """
    row = db.get_scan(int(scan_id))
    if row is None:
        return ""
    return row["mode"] or ""
