"""Tapşırıq kimliyi, həyat dövrü və idempotentlik (Faza 3).

Məqsəd: eyni MƏNTİQİ işin (task) iki dəfə planlaşdırılmasının/icrasının
qarşısını almaq — L AKİN məşru, FƏRQLİ testləri BOĞMAMAQ.

Prinsiplər:
  * `task_identity` DETERMİNİSTİKDİR və yalnız işi həqiqətən fərqləndirən
    ölçüləri ehtiva edir: `scan_id`, mühərrik, normalizə olunmuş endpoint
    kimliyi, HTTP metodu, parametr kimliyi, test tipi, test profili/konfiq
    versiyası. Əlaqəsiz sahələr (vaxt, təsadüfi id) DAXİL EDİLMİR.
  * Həyat dövrü: `queued → running → completed|partial|failed|timed_out|
    cancelled|skipped` (mövcud `StageResult` status modeli ilə uyğundur).
  * Yalnız BOUNDED retry: `failed`/`timed_out`/`cancelled` hallarında
    `max_attempts`-dən çox olmayaraq təkrar icazə verilir.
  * Heç bir qərar SƏSSİZCƏ verilmir — hər biri səbəblə qeyd olunur.
  * Defolt olaraq BİR PROSES daxilində (skan) işləyir. Skan tək prosesdə
    icra olunduğu üçün bu kifayətdir (bax: `qbh/urlintel.py` audit qeydi) —
    davamlı (durable) saxlama tələb olunmur və DB miqrasiyası TƏLƏB EDİLMİR.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# Həyat dövrü
# --------------------------------------------------------------------------- #
STATE_QUEUED = "queued"
STATE_RUNNING = "running"
STATE_COMPLETED = "completed"
STATE_PARTIAL = "partial"
STATE_FAILED = "failed"
STATE_TIMED_OUT = "timed_out"
STATE_CANCELLED = "cancelled"
STATE_SKIPPED = "skipped"

LIFECYCLE = (STATE_QUEUED, STATE_RUNNING, STATE_COMPLETED, STATE_PARTIAL,
             STATE_FAILED, STATE_TIMED_OUT, STATE_CANCELLED, STATE_SKIPPED)

#: Yenidən icra YALNIZ bu hallardan sonra (bounded) mümkündür.
RETRYABLE_STATES = frozenset({STATE_PARTIAL, STATE_FAILED, STATE_TIMED_OUT,
                              STATE_CANCELLED})

#: Artıq bitmiş (təkrar planlaşdırılmır) hallar.
TERMINAL_STATES = frozenset({STATE_COMPLETED, STATE_PARTIAL, STATE_FAILED,
                             STATE_TIMED_OUT, STATE_CANCELLED, STATE_SKIPPED})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Kimliklər
# --------------------------------------------------------------------------- #
def _digest(parts) -> str:
    raw = "\x1f".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def task_identity(scan_id, engine: str, endpoint: str, *,
                  method: str = "GET", param: str = "", test_type: str = "",
                  profile: str = "") -> str:
    """Məntiqi tapşırığın DETERMİNİSTİK kimliyi.

    `endpoint` — `urlintel.endpoint_identity()` nəticəsi (sorğu parametrləri
    olmadan). Fərqli parametrlər `param` ilə ayrılır → `?id=1` ilə `?id=2`
    FƏRQLİ tapşırıqdır.
    """
    return _digest([scan_id or 0, engine or "", endpoint or "",
                    (method or "GET").upper(), param or "", test_type or "",
                    profile or ""])


def event_identity(kind: str, detail: str = "") -> str:
    """Zəncir hadisəsinin kimliyi (təkrarlanan emissiyanı ayırmaq üçün)."""
    return _digest(["chain", kind or "", detail or ""])


# --------------------------------------------------------------------------- #
# Tapşırıq qeydi
# --------------------------------------------------------------------------- #
@dataclass
class TaskRecord:
    identity: str
    engine: str = ""
    endpoint: str = ""
    method: str = "GET"
    param: str = ""
    test_type: str = ""
    profile: str = ""
    state: str = STATE_QUEUED
    attempts: int = 0
    reason: str = ""
    first_seen: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)


@dataclass(frozen=True)
class TaskDecision:
    identity: str
    create: bool
    state: str
    reason: str
    duplicate: bool = False


@dataclass
class TaskStats:
    considered: int = 0
    queued: int = 0
    deduplicated: int = 0
    started: int = 0
    retried: int = 0
    completed: int = 0
    partial: int = 0
    failed: int = 0
    timed_out: int = 0
    cancelled: int = 0
    skipped: int = 0
    pending: int = 0

    def to_dict(self) -> dict:
        return {
            "considered": self.considered,
            "queued": self.queued,
            "deduplicated": self.deduplicated,
            "executed": self.started,
            "retried": self.retried,
            "completed": self.completed,
            "partial": self.partial,
            "failed": self.failed,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "skipped": self.skipped,
            "pending": self.pending,
        }


class TaskLedger:
    """Idempotentlik dəftəri — hər məntiqi tapşırıq üçün tək qeyd."""

    def __init__(self, *, max_attempts: int = 3):
        self.max_attempts = max(1, int(max_attempts))
        self.tasks: dict[str, TaskRecord] = {}
        self.stats = TaskStats()

    # ------------------------------------------------------------------ lookup
    def get(self, identity: str) -> TaskRecord | None:
        return self.tasks.get(identity)

    @property
    def pending(self) -> int:
        return sum(1 for t in self.tasks.values()
                   if t.state in (STATE_QUEUED, STATE_RUNNING))

    # ------------------------------------------------------------------ decide
    def consider(self, identity: str, *, engine: str = "", endpoint: str = "",
                 method: str = "GET", param: str = "", test_type: str = "",
                 profile: str = "", force: bool = False) -> TaskDecision:
        """Tapşırığı qeyd edir və `create` qərarını səbəblə qaytarır."""
        self.stats.considered += 1
        rec = self.tasks.get(identity)
        if rec is None:
            rec = TaskRecord(identity=identity, engine=engine, endpoint=endpoint,
                             method=method, param=param, test_type=test_type,
                             profile=profile, state=STATE_QUEUED)
            self.tasks[identity] = rec
            self.stats.queued += 1
            self._sync_pending()
            return TaskDecision(identity, True, STATE_QUEUED,
                                "yeni tapşırıq — növbəyə əlavə edildi")

        rec.updated_at = _now()

        if rec.state == STATE_QUEUED:
            self.stats.deduplicated += 1
            return TaskDecision(identity, False, rec.state,
                                "artıq növbədədir — təkrar planlaşdırılmadı",
                                duplicate=True)
        if rec.state == STATE_RUNNING:
            self.stats.deduplicated += 1
            return TaskDecision(identity, False, rec.state,
                                "artıq icra olunur — dublikat başladılmadı",
                                duplicate=True)
        if rec.state == STATE_COMPLETED:
            if force:
                self.stats.retried += 1
                rec.state = STATE_QUEUED
                rec.reason = "məcburi təkrar (açıq səbəb göstərildi)"
                self._sync_pending()
                return TaskDecision(identity, True, rec.state, rec.reason)
            self.stats.deduplicated += 1
            return TaskDecision(identity, False, rec.state,
                                "artıq uğurla tamamlanıb — təkrar edilmir",
                                duplicate=True)
        if rec.state == STATE_SKIPPED:
            self.stats.deduplicated += 1
            return TaskDecision(identity, False, rec.state,
                                "əvvəl atlanmış — təkrar edilmir",
                                duplicate=True)
        # RETRYABLE_STATES
        previous = rec.state
        if rec.attempts < self.max_attempts:
            rec.attempts += 1
            rec.state = STATE_QUEUED
            rec.reason = (f"{previous} → bounded retry "
                          f"(cəhd {rec.attempts}/{self.max_attempts})")
            self.stats.retried += 1
            self._sync_pending()
            return TaskDecision(identity, True, rec.state, rec.reason)
        self.stats.deduplicated += 1
        return TaskDecision(identity, False, rec.state,
                            f"təkrar cəhd limiti aşıldı "
                            f"({rec.attempts}/{self.max_attempts})",
                            duplicate=True)

    # -------------------------------------------------------------------- mark
    def mark(self, identity: str, state: str, reason: str = "") -> TaskRecord | None:
        """Tapşırıq vəziyyətini yeniləyir (statistikalar sinxron qalır)."""
        if state not in LIFECYCLE:
            raise ValueError(f"etibarsız həyat dövrü vəziyyəti: {state!r}")
        rec = self.tasks.get(identity)
        if rec is None:
            return None
        rec.state = state
        rec.updated_at = _now()
        if reason:
            rec.reason = reason
        if state == STATE_RUNNING:
            self.stats.started += 1
        elif state == STATE_COMPLETED:
            self.stats.completed += 1
        elif state == STATE_PARTIAL:
            self.stats.partial += 1
        elif state == STATE_FAILED:
            self.stats.failed += 1
        elif state == STATE_TIMED_OUT:
            self.stats.timed_out += 1
        elif state == STATE_CANCELLED:
            self.stats.cancelled += 1
        elif state == STATE_SKIPPED:
            self.stats.skipped += 1
        self._sync_pending()
        return rec

    def _sync_pending(self) -> None:
        self.stats.pending = self.pending

    def snapshot(self) -> dict:
        self._sync_pending()
        return self.stats.to_dict()


# --------------------------------------------------------------------------- #
# Zəncir hadisə idempotentliyi + dövr/idarəetmə
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class EventDecision:
    accept: bool
    reason: str
    identity: str = ""


@dataclass
class EventStats:
    emitted: int = 0
    received: int = 0
    duplicate: int = 0
    conditions_rejected: int = 0
    cyclic: int = 0
    scheduled: int = 0
    suppressed: int = 0
    scheduled_tasks: int = 0

    def to_dict(self) -> dict:
        return {
            "emitted": self.emitted,
            "received": self.received,
            "duplicate": self.duplicate,
            "conditions_rejected": self.conditions_rejected,
            "cyclic": self.cyclic,
            "scheduled": self.scheduled,
            "scheduled_tasks": self.scheduled_tasks,
            "suppressed": self.suppressed,
        }


class EventLedger:
    """Zəncir hadisə dəftəri: təkrarlanan emissiya + dövr + dərinlik nəzarəti.

    Diqqət: bu, HADİSƏ səviyyəsində deduplikasiyadır — faktiki tapşırıq
    İCRASININ deduplikasiyası `TaskLedger`-in işidir. İkisi AYRIDIR.
    """

    def __init__(self, *, max_depth: int = 3, max_attempts: int = 3):
        self.max_depth = max(0, int(max_depth))
        self.max_attempts = max(1, int(max_attempts))
        self.seen: dict[str, int] = {}          # hadisə kimliyi → sayı
        self.links: dict[tuple, int] = {}       # (mənbə, hədəf) → cəhd sayı
        self.stats = EventStats()

    def accept(self, kind: str, detail: str = "") -> EventDecision:
        """Təkrarlanan hadisəni rədd edir (eyni kind+detail)."""
        ident = event_identity(kind, detail)
        self.stats.received += 1
        count = self.seen.get(ident, 0)
        if count:
            self.seen[ident] = count + 1
            self.stats.duplicate += 1
            self.stats.suppressed += 1
            return EventDecision(False, "dublikat zəncir hadisəsi (eyni "
                                        "kind+detail)", ident)
        self.seen[ident] = 1
        self.stats.emitted += 1
        return EventDecision(True, "yeni zəncir hadisəsi", ident)

    def guard(self, *, source: str, destination: str,
              depth: int = 0, identity: str = "") -> EventDecision:
        """Dövr və təkrar tetiklemə nəzarəti (məhdud dərinlik/cəhd).

        `identity` — hadisə kimliyi (`accept` nəticəsi). Verildikdə cəhd
        limiti PER-HADİSƏ tətbiq olunur → FƏRQLİ endpoint-lər bir-birini
        AÇ QOYMAZ (məşru davam testləri boğulmur). Verilmədikdə isə
        (məs. naməlum/ümumi hal) cəhd limiti (mənbə→hədəf) üzrə qlobaldır —
        bu, dövr/gizli təkrar selinə qarşı təhlükəsizlik şəbəkəsidir.
        """
        if depth > self.max_depth:
            self.stats.conditions_rejected += 1
            return EventDecision(False,
                                 f"zəncir dərinliyi limiti aşıldı "
                                 f"({depth}/{self.max_depth})")
        key = (source, destination, identity or "")
        attempts = self.links.get(key, 0) + 1
        self.links[key] = attempts
        if attempts > self.max_attempts:
            self.stats.conditions_rejected += 1
            self.stats.cyclic += 1
            return EventDecision(False,
                                 f"təkrar/dövri zəncir cəhdi rədd edildi "
                                 f"({source}→{destination}, cəhd {attempts})")
        self.stats.scheduled += 1
        return EventDecision(True, f"{source}→{destination} planlaşdırıldı")

    def snapshot(self) -> dict:
        return self.stats.to_dict()
