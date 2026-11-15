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
  * Defolt olaraq BİR PROSES daxilində (skan) işləyir. **Faza 2 (§4):** əlavə
    olaraq OPSİONAL davamlı saxlama (`store=`) dəstəklənir — çökmədən sonra
    bərpa üçün hər keçid `task_state`/`event_state`-ə yazılır. `store`
    verilmədikdə davranış ƏVVƏLKİ kimidir (yalnız RAM).
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

_log = logging.getLogger("qbh.tasks")

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
                  profile: str = "", identity_level: str = "",
                  identity: str = "") -> str:
    """Məntiqi tapşırığın DETERMİNİSTİK kimliyi.

    `endpoint` — `urlintel.endpoint_identity()` nəticəsi (sorğu parametrləri
    olmadan). Fərqli parametrlər `param` ilə ayrılır → `?id=1` ilə `?id=2`
    FƏRQLİ tapşırıqdır.

    Faza 1 (§3.1): çox-səviyyəli URL kimliyi dəstəyi. `identity_level` və
    `identity` verildikdə (`urlintel.URLIdentity.get(level)`) kimliyə əlavə
    olunur. Hər ikisi boş olduqda davranış ƏVVƏLKİ kimidir (geriyə uyğun).
    """
    parts = [scan_id or 0, engine or "", endpoint or "",
             (method or "GET").upper(), param or "", test_type or "",
             profile or ""]
    if identity_level or identity:
        parts.extend([identity_level or "", identity or ""])
    return _digest(parts)


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
    #: Faza 2 (§4.2): mərhələnin nəticə datası (`sr.data` JSON) — bərpadan
    #: sonra aşağı mərhələlər (məs. `deep_enum` → `recon`) onu istifadə edir
    #: ki, davam İTİRİLMİŞ kəşfi TƏKRAR ETMƏDƏN əhatəni AZALTMAĞA BƏBƏB olmasın.
    result_data: dict = field(default_factory=dict)


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
    """Idempotentlik dəftəri — hər məntiqi tapşırıq üçün tək qeyd.

    `store` (Faza 2, §4.2) verilərsə, hər vəziyyət keçidi davamlı saxlamaya
    yazılır. `store=None` → yalnız RAM (əvvəlki davranış).
    """

    def __init__(self, *, max_attempts: int = 3, store=None):
        self.max_attempts = max(1, int(max_attempts))
        self.tasks: dict[str, TaskRecord] = {}
        self.stats = TaskStats()
        #: Opsional davamlı saxlama adapteri (`recovery.DurableStore`).
        self.store = store

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
            self._persist(identity)
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
                self._persist(identity)
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
            self._persist(identity)
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
        self._persist(identity)
        return rec

    def _persist(self, identity: str) -> None:
        """Keçiddən SONRA davamlı saxlamaya yazır (store yoxdursa no-op)."""
        if self.store is None:
            return
        self.persist_to_db(identity)

    def persist_to_db(self, identity: str | None = None, *,
                      last_error: str = "", result_data=None) -> int:
        """Tapşırıq(lar)ı davamlı saxlamaya yazır (bərpa üçün).

        `identity=None` → bütün tapşırıqlar. `store` qoşulmayıbsa heç nə
        edilmir (0 qaytarılır) — in-memory əməliyyat DƏYİŞMİR (geriyə uyğun).
        Qaytarır: yazılmış sətir sayı.
        """
        if self.store is None:
            return 0
        if identity is not None:
            rec = self.tasks.get(identity)
            targets = [rec] if rec is not None else []
        else:
            targets = list(self.tasks.values())
        written = 0
        for rec in targets:
            try:
                data = result_data if result_data is not None \
                    else (rec.result_data or None)
                self.store.persist_task(rec, last_error=last_error,
                                        result_data=data)
                written += 1
            except Exception as exc:      # pragma: no cover - DB əlçatmazdır
                _log.warning("tapşırıq davamlı saxlanmadı (%s): %s",
                             rec.identity, exc)
        return written

    def restore(self, records) -> dict:
        """Davamlı vəziyyətdən tapşırıqları yükləyir (RAM dəftərini DOLDURUR).

        * `running` → `cancelled` (retryable) kimi bərpa olunur: proses
          çökdüyü üçün yarımçıq qalmış tapşırıq bounded şəkildə TƏKRAR
          planlaşdırıla bilər (`consider` onu yenidən `queued` edəcək).
        * `queued` → olduğu kimi (yenə planlaşdırılacaq).
        * `completed`/`skipped`/digər terminal hallar OLDUĞU KİMİ qalır →
          TƏKRAR İCRA OLUNMUR (`consider` `create=False` qaytarır).
        * `attempts`/`reason` tarixçəsi QORUNUR.

        Qaytarır: `{"restored", "requeued", "terminal"}` sayları.
        """
        counts = {"restored": 0, "requeued": 0, "terminal": 0}
        for rec in records or ():
            if rec is None or not getattr(rec, "identity", ""):
                continue
            if rec.identity in self.tasks:
                continue
            if rec.state == STATE_RUNNING:
                rec.state = STATE_CANCELLED
                rec.reason = "bərpa: proses çökdü → yenidən növbəyə"
                counts["requeued"] += 1
            elif rec.state in (STATE_QUEUED, STATE_CANCELLED, STATE_FAILED,
                               STATE_TIMED_OUT, STATE_PARTIAL):
                counts["requeued"] += 1
            else:
                counts["terminal"] += 1
            self.tasks[rec.identity] = rec
            counts["restored"] += 1
        self._sync_pending()
        return counts

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

    def __init__(self, *, max_depth: int = 3, max_attempts: int = 3,
                 store=None):
        self.max_depth = max(0, int(max_depth))
        self.max_attempts = max(1, int(max_attempts))
        self.seen: dict[str, int] = {}          # hadisə kimliyi → sayı
        self.links: dict[tuple, int] = {}       # (mənbə, hədəf) → cəhd sayı
        self.stats = EventStats()
        #: Opsional davamlı saxlama adapteri (`recovery.DurableStore`).
        self.store = store
        #: Hadisə kimliyi → `event_type` (bərpa üçün).
        self.kinds: dict[str, str] = {}

    def accept(self, kind: str, detail: str = "") -> EventDecision:
        """Təkrarlanan hadisəni rədd edir (eyni kind+detail)."""
        ident = event_identity(kind, detail)
        self.stats.received += 1
        count = self.seen.get(ident, 0)
        if count:
            self.seen[ident] = count + 1
            self.stats.duplicate += 1
            self.stats.suppressed += 1
            self._persist_event(ident, kind, detail)
            return EventDecision(False, "dublikat zəncir hadisəsi (eyni "
                                        "kind+detail)", ident)
        self.seen[ident] = 1
        self.kinds[ident] = kind
        self.stats.emitted += 1
        self._persist_event(ident, kind, detail)
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

    def _persist_event(self, ident: str, kind: str, detail: str) -> None:
        """Hadisəni davamlı saxlamaya yazır (store yoxdursa no-op)."""
        if self.store is None:
            return
        try:
            self.store.persist_event(ident, event_type=kind,
                                     count=self.seen.get(ident, 1),
                                     detail=detail)
        except Exception as exc:          # pragma: no cover - DB əlçatmazdır
            _log.warning("hadisə davamlı saxlanmadı (%s): %s", ident, exc)

    def persist_to_db(self) -> int:
        """Bütün görülmüş hadisələri davamlı saxlamaya yazır (0: store yoxdur)."""
        if self.store is None:
            return 0
        written = 0
        for ident, count in self.seen.items():
            try:
                self.store.persist_event(ident,
                                         event_type=self.kinds.get(ident, ""),
                                         count=count)
                written += 1
            except Exception as exc:      # pragma: no cover
                _log.warning("hadisə davamlı saxlanmadı (%s): %s", ident, exc)
        return written

    def restore(self, events) -> int:
        """Davamlı vəziyyətdən görülmüş hadisələri bərpa edir.

        `events` — `(event_id, event_type, count)` üçlüklərinin ardıcıllığı.
        Təkrarlanan hadisələr YENİDƏN emal edilməsin deyə `seen` doldurulur.
        Qaytarır: bərpa olunmuş hadisə sayı.
        """
        restored = 0
        for item in events or ():
            try:
                ident, kind, count = item
            except (TypeError, ValueError):
                continue
            if not ident or ident in self.seen:
                continue
            self.seen[ident] = max(1, int(count or 1))
            self.kinds[ident] = kind or ""
            restored += 1
        return restored

    def snapshot(self) -> dict:
        return self.stats.to_dict()
