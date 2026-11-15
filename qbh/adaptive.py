"""Sübut-əsaslı adaptiv test idarəsi (Faza 5).

Axın::

    Kəşf → Uyğunluq → İlkin test → Siqnal qiymətləndirməsi →
    Şərti davam testi → Validasiya → Yekun nəticə

Prinsiplər:
  * Davam testi YALNIZ şərt ödənildikdə planlaşdırılır.
  * Təkrarlanan hadisə eyni testi TƏKRAR işlətməz (tapşırıq kimliyi +
    `TaskLedger` idempotentliyi).
  * Aşkarlama (detection) ilə validasiya AYRI qalır.
  * Neqativ / qeyri-müəyyən / qismən nəticələr İTİRİLMİR — səbəblə qeyd olunur.
  * Siqnal HEÇ VAXT avtomatik "təsdiqlənmiş zəiflik"ə ÇEVRİLMİR — bu modul
    yalnız "növbəti addım" qərarını verir, tapıntı yaratmır.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from .tasks import (STATE_CANCELLED, STATE_COMPLETED, STATE_FAILED,
                    STATE_PARTIAL, STATE_SKIPPED, TaskLedger)

_log = logging.getLogger("qbh.adaptive")

# --------------------------------------------------------------------------- #
# Siqnal gücü
# --------------------------------------------------------------------------- #
STRENGTH_NONE = "none"
STRENGTH_WEAK = "weak"
STRENGTH_STRONG = "strong"

#: Nəticə sinifləri (detection ≠ validation).
#: `validated` YALNIZ real validasiya nəticəsində istifadə olunur — siqnal
#: özü HEÇ VAXT avtomatik "təsdiqlənmiş" sayılmır.
OUTCOME_VALIDATED = "validated"      # → completed (yalnız real validasiya)
OUTCOME_COMPLETED = "completed"      # → completed (icra olundu, iddia yox)
OUTCOME_REJECTED = "rejected"        # → failed (işləndi, nəticəsiz)
OUTCOME_FAILED = "failed"            # → failed (icra xətası)
OUTCOME_INCONCLUSIVE = "inconclusive"  # → partial
OUTCOME_PARTIAL = "partial"          # → partial
OUTCOME_CANCELLED = "cancelled"      # → cancelled


def classify_strength(*, callback: bool = False, marker: bool = False,
                      data: bool = False, reflection: bool = False,
                      error_based: bool = False, matched: bool = False) -> str:
    """Mövcud sübut işarələrindən siqnal gücünü təyin edir.

    * `callback`/`marker`/`data`/`error_based` → GÜCLÜ (riyazi/OOB sübut).
    * `reflection`/`matched` → ZƏİF (yalnız oxuma-əsaslı işarə).
    * heç biri → YOXDUR.
    """
    if callback or marker or data or error_based:
        return STRENGTH_STRONG
    if reflection or matched:
        return STRENGTH_WEAK
    return STRENGTH_NONE


def classify_outcome(*, validated: bool = False, rejected: bool = False,
                     partial: bool = False) -> str:
    if partial:
        return OUTCOME_PARTIAL
    if validated:
        return OUTCOME_VALIDATED
    if rejected:
        return OUTCOME_REJECTED
    return OUTCOME_INCONCLUSIVE


@dataclass(frozen=True)
class Signal:
    kind: str
    strength: str
    detail: str = ""
    evidence: str = ""
    finding_id: int | None = None


@dataclass(frozen=True)
class FollowUp:
    proceed: bool
    reason: str
    actions: tuple = ()
    identity: str = ""


@dataclass
class AdaptiveStats:
    signals: int = 0
    none: int = 0
    weak: int = 0
    strong: int = 0
    scheduled: int = 0
    dispatched: int = 0
    unsupported: int = 0
    skipped_no_signal: int = 0
    skipped_duplicate: int = 0
    validated: int = 0
    completed: int = 0
    rejected: int = 0
    failed: int = 0
    cancelled: int = 0
    inconclusive: int = 0
    partial: int = 0

    def to_dict(self) -> dict:
        return {
            "signals": self.signals,
            "none": self.none,
            "weak": self.weak,
            "strong": self.strong,
            "scheduled": self.scheduled,
            "dispatched": self.dispatched,
            "unsupported": self.unsupported,
            "skipped_no_signal": self.skipped_no_signal,
            "skipped_duplicate": self.skipped_duplicate,
            "validated": self.validated,
            "completed": self.completed,
            "rejected": self.rejected,
            "failed": self.failed,
            "cancelled": self.cancelled,
            "inconclusive": self.inconclusive,
            "partial": self.partial,
        }


class AdaptiveController:
    """Siqnal → şərti davam testi qərarlarını verən idarəçi."""

    def __init__(self, *, ledger: TaskLedger | None = None,
                 max_attempts: int = 3, metrics=None, store=None):
        self.ledger = ledger if ledger is not None else TaskLedger(
            max_attempts=max_attempts)
        self.metrics = metrics
        self.stats = AdaptiveStats()
        self.decisions: list[dict] = []
        #: Opsional davamlı saxlama adapteri (`recovery.DurableStore`, Faza 2
        #: §4.2). `None` → yalnız RAM (əvvəlki davranış). Verildikdə hər
        #: planlaşdırılmış davam testi `followup_queue`-ə yazılır və nəticə
        #: terminal statusla yenilənir.
        self.store = store

    # ------------------------------------------------------------------ decide
    def evaluate(self, signal: Signal, *, identity: str,
                 actions: tuple = ()) -> FollowUp:
        """Siqnala əsaslanaraq davam testi planlaşdırılsınmı (səbəblə)."""
        self.stats.signals += 1
        if signal.strength == STRENGTH_NONE:
            self.stats.none += 1
            self.stats.skipped_no_signal += 1
            return self._record(FollowUp(
                False, "siqnal yoxdur — davam testi planlaşdırılmadı",
                (), identity))
        if signal.strength == STRENGTH_WEAK:
            self.stats.weak += 1
            reason = "zəif siqnal → yalnız təsdiq/validasiya addımı"
        else:
            self.stats.strong += 1
            reason = "güclü sübut → hədəfli davam testi"

        decision = self.ledger.consider(
            identity, engine=identity.split(":")[0] if ":" in identity else "",
            test_type="chain_followup")
        if not decision.create:
            self.stats.skipped_duplicate += 1
            return self._record(FollowUp(
                False, f"təkrar/tamamlanmış tapşırıq — {decision.reason}",
                (), identity))
        # `consider` tapşırığı artıq `queued` vəziyyətinə keçirdi. Burada
        # `partial` (təkrar-icra edilə bilən) İŞARƏLƏMİRİK — əks halda eyni
        # siqnalın təkrar emissiyası YALANÇI "bounded retry" kimi yenidən
        # planlaşdırılardı. Nəticə `record_outcome` ilə yazılır.
        self.stats.scheduled += 1
        self._persist_followup(identity, actions, status="pending")
        return self._record(FollowUp(True, reason, tuple(actions), identity))

    def record_outcome(self, identity: str, outcome: str,
                       note: str = "") -> None:
        """Davam testinin REAL nəticəsini qeyd edir (nəticə İTİRİLMİR).

        Bu metod YALNIZ icra BİTDİKDƏN SONRA çağırılmalıdır — planlaşdırma
        anında deyil. Beləliklə statistikalar FAKTİKİ icranı əks etdirir.
        """
        mapping = {
            OUTCOME_VALIDATED: (STATE_COMPLETED, "validated"),
            OUTCOME_COMPLETED: (STATE_COMPLETED, "completed"),
            OUTCOME_REJECTED: (STATE_FAILED, "rejected"),
            OUTCOME_FAILED: (STATE_FAILED, "failed"),
            OUTCOME_INCONCLUSIVE: (STATE_PARTIAL, "inconclusive"),
            OUTCOME_PARTIAL: (STATE_PARTIAL, "partial"),
            OUTCOME_CANCELLED: (STATE_CANCELLED, "cancelled"),
        }
        state, label = mapping.get(outcome, (STATE_PARTIAL, "inconclusive"))
        self.ledger.mark(identity, state, note or label)
        self.stats.dispatched += 1
        # Davamlı növbədə davam testi REAL icradan sonra terminal status alır
        # (Faza 2 §4.2): "executed" (icra olundu) və ya "failed" (xəta/rədd).
        fu_status = "failed" if state in (STATE_FAILED, STATE_CANCELLED) \
            else "executed"
        self._persist_followup(identity, (), status=fu_status)
        if outcome == OUTCOME_VALIDATED:
            self.stats.validated += 1
        elif outcome == OUTCOME_COMPLETED:
            self.stats.completed += 1
        elif outcome == OUTCOME_REJECTED:
            self.stats.rejected += 1
        elif outcome == OUTCOME_FAILED:
            self.stats.failed += 1
        elif outcome == OUTCOME_CANCELLED:
            self.stats.cancelled += 1
        elif outcome == OUTCOME_PARTIAL:
            self.stats.partial += 1
        else:
            self.stats.inconclusive += 1

    def record_unsupported(self, identity: str, note: str) -> None:
        """Dəstəklənməyən / dəlegasiya olunan davam hərəkətini AÇIQ qeyd edir.

        Belə tapşırıq `queued` vəziyyətində ƏBƏDİ qalmamalıdır — terminal
        `skipped` vəziyyətinə keçir və səbəb audit üçün saxlanılır.
        """
        self.ledger.mark(identity, STATE_SKIPPED, note)
        self.stats.unsupported += 1
        self._persist_followup(identity, (), status="skipped")

    # ------------------------------------------------------ davamlılıq (Faza 2)
    def _persist_followup(self, identity: str, actions, *, status: str) -> None:
        """Davam testini davamlı növbəyə yazır/yeniləyir (store yoxsa no-op).

        `status="pending"` → yeni gözləyən sətir; digər statuslar → mövcud
        gözləyən sətri terminal statusla yeniləyir (yalnız REAL nəticədən
        sonra — planlaşdırma anında deyil).
        """
        if self.store is None or not identity:
            return
        try:
            if status == "pending":
                self.store.persist_followup(
                    identity, ";".join(a for a in (actions or ())) or identity,
                    status="pending")
            else:
                self.store.mark_followup(identity, status)
        except Exception as exc:      # pragma: no cover - DB əlçatmazdır
            _log.warning("davam testi davamlı saxlanmadı (%s): %s",
                         identity, exc)

    def restore_followups(self, records) -> int:
        """Davamlı növbədən GÖZLƏYƏN davam testlərini auditə bərpa edir.

        `records` — `followup_queue` sətirləri (mapping/`sqlite3.Row`).
        Qaytarır: bərpa olunmuş davam testi sayı.
        """
        restored = 0
        for rec in records or ():
            try:
                identity = rec["prerequisite_hash"] or ""
                action = rec["proposed_action"] or ""
            except (TypeError, IndexError, KeyError):
                continue
            if not identity or any(d.get("identity") == identity
                                   for d in self.decisions):
                continue
            self.decisions.append({
                "identity": identity, "proceed": True,
                "reason": "bərpa: gözləyən davam testi",
                "actions": [action] if action else [],
            })
            self.stats.scheduled += 1
            restored += 1
        return restored

    def _record(self, fu: FollowUp) -> FollowUp:
        self.decisions.append({
            "identity": fu.identity,
            "proceed": fu.proceed,
            "reason": fu.reason,
            "actions": list(fu.actions),
        })
        return fu

    def snapshot(self) -> dict:
        return self.stats.to_dict()
