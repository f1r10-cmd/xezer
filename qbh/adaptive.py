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

from dataclasses import dataclass

from .tasks import STATE_COMPLETED, STATE_FAILED, STATE_PARTIAL, TaskLedger

# --------------------------------------------------------------------------- #
# Siqnal gücü
# --------------------------------------------------------------------------- #
STRENGTH_NONE = "none"
STRENGTH_WEAK = "weak"
STRENGTH_STRONG = "strong"

#: Nəticə sinifləri (detection ≠ validation).
OUTCOME_VALIDATED = "validated"
OUTCOME_REJECTED = "rejected"
OUTCOME_INCONCLUSIVE = "inconclusive"
OUTCOME_PARTIAL = "partial"


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
    skipped_no_signal: int = 0
    skipped_duplicate: int = 0
    validated: int = 0
    rejected: int = 0
    inconclusive: int = 0
    partial: int = 0

    def to_dict(self) -> dict:
        return {
            "signals": self.signals,
            "none": self.none,
            "weak": self.weak,
            "strong": self.strong,
            "scheduled": self.scheduled,
            "skipped_no_signal": self.skipped_no_signal,
            "skipped_duplicate": self.skipped_duplicate,
            "validated": self.validated,
            "rejected": self.rejected,
            "inconclusive": self.inconclusive,
            "partial": self.partial,
        }


class AdaptiveController:
    """Siqnal → şərti davam testi qərarlarını verən idarəçi."""

    def __init__(self, *, ledger: TaskLedger | None = None,
                 max_attempts: int = 3, metrics=None):
        self.ledger = ledger if ledger is not None else TaskLedger(
            max_attempts=max_attempts)
        self.metrics = metrics
        self.stats = AdaptiveStats()
        self.decisions: list[dict] = []

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
        return self._record(FollowUp(True, reason, tuple(actions), identity))

    def record_outcome(self, identity: str, outcome: str,
                       note: str = "") -> None:
        """Davam testinin nəticəsini qeyd edir (nəticə İTİRİLMİR)."""
        mapping = {
            OUTCOME_VALIDATED: (STATE_COMPLETED, "validated"),
            OUTCOME_REJECTED: (STATE_FAILED, "rejected"),
            OUTCOME_INCONCLUSIVE: (STATE_PARTIAL, "inconclusive"),
            OUTCOME_PARTIAL: (STATE_PARTIAL, "partial"),
        }
        state, label = mapping.get(outcome, (STATE_PARTIAL, "inconclusive"))
        self.ledger.mark(identity, state, note or label)
        if outcome == OUTCOME_VALIDATED:
            self.stats.validated += 1
        elif outcome == OUTCOME_REJECTED:
            self.stats.rejected += 1
        elif outcome == OUTCOME_PARTIAL:
            self.stats.partial += 1
        else:
            self.stats.inconclusive += 1

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
