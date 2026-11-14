"""Faza 5 (§9) — sübut-əsaslı adaptiv test nəzarəti testləri.

Yoxlanılan prinsiplər:
  * Siqnal gücü sübut işarələrindən təyin olunur (yoxdur/zəif/güclü).
  * Davam testi YALNIZ şərt ödənildikdə planlaşdırılır.
  * Eyni siqnalın TƏKRAR emissiyası eyni testi TƏKRAR işlətmir.
  * Fərqli tapşırıq kimlikləri bir-birindən asılıdır (məşru iş boğulmur).
  * Nəticələr (validated/rejected/inconclusive/partial) İTİRİLMİR.
  * Siqnal HEÇ VAXT avtomatik "təsdiqlənmiş zəiflik"ə çevrilmir.
"""
from __future__ import annotations

from qbh.adaptive import (OUTCOME_INCONCLUSIVE, OUTCOME_PARTIAL,
                          OUTCOME_REJECTED, OUTCOME_VALIDATED,
                          STRENGTH_NONE, STRENGTH_STRONG, STRENGTH_WEAK,
                          AdaptiveController, Signal, classify_outcome,
                          classify_strength)
from qbh.tasks import STATE_COMPLETED, STATE_FAILED, STATE_PARTIAL, TaskLedger


class TestStrength:
    def test_none(self):
        assert classify_strength() == STRENGTH_NONE

    def test_weak_markers(self):
        assert classify_strength(reflection=True) == STRENGTH_WEAK
        assert classify_strength(matched=True) == STRENGTH_WEAK

    def test_strong_markers(self):
        for kw in ("callback", "marker", "data", "error_based"):
            assert classify_strength(**{kw: True}) == STRENGTH_STRONG

    def test_strong_wins_over_weak(self):
        assert classify_strength(reflection=True, callback=True) == \
            STRENGTH_STRONG


class TestOutcomeClassification:
    def test_partial_priority(self):
        assert classify_outcome(partial=True, validated=True) == OUTCOME_PARTIAL

    def test_validated(self):
        assert classify_outcome(validated=True) == OUTCOME_VALIDATED

    def test_rejected(self):
        assert classify_outcome(rejected=True) == OUTCOME_REJECTED

    def test_default_inconclusive(self):
        assert classify_outcome() == OUTCOME_INCONCLUSIVE


def _ctl():
    return AdaptiveController(ledger=TaskLedger())


class TestController:
    def test_no_signal_skips(self):
        c = _ctl()
        fu = c.evaluate(Signal("sqli_signal", STRENGTH_NONE), identity="i1")
        assert fu.proceed is False
        assert c.stats.skipped_no_signal == 1

    def test_weak_signal_confirm_only(self):
        c = _ctl()
        fu = c.evaluate(Signal("xss_signal", STRENGTH_WEAK), identity="i1")
        assert fu.proceed is True
        assert "zəif" in fu.reason
        assert c.stats.weak == 1

    def test_strong_signal_targeted(self):
        c = _ctl()
        fu = c.evaluate(Signal("vuln_js_lib", STRENGTH_STRONG), identity="i1")
        assert fu.proceed is True
        assert "güclü" in fu.reason
        assert c.stats.strong == 1

    def test_repeated_signal_not_rescheduled(self):
        c = _ctl()
        assert c.evaluate(Signal("xss_signal", STRENGTH_WEAK),
                          identity="i1").proceed is True
        fu = c.evaluate(Signal("xss_signal", STRENGTH_WEAK), identity="i1")
        assert fu.proceed is False
        assert c.stats.skipped_duplicate == 1

    def test_distinct_identities_independent(self):
        c = _ctl()
        assert c.evaluate(Signal("xss_signal", STRENGTH_WEAK),
                          identity="i1").proceed is True
        assert c.evaluate(Signal("xss_signal", STRENGTH_WEAK),
                          identity="i2").proceed is True

    def test_extra_strong_signal_after_schedule_is_blocked(self):
        # Eyni tapşırıq üçün təkrar siqnal (güclü olsa da) yenidən
        # planlaşdırılmır.
        c = _ctl()
        c.evaluate(Signal("sqli_signal", STRENGTH_WEAK), identity="i1")
        fu = c.evaluate(Signal("sqli_signal", STRENGTH_STRONG), identity="i1")
        assert fu.proceed is False

    def test_validated_outcome_marks_completed(self):
        c = AdaptiveController(ledger=TaskLedger())
        c.evaluate(Signal("xss_signal", STRENGTH_WEAK), identity="i1")
        c.record_outcome("i1", OUTCOME_VALIDATED)
        assert c.ledger.get("i1").state == STATE_COMPLETED
        assert c.stats.validated == 1

    def test_rejected_outcome_marks_failed(self):
        c = AdaptiveController(ledger=TaskLedger())
        c.evaluate(Signal("xss_signal", STRENGTH_WEAK), identity="i1")
        c.record_outcome("i1", OUTCOME_REJECTED)
        assert c.ledger.get("i1").state == STATE_FAILED
        assert c.stats.rejected == 1

    def test_inconclusive_preserved(self):
        c = AdaptiveController(ledger=TaskLedger())
        c.evaluate(Signal("xss_signal", STRENGTH_WEAK), identity="i1")
        c.record_outcome("i1", OUTCOME_INCONCLUSIVE)
        assert c.ledger.get("i1").state == STATE_PARTIAL
        assert c.stats.inconclusive == 1

    def test_partial_preserved(self):
        c = AdaptiveController(ledger=TaskLedger())
        c.evaluate(Signal("xss_signal", STRENGTH_WEAK), identity="i1")
        c.record_outcome("i1", OUTCOME_PARTIAL)
        assert c.ledger.get("i1").state == STATE_PARTIAL
        assert c.stats.partial == 1

    def test_followup_does_not_create_finding(self):
        c = _ctl()
        c.evaluate(Signal("sqli_signal", STRENGTH_STRONG), identity="i1")
        assert not hasattr(c, "findings")
        assert c.snapshot()["scheduled"] == 1

    def test_decisions_recorded(self):
        c = _ctl()
        c.evaluate(Signal("xss_signal", STRENGTH_WEAK), identity="i1")
        assert c.decisions[-1]["identity"] == "i1"
        assert c.decisions[-1]["proceed"] is True

    def test_snapshot_keys(self):
        snap = _ctl().snapshot()
        for key in ("signals", "none", "weak", "strong", "scheduled",
                    "skipped_no_signal", "skipped_duplicate", "validated",
                    "rejected", "inconclusive", "partial"):
            assert key in snap
