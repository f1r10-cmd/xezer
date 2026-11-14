"""Faza 3 (§7) — tapşırıq kimliyi, həyat dövrü və idempotentlik testləri.

Yoxlanılan prinsiplər:
  * `task_identity` deterministikdir və YALNIZ mənalı ölçüləri ayırır.
  * `TaskLedger` yeni tapşırığı qəbul edir, təkrarları (queued/running/
    completed) RƏDD edir, uğursuzluqları isə BOUNDED təkrar edir.
  * Fərqli parametrlər FƏRQLİ tapşırıqdır (məşru iş boğulmur).
  * `EventLedger` təkrarlanan hadisəni rədd edir və dövr/dərinlik cəhdlərini
    məhdudlaşdırır. Hadisə deduplikasiyası ilə TAPŞIRIQ icra deduplikasiyası
    AYRIDIR (ikisi də ayrıca yoxlanılır).
"""
from __future__ import annotations

import pytest

from qbh.tasks import (EventLedger, STATE_CANCELLED, STATE_COMPLETED,
                       STATE_FAILED, STATE_QUEUED, STATE_RUNNING,
                       STATE_SKIPPED, STATE_TIMED_OUT, TaskLedger, event_identity,
                       task_identity)


class TestTaskIdentity:
    def test_deterministic_and_fixed_length(self):
        a = task_identity(1, "sqli", "http://h/p", param="id=1")
        b = task_identity(1, "sqli", "http://h/p", param="id=1")
        assert a == b
        assert len(a) == 32

    def test_param_distinguishes(self):
        assert task_identity(1, "sqli", "http://h/p", param="id=1") != \
            task_identity(1, "sqli", "http://h/p", param="id=2")

    def test_engine_distinguishes(self):
        assert task_identity(1, "sqli", "http://h/p") != \
            task_identity(1, "xss", "http://h/p")

    def test_scan_distinguishes(self):
        assert task_identity(1, "sqli", "http://h/p") != \
            task_identity(2, "sqli", "http://h/p")

    def test_method_testtype_profile_distinguish(self):
        base = task_identity(1, "sqli", "http://h/p")
        assert task_identity(1, "sqli", "http://h/p", method="POST") != base
        assert task_identity(1, "sqli", "http://h/p", test_type="blind") != base
        assert task_identity(1, "sqli", "http://h/p", profile="v2") != base

    def test_event_identity_deterministic(self):
        assert event_identity("sqli_signal", "x") == event_identity(
            "sqli_signal", "x")
        assert event_identity("sqli_signal", "x") != event_identity(
            "sqli_signal", "y")


class TestTaskLedger:
    def test_new_task_queued(self):
        led = TaskLedger()
        d = led.consider("a")
        assert d.create is True
        assert d.state == STATE_QUEUED
        assert led.stats.queued == 1

    def test_duplicate_queued_blocked(self):
        led = TaskLedger()
        led.consider("a")
        d = led.consider("a")
        assert d.create is False
        assert d.duplicate is True
        assert led.stats.deduplicated == 1

    def test_duplicate_running_blocked(self):
        led = TaskLedger()
        led.consider("a")
        led.mark("a", STATE_RUNNING)
        d = led.consider("a")
        assert d.create is False
        assert "icra olunur" in d.reason
        assert led.stats.started == 1

    def test_duplicate_completed_blocked(self):
        led = TaskLedger()
        led.consider("a")
        led.mark("a", STATE_COMPLETED)
        d = led.consider("a")
        assert d.create is False
        assert "tamamlanıb" in d.reason
        assert led.stats.completed == 1

    def test_force_recreates_completed(self):
        led = TaskLedger()
        led.consider("a")
        led.mark("a", STATE_COMPLETED)
        d = led.consider("a", force=True)
        assert d.create is True
        assert led.stats.retried == 1

    def test_bounded_retry_after_failure(self):
        led = TaskLedger(max_attempts=2)
        led.consider("a")
        led.mark("a", STATE_FAILED)
        w1 = led.consider("a")
        assert w1.create is True
        assert led.tasks["a"].attempts == 1
        led.mark("a", STATE_FAILED)
        w2 = led.consider("a")
        assert w2.create is True
        assert led.tasks["a"].attempts == 2
        led.mark("a", STATE_FAILED)
        w3 = led.consider("a")
        assert w3.create is False
        assert "limit" in w3.reason

    def test_timed_out_retryable(self):
        led = TaskLedger()
        led.consider("a")
        led.mark("a", STATE_TIMED_OUT)
        assert led.consider("a").create is True
        assert led.stats.timed_out == 1

    def test_cancelled_explicit_reschedule(self):
        led = TaskLedger()
        led.consider("a")
        led.mark("a", STATE_CANCELLED)
        d = led.consider("a")
        assert d.create is True
        assert "retry" in d.reason

    def test_skipped_not_repeated(self):
        led = TaskLedger()
        led.consider("a")
        led.mark("a", STATE_SKIPPED)
        assert led.consider("a").create is False

    def test_distinct_params_are_independent(self):
        led = TaskLedger()
        assert led.consider("id1").create is True
        assert led.consider("id2").create is True
        assert led.stats.deduplicated == 0

    def test_pending_and_snapshot(self):
        led = TaskLedger()
        led.consider("a")
        led.consider("b")
        assert led.pending == 2
        led.mark("a", STATE_RUNNING)
        led.mark("a", STATE_COMPLETED)
        snap = led.snapshot()
        assert snap["completed"] == 1
        assert snap["executed"] == 1
        assert snap["pending"] == 1

    def test_mark_rejects_invalid_state(self):
        led = TaskLedger()
        led.consider("a")
        with pytest.raises(ValueError):
            led.mark("a", "bogus")

    def test_mark_unknown_identity_returns_none(self):
        assert TaskLedger().mark("missing", STATE_COMPLETED) is None


class TestEventLedger:
    def test_duplicate_event_rejected(self):
        ev = EventLedger()
        assert ev.accept("sqli_signal", "http://h/p?id=1").accept is True
        d = ev.accept("sqli_signal", "http://h/p?id=1")
        assert d.accept is False
        assert ev.stats.received == 2
        assert ev.stats.duplicate == 1

    def test_distinct_detail_accepted(self):
        ev = EventLedger()
        ev.accept("sqli_signal", "http://h/p?id=1")
        assert ev.accept("sqli_signal", "http://h/p?id=2").accept is True

    def test_cycle_guard_limits_repeats(self):
        ev = EventLedger(max_attempts=2)
        assert ev.guard(source="a", destination="b").accept is True
        assert ev.guard(source="a", destination="b").accept is True
        d = ev.guard(source="a", destination="b")
        assert d.accept is False
        assert ev.stats.cyclic == 1

    def test_depth_limit(self):
        ev = EventLedger(max_depth=1)
        assert ev.guard(source="a", destination="b", depth=1).accept is True
        d = ev.guard(source="a", destination="b", depth=2)
        assert d.accept is False
        assert ev.stats.conditions_rejected == 1

    def test_snapshot_keys(self):
        snap = EventLedger().snapshot()
        for key in ("emitted", "received", "duplicate", "conditions_rejected",
                    "cyclic", "scheduled", "suppressed"):
            assert key in snap
