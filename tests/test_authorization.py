"""Faza 1 avtorizasiya konteksti testləri — vahid scope/RoE qərar mərkəzi.

Yoxlanılan prinsiplər:
  * `authorize_url` — YALNIZ scope xaricini rədd edir (fail-closed).
  * Scope daxilində hər şey açıqdır; proqram qaydaları yalnız açıq
    qadağaları bağlayır.
  * Wildcard auto-expansion və `filter_hosts` düzgün işləyir.
  * Ləğv (cancellation) və deadline `ensure_active` ilə hörmətlə qarşılanır.
  * Heç bir test xarici hədəfə müraciət etmir.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from qbh.authorization import (Authorization, NotAuthorized, RuleForbidden,
                               ScanExpired, from_config)


def _scope(load_config, in_scope, out_of_scope=(), **kw):
    return load_config([
        {"domain": "example.com", "in_scope": list(in_scope),
         "out_of_scope": list(out_of_scope)}], **kw)


# ---------------------------------------------------------------- authorize_url
class TestAuthorizeUrl:
    def test_in_scope_url_returned(self, load_config):
        cfg = _scope(load_config, ["example.com"])
        auth = from_config(cfg)
        url = "https://example.com/a?b=1"
        assert auth.authorize_url(url) == url

    def test_out_of_scope_url_denied(self, load_config):
        auth = from_config(_scope(load_config, ["example.com"]))
        with pytest.raises(NotAuthorized):
            auth.authorize_url("https://evil.com/")

    def test_empty_scope_fails_closed(self, load_config):
        # Boş scope konfiq yüklənməsi onsuz da qadağandır; birbaşa Authorization
        # ilə boş scope semantikasını yoxlayırıq.
        auth = Authorization(scope=None)
        assert auth.is_authorized("example.com") is False
        with pytest.raises(NotAuthorized):
            auth.authorize_url("https://example.com")

    def test_invalid_url_denied(self, load_config):
        auth = from_config(_scope(load_config, ["example.com"]))
        with pytest.raises(NotAuthorized):
            auth.authorize_url("https://exa mple.com/")

    def test_wildcard_subdomain_allowed(self, load_config):
        auth = from_config(_scope(load_config, ["*.example.com"]))
        assert auth.authorize_url("https://a.example.com/x") == \
            "https://a.example.com/x"
        with pytest.raises(NotAuthorized):
            auth.authorize_url("https://example.com/")  # root, not matched

    def test_deny_rule_wins(self, load_config):
        auth = from_config(_scope(
            load_config, ["*.example.com"], ["admin.example.com"]))
        assert auth.authorize_url("https://shop.example.com/") == \
            "https://shop.example.com/"
        with pytest.raises(NotAuthorized):
            auth.authorize_url("https://admin.example.com/")


# ---------------------------------------------------------------- filter_hosts
class TestFilterHosts:
    def test_filters_out_of_scope(self, load_config):
        auth = from_config(_scope(load_config, ["*.example.com"]))
        got = auth.filter_hosts(
            ["a.example.com", "evil.com", "b.example.com", "a.example.com"])
        assert got == ["a.example.com", "b.example.com"]

    def test_authorize_host_returns_canonical(self, load_config):
        auth = from_config(_scope(load_config, ["example.com"]))
        assert auth.authorize_host("EXAMPLE.COM.") == "example.com"

    def test_wildcard_expansion_flag(self, load_config):
        auth = from_config(_scope(load_config, ["*.example.com"]))
        assert auth.allows_wildcard_expansion() is True
        auth2 = from_config(_scope(
            load_config, ["*.example.com"],
            extra={"program_rules": {"allow_wildcard_expansion": False}}))
        assert auth2.allows_wildcard_expansion() is False


# ---------------------------------------------------------------- RoE gating
class TestRuleGating:
    def test_forbidden_action_denied(self, load_config):
        cfg = _scope(load_config, ["example.com"],
                     extra={"program_rules": {"forbidden": ["active_fuzz"]}})
        auth = from_config(cfg)
        assert auth.allows("active_fuzz") is False
        with pytest.raises(RuleForbidden):
            auth.require("active_fuzz")

    def test_unmentioned_action_allowed(self, load_config):
        cfg = _scope(load_config, ["example.com"],
                     extra={"program_rules": {"forbidden": ["active_fuzz"]}})
        auth = from_config(cfg)
        assert auth.allows("bypass") is True  # qadağan deyil → açıq

    def test_passive_profile_disables_active_fuzz(self, load_config):
        cfg = _scope(load_config, ["example.com"],
                     extra={"aggressiveness": "passive"})
        auth = from_config(cfg)
        assert auth.allows("active_fuzz") is False

    def test_aggressive_profile_enables_active_fuzz(self, load_config):
        cfg = _scope(load_config, ["example.com"],
                     extra={"aggressiveness": "aggressive"})
        auth = from_config(cfg)
        assert auth.allows("active_fuzz") is True

    def test_passive_profile_disables_intrusive_templates(self, load_config):
        cfg = _scope(load_config, ["example.com"],
                     extra={"aggressiveness": "passive"})
        assert from_config(cfg).allows("intrusive_templates") is False

    def test_aggressive_profile_enables_intrusive_templates(self, load_config):
        cfg = _scope(load_config, ["example.com"],
                     extra={"aggressiveness": "aggressive"})
        assert from_config(cfg).allows("intrusive_templates") is True


# ---------------------------------------------------------------- lifecycle
class TestCancellationAndDeadline:
    def test_cancel_marks_cancelled_and_raises(self):
        auth = Authorization(scope=None)
        assert auth.is_cancelled() is False
        auth.cancel()
        assert auth.is_cancelled() is True
        with pytest.raises(ScanExpired):
            auth.ensure_active()

    def test_canceller_event_propagates(self):
        ev = asyncio.Event()
        auth = Authorization(scope=None, canceller=ev)
        ev.set()
        assert auth.is_cancelled() is True
        with pytest.raises(ScanExpired):
            auth.ensure_active()

    def test_deadline_expired(self):
        auth = Authorization(scope=None, deadline=time.time() - 1)
        assert auth.expired() is True
        with pytest.raises(ScanExpired):
            auth.ensure_active()

    def test_deadline_future_ok(self):
        auth = Authorization(scope=None, deadline=time.time() + 30)
        assert auth.expired() is False
        auth.ensure_active()  # atmalı deyil
        assert auth.remaining() is not None and auth.remaining() > 0

    def test_summary_shape(self, load_config):
        cfg = _scope(load_config, ["example.com"],
                     extra={"program_rules": {"forbidden": ["bypass"]}})
        auth = from_config(cfg, scan_id=7)
        s = auth.summary()
        assert s["scan_id"] == 7
        assert s["aggressiveness"] == "aggressive"
        assert "bypass" in s["forbidden"]
        assert s["cancelled"] is False
