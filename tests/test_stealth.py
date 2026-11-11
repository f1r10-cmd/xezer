"""Faza 2 stealth qatı testləri — `qbh/stealth/`.

Yoxlanılan prinsiplər:
  * `detect_waf` başlıq/cookie/gövdə imzalarını düzgün tutuşdurur; tanınmayan
    cavab üçün DÜRÜST şəkildə `none` qaytarır (sübutsuz "WAF var" iddiası yox).
  * WAF identikliyi `tamper_for`/`encodings_for`/`rate_factor_for` qərarlarına
    çevrilir (SQLi tamper, bypass sırası, subprocess rate azaltma).
  * `EscalationLadder` addım-addım eskalasiya edir və uğurda histerezis ilə enir.
  * `plan_proxy` Tor-u YALNIZ həssas fazalarda işə salır (bulk sürəti qorunur).
  * `Pacer` heç vaxt `pacing_max_overhead` büdcəsini AŞMIR (sürət müqaviləsi).
  * `ImpersonatingTransport` mövcud deyilsə dürüst şəkildə bildirir və heç vaxt
    saxta "təqlid edirik" iddiası vermir.

Heç bir test xarici hədəfə müraciət etmir.
"""
from __future__ import annotations

import random

import pytest

from qbh.stealth import (EscalationLadder, ImpersonatingTransport, Pacer,
                         StealthStack, WafProfile, detect_waf, encodings_for,
                         impersonation_available, is_sensitive_phase,
                         plan_proxy, rate_factor_for, resolve_target, tamper_for)
from qbh.stealth.ladder import LEVELS, MAX_LEVEL


# --------------------------------------------------------------------- WAF
class TestWafDetect:
    def test_cloudflare_by_header(self):
        prof = detect_waf(status=403, headers={"CF-Ray": "8f1", "Server": "x"})
        assert prof.name == "cloudflare"
        assert prof.detected is True
        assert prof.confidence > 0.0

    def test_cloudflare_by_body(self):
        prof = detect_waf(status=403,
                          body="Attention Required! | Cloudflare")
        assert prof.name == "cloudflare"

    def test_imperva_by_cookie(self):
        prof = detect_waf(headers={"Set-Cookie": "visid_incap_123=abc; Path=/"})
        assert prof.name == "imperva"

    def test_akamai_by_body(self):
        prof = detect_waf(body="Reference #18.abcd1234")
        assert prof.name == "akamai"

    def test_generic_block_page(self):
        prof = detect_waf(status=403, body="Access denied")
        assert prof.name == "generic"

    def test_unknown_returns_none_honestly(self):
        prof = detect_waf(status=200, headers={"Server": "nginx"}, body="hello")
        assert prof.name == "none"
        assert prof.detected is False
        assert prof.confidence == 0.0

    def test_confidence_is_capped(self):
        prof = detect_waf(
            status=403,
            headers={"CF-Ray": "x", "CF-Cache-Status": "HIT",
                     "Server": "cloudflare"},
            body="cf-error-details __cf_chl_ Attention Required! | Cloudflare")
        assert prof.confidence <= 0.95

    def test_to_dict_shape(self):
        prof = detect_waf(headers={"CF-Ray": "x"})
        d = prof.to_dict()
        assert set(d) == {"name", "confidence", "evidence", "status"}
        assert isinstance(d["evidence"], list)


class TestWafDecisions:
    def test_tamper_for_cloudflare(self):
        assert tamper_for("cloudflare") == [
            "space2comment", "randomcase", "charencode"]

    def test_tamper_case_insensitive(self):
        assert tamper_for("CloudFlare") == tamper_for("cloudflare")

    def test_tamper_unknown_and_empty(self):
        assert tamper_for("") == []
        assert tamper_for("nonesuch") == []

    def test_encodings_for_cloudflare_order(self):
        tricks = encodings_for("cloudflare")
        assert tricks and tricks[0] == "path-upper"

    def test_encodings_unknown_empty(self):
        assert encodings_for("") == []

    def test_rate_factor_known(self):
        assert rate_factor_for("imperva") == 0.4
        assert rate_factor_for("cloudflare") == 0.5

    def test_rate_factor_defaults(self):
        assert rate_factor_for("") == 1.0
        assert rate_factor_for("nonesuch") == 0.75


# ------------------------------------------------------------------- ladder
class TestEscalationLadder:
    def test_first_429_with_retry_after_is_level_1(self):
        ladder = EscalationLadder()
        dec = ladder.on_block(429, retry_after=30)
        assert dec.level == 1
        assert dec.action == "respect_retry_after"
        assert dec.rate_factor == 1.0
        assert dec.defer_intrusive is False

    def test_first_403_skips_to_rotation(self):
        ladder = EscalationLadder()
        dec = ladder.on_block(403)
        assert dec.level == 2
        assert dec.action == "rotate_identity"

    def test_escalation_path_to_defer(self):
        ladder = EscalationLadder()
        ladder.on_block(429, retry_after=5)   # level 1
        assert ladder.on_block(403).action == "waf_adapt_backoff"  # level 3
        assert ladder.on_block(403).action == "stealth_mode"       # level 4
        dec = ladder.on_block(403)                                  # level 5
        assert dec.action == "defer_intrusive"
        assert dec.defer_intrusive is True
        assert ladder.allows_intrusive() is False

    def test_capped_at_max_level(self):
        ladder = EscalationLadder()
        for _ in range(10):
            dec = ladder.on_block(403)
        assert dec.level == MAX_LEVEL

    def test_success_hysteresis(self):
        ladder = EscalationLadder()
        for _ in range(4):
            ladder.on_block(403)
        assert ladder.level == MAX_LEVEL
        # hər uğur bir pillə aşağı (blok sayı azalır).
        ladder.on_success()
        ladder.on_success()
        ladder.on_success()
        ladder.on_success()
        assert ladder.level == 0
        assert ladder.allows_intrusive() is True

    def test_reset(self):
        ladder = EscalationLadder()
        ladder.on_block(403)
        ladder.reset()
        assert ladder.level == 0
        assert ladder.blocks == 0

    def test_rate_factor_and_state_shape(self):
        ladder = EscalationLadder()
        ladder.on_block(429, retry_after=1)
        ladder.on_block(403)
        assert ladder.rate_factor == LEVELS[3][1]
        st = ladder.state()
        assert set(st) == {"level", "blocks", "action", "rate_factor",
                           "defer_intrusive"}
        assert isinstance(ladder.history, list) and ladder.history

    def test_no_blocks_allows_intrusive(self):
        assert EscalationLadder().allows_intrusive() is True


# -------------------------------------------------------------------- proxy
class TestProxyStrategy:
    def test_off_is_direct(self):
        plan = plan_proxy("off", "recon")
        assert plan.effective == "direct"
        assert plan.use_tor is False

    def test_tor_downgraded_on_bulk_phase(self):
        plan = plan_proxy("tor", "recon")
        assert plan.effective == "direct"
        assert plan.use_tor is False
        assert "bulk" in plan.reason or "sürəti" in plan.reason

    def test_tor_active_on_sensitive_phase(self):
        plan = plan_proxy("tor", "poc")
        assert plan.effective == "tor"
        assert plan.use_tor is True

    def test_tor_forced_when_constraint_disabled(self):
        plan = plan_proxy("tor", "recon", tor_for_sensitive_only=False)
        assert plan.effective == "tor"

    def test_single_rotate_residential(self):
        assert plan_proxy("single", "recon").effective == "single"
        assert plan_proxy("rotate", "recon").rotate is True
        res = plan_proxy("residential", "recon")
        assert res.residential is True and res.rotate is True

    def test_unknown_strategy_falls_back_to_off(self):
        assert plan_proxy("bogus", "recon").effective == "direct"

    def test_is_sensitive_phase(self):
        assert is_sensitive_phase("poc") is True
        assert is_sensitive_phase("recon") is False
        assert is_sensitive_phase("unknown-phase") is False

    def test_to_dict_shape(self):
        d = plan_proxy("tor", "poc").to_dict()
        assert set(d) == {"strategy", "effective", "use_tor", "rotate",
                          "residential", "phase", "reason"}


# ------------------------------------------------------------------- pacing
class TestPacer:
    def test_budget_formula(self):
        p = Pacer(profile="aggressive", rate=5.0, max_overhead=1.15)
        assert p.budget == pytest.approx((1.15 - 1.0) / 5.0)

    def test_delay_never_exceeds_budget(self):
        p = Pacer(profile="passive", rate=2.0, max_overhead=1.2,
                  rng=random.Random(7))
        for _ in range(300):
            assert p.delay() <= p.budget + 1e-9

    def test_zero_budget_when_overhead_is_one(self):
        p = Pacer(profile="passive", rate=5.0, max_overhead=1.0)
        assert p.budget == 0.0
        assert p.delay() == 0.0

    def test_stats_within_budget(self):
        p = Pacer(profile="normal", rate=4.0, max_overhead=1.15,
                  rng=random.Random(3))
        for _ in range(200):
            p.delay()
        st = p.stats()
        assert st["count"] == 200
        assert st["within_budget"] is True
        assert st["avg_delay"] <= st["budget"] + 1e-9
        assert 0.0 <= st["avg_delay"] <= st["budget"]
        assert st["profile"] == "normal"

    def test_invalid_profile_falls_back(self):
        p = Pacer(profile="nonesuch")
        assert p.profile == "aggressive"

    async def test_wait_returns_delay(self):
        p = Pacer(profile="aggressive", rate=1000.0, max_overhead=1.15)
        got = await p.wait()
        assert 0.0 <= got <= p.budget + 1e-9


# ------------------------------------------------------------ impersonation
class TestImpersonation:
    def test_resolve_known_browser(self):
        assert resolve_target("chrome") == "chrome131"

    def test_resolve_off_and_unknown(self):
        assert resolve_target("off") is None
        assert resolve_target("nonesuch") is None
        assert resolve_target("") is None

    def test_availability_is_bool(self):
        assert isinstance(impersonation_available(), bool)

    def test_transport_off_is_disabled(self):
        t = ImpersonatingTransport("off")
        assert t.enabled is False
        assert t.available is False
        assert t.summary()["reason"] == "təqlid söndürülüb"

    def test_transport_summary_is_honest_when_lib_missing(self):
        t = ImpersonatingTransport("chrome")
        assert t.enabled is True
        if not impersonation_available():
            assert t.available is False
            assert "curl_cffi" in t.summary()["reason"]

    async def test_request_raises_when_unavailable(self):
        if impersonation_available():
            pytest.skip("curl_cffi quraşdırılıb — mövcudluq testi keçilir")
        t = ImpersonatingTransport("chrome")
        with pytest.raises(RuntimeError):
            await t.request("GET", "http://127.0.0.1/")

    async def test_request_off_raises(self):
        t = ImpersonatingTransport("off")
        with pytest.raises(RuntimeError):
            await t.request("GET", "http://127.0.0.1/")


# ------------------------------------------------------------ stealth stack
class TestStealthStack:
    def test_empty_has_no_waf(self):
        assert StealthStack().waf_name == ""

    def test_note_waf_ignores_undetected(self):
        stack = StealthStack()
        stack.note_waf(WafProfile(name="none"))
        assert stack.waf_name == ""
        assert stack.audit == []

    def test_note_waf_records(self):
        stack = StealthStack()
        stack.note_waf(detect_waf(headers={"CF-Ray": "x"}))
        assert stack.waf_name == "cloudflare"
        assert stack.audit[-1]["event"] == "waf_detected"

    def test_keeps_strongest_profile(self):
        stack = StealthStack()
        stack.note_waf(WafProfile(name="akamai", confidence=0.9))
        stack.note_waf(WafProfile(name="cloudflare", confidence=0.4))
        assert stack.waf_name == "akamai"

    def test_proxy_plan_uses_config(self):
        from qbh.config import StealthConfig

        stack = StealthStack(cfg=StealthConfig(proxy_strategy="tor"))
        assert stack.proxy_plan("poc").use_tor is True
        assert stack.proxy_plan("recon").use_tor is False

    def test_summary_shape(self):
        s = StealthStack().summary()
        assert set(s) == {"impersonate", "pacing", "waf"}
