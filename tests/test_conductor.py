"""Faza 2.1 — Conductor inteqrasiya testləri.

Yoxlanılan prinsiplər:
  * `_run_stage` HEÇ VAXT `None` qaytarmır; `EngineResult`-i `StageResult`-a
    düzgün çevirir (ok/skipped/failed) və xətanı səssizcə udmur.
  * `resolve_targets` fail-closed işləyir: scope xarici hədəf rədd edilir;
    hamısı rədd olunarsa `PipelineAbort` qalxır.
  * `_pipeline` skanı qeydə alır, MƏCBURİ subprocess egress qapısını
    aktivləşdirir, hesabat yaradır və son statusu (completed/partial/failed/
    cancelled) düzgün yazır.
  * `run_recon` / `run_vuln` mərhələləri gözlənilən sıra ilə çağırır;
    `_run_offensive` həm RoE (`active_fuzz`), həm Guardian nərdivanı
    qapılarına hörmət edir və atlandıqda bunu AÇIQ bildirir.

Heç bir test xarici şəbəkəyə müraciət etmir — yalnız `127.0.0.1` loopback
konfiqurasiyası və mock mühərriklər istifadə olunur.
"""
from __future__ import annotations

import argparse
import asyncio

import pytest

from qbh import conductor as conductor_mod
from qbh import db
from qbh.adapters.base import current_process_guard
from qbh.conductor import Conductor, PipelineAbort
from qbh.installer import ToolReport, ToolStatus
from qbh.results import EngineResult, StageResult, now_iso

# ------------------------------------------------------------------ helpers


def _scan_status(scan_id: int) -> str | None:
    row = db.get_db().execute(
        "SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
    return row["status"] if row else None


def _tool(name: str, *, required: bool = False, present: bool = True,
          install_kind: str = "manual") -> ToolStatus:
    return ToolStatus(name=name, required=required, present=present,
                      install_kind=install_kind)


def _report(tools: list[ToolStatus]) -> ToolReport:
    return ToolReport(os_ok=True, os_detail="Linux loopback",
                      go_available=False, go_version="", tools=tools)


def _args(**kw) -> argparse.Namespace:
    return argparse.Namespace(
        config="", mode=kw.pop("mode", "full"), aggressiveness=None,
        proxy=kw.pop("proxy", "off"), rate=kw.pop("rate", None),
        severity=kw.pop("severity", "low"),
        auto_install=kw.pop("auto_install", False),
        dry_run=kw.pop("dry_run", False),
        targets=kw.pop("targets", None),
        active_fuzz=kw.pop("active_fuzz", None),
        race_fixture=kw.pop("race_fixture", None),
        race_count=kw.pop("race_count", 10),
        race_concurrency=kw.pop("race_concurrency", 4),
    )


@pytest.fixture
def make_conductor(tmp_db, loopback_config):
    """Loopback konfiq üzərində real `Conductor` qurur (şəbəkəsiz)."""
    def _make(cfg=None, **kw) -> Conductor:
        return Conductor(cfg or loopback_config, _args(**kw))
    return _make


def _stage(name: str, status: str = "ok", **kw) -> StageResult:
    return StageResult(stage=name, status=status, started_at=now_iso(), **kw)


# --------------------------------------------------------------- _run_stage


class TestRunStage:
    async def test_ok_result_is_recorded_and_counts_findings(self, make_conductor):
        c = make_conductor()

        async def factory():
            return EngineResult(stage="x", ok=True, findings=3)

        sr = await c._run_stage("x", "127.0.0.1", factory)
        assert sr.status == "ok"
        assert sr.findings_count == 3
        assert c.stages == [sr]
        assert sr.duration >= 0.0

    async def test_skip_maps_to_skipped_status(self, make_conductor):
        c = make_conductor()

        async def factory():
            res = EngineResult(stage="y", ok=True)
            return res.skip("alət yoxdur")

        sr = await c._run_stage("y", "", factory)
        assert sr.status == "skipped"
        assert any("alət yoxdur" in w for w in sr.warnings)

    async def test_fail_maps_to_failed_status(self, make_conductor):
        c = make_conductor()

        async def factory():
            res = EngineResult(stage="z", ok=True)
            res.fail("partladı")
            return res

        sr = await c._run_stage("z", "", factory)
        assert sr.status == "failed"
        assert any("partladı" in e for e in sr.errors)

    async def test_exception_is_caught_not_swallowed(self, make_conductor):
        c = make_conductor()

        async def factory():
            raise ValueError("gözlənilməz")

        sr = await c._run_stage("boom", "", factory)
        assert sr.status == "failed"
        assert any("gözlənilməz" in e for e in sr.errors)
        assert c.failed_stages == [sr]

    async def test_cancelled_error_is_reraised_and_recorded(self, make_conductor):
        c = make_conductor()

        async def factory():
            raise asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            await c._run_stage("cancel", "", factory)
        assert c.stages[0].status == "cancelled"

    async def test_non_engine_result_maps_to_ok(self, make_conductor):
        c = make_conductor()

        async def factory():
            return None

        sr = await c._run_stage("plain", "", factory)
        assert sr.status == "ok"

    async def test_record_failure_is_not_fatal(self, make_conductor, monkeypatch,
                                               capsys):
        c = make_conductor()
        c.scan_id = db.start_scan("test", "full")

        def boom(*a, **k):
            raise RuntimeError("db bağlıdır")

        monkeypatch.setattr(db, "record_stage", boom)

        async def factory():
            return EngineResult(stage="x", ok=True)

        sr = await c._run_stage("x", "", factory)
        assert sr.status == "ok"
        assert "qeydə alına bilmədi" in capsys.readouterr().out

    async def test_record_writes_stage_row(self, make_conductor):
        c = make_conductor()
        c.scan_id = db.start_scan("test", "full")

        async def factory():
            return EngineResult(stage="x", ok=True)

        await c._run_stage("x", "127.0.0.1", factory)
        row = db.get_db().execute(
            "SELECT status FROM stage_status WHERE scan_id=? AND module=?",
            (c.scan_id, "x")).fetchone()
        assert row["status"] == "ok"


# ---------------------------------------------------------- resolve_targets


class TestResolveTargets:
    def test_in_scope_target_accepted(self, make_conductor):
        c = make_conductor(targets="127.0.0.1")
        assert c.resolve_targets() == ["127.0.0.1"]
        assert c.authorized_targets == ["127.0.0.1"]

    def test_out_of_scope_target_aborts(self, make_conductor):
        c = make_conductor(targets="evil.example.com")
        with pytest.raises(PipelineAbort):
            c.resolve_targets()

    def test_mixed_targets_keep_only_in_scope(self, make_conductor):
        c = make_conductor(targets="127.0.0.1,evil.example.com")
        assert c.resolve_targets() == ["127.0.0.1"]

    def test_duplicates_are_collapsed(self, make_conductor):
        c = make_conductor(targets="127.0.0.1,127.0.0.1")
        assert c.resolve_targets() == ["127.0.0.1"]

    def test_blank_entries_ignored(self, make_conductor):
        c = make_conductor(targets="  ,127.0.0.1, ")
        assert c.resolve_targets() == ["127.0.0.1"]

    def test_falls_back_to_config_targets(self, make_conductor):
        c = make_conductor(targets=None)
        assert c.resolve_targets() == ["127.0.0.1"]


# ------------------------------------------------------------------ pipeline


class TestPipeline:
    async def test_completes_and_finishes_scan(self, make_conductor, monkeypatch):
        c = make_conductor()
        generated = []
        monkeypatch.setattr(c, "generate_report",
                            lambda: generated.append(True) or "r.md")
        seen = {}

        async def body():
            seen["guard"] = current_process_guard()
            seen["scan_id"] = c.scan_id

        await c._pipeline("full", body)
        assert seen["guard"] is not None          # egress qapısı aktiv idi
        assert current_process_guard() is None    # context-dən sonra sıfırlandı
        assert seen["scan_id"] == c.scan_id
        assert generated == [True]
        assert _scan_status(c.scan_id) == "completed"

    async def test_partial_when_some_stages_fail(self, make_conductor,
                                                 monkeypatch):
        c = make_conductor()
        monkeypatch.setattr(c, "generate_report", lambda: "r")

        async def body():
            c.stages.append(_stage("a", "ok"))
            c.stages.append(_stage("b", "failed"))

        await c._pipeline("full", body)
        assert _scan_status(c.scan_id) == "partial"

    async def test_failed_when_all_stages_fail(self, make_conductor, monkeypatch):
        c = make_conductor()
        monkeypatch.setattr(c, "generate_report", lambda: "r")

        async def body():
            c.stages.append(_stage("a", "failed"))
            c.stages.append(_stage("b", "failed"))

        await c._pipeline("full", body)
        assert _scan_status(c.scan_id) == "failed"

    async def test_cancel_is_recorded_and_audited(self, make_conductor,
                                                  monkeypatch):
        c = make_conductor()
        monkeypatch.setattr(c, "generate_report", lambda: "r")
        cancelled = []
        monkeypatch.setattr(c.authorization, "cancel",
                            lambda: cancelled.append(True))

        async def body():
            raise asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            await c._pipeline("full", body)
        assert cancelled == [True]
        assert _scan_status(c.scan_id) == "cancelled"

    async def test_report_generated_even_if_body_raises(self, make_conductor,
                                                        monkeypatch):
        c = make_conductor()
        generated = []
        monkeypatch.setattr(c, "generate_report",
                            lambda: generated.append(True) or "r")

        async def body():
            raise RuntimeError("gözlənilməyən çökmə")

        with pytest.raises(RuntimeError):
            await c._pipeline("full", body)
        assert generated == [True]                 # finally bloku işlədi
        assert _scan_status(c.scan_id) == "completed"


# -------------------------------------------------------------- run_modes


class TestRunModes:
    async def test_run_full_calls_recon_then_vuln(self, make_conductor,
                                                  monkeypatch):
        c = make_conductor()
        order = []

        async def fake_recon():
            order.append("recon")

        async def fake_vuln():
            order.append("vuln")

        monkeypatch.setattr(c, "run_recon", fake_recon)
        monkeypatch.setattr(c, "run_vuln", fake_vuln)
        monkeypatch.setattr(c, "generate_report", lambda: "r")
        await c.run_full()
        assert order == ["recon", "vuln"]

    async def test_run_recon_mode_uses_pipeline(self, make_conductor,
                                                monkeypatch):
        c = make_conductor()
        called = []

        async def fake_recon():
            called.append(True)

        monkeypatch.setattr(c, "run_recon", fake_recon)
        monkeypatch.setattr(c, "generate_report", lambda: "r")
        await c.run_recon_mode()
        assert called == [True]
        assert _scan_status(c.scan_id) == "completed"

    async def test_run_vuln_mode_resolves_targets_first(self, make_conductor,
                                                        monkeypatch):
        c = make_conductor(targets="127.0.0.1")
        order = []
        monkeypatch.setattr(c, "resolve_targets",
                            lambda: order.append("resolve") or ["127.0.0.1"])

        async def fake_vuln():
            order.append("vuln")

        monkeypatch.setattr(c, "run_vuln", fake_vuln)
        monkeypatch.setattr(c, "generate_report", lambda: "r")
        await c.run_vuln_mode()
        assert order == ["resolve", "vuln"]

    async def test_run_recon_invokes_expected_stages(self, make_conductor,
                                                     monkeypatch):
        c = make_conductor()
        calls = []

        async def fake_ensure():
            return None

        monkeypatch.setattr(c, "_ensure_tools", fake_ensure)

        async def rec(stage, target, factory):
            calls.append((stage, target))
            data = {"subdomains": {"sub.127.0.0.1"}} if stage == "deep_enum" \
                else {}
            return StageResult(stage=stage, status="ok", started_at=now_iso(),
                               data=data)

        monkeypatch.setattr(c, "_run_stage", rec)
        await c.run_recon()
        stages = [s for s, _ in calls]
        for expected in ("deep_enum", "recon", "bbot", "waymore", "dnstwist"):
            assert expected in stages
        assert ("gowitness", "") in calls   # inventar canlı hostlardan SONRA

    async def test_run_vuln_invokes_expected_stages(self, make_conductor,
                                                    monkeypatch):
        c = make_conductor()
        calls = []

        async def fake_ensure():
            return None

        monkeypatch.setattr(c, "_ensure_tools", fake_ensure)

        async def rec(stage, target, factory):
            calls.append(stage)
            return StageResult(stage=stage, status="ok", started_at=now_iso())

        monkeypatch.setattr(c, "_run_stage", rec)
        await c.run_vuln()
        for expected in ("fingerprint", "wafdetect", "vuln", "js", "content",
                         "ferox", "api_enum", "api_fuzz", "param_enum",
                         "race", "cve_intel", "library_cve", "validation",
                         "chain"):
            assert expected in calls
        # offensive mühərriklər (default aggressive profil → aktivdir)
        assert "sqli" in calls and "xss" in calls

    async def test_run_chain_uses_chain_pipeline(self, make_conductor,
                                                 monkeypatch):
        import qbh.chain as chain_mod

        class FakePipeline:
            def __init__(self, ctx):
                self.ctx = ctx

            async def run(self):
                return "CHAIN_RESULT"

            def audit(self):
                return {"steps": 1}

        monkeypatch.setattr(chain_mod, "ChainPipeline", FakePipeline)
        c = make_conductor()
        assert await c._run_chain() == "CHAIN_RESULT"
        assert c.chain is not None


# ------------------------------------------------------------ _run_offensive


class TestRunOffensive:
    async def test_active_fuzz_forbidden_by_roe_skips_intrusive(self,
                                                                make_conductor,
                                                                load_config,
                                                                monkeypatch,
                                                                capsys):
        cfg = load_config(
            [{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
              "out_of_scope": []}],
            extra={"program_rules": {"forbidden": ["active_fuzz"]}})
        c = make_conductor(cfg=cfg)
        calls = []

        async def rec(stage, target, factory):
            calls.append(stage)
            return StageResult(stage=stage, status="ok", started_at=now_iso())

        monkeypatch.setattr(c, "_run_stage", rec)
        assert c.ctx.allows("active_fuzz") is False
        await c._run_offensive()
        assert calls == ["sqli", "xss"]
        assert "aktiv fuzz qadağandır" in capsys.readouterr().out

    async def test_guardian_ladder_defers_intrusive(self, make_conductor,
                                                    monkeypatch, capsys):
        c = make_conductor()
        # Nərdivanı 5-ci səviyyəyə qaldır → intrusiv fazalar təxirə salınır.
        c.guardian.ladder.level = 5
        assert c.guardian.allows_intrusive() is False
        calls = []

        async def rec(stage, target, factory):
            calls.append(stage)
            return StageResult(stage=stage, status="ok", started_at=now_iso())

        monkeypatch.setattr(c, "_run_stage", rec)
        await c._run_offensive()
        assert calls == []
        assert "təxirə salıb" in capsys.readouterr().out

    async def test_intrusive_engines_run_when_allowed(self, make_conductor,
                                                      monkeypatch):
        c = make_conductor()
        calls = []

        async def rec(stage, target, factory):
            calls.append(stage)
            return StageResult(stage=stage, status="ok", started_at=now_iso())

        monkeypatch.setattr(c, "_run_stage", rec)
        await c._run_offensive()
        assert calls == ["sqli", "xss", "ssti", "ssrf", "jwt", "sourcecode"]


# ---------------------------------------------------------------- reporting


class TestGenerateReport:
    def test_passes_expected_meta(self, make_conductor, monkeypatch):
        c = make_conductor()
        c.authorized_targets = ["127.0.0.1"]
        c.scan_id = 42
        captured = {}

        def fake_generate(**kw):
            captured.update(kw)
            return "/tmp/report.md"

        monkeypatch.setattr(conductor_mod.generator, "generate", fake_generate)
        assert c.generate_report() == "/tmp/report.md"
        assert captured["severity_min"] == "low"
        meta = captured["meta"]
        assert meta["program"] == "test"
        assert meta["scan_id"] == 42
        assert meta["targets"] == ["127.0.0.1"]
        assert meta["mode"] == "full"
        assert meta["rate"] == c.ctx.rate
        assert "block_audit" in meta and "ladder" in meta and "stealth" in meta

    def test_swallows_generator_failure(self, make_conductor, monkeypatch,
                                        capsys):
        c = make_conductor()

        def boom(**kw):
            raise RuntimeError("disk dolub")

        monkeypatch.setattr(conductor_mod.generator, "generate", boom)
        assert c.generate_report() is None
        assert "Hesabat yaradıla bilmədi" in capsys.readouterr().out


class TestSummary:
    def test_failed_stages_property(self, make_conductor):
        c = make_conductor()
        c.stages = [_stage("a", "ok"), _stage("b", "failed")]
        assert [s.stage for s in c.failed_stages] == ["b"]

    def test_print_summary_lists_stages(self, make_conductor, capsys):
        c = make_conductor()
        c.stages.append(_stage("x", "ok", findings_count=2, duration=0.5))
        c.print_summary()
        out = capsys.readouterr().out
        assert "İCRA XÜLASƏSİ" in out
        assert "x" in out

    def test_print_summary_empty(self, make_conductor, capsys):
        c = make_conductor()
        c.print_summary()
        assert "icra olunmadı" in capsys.readouterr().out

    def test_print_summary_reports_guardian_events(self, make_conductor,
                                                   monkeypatch, capsys):
        c = make_conductor()
        monkeypatch.setattr(c.guardian, "summary", lambda: {
            "blocks": 2, "blocked_hosts": ["127.0.0.1"], "rotations": 1,
            "ladder": {"level": 3, "action": "waf_adapt_backoff"}})
        c.print_summary()
        out = capsys.readouterr().out
        assert "blok hadisəsi" in out
        assert "rotasiyası" in out
        assert "nərdivanı" in out

    def test_print_summary_reports_detected_waf(self, make_conductor, capsys):
        from qbh.stealth.waf import WafProfile

        c = make_conductor()
        c.ctx.stealth.waf = WafProfile(name="Cloudflare", confidence=0.9)
        c.print_summary()
        assert "WAF: Cloudflare" in capsys.readouterr().out


class TestInit:
    def test_cli_rate_is_capped_by_profile(self, make_conductor):
        c = make_conductor(rate=2)
        assert c.policy.rate <= c.cfg.effective_rate


# --------------------------------------------------------------- tool phase


class TestToolPhase:
    async def test_ensure_tools_runs_detection_once(self, make_conductor,
                                                    monkeypatch):
        c = make_conductor()
        calls = []

        async def fake_check(only=None):
            calls.append(True)
            return _report([_tool("nuclei", required=True, present=True)])

        monkeypatch.setattr(conductor_mod, "check_tools", fake_check)
        await c._ensure_tools()
        await c._ensure_tools()
        assert len(calls) == 1
        assert c.tool_report is not None

    async def test_ensure_tools_auto_install_path(self, make_conductor,
                                                  monkeypatch):
        c = make_conductor(auto_install=True)
        report = _report([_tool("nuclei", required=True, present=False)])
        dry_runs = []

        async def fake_check(only=None):
            return report

        async def fake_install(rep, *, dry_run=False):
            dry_runs.append(dry_run)
            return rep

        monkeypatch.setattr(conductor_mod, "check_tools", fake_check)
        monkeypatch.setattr(conductor_mod, "install_tools", fake_install)
        monkeypatch.setattr(conductor_mod, "format_report", lambda r: "")
        await c._ensure_tools()
        assert dry_runs == [False]     # args.dry_run False → real qurulum cəhdi

    async def test_ensure_tools_missing_without_auto_install(self,
                                                             make_conductor,
                                                             monkeypatch,
                                                             capsys):
        c = make_conductor(auto_install=False)
        report = _report([_tool("nuclei", required=True, present=False)])

        async def fake_check(only=None):
            return report

        monkeypatch.setattr(conductor_mod, "check_tools", fake_check)
        await c._ensure_tools()
        assert "--mode install --auto-install" in capsys.readouterr().out

    async def test_install_only_returns_zero_when_required_present(
            self, make_conductor, monkeypatch):
        c = make_conductor()
        report = _report([_tool("nuclei", required=True, present=True)])
        dry_runs = []

        async def fake_check(only=None):
            return report

        async def fake_install(rep, *, dry_run=False):
            dry_runs.append(dry_run)
            return rep

        monkeypatch.setattr(conductor_mod, "check_tools", fake_check)
        monkeypatch.setattr(conductor_mod, "install_tools", fake_install)
        monkeypatch.setattr(conductor_mod, "format_report", lambda r: "")
        assert await c.install_only() == 0
        assert dry_runs == [True]      # default: dry-run (auto-install yoxdur)

    async def test_install_only_returns_one_when_required_missing(
            self, make_conductor, monkeypatch):
        c = make_conductor()
        report = _report([_tool("nuclei", required=True, present=False)])

        async def fake_check(only=None):
            return report

        async def fake_install(rep, *, dry_run=False):
            return rep

        monkeypatch.setattr(conductor_mod, "check_tools", fake_check)
        monkeypatch.setattr(conductor_mod, "install_tools", fake_install)
        monkeypatch.setattr(conductor_mod, "format_report", lambda r: "")
        assert await c.install_only() == 1
