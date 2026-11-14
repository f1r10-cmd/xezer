"""Mühərrik kontrakt və təhlükəsizlik qapısı testləri.

Yoxlanılan prinsiplər:
  * Hər mühərrik `EngineResult` qaytarır — HEÇ VAXT `None` deyil.
  * Boş baza (host yoxdur) halında mühərriklər xəta atmadan `skipped`
    qaytarır (xarici alət çağırışı baş vermir).
  * Scope qapısı MÜHƏRRİK sərhədində işləyir: scope xarici domain
    `fail` ilə rədd olunur, alət işə salınmır.
  * Dağıdıcı mühərriklər (race, api_fuzz) default olaraq DEAKTİVDİR.
  * Heç bir test xarici hədəfə müraciət etmir.
"""
from __future__ import annotations

import json

import pytest

from qbh.results import EngineResult

# ---------------------------------------------------------------- kontrakt
#: (modul, sinif adı, `run` üçün arqumentlər)
#: deep_enum/recon scope xarici domain ilə çağırılır → mühərrik HEÇ BİR alət
#: və ya şəbəkə əməliyyatına keçmədən `fail` qaytarır (təhlükəsiz kontrakt).
ENGINE_SPECS = [
    ("qbh.engines.deep_enum", "DeepEnumEngine", ("evil.example.com",)),
    ("qbh.engines.recon", "ReconEngine", ("evil.example.com",)),
    ("qbh.engines.fingerprint", "FingerprintEngine", ()),
    ("qbh.engines.vuln", "VulnEngine", ()),
    ("qbh.engines.jsanalysis", "JSAnalysisEngine", ()),
    ("qbh.engines.content", "ContentEngine", ()),
    ("qbh.engines.ferox", "FeroxEngine", ()),
    ("qbh.engines.api_enum", "APIEnumEngine", ()),
    ("qbh.engines.api_fuzz", "APIFuzzEngine", ()),
    ("qbh.engines.param_enum", "ParamEnumEngine", ()),
    ("qbh.engines.race", "RaceEngine", ()),
    ("qbh.engines.validation", "ValidationEngine", ()),
]


def _load(mod_path: str, cls_name: str):
    import importlib

    mod = importlib.import_module(mod_path)
    return getattr(mod, cls_name)


class TestEngineContract:
    """Boş baza ilə hər mühərrik təhlükəsiz şəkildə nəticə qaytarmalıdır."""

    @pytest.mark.parametrize("mod_path,cls_name,extra", ENGINE_SPECS)
    async def test_returns_engine_result(self, tmp_db, make_ctx,
                                         mod_path, cls_name, extra):
        cls = _load(mod_path, cls_name)
        engine = cls(make_ctx())
        result = await engine.run(*extra)
        assert isinstance(result, EngineResult)
        assert result.stage == engine.name
        assert result.ok is not False or result.errors  # fail → səbəb var

    @pytest.mark.parametrize("mod_path,cls_name,extra", ENGINE_SPECS)
    async def test_no_exception_on_empty_db(self, tmp_db, make_ctx,
                                            mod_path, cls_name, extra):
        """Boş bazada heç bir mühərrik gözlənilməz istisna atmamalıdır."""
        cls = _load(mod_path, cls_name)
        result = await cls(make_ctx()).run(*extra)
        assert isinstance(result, EngineResult)

    async def test_cve_intel_module_level_run(self, tmp_db, make_ctx):
        """cve_intel funksiya-əsaslı `run(ctx)` kontraktına malikdir."""
        from qbh.engines import cve_intel

        result = await cve_intel.run(make_ctx())
        assert isinstance(result, EngineResult)
        assert result.skipped is True  # yaşayan host yoxdur


class TestSafetyGates:
    """Dağıdıcı/qeyri-təhlükəsiz funksiyaların default qapalı olması."""

    async def test_race_disabled_without_fixture(self, tmp_db, make_ctx):
        from qbh.engines.race import RaceEngine

        res = await RaceEngine(make_ctx(race_fixture=None)).run()
        assert res.skipped is True
        assert res.ok is True

    async def test_race_rejects_non_loopback_fixture(self, tmp_db, make_ctx):
        from qbh.engines.race import RaceEngine

        res = await RaceEngine(make_ctx(race_fixture="http://evil.example.com/race")).run()
        assert res.ok is False
        assert any("loopback" in e for e in res.errors)

    async def test_api_fuzz_requires_active_flag(self, tmp_db, make_ctx):
        from qbh.engines.api_fuzz import APIFuzzEngine

        res = await APIFuzzEngine(make_ctx(active_fuzz=False)).run()
        assert res.skipped is True
        assert any("active-fuzz" in w for w in res.warnings)


class TestVulnTemplateProfile:
    """`intrusive_templates` profil açarı nuclei istisna siyahısına təsir edir."""

    def test_aggressive_uses_minimal_excludes(self, tmp_db, make_ctx):
        from qbh.engines.vuln import DESTRUCTIVE_ONLY, VulnEngine

        assert VulnEngine(make_ctx())._exclude_tags() == DESTRUCTIVE_ONLY

    def test_passive_uses_broad_excludes(self, tmp_db, make_ctx, load_config):
        from qbh.engines.vuln import EXCLUDE_TAGS, VulnEngine

        cfg = load_config([
            {"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
             "out_of_scope": []}], extra={"aggressiveness": "passive"})
        assert VulnEngine(make_ctx(cfg))._exclude_tags() == EXCLUDE_TAGS


class TestEngineScopeBoundary:
    """Scope qapısı mühərrik sərhədində MÜTLƏQ tətbiq olunur."""

    async def test_deep_enum_out_of_scope_fails(self, tmp_db, make_ctx):
        from qbh.engines.deep_enum import DeepEnumEngine

        res = await DeepEnumEngine(make_ctx()).run("evil.example.com")
        assert res.ok is False
        assert any("scope" in e.lower() for e in res.errors)

    async def test_recon_out_of_scope_fails(self, tmp_db, make_ctx):
        from qbh.engines.recon import ReconEngine

        res = await ReconEngine(make_ctx()).run("evil.example.com")
        assert res.ok is False
        assert any("scope" in e.lower() for e in res.errors)

    async def test_recon_rejects_out_of_scope_subdomains(self, tmp_db, make_ctx):
        """Scope-daxili domain, scope xarici subdomain-lərlə → heç biri keçməz."""
        from qbh.engines.recon import ReconEngine

        # 127.0.0.1 scope-dadır, amma aşağıdakı subdomain-lər deyil.
        res = await ReconEngine(make_ctx()).run(
            "127.0.0.1", subdomains=["evil.example.com", "attacker.test"])
        assert res.ok is False
        assert any("scope-daxili" in e for e in res.errors)


class TestEngineResultShape:
    """`EngineResult` açıq uğur/uğursuzluq semantikasına malikdir."""

    def test_defaults(self):
        r = EngineResult(stage="demo")
        assert r.ok is True
        assert r.skipped is False
        assert r.findings == 0
        assert r.errors == [] and r.warnings == []

    def test_fail_sets_not_ok_and_records_error(self):
        r = EngineResult(stage="demo").skip("yox")
        assert r.skipped is True
        r.fail("qırıldı")
        assert r.ok is False
        assert "qırıldı" in r.errors


# ======================================================================
# M3 Nuclei — icra nəticəsi, host uyğunlaşdırması, template konfiqi
# ======================================================================


def _vuln_ctx(make_ctx, cfg=None, scan_id=1):
    """Real `Context` + avtorizasiya (loopback) qurur."""
    from qbh.authorization import from_config

    ctx = make_ctx(cfg)
    ctx.authorization = from_config(ctx.cfg, scan_id)
    ctx.scan_id = scan_id
    return ctx


def _seed_host(sub="127.0.0.1", scan_id=1, strategy="generic", status=200):
    from qbh import db

    return db.upsert_host(sub, scan_id=scan_id, status_code=status,
                          strategy=strategy)


def _nuclei_line(host, *, template_id="demo-tpl", name="Demo nəticə",
                 severity="high", tags=None, matched=None, desc=""):
    """Nuclei `-jsonl` sətri (real gedişə uyğun minimal)."""
    import json as _json

    return _json.dumps({
        "template-id": template_id,
        "info": {"name": name, "severity": severity,
                 "tags": tags or [], "description": desc},
        "matched-at": matched or f"https://{host}/x",
        "curl-command": f"curl -s https://{host}/x",
    })


async def _run_vuln(monkeypatch, ctx, *procs):
    """`vuln.run_process`-i mock-layır.

    Bir neçə `ProcResult` verilərsə sıra ilə qaytarılır (məs. əvvəlcə template
    yeniləmə, sonra skan); sonuncu təkrarlanır.
    """
    from qbh.engines import vuln as vuln_mod

    queue = list(procs)
    calls: list[list[str]] = []

    async def fake(cmd, **kw):
        calls.append(list(cmd))
        return queue.pop(0) if len(queue) > 1 else queue[0]

    monkeypatch.setattr(vuln_mod, "run_process", fake)
    res = await vuln_mod.VulnEngine(ctx).run()
    return res, calls


# ---------------------------------------------------------- icra vəziyyətləri
class TestVulnProcessStates:
    """Hər proses vəziyyəti AÇIQ idarə olunur (recon.py ilə uyğun)."""

    async def test_missing_warns_and_is_graceful(self, tmp_db, make_ctx,
                                                 monkeypatch):
        from qbh.adapters.base import ProcResult

        _seed_host()
        res, _ = await _run_vuln(monkeypatch, _vuln_ctx(make_ctx),
                                 ProcResult(-1, missing=True))
        assert res.ok is True                      # graceful, crash yox
        assert any("nuclei tapılmadı" in w for w in res.warnings)
        assert res.findings == 0

    async def test_blocked_is_failure(self, tmp_db, make_ctx, monkeypatch):
        from qbh.adapters.base import ProcResult

        _seed_host()
        res, _ = await _run_vuln(monkeypatch, _vuln_ctx(make_ctx),
                                 ProcResult(-1, blocked=True))
        assert res.ok is False
        assert any("BLOKLADI" in e for e in res.errors)

    async def test_success_zero_findings_is_ok(self, tmp_db, make_ctx,
                                               monkeypatch):
        from qbh.adapters.base import ProcResult

        _seed_host()
        res, _ = await _run_vuln(monkeypatch, _vuln_ctx(make_ctx),
                                 ProcResult(0, stdout=b""))
        assert res.ok is True
        assert res.errors == []
        assert res.findings == 0

    async def test_nonzero_zero_findings_is_failure(self, tmp_db, make_ctx,
                                                    monkeypatch):
        from qbh.adapters.base import ProcResult

        _seed_host()
        res, _ = await _run_vuln(monkeypatch, _vuln_ctx(make_ctx),
                                 ProcResult(2, stderr=b"kaboom"))
        assert res.ok is False
        assert any("uğursuz" in e for e in res.errors)

    async def test_timeout_preserves_findings_marks_incomplete(
            self, tmp_db, make_ctx, monkeypatch):
        """Timeout etibarlı tapıntıları ATMAZ; natamamlıq bildirilir."""
        from qbh.adapters.base import ProcResult

        _seed_host()
        out = _nuclei_line("127.0.0.1").encode() + b"\n"
        res, _ = await _run_vuln(monkeypatch, _vuln_ctx(make_ctx),
                                 ProcResult(-1, stdout=out, timed_out=True))
        assert res.findings == 1
        assert res.ok is False
        assert any("NATAMAM" in e for e in res.errors)

    async def test_nonzero_exit_preserves_findings(self, tmp_db, make_ctx,
                                                   monkeypatch):
        from qbh.adapters.base import ProcResult

        _seed_host()
        out = _nuclei_line("127.0.0.1").encode() + b"\n"
        res, _ = await _run_vuln(monkeypatch, _vuln_ctx(make_ctx),
                                 ProcResult(1, stdout=out, stderr=b"warn"))
        assert res.findings == 1
        assert res.ok is False
        assert any("uğursuz" in e for e in res.errors)

    async def test_malformed_lines_do_not_discard_valid(self, tmp_db,
                                                        make_ctx, monkeypatch):
        from qbh.adapters.base import ProcResult

        _seed_host()
        out = b"{bu etibarsiz json\n" + _nuclei_line("127.0.0.1").encode() + b"\n"
        res, _ = await _run_vuln(monkeypatch, _vuln_ctx(make_ctx),
                                 ProcResult(0, stdout=out))
        assert res.findings == 1
        assert any("xətalı JSON" in w for w in res.warnings)

    async def test_diagnostics_counters_recorded(self, tmp_db, make_ctx,
                                                 monkeypatch):
        from qbh.adapters.base import ProcResult

        _seed_host()
        out = (_nuclei_line("127.0.0.1").encode() + b"\n"
               + b"{bad\n"
               + _nuclei_line("evil.test").encode() + b"\n")
        res, _ = await _run_vuln(monkeypatch, _vuln_ctx(make_ctx),
                                 ProcResult(0, stdout=out))
        diag = res.data["nuclei"]["generic"]
        assert set(diag) == {"lines", "valid", "malformed", "no_host",
                             "out_of_scope", "excluded", "accepted"}
        assert diag["lines"] == 3
        assert diag["valid"] == 2
        assert diag["malformed"] == 1
        assert diag["out_of_scope"] == 1
        assert diag["accepted"] == 1


# ------------------------------------------------------------ host uyğunluğu
class TestVulnHostAssociation:
    """Nəticələr YALNIZ cari skanın hostları ilə DƏQİQ uyğunlaşır."""

    def _engine(self, make_ctx):
        from qbh.engines.vuln import VulnEngine

        return VulnEngine(_vuln_ctx(make_ctx))

    def _parse(self, eng, host_map, raw, excluded=None):
        return eng._parse_and_store(raw, host_map, excluded or set(),
                                    EngineResult(stage="vuln"))

    def test_exact_match_accepted(self, tmp_db, make_ctx):
        from qbh import db

        hid = db.upsert_host("example.com", 1, status_code=200)
        stats = self._parse(
            self._engine(make_ctx), {"example.com": hid},
            _nuclei_line("example.com", matched="https://example.com/a").encode())
        assert stats.accepted == 1
        assert stats.out_of_scope == 0

    @pytest.mark.parametrize("matched", [
        "HTTPS://Example.COM/Path",           # böyük/kiçik hərf
        "https://example.com./path",          # sağdakı nöqtə
        "https://example.com:8443/path",      # açıq port
        "example.com:443/schemesiz",          # sxemsiz host:port
    ])
    def test_normalization_variants_match(self, tmp_db, make_ctx, matched):
        from qbh import db

        hid = db.upsert_host("example.com", 1, status_code=200)
        stats = self._parse(
            self._engine(make_ctx), {"example.com": hid},
            _nuclei_line("example.com", matched=matched).encode())
        assert stats.accepted == 1, matched
        assert stats.out_of_scope == 0

    def test_ipv4_match(self, tmp_db, make_ctx):
        from qbh import db

        hid = db.upsert_host("127.0.0.1", 1, status_code=200)
        stats = self._parse(
            self._engine(make_ctx), {"127.0.0.1": hid},
            _nuclei_line("127.0.0.1",
                         matched="https://127.0.0.1:8443/x").encode())
        assert stats.accepted == 1

    def test_ipv6_match(self, tmp_db, make_ctx):
        from qbh import db

        hid = db.upsert_host("::1", 1, status_code=200)
        stats = self._parse(
            self._engine(make_ctx), {"::1": hid},
            _nuclei_line("::1", matched="https://[::1]:8443/x").encode())
        assert stats.accepted == 1

    def test_subdomain_collision_rejected(self, tmp_db, make_ctx):
        """`example.com` `example.com.attacker.test` ilə HEÇ VAXT uyğunlaşmaz."""
        from qbh import db

        hid = db.upsert_host("example.com", 1, status_code=200)
        stats = self._parse(
            self._engine(make_ctx), {"example.com": hid},
            _nuclei_line("example.com",
                         matched="https://example.com.attacker.test/path").encode())
        assert stats.accepted == 0
        assert stats.out_of_scope == 1

    def test_unrelated_hostname_rejected(self, tmp_db, make_ctx):
        from qbh import db

        hid = db.upsert_host("example.com", 1, status_code=200)
        stats = self._parse(
            self._engine(make_ctx), {"example.com": hid},
            _nuclei_line("evil.test", matched="https://evil.test/x").encode())
        assert stats.accepted == 0
        assert stats.out_of_scope == 1

    @pytest.mark.parametrize("matched", ["http://", "https:///path", ""])
    def test_malformed_or_hostless_rejected(self, tmp_db, make_ctx, matched):
        stats = self._parse(
            self._engine(make_ctx), {"example.com": 1},
            json.dumps({"template-id": "x", "info": {},
                        "matched-at": matched}).encode())
        assert stats.accepted == 0
        assert stats.no_host == 1

    def test_excluded_template_rejected(self, tmp_db, make_ctx):
        from qbh import db

        hid = db.upsert_host("example.com", 1, status_code=200)
        stats = self._parse(
            self._engine(make_ctx), {"example.com": hid},
            _nuclei_line("example.com", tags=["intrusive"]).encode(),
            excluded={"intrusive"})
        assert stats.accepted == 0
        assert stats.excluded == 1


# ------------------------------------------------------- template konfiqi
class TestVulnTemplateConfig:
    _LOOPBACK = {"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
                 "out_of_scope": []}

    def test_missing_keys_preserve_defaults(self, tmp_db, load_config):
        cfg = load_config([dict(self._LOOPBACK)])
        assert cfg.vuln.allow_all_templates is False
        assert cfg.vuln.allow_destructive is False
        assert cfg.vuln.update_templates is False

    def test_strict_boolean_accepted(self, tmp_db, load_config):
        cfg = load_config([dict(self._LOOPBACK)],
                          extra={"vuln": {"allow_all_templates": True}})
        assert cfg.vuln.allow_all_templates is True

    @pytest.mark.parametrize("bad", ["true", "false", 1, 0, [], {}])
    @pytest.mark.parametrize("key", ["allow_all_templates",
                                     "allow_destructive", "update_templates"])
    def test_invalid_boolean_rejected(self, tmp_db, load_config, key, bad):
        from qbh.config import ConfigError

        with pytest.raises(ConfigError):
            load_config([dict(self._LOOPBACK)], extra={"vuln": {key: bad}})

    def test_allow_all_templates_drops_tag_filter(self, tmp_db, make_ctx,
                                                 load_config):
        from qbh.engines.vuln import VulnEngine

        cfg = load_config([dict(self._LOOPBACK)],
                          extra={"vuln": {"allow_all_templates": True}})
        assert VulnEngine(make_ctx(cfg))._template_args("wordpress") == []

    def test_default_keeps_tag_filter(self, tmp_db, make_ctx):
        from qbh.engines.vuln import VulnEngine

        assert VulnEngine(make_ctx())._template_args("wordpress") == \
            ["-tags", "wordpress,wp-plugin,wp-theme"]

    async def test_allow_all_templates_command_has_no_tags(
            self, tmp_db, make_ctx, load_config, monkeypatch):
        from qbh.adapters.base import ProcResult

        _seed_host()
        cfg = load_config([dict(self._LOOPBACK)],
                          extra={"vuln": {"allow_all_templates": True}})
        _, calls = await _run_vuln(monkeypatch, _vuln_ctx(make_ctx, cfg),
                                   ProcResult(0, stdout=b""))
        assert "-tags" not in calls[0]
        assert "-exclude-tags" in calls[0]    # scope/RoE qoruması qalır

    def test_destructive_opens_non_destructive_intrusive(
            self, tmp_db, make_ctx, load_config):
        from qbh.engines.vuln import DESTRUCTIVE_ONLY, VulnEngine

        cfg = load_config([dict(self._LOOPBACK)],
                          extra={"aggressiveness": "passive",
                                 "vuln": {"allow_destructive": True}})
        eng = VulnEngine(make_ctx(cfg))
        assert eng._destructive_opt_in() is True
        excl = eng._exclude_tags()
        assert excl == DESTRUCTIVE_ONLY
        # DoS/brute-force/creds-stuffing HƏMİŞƏ istisna qalır.
        for tag in ("dos", "brute-force", "creds-stuffing", "fuzz"):
            assert tag in excl
        # Qeyri-zərərli intrusiv kateqoriyalar AÇILIR.
        for tag in ("intrusive", "default-login", "file-upload", "rce-oob"):
            assert tag not in excl

    def test_destructive_off_keeps_broad_excludes(self, tmp_db, make_ctx,
                                                  load_config):
        from qbh.engines.vuln import EXCLUDE_TAGS, VulnEngine

        cfg = load_config([dict(self._LOOPBACK)],
                          extra={"aggressiveness": "passive"})
        assert VulnEngine(make_ctx(cfg))._exclude_tags() == EXCLUDE_TAGS

    def test_roe_forbidden_overrides_destructive(self, tmp_db, make_ctx,
                                                load_config):
        from qbh.engines.vuln import EXCLUDE_TAGS, VulnEngine

        cfg = load_config([dict(self._LOOPBACK)], extra={
            "aggressiveness": "passive",
            "program_rules": {"forbidden": ["intrusive_templates"]},
            "vuln": {"allow_destructive": True}})
        eng = VulnEngine(make_ctx(cfg))
        assert eng._destructive_opt_in() is False
        assert eng._exclude_tags() == EXCLUDE_TAGS

    async def test_update_templates_off_no_update(self, tmp_db, make_ctx,
                                                  monkeypatch):
        from qbh.adapters.base import ProcResult

        _seed_host()
        _, calls = await _run_vuln(monkeypatch, _vuln_ctx(make_ctx),
                                   ProcResult(0, stdout=b""))
        assert all("-update-templates" not in c for c in calls)

    async def test_update_templates_on_invokes_update(self, tmp_db, make_ctx,
                                                      load_config, monkeypatch):
        from qbh.adapters.base import ProcResult

        _seed_host()
        cfg = load_config([dict(self._LOOPBACK)],
                          extra={"vuln": {"update_templates": True}})
        res, calls = await _run_vuln(
            monkeypatch, _vuln_ctx(make_ctx, cfg),
            ProcResult(0, stdout=b"nuclei v3.3.7"), ProcResult(0, stdout=b""))
        assert any("-update-templates" in c for c in calls)
        assert res.data.get("templates_version") == "v3.3.7"

    async def test_update_templates_failure_reported(self, tmp_db, make_ctx,
                                                     load_config, monkeypatch):
        from qbh.adapters.base import ProcResult

        _seed_host()
        cfg = load_config([dict(self._LOOPBACK)],
                          extra={"vuln": {"update_templates": True}})
        res, _ = await _run_vuln(
            monkeypatch, _vuln_ctx(make_ctx, cfg),
            ProcResult(1, stderr=b"update boom"), ProcResult(0, stdout=b""))
        assert res.ok is False
        assert any("yeniləmə" in e for e in res.errors)


# ------------------------------------------------------- mövcud davranış
class TestVulnExistingBehavior:
    """Mövcud seçim/sərhəd davranışı QORUNUR."""

    def test_strategy_specific_templates(self, tmp_db, make_ctx):
        from qbh.engines.vuln import VulnEngine

        eng = VulnEngine(make_ctx())
        assert eng._template_args("wordpress") == \
            ["-tags", "wordpress,wp-plugin,wp-theme"]
        assert eng._template_args("nginx") == ["-tags", "nginx"]
        assert eng._template_args("apache") == ["-tags", "apache,httpd"]
        assert eng._template_args("php") == ["-tags", "php"]
        assert eng._template_args("nodejs") == ["-tags", "nodejs"]
        assert eng._template_args("generic") == \
            ["-tags", "misconfig,exposure,takeover,panel"]
        assert eng._template_args("unknown") == \
            ["-tags", "misconfig,exposure,takeover,panel"]

    def test_intrusive_profile_excludes(self, tmp_db, make_ctx):
        from qbh.engines.vuln import DESTRUCTIVE_ONLY, VulnEngine

        assert VulnEngine(make_ctx())._exclude_tags() == DESTRUCTIVE_ONLY

    async def test_command_preserves_security_flags(self, tmp_db, make_ctx,
                                                    monkeypatch):
        from qbh.adapters.base import ProcResult

        _seed_host()
        _, calls = await _run_vuln(monkeypatch, _vuln_ctx(make_ctx),
                                   ProcResult(0, stdout=b""))
        cmd = calls[0]
        assert "-no-interactsh" in cmd
        assert "-jsonl" in cmd
        assert cmd[cmd.index("-severity") + 1] == "medium,high,critical"
        assert cmd[cmd.index("-rl") + 1] == "10"     # WAF yox → base rate
        assert cmd[cmd.index("-c") + 1] == "25"

    async def test_only_current_scan_hosts_targeted(self, tmp_db, make_ctx,
                                                    load_config, monkeypatch):
        from qbh import db
        from qbh.adapters.base import ProcResult
        from qbh.engines import vuln as vuln_mod

        db.upsert_host("127.0.0.1", 1, status_code=200)
        db.upsert_host("127.0.0.2", 2, status_code=200)   # fərqli skan
        cfg = load_config([{"domain": "127.0.0.1",
                            "in_scope": ["127.0.0.1", "127.0.0.2"],
                            "out_of_scope": []}])
        seen: dict = {}

        async def fake(cmd, **kw):
            if "-l" in cmd:
                with open(cmd[cmd.index("-l") + 1], encoding="utf-8") as fh:
                    seen["targets"] = fh.read().splitlines()
            return ProcResult(0, stdout=b"")

        monkeypatch.setattr(vuln_mod, "run_process", fake)
        await vuln_mod.VulnEngine(_vuln_ctx(make_ctx, cfg, scan_id=1)).run()
        assert seen["targets"] == ["https://127.0.0.1"]

    async def test_out_of_scope_host_never_scanned(self, tmp_db, make_ctx,
                                                   monkeypatch):
        from qbh import db
        from qbh.adapters.base import ProcResult
        from qbh.engines import vuln as vuln_mod

        db.upsert_host("evil.example.com", 1, status_code=200)  # scope xaric
        calls: list = []

        async def fake(cmd, **kw):
            calls.append(list(cmd))
            return ProcResult(0, stdout=b"")

        monkeypatch.setattr(vuln_mod, "run_process", fake)
        res = await vuln_mod.VulnEngine(_vuln_ctx(make_ctx, scan_id=1)).run()
        assert calls == []    # heç bir alt-proses başladılmadı
        assert any("icazəli hədəf yoxdur" in w for w in res.warnings)
