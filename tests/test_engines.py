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
