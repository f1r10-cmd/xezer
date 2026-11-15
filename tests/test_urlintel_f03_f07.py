"""F-03 (URL Intelligence inteqrasiyası) və F-07 (deferred yenidən baxış).

Yoxlanılan prinsiplər (hamısı şəbəkəsiz — yalnız qərar qatı və izolyasiyalı DB):

F-03:
  * `param` mühərriki injeksiya mühərriklərindən AYRIDIR: statik resursları
    istisna edir, lakin parametrsiz dinamik endpoint UYĞUNDUR (gizli parametr
    axtarışının hədəfi) → kəşf boğulmur.
  * `js`/`library_cve` yalnız JavaScript resurslarını qəbul edir.
  * `plan_rows(engine=...)` uyğunluq səbəblərini və metrikaları qeyd edir;
    orijinal URL / host_id sətirləri TOXUNULMAZ qalır.
  * Host-səviyyəli mühərriklər (content, api_enum) URL-səviyyəli süzgəcə
    MƏCBUR EDİLMİR — bu, qəsdən belədir (kəşfi boğmamaq üçün).

F-07:
  * Təxirə salınmış endpoint kimliyi + səbəbi + dəlil imzası ilə saxlanılır.
  * Yenidən baxış YALNIZ dəlil DƏYİŞDİKDƏ baş verir (dəyişməyən dəlil təkrar
    emal olunmur; sonsuz dövr qurulmur — bounded `max_rounds`).
  * Uyğun hala keçənlər reyestrdən ÇIXARILIR (təkrar yüksəliş yoxdur).
  * Zəncir (chain) parametr kəşfinin verdiyi YENİ dəlillə yenidən baxış aparır.
  * Heç bir yeni HTTP trafiki yaradılmır (bu, yalnız uyğunluq qərarıdır).
"""
from __future__ import annotations

from qbh import urlintel as u
from qbh.chain import ChainPipeline
from qbh.metrics import OrchestrationMetrics

# --------------------------------------------------------------------------- #
# F-03 — mühərrik uyğunluğu qaydaları
# --------------------------------------------------------------------------- #


class TestParamEngineRule:
    def test_param_engine_not_an_injection_engine(self):
        assert "param" not in u.INJECT_ENGINES
        assert set(u.INJECT_ENGINES) == {"sqli", "xss", "ssti", "ssrf"}
        assert "param" in u.ENGINES

    def test_param_engine_eligible_for_paramless_dynamic(self):
        # Parametr kəşfinin MƏHZ hədəfi parametrsiz dinamik endpoint-dir.
        assert u.evaluate(u.analyze("http://h/page"), "param").eligible is True
        assert u.evaluate(u.analyze("http://h/page?id=1"),
                          "param").eligible is True

    def test_param_engine_skips_static_and_js(self):
        for target in ("http://h/style.css", "http://h/logo.png",
                       "http://h/app.js", "http://h/f.woff2"):
            d = u.evaluate(u.analyze(target), "param")
            assert d.eligible is False, target
            assert d.status == "ineligible"
            assert d.reason.startswith("SKIPPED")

    def test_param_decision_records_reason_and_original(self):
        ep = u.analyze("http://h/style.css")
        d = u.evaluate(ep, "param")
        assert "statik" in d.reason
        assert d.evidence == ep.original


class TestJSEngineRules:
    def test_js_and_library_cve_only_accept_javascript(self):
        for engine in ("js", "library_cve"):
            assert u.evaluate(u.analyze("http://h/app.js"),
                              engine).eligible is True
            assert u.evaluate(u.analyze("http://h/bundle", is_js=True),
                              engine).eligible is True
            assert u.evaluate(u.analyze("http://h/style.css"),
                              engine).eligible is False
            assert u.evaluate(u.analyze("http://h/api/v1/users"),
                              engine).eligible is False

    def test_js_exclusion_reason_recorded(self):
        d = u.evaluate(u.analyze("http://h/style.css"), "js")
        assert d.status == "ineligible"
        assert "JS" in d.reason


#: JS/müxtəlif tipli resursları əhatə edən deterministik fixture.
ROWS_MIXED = [
    {"id": 1, "url": "http://h/app.js", "is_js": 1, "source": "katana",
     "subdomain": "h"},
    {"id": 2, "url": "http://h/lib.js", "is_js": 1, "source": "gau",
     "subdomain": "h"},
    {"id": 3, "url": "http://h/style.css", "is_js": 0, "source": "katana",
     "subdomain": "h"},
    {"id": 4, "url": "http://h/api/v1/users", "is_js": 0, "source": "katana",
     "subdomain": "h"},
    {"id": 5, "url": "http://h/page", "is_js": 0, "source": "katana",
     "subdomain": "h"},
]


class TestPlanRowsIntegration:
    def test_js_engine_keeps_only_js_rows(self):
        kept, plan = u.UrlIntelligence().plan_rows(ROWS_MIXED, engine="js",
                                                   limit=10)
        assert plan.eligible == 2
        # css + /api + /page — heç biri JS deyil → hamısı istisna olunur.
        assert plan.excluded == 3
        assert plan.deferred == 0
        assert {r["id"] for r in kept} == {1, 2}

    def test_param_engine_keeps_dynamic_not_static(self):
        kept, plan = u.UrlIntelligence().plan_rows(ROWS_MIXED, engine="param",
                                                   limit=10)
        # app.js/lib.js/style.css istisna; api + page uyğun.
        assert {r["id"] for r in kept} == {4, 5}
        assert plan.excluded == 3

    def test_rows_preserve_original_columns(self):
        kept, _ = u.UrlIntelligence().plan_rows(ROWS_MIXED, engine="js",
                                                limit=10)
        row = next(r for r in kept if r["id"] == 1)
        # Sətirlər OLDUĞU KİMİ qaytarılır — host_id/subdomain toxunulmaz.
        assert row["url"] == "http://h/app.js"
        assert row["subdomain"] == "h"

    def test_engine_metrics_recorded_per_engine(self):
        m = OrchestrationMetrics()
        u.UrlIntelligence(metrics=m).plan_rows(ROWS_MIXED, engine="js",
                                               limit=10)
        assert m.eligible["js"] == 2
        assert m.excluded["js"] == 3
        assert all(r.startswith("SKIPPED")
                   for r in m.exclusion_reasons)

    def test_dedup_within_plan(self):
        rows = ROWS_MIXED + [
            {"id": 6, "url": "http://h/app.js", "is_js": 1, "source": "ffuf",
             "subdomain": "h"}]
        kept, plan = u.UrlIntelligence().plan_rows(rows, engine="js", limit=10)
        assert plan.duplicates == 1
        assert {r["id"] for r in kept} == {1, 2}


# --------------------------------------------------------------------------- #
# F-07 — deferred endpoint-lərin dəlil əsaslı yenidən baxışı
# --------------------------------------------------------------------------- #

ROWS_DEFER = [
    {"id": 1, "url": "http://h/mystery", "is_js": 0, "source": "katana",
     "subdomain": "h"},
]


def _defer(engine: str):
    """Bir deferred endpoint yaradır və `(intel, metrics, identity)` qaytarır."""
    m = OrchestrationMetrics()
    intel = u.UrlIntelligence(metrics=m)
    intel.plan_rows(ROWS_DEFER, engine=engine, limit=10)
    return intel, m, u.endpoint_identity("http://h/mystery")


class TestDeferredRegistry:
    def test_deferred_entry_records_identity_and_reason(self):
        intel, _, ident = _defer("sqli")
        entry = intel.deferred_registry[("sqli", ident)]
        assert entry.identity == ident
        assert entry.reason.startswith("DEFERRED")
        assert entry.signature == ()        # parametr yoxdur → boş imza
        assert entry.rechecks == 0

    def test_first_reason_is_stable(self):
        intel, _, ident = _defer("sqli")
        before = intel.deferred_registry[("sqli", ident)].reason
        # Eyni endpoint yenidən planlaşdırılsa da ilk qeyd saxlanılır.
        intel.plan_rows(ROWS_DEFER, engine="sqli", limit=10)
        assert intel.deferred_registry[("sqli", ident)].reason == before


class TestReconsider:
    def test_unchanged_evidence_is_not_reprocessed(self):
        intel, m, ident = _defer("sqli")
        promoted = intel.reconsider("sqli", {ident: ()})   # imza dəyişməyib
        assert promoted == []
        assert intel.deferred_registry[("sqli", ident)].rechecks == 0
        assert m.reconsidered["sqli"] == 0
        assert m.remained_deferred["sqli"] == 0

    def test_new_evidence_promotes(self):
        intel, m, ident = _defer("sqli")
        promoted = intel.reconsider("sqli", {ident: ("id",)})
        assert len(promoted) == 1
        assert promoted[0]["engine"] == "sqli"
        assert promoted[0]["evidence"] == ["id"]
        assert ("sqli", ident) not in intel.deferred_registry   # çıxarıldı
        assert m.reconsidered["sqli"] == 1

    def test_absent_evidence_entry_untouched(self):
        intel, _, ident = _defer("sqli")
        assert intel.reconsider("sqli", {}) == []
        assert ("sqli", ident) in intel.deferred_registry

    def test_engine_scoped(self):
        intel, _, ident = _defer("sqli")
        assert intel.reconsider("xss", {ident: ("q",)}) == []
        assert ("sqli", ident) in intel.deferred_registry

    def test_remains_deferred_records_reason_and_metric(self):
        # SSRF yönləndirmə/fayl parametri tələb edir → 'id' kifayət etmir.
        intel, m, ident = _defer("ssrf")
        promoted = intel.reconsider("ssrf", {ident: ("id",)})
        assert promoted == []
        entry = intel.deferred_registry[("ssrf", ident)]
        assert entry.rechecks == 1
        assert entry.signature == ("id",)          # yeni dəlil imzası saxlanıldı
        assert m.remained_deferred["ssrf"] == 1

    def test_bounded_no_infinite_loop(self):
        intel, m, ident = _defer("ssrf")
        intel.reconsider("ssrf", {ident: ("id",)}, max_rounds=1)
        # Yenidən YENİ dəlil gəlsə də büdcə tükənib → təkrar emal YOX.
        again = intel.reconsider("ssrf", {ident: ("id", "url")}, max_rounds=1)
        assert again == []
        assert intel.deferred_registry[("ssrf", ident)].rechecks == 1
        assert m.remained_deferred["ssrf"] == 1

    def test_promotion_is_one_way(self):
        intel, _, ident = _defer("sqli")
        intel.reconsider("sqli", {ident: ("id",)})
        # Uyğun hala keçdikdən sonra təkrar yüksəliş olmur.
        assert intel.reconsider("sqli", {ident: ("id", "q")}) == []
        assert ("sqli", ident) not in intel.deferred_registry


class TestEvidenceSignature:
    def test_signature_is_sorted_and_deterministic(self):
        ep = u.analyze("http://h/p?b=2&a=1")
        assert u.evidence_signature(ep) == ("a", "b")
        ep2 = u.analyze("http://h/p?a=1&b=2")
        assert u.evidence_signature(ep2) == ("a", "b")


# --------------------------------------------------------------------------- #
# F-07 — zəncir inteqrasiyası (parametr kəşfi → yenidən baxış)
# --------------------------------------------------------------------------- #


def _chain_ctx(make_ctx):
    from qbh.authorization import from_config
    from qbh.tasks import EventLedger, TaskLedger

    ctx = make_ctx()
    ctx.authorization = from_config(ctx.cfg)
    ctx.scan_id = 1
    ctx.event_ledger = EventLedger()
    ctx.task_ledger = TaskLedger()
    ctx.orchestration = OrchestrationMetrics()
    ctx.stage_status = {}
    return ctx


class TestChainReconsideration:
    def test_param_discovery_promotes_deferred_endpoint(self, tmp_db, make_ctx):
        from qbh import db

        ctx = _chain_ctx(make_ctx)
        pipe = ChainPipeline(ctx)
        # 1) Əvvəlcə parametrsiz endpoint SQLi üçün deferred olur.
        intel = u.get_url_intelligence(ctx)
        intel.plan_rows(
            [{"id": 1, "url": "http://127.0.0.1/mystery", "is_js": 0,
              "source": "katana", "subdomain": "127.0.0.1"}],
            engine="sqli", limit=10)
        ident = u.endpoint_identity("http://127.0.0.1/mystery")
        assert ("sqli", ident) in intel.deferred_registry
        # 2) Parametr kəşfi YENİ dəlil yazır (##params: markeri).
        hid = db.upsert_host("127.0.0.1", status_code=200, scan_id=1)
        db.insert_url(hid, "http://127.0.0.1/mystery##params:id",
                      "priority-param", False, scan_id=1)

        pipe._reconsider_deferred()

        assert pipe.reconsidered
        assert pipe.reconsidered[0]["engine"] == "sqli"
        assert ("sqli", ident) not in intel.deferred_registry
        assert ctx.orchestration.reconsidered["sqli"] == 1

    def test_no_new_evidence_is_noop(self, tmp_db, make_ctx):
        ctx = _chain_ctx(make_ctx)
        pipe = ChainPipeline(ctx)
        intel = u.get_url_intelligence(ctx)
        intel.plan_rows(
            [{"id": 1, "url": "http://127.0.0.1/mystery", "is_js": 0,
              "source": "katana", "subdomain": "127.0.0.1"}],
            engine="sqli", limit=10)
        pipe._reconsider_deferred()          # DB-də ##params: YOXDUR
        assert pipe.reconsidered == []
        assert ctx.orchestration.reconsidered["sqli"] == 0

    def test_repeated_reconsider_does_not_duplicate(self, tmp_db, make_ctx):
        from qbh import db

        ctx = _chain_ctx(make_ctx)
        pipe = ChainPipeline(ctx)
        intel = u.get_url_intelligence(ctx)
        intel.plan_rows(
            [{"id": 1, "url": "http://127.0.0.1/mystery", "is_js": 0,
              "source": "katana", "subdomain": "127.0.0.1"}],
            engine="sqli", limit=10)
        hid = db.upsert_host("127.0.0.1", status_code=200, scan_id=1)
        db.insert_url(hid, "http://127.0.0.1/mystery##params:id",
                      "priority-param", False, scan_id=1)

        pipe._reconsider_deferred()
        first = ctx.orchestration.reconsidered["sqli"]
        pipe._reconsider_deferred()          # ikinci dəfə — təkrar yox
        assert ctx.orchestration.reconsidered["sqli"] == first == 1


# --------------------------------------------------------------------------- #
# Faza 2 — cavab metadata-sı ilə təsnifatın dəqiqləşdirilməsi
# --------------------------------------------------------------------------- #


class TestResponseMetadataRefinement:
    """Cavab metadata-sı YALNIZ uyğunluğu dəyişməyən dəqiqləşdirmə üçün işlədilir."""

    def test_applied_refinement_preserves_url_and_records_evidence(self):
        intel = u.UrlIntelligence()
        url = "http://h/mystery"
        ref = intel.refine_from_response(url, content_type="text/html",
                                         source="ffuf")
        assert ref is not None and ref.applied is True
        # Orijinal URL TOXUNULMAZ, yalnız kateqoriya dəqiqləşir.
        assert ref.original == url
        assert ref.from_category == u.CAT_UNKNOWN
        assert ref.to_category == u.CAT_HTML
        # Yeni dəlil qeyd olunur.
        assert "content-type=text/html" in ref.evidence
        assert "ffuf" in ref.evidence
        assert intel.refinements[u.normalize_url(url)] is ref
        assert intel.refinement_stats["applied"] == 1
        assert intel.refinement_stats["refused"] == 0

    def test_applied_refinement_does_not_change_any_engine_verdict(self):
        intel = u.UrlIntelligence()
        url = "http://h/mystery"
        base = u.analyze(url)
        intel.refine_from_response(url, content_type="text/html")
        refined = intel.apply_refinement(u.analyze(url))
        assert refined.category == u.CAT_HTML
        assert refined.original == base.original          # orijinal dəyişməz
        assert refined.normalized == base.normalized
        for engine in u.ENGINES:
            assert (u.evaluate(base, engine).eligible
                    == u.evaluate(refined, engine).eligible), engine

    def test_no_oscillation_first_evidence_wins(self):
        intel = u.UrlIntelligence()
        url = "http://h/mystery"
        first = intel.refine_from_response(url, content_type="text/html")
        # Fərqli cavab metadata-sı gəlsə də İLK dəlil qalib gəlir (salınım yox).
        second = intel.refine_from_response(url, content_type="image/png")
        assert second is first
        assert second.to_category == u.CAT_HTML
        assert intel.refinement_stats["applied"] == 1
        assert intel.refinement_stats["refused"] == 0

    def test_refused_when_eligibility_would_change(self):
        intel = u.UrlIntelligence()
        url = "http://h/mystery?id=1"
        before = u.evaluate(u.analyze(url), "sqli")
        assert before.eligible is True
        ref = intel.refine_from_response(url, content_type="image/png",
                                         source="ffuf")
        assert ref is not None and ref.applied is False
        assert ref.reason.startswith("REFUSED")
        assert "sqli" in ref.reason              # dəyişəcək mühərriklər göstərilir
        # Uyğunluq DƏYİŞMƏZ qalır — injeksiya testi susturulmur (evasion yox).
        assert u.evaluate(u.analyze(url), "sqli").eligible is True
        # Rədd də birtərəfli qeyd olunur (qaytarılan qeyd sabitdir).
        assert intel.refine_from_response(url, content_type="text/css") is ref
        assert intel.refinement_stats["refused"] == 1
        assert intel.refinement_stats["applied"] == 0

    def test_refinement_is_scoped_to_exact_url(self):
        intel = u.UrlIntelligence()
        # Dəlil müşahidə olunduğu DƏQİQ URL-ə bağlanır: sorğu parametrləri
        # fərqli olan URL-ə ekstrapolyasiya OLUNMUR.
        intel.refine_from_response("http://h/mystery", content_type="text/html")
        other = u.analyze("http://h/mystery?id=1")
        assert intel.apply_refinement(other) is other

    def test_apply_guard_refuses_non_neutral_refinement(self):
        # İkinci qoruma: reyestrdə (hipotetik olaraq) uyğunluğu dəyişəcək bir
        # dəqiqləşdirmə olsa belə, tətbiq ZAMANI yenidən yoxlanılır.
        intel = u.UrlIntelligence()
        ep = u.analyze("http://h/mystery?id=1")
        key = ep.normalized or ep.original
        intel.refinements[key] = u.Refinement(
            identity=ep.identity, original=ep.original,
            from_category=ep.category, to_category=u.CAT_IMAGE,
            applied=True, reason="test")
        assert intel.apply_refinement(ep) is ep        # uyğunluq dəyişir → rədd

    def test_no_op_when_category_unchanged(self):
        intel = u.UrlIntelligence()
        assert intel.refine_from_response(
            "http://h/mystery", content_type="application/octet-stream") is None
        assert intel.refinements == {}

    def test_extension_is_authoritative_over_content_type(self):
        # `.js` uzantısı artıq JS deməkdir → cavab metadata-sı dəyişiklik yaratmır.
        intel = u.UrlIntelligence()
        assert intel.refine_from_response(
            "http://h/app.js", content_type="text/html") is None
        assert intel.refinements == {}

    def test_missing_content_type_is_noop(self):
        intel = u.UrlIntelligence()
        assert intel.refine_from_response("http://h/mystery") is None
        assert intel.refinements == {}

    def test_refinement_metrics_are_recorded(self):
        m = OrchestrationMetrics()
        intel = u.UrlIntelligence(metrics=m)
        intel.refine_from_response("http://h/mystery", content_type="text/html")
        intel.refine_from_response("http://h/other?id=1",
                                   content_type="image/png")
        assert m.refined_applied == 1
        assert m.refined_refused == 1
        assert m.snapshot()["response_refinement"] == {"applied": 1, "refused": 1}
        summary = intel.refinements_summary()
        assert summary["applied"] == 1 and summary["refused"] == 1
        assert len(summary["entries"]) == 2

    def test_plan_rows_consumes_refinement(self):
        intel = u.UrlIntelligence()
        intel.refine_from_response("http://h/mystery", content_type="text/html")
        rows = [{"id": 1, "url": "http://h/mystery", "is_js": 0,
                 "source": "ffuf", "subdomain": "h"}]
        kept, plan = intel.plan_rows(rows, engine="content", limit=10)
        # Uyğunluq dəyişməz → sətir qorunur; qərar səbəbi qeyd olunur.
        assert [r["id"] for r in kept] == [1]
        assert plan.eligible == 1

