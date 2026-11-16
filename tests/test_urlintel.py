"""Faza 1 (§5) — URL Intelligence deterministik testləri.

Yoxlanılan prinsiplər (heç bir xarici şəbəkə trafiki yoxdur):
  * Deterministik normalizasiya (host/sxem/port/fragment/yol/sorğu).
  * Sorğu parametrlərinin (ad + DƏYƏR) qorunması: `?id=1` ≠ `?id=2`.
  * Təkrar parametr adları qorunur.
  * SƏHV birləşmənin qarşısı alınır (`/a%2Fb` ≠ `/a/b`).
  * Statik resurs təsnifatı + naməlum endpoint-in ATILMAMASI.
  * Endpoint ailələri (izlənə bilənlik qorunur).
  * Mühərrik uyğunluğu AÇIQLANAN səbəblə (eligible/ineligible/deferred).
  * Scope rəddi (scope xarici URL qəbul edilmir).
"""
from __future__ import annotations

import pytest

from qbh import urlintel as u
from qbh.metrics import OrchestrationMetrics
from qbh.scope import ScopeError

# --------------------------------------------------------------------------- #
# Normalizasiya
# --------------------------------------------------------------------------- #


class TestNormalization:
    def test_host_lowercased(self):
        assert u.normalize_url("HTTP://Example.COM/Path") == \
            "http://example.com/Path"

    def test_scheme_lowercased(self):
        assert u.normalize_url("HTTPS://example.com/a") == \
            "https://example.com/a"

    def test_default_http_port_removed(self):
        assert u.normalize_url("http://example.com:80/x") == \
            "http://example.com/x"

    def test_default_https_port_removed(self):
        assert u.normalize_url("https://example.com:443/y") == \
            "https://example.com/y"

    def test_non_default_port_kept(self):
        assert u.normalize_url("http://example.com:8080/x") == \
            "http://example.com:8080/x"

    def test_fragment_dropped(self):
        assert u.normalize_url("http://example.com/x#frag") == \
            "http://example.com/x"

    def test_repeated_and_trailing_slash(self):
        assert u.normalize_url("http://example.com//a//b/") == \
            "http://example.com/a/b"

    def test_query_order_normalized(self):
        assert u.normalize_url("http://example.com/p?b=2&a=1") == \
            "http://example.com/p?a=1&b=2"

    def test_unreserved_encoded_decoded(self):
        assert u.normalize_url("http://example.com/%7Euser") == \
            "http://example.com/~user"

    def test_non_http_scheme_rejected(self):
        assert u.normalize_url("mailto:x@y.com") is None
        assert u.normalize_url("javascript:alert(1)") is None

    def test_empty_or_blank_rejected(self):
        assert u.normalize_url("") is None
        assert u.normalize_url("   ") is None


class TestIncorrectMergePrevention:
    def test_different_id_values_not_merged(self):
        assert u.normalize_url("http://h/product?id=1") != \
            u.normalize_url("http://h/product?id=2")

    def test_different_search_terms_not_merged(self):
        assert u.normalize_url("http://h/search?q=admin") != \
            u.normalize_url("http://h/search?q=user")

    def test_encoded_slash_not_merged_with_slash(self):
        encoded = u.normalize_url("http://h/a%2Fb")
        plain = u.normalize_url("http://h/a/b")
        assert encoded != plain
        assert "%2F" in encoded

    def test_repeated_param_names_preserved(self):
        assert u.normalize_url("http://h/p?id=1&id=2") == \
            "http://h/p?id=1&id=2"

    def test_identity_same_for_different_values(self):
        assert u.endpoint_identity("http://h/product?id=1") == \
            u.endpoint_identity("http://h/product?id=2")

    def test_identity_strips_query(self):
        assert u.endpoint_identity("http://h/product?id=1") == \
            "http://h/product"


class TestIdentityAndFamily:
    def test_family_groups_numeric_paths(self):
        assert u.endpoint_family("http://h/product/1") == \
            u.endpoint_family("http://h/product/2")

    def test_family_groups_uuid_paths(self):
        a = u.endpoint_family("http://h/item/550e8400-e29b-41d4-a716-446655440000")
        b = u.endpoint_family("http://h/item/550e8400-e29b-41d4-a716-446655440001")
        assert a == b

    def test_family_keeps_static_segments(self):
        assert u.endpoint_family("http://h/admin/list") == \
            "http://h/admin/list"


# --------------------------------------------------------------------------- #
# Parametr intellekti
# --------------------------------------------------------------------------- #


class TestParameterIntelligence:
    def test_categories(self):
        assert u.classify_param("id", "1") == u.CAT_NUMERIC
        assert u.classify_param("q", "admin") == u.CAT_SEARCHP
        assert u.classify_param("page", "2") == u.CAT_PAGINATION
        assert u.classify_param("sort", "asc") == u.CAT_SORT
        assert u.classify_param("url", "http://x") == u.CAT_REDIRECT
        assert u.classify_param("file", "a.txt") == u.CAT_FILE
        assert u.classify_param("foo", "bar") == u.CAT_UNKNOWN_P

    def test_digit_value_is_numeric(self):
        assert u.classify_param("weird", "42") == u.CAT_NUMERIC

    def test_urlish_value_is_redirect(self):
        assert u.classify_param("weird", "https://e.com/x") == u.CAT_REDIRECT

    def test_extract_params_query(self):
        params = {p.name: p for p in u.extract_params("http://h/p?id=7&q=hi")}
        assert params["id"].category == u.CAT_NUMERIC
        assert params["q"].category == u.CAT_SEARCHP
        assert params["id"].location == "query"
        assert params["id"].value == "7"

    def test_extract_params_repeated_names(self):
        names = [p.name for p in u.extract_params("http://h/p?id=1&id=2")]
        assert names == ["id", "id"]

    def test_extract_params_empty(self):
        assert u.extract_params("http://h/p") == ()


# --------------------------------------------------------------------------- #
# Təsnifat
# --------------------------------------------------------------------------- #


class TestClassification:
    def test_static_assets(self):
        assert u.classify_url("http://h/s.css") == u.CAT_CSS
        assert u.classify_url("http://h/l.png") == u.CAT_IMAGE
        assert u.classify_url("http://h/f.woff2") == u.CAT_FONT
        assert u.classify_url("http://h/d.pdf") == u.CAT_STATIC

    def test_js(self):
        assert u.classify_url("http://h/app.js") == u.CAT_JS
        assert u.classify_url("http://h/bundle", is_js=True) == u.CAT_JS

    def test_api_and_auth(self):
        assert u.classify_url("http://h/api/v1/users") == u.CAT_API
        assert u.classify_url("http://h/login") == u.CAT_AUTH

    def test_download(self):
        assert u.classify_url("http://h/download/report") == u.CAT_DOWNLOAD

    def test_dynamic_and_search(self):
        p = u.extract_params("http://h/search?q=admin")
        assert u.classify_url("http://h/search?q=admin", params=p) == u.CAT_SEARCH
        p2 = u.extract_params("http://h/page?id=1")
        assert u.classify_url("http://h/page?id=1", params=p2) == u.CAT_DYNAMIC

    def test_unknown_not_discarded(self):
        assert u.classify_url("http://h/mystery") == u.CAT_UNKNOWN


# --------------------------------------------------------------------------- #
# Mühərrik uyğunluğu
# --------------------------------------------------------------------------- #


class TestEligibility:
    def test_sqli_numeric_dynamic_eligible(self):
        d = u.evaluate(u.analyze("http://h/product?id=1"), "sqli")
        assert d.eligible is True
        assert d.status == "eligible"
        assert "ELIGIBLE" in d.reason

    def test_static_css_excluded_from_sqli(self):
        d = u.evaluate(u.analyze("http://h/style.css"), "sqli")
        assert d.eligible is None
        assert d.status == "deferred"
        assert d.reason.startswith("DEFERRED")
        assert "statik" in d.reason

    def test_no_params_deferred(self):
        d = u.evaluate(u.analyze("http://h/mystery"), "sqli")
        assert d.eligible is None
        assert d.status == "deferred"

    def test_xss_search_eligible(self):
        assert u.evaluate(u.analyze("http://h/search?q=admin"),
                          "xss").eligible is True

    def test_ssti_dynamic_eligible(self):
        assert u.evaluate(u.analyze("http://h/page?id=1"),
                          "ssti").eligible is True

    def test_ssrf_redirect_eligible(self):
        assert u.evaluate(u.analyze("http://h/fetch?url=http://x"),
                          "ssrf").eligible is True

    def test_api_engine_scoped_to_api_category(self):
        assert u.evaluate(u.analyze("http://h/api/v1/users"),
                          "api").eligible is True
        assert u.evaluate(u.analyze("http://h/index.html"),
                          "api").eligible is None

    def test_js_engine_scoped_to_js(self):
        assert u.evaluate(u.analyze("http://h/app.js"),
                          "js").eligible is True
        assert u.evaluate(u.analyze("http://h/logo.png"),
                          "js").eligible is None

    def test_image_excluded_from_content(self):
        assert u.evaluate(u.analyze("http://h/logo.png"),
                          "content").eligible is None

    def test_decision_records_original_url(self):
        ep = u.analyze("http://h/product?id=1")
        assert u.evaluate(ep, "sqli").evidence == ep.original


# --------------------------------------------------------------------------- #
# Dublikat + ailə qruplaşdırması
# --------------------------------------------------------------------------- #


class TestGrouping:
    def test_dedupe_keeps_first(self):
        eps = [u.analyze("http://h/p?id=1"), u.analyze("http://h/p?id=1"),
               u.analyze("http://h/p?id=2")]
        unique, dups = u.dedupe_endpoints(eps)
        assert len(unique) == 2
        assert len(dups) == 1
        assert unique[0].original == "http://h/p?id=1"

    def test_families_traceable(self):
        eps = [u.analyze("http://h/product/1"), u.analyze("http://h/product/2")]
        fam = u.families(eps)
        key = u.endpoint_family("http://h/product/1")
        assert set(fam[key]) == {"http://h/product/1", "http://h/product/2"}


# --------------------------------------------------------------------------- #
# plan_rows / intake + metrikalar
# --------------------------------------------------------------------------- #

ROWS = [
    {"id": 1, "url": "http://h/a.css", "is_js": 0, "source": "katana",
     "subdomain": "h"},
    {"id": 2, "url": "http://h/p?id=1", "is_js": 0, "source": "katana",
     "subdomain": "h"},
    {"id": 3, "url": "http://h/p?id=1", "is_js": 0, "source": "gau",
     "subdomain": "h"},
    {"id": 4, "url": "http://h/mystery", "is_js": 0, "source": "katana",
     "subdomain": "h"},
    {"id": 5, "url": "http://h/app.js", "is_js": 1, "source": "katana",
     "subdomain": "h"},
]


class TestPlanRows:
    def test_filtering_and_dedup(self):
        kept, plan = u.UrlIntelligence().plan_rows(ROWS, engine="sqli",
                                                   limit=10)
        assert plan.raw == 5
        assert plan.unique == 4
        assert plan.duplicates == 1
        assert plan.eligible == 1        # yalnız p?id=1
        assert plan.excluded == 0        # a.css + app.js
        assert plan.deferred == 3        # mystery
        assert [r["id"] for r in kept] == [2]

    def test_exclusion_reasons_recorded(self):
        _, plan = u.UrlIntelligence().plan_rows(ROWS, engine="sqli", limit=10)
        assert sum(plan.exclusion_reasons.values()) == plan.excluded
        assert all(r.startswith("SKIPPED")
                   for r in plan.exclusion_reasons)

    def test_no_engine_keeps_all_without_filtering(self):
        kept, plan = u.UrlIntelligence().plan_rows(ROWS, limit=None)
        assert plan.eligible == 0
        assert len(kept) == plan.unique

    def test_limit_applied_after_priority_sort(self):
        kept, _ = u.UrlIntelligence().plan_rows(ROWS, engine="sqli", limit=1)
        assert len(kept) == 1


class TestIntakeAndMetrics:
    def test_intake_counts(self):
        intake = u.UrlIntelligence().intake(ROWS)
        assert intake.raw == 5
        assert intake.unique == 4
        assert intake.duplicates == 1
        assert intake.families == 4

    def test_metrics_recorded(self):
        m = OrchestrationMetrics()
        intel = u.UrlIntelligence(metrics=m)
        intel.intake(ROWS)
        assert m.urls_raw == 5
        assert m.urls_unique == 4
        assert m.urls_duplicate == 1
        intel.plan_rows(ROWS, engine="sqli", limit=10)
        assert m.eligible["sqli"] == 1
        assert m.excluded["sqli"] == 0
        assert m.deferred["sqli"] == 3
        snap = m.snapshot()
        assert snap["urls"]["raw"] == 5
        assert snap["eligibility"]["eligible"]["sqli"] == 1


def test_fetch_limit_expands_only_when_filtering():
    assert u.fetch_limit(20, 20, filtering=False) == 20
    assert u.fetch_limit(20, 20, filtering=True) == 120
    assert u.fetch_limit(None, 20, filtering=False) == 20


# --------------------------------------------------------------------------- #
# Scope rəddi
# --------------------------------------------------------------------------- #


class TestScopeRejection:
    def test_out_of_scope_url_rejected(self, tmp_db, make_ctx):
        ctx = make_ctx()
        with pytest.raises(ScopeError):
            ctx.authorize_url("http://evil.example.com/x?id=1")

    def test_in_scope_url_accepted(self, tmp_db, make_ctx):
        ctx = make_ctx()
        assert ctx.authorize_url("http://127.0.0.1/x?id=1")
