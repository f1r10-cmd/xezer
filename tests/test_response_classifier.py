"""Faza 1, §3.3 — Təhlükəsiz cavab təsnifatı (`ResponseClassifier`).

Yoxlanılan prinsiplər (şəbəkəsiz, deterministik):

  * 403 → auth tələb oluna bilər → SAXLANILIR (bypass/auth-kontekst siqnalı).
  * 404 → soft-404 mümkündür → AŞAĞI prioritetlə SAXLANILIR (atılmır).
  * 405 → metod uyğunsuzluğu → DİGƏR metodlar sınanır (siqnal).
  * 500 → injeksiya siqnalı → ƏLAVƏ test üçün SAXLANILIR.
  * HEAD ≠ GET — ekvivalentlik HEÇ VAXT fərz olunmur.
  * Hər təsnifat `reason` və `evidence_refs` qeyd edir.
"""
from __future__ import annotations

from qbh.response_classifier import (
    CLASS_AUTH_REQUIRED,
    CLASS_CLIENT_ERROR,
    CLASS_METHOD_MISMATCH,
    CLASS_RATE_LIMITED,
    CLASS_REDIRECT,
    CLASS_SERVER_ERROR,
    CLASS_SOFT_NOT_FOUND,
    CLASS_SUCCESS,
    CLASS_UNKNOWN,
    ResponseClassifier,
)


def _c(**kw):
    return ResponseClassifier().classify(**kw)


# --------------------------------------------------------------------------- #
# 403 / 404 / 405 / 500 — ATILMIR, ƏHƏMİYYƏTLİ siqnal sayılır
# --------------------------------------------------------------------------- #
class TestPreservedStatuses:
    def test_403_is_actionable_not_discarded(self):
        r = _c(status=403, method="GET")
        assert r.kind == CLASS_AUTH_REQUIRED
        assert r.testable is True
        assert r.suggests_bypass is True
        assert r.priority > 0
        assert "SAXLANILIR" in r.reason

    def test_404_soft_not_found_low_priority_but_testable(self):
        r = _c(status=404, method="GET")
        assert r.kind == CLASS_SOFT_NOT_FOUND
        assert r.testable is True
        assert r.priority > 0                # SIFIR deyil → atılmır
        assert "ATILMIR" in r.reason

    def test_405_method_mismatch_suggests_other_methods(self):
        r = _c(status=405, method="POST")
        assert r.kind == CLASS_METHOD_MISMATCH
        assert r.testable is True
        assert r.try_methods
        assert "POST" not in r.try_methods   # cari metod təklif olunmur

    def test_405_respects_allow_header(self):
        r = _c(status=405, method="POST",
               response_structure={"allow": "GET, HEAD"})
        assert r.try_methods == ("GET", "HEAD")

    def test_500_server_error_elevated(self):
        r = _c(status=500, method="GET")
        assert r.kind == CLASS_SERVER_ERROR
        assert r.testable is True
        assert r.priority >= 4
        assert "injeksiya" in r.reason.lower()

    def test_all_preserved_statuses_record_reason_and_evidence(self):
        for code in (200, 301, 400, 401, 403, 404, 405, 429, 500, 503, 0):
            r = _c(status=code, method="GET", content_type="text/html")
            assert r.reason.strip(), code
            assert r.evidence_refs, code
            assert any("status=" in e for e in r.evidence_refs)
            assert r.as_dict()["status"] == code


# --------------------------------------------------------------------------- #
# HEAD ≠ GET
# --------------------------------------------------------------------------- #
class TestHeadNotEqualToGet:
    def test_head_classification_never_assumes_equivalence(self):
        r = _c(status=200, method="HEAD")
        assert r.head_get_equivalent is False
        assert "GET" in r.reason

    def test_compare_head_get_detects_difference(self):
        rc = ResponseClassifier()
        head = rc.classify(status=200, method="HEAD")
        get = rc.classify(status=403, method="GET")
        diff = rc.compare_head_get(head, get)
        assert diff.head_get_equivalent is False
        assert diff.status_change is True
        assert "HEAD ≠ GET" in diff.reason

    def test_compare_head_get_same_status_still_not_equivalent(self):
        rc = ResponseClassifier()
        head = rc.classify(status=200, method="HEAD")
        get = rc.classify(status=200, method="GET")
        same = rc.compare_head_get(head, get)
        assert same.head_get_equivalent is False

    def test_every_result_head_get_equivalent_false(self):
        for method in ("GET", "POST", "HEAD", "OPTIONS"):
            assert _c(status=200, method=method).head_get_equivalent is False


# --------------------------------------------------------------------------- #
# Davranış detalları
# --------------------------------------------------------------------------- #
class TestClassificationDetails:
    def test_429_is_block_not_test_result(self):
        r = _c(status=429, method="GET")
        assert r.kind == CLASS_RATE_LIMITED
        assert r.testable is False
        assert "Guardian" in r.reason

    def test_redirect_recorded(self):
        r = _c(status=302, method="GET", redirect_behavior="location:/login")
        assert r.kind == CLASS_REDIRECT
        assert r.testable is True
        assert any("redirect_behavior" in e for e in r.evidence_refs)

    def test_client_error_preserved(self):
        r = _c(status=400, method="GET")
        assert r.kind == CLASS_CLIENT_ERROR
        assert r.testable is True

    def test_unknown_status_not_discarded(self):
        r = _c(status=0, method="GET")
        assert r.kind == CLASS_UNKNOWN
        assert r.testable is True

    def test_success_classification(self):
        r = _c(status=200, method="GET")
        assert r.kind == CLASS_SUCCESS
        assert r.testable is True

    def test_content_type_does_not_change_testability(self):
        # Content-Type HƏDƏF tərəfindən idarə olunur → test qabiliyyətini
        # DƏYİŞMƏMƏLİDİR (yalnız qeyd olunur).
        a = _c(status=200, method="GET", content_type="text/html")
        b = _c(status=200, method="GET", content_type="application/octet-stream")
        assert a.testable == b.testable
        assert a.kind == b.kind
        assert a.content_type != b.content_type

    def test_status_change_raises_priority_and_notes(self):
        base = _c(status=403, method="GET")
        changed = _c(status=403, method="GET",
                     previous_observations={"status": 200})
        assert changed.status_change is True
        assert changed.priority > base.priority
        assert "dəyişdi" in changed.reason

    def test_endpoint_role_recorded_not_suppressing(self):
        r = _c(status=404, method="GET", endpoint_role="api")
        assert r.testable is True
        assert any("endpoint_role=api" in e for e in r.evidence_refs)

    def test_invalid_status_does_not_crash(self):
        r = _c(status=None, method="GET")
        assert r.kind == CLASS_UNKNOWN
        assert r.testable is True

    def test_method_normalised_uppercase(self):
        r = _c(status=405, method="post")
        assert r.method == "POST"
        assert "POST" not in r.try_methods
