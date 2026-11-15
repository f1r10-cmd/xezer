"""Faza 1, §3.2 — 4-hallı mühərrik uyğunluğu (`compute_eligibility`).

Yoxlanılan prinsiplər (hamısı şəbəkəsiz — yalnız qərar qatı):

  * Naməlumluq ATILMA deyil: texnologiya profili (fingerprint) YOXDURSA və ya
    NATAMAMdırsa, texnologiya-şərtli mühərrik `unknown` qaytarır — `ineligible`
    DEYİL. Yəni `eligible is None` olur, `False` olmur.
  * Profil gəldikdə `unknown` QƏTİ hala çevrilir: texnologiya tələbi
    ödənirsə → `eligible`, ödənmirsə → `ineligible` — HƏR İKİ halda səbəb
    (`reason`) qeyd olunur.
  * Heç bir test YALNIZ profil natamam olduğu üçün atılmır: `unknown` halında
    `skip` səbəbi YOXDUR (`reason` "UNKNOWN" ilə başlayır, "SKIPPED" ilə yox).
  * URL-nümunəsinin qəti qərarı (statik resurs) profil tərəfindən
    YUMŞALDILMIR — belə endpoint hər halda `ineligible` qalır.
  * `fingerprint=None` → geriyə-uyğun `evaluate()` davranışı (heç nə dəyişmir).
"""
from __future__ import annotations

import pytest

from qbh import urlintel as u


# --------------------------------------------------------------------------- #
# Geriyə uyğunluq: profil yoxdursa `evaluate` ilə eyni qərar
# --------------------------------------------------------------------------- #
class TestBackwardCompatibleWithoutFingerprint:
    @pytest.mark.parametrize("engine", u.ENGINES)
    def test_matches_evaluate_when_no_fingerprint(self, engine):
        ep = u.analyze("http://h/page?id=1")
        assert u.compute_eligibility(ep, engine) == u.evaluate(ep, engine)

    def test_fingerprint_gated_set_is_documented(self):
        assert set(u.FINGERPRINT_GATED) == {"ssti", "jwt", "library_cve"}
        assert u.FINGERPRINT_GATED == tuple(u.FINGERPRINT_REQUIRES)


# --------------------------------------------------------------------------- #
# Naməlumluq → `unknown` (atılma deyil)
# --------------------------------------------------------------------------- #
class TestUnknownIsNotIneligible:
    @pytest.mark.parametrize("engine,target", [
        ("ssti", "http://h/page?id=1"),
        ("jwt", "http://h/login"),
        ("library_cve", "http://h/app.js"),
    ])
    def test_missing_fingerprint_is_unknown_not_ineligible(self, engine, target):
        ep = u.analyze(target)
        d = u.compute_eligibility(ep, engine, fingerprint=None)
        # Profil YOXDUR → texnologiya qapısı tətbiq olunmur → əsas qərar qalır.
        assert d == u.evaluate(ep, engine)
        assert d.status != u.STATUS_UNKNOWN

    @pytest.mark.parametrize("engine,target", [
        ("ssti", "http://h/page?id=1"),
        ("jwt", "http://h/login"),
        ("library_cve", "http://h/app.js"),
    ])
    def test_incomplete_fingerprint_yields_unknown(self, engine, target):
        # NATAMAM profil: yalnız "nginx" bilinir, backend texnologiyası yoxdur.
        fp = u.Fingerprint.from_iterable(["nginx"], complete=False,
                                         source="headers")
        d = u.compute_eligibility(u.analyze(target), engine, fingerprint=fp)
        assert d.status == u.STATUS_UNKNOWN
        assert d.eligible is None
        assert d.eligible is not False            # ATILMIR
        assert d.reason.startswith("UNKNOWN")
        assert not d.reason.startswith("SKIPPED")

    def test_never_skipped_solely_because_incomplete(self):
        # `unknown` halı `skip` DEYİL — qərarda atılma sözü olmamalıdır.
        fp = u.Fingerprint.from_iterable([], complete=False)
        targets = {
            "ssti": "http://h/page?id=1",
            "jwt": "http://h/login",
            "library_cve": "http://h/app.js",
        }
        for engine in u.FINGERPRINT_GATED:
            ep = u.analyze(targets[engine])
            d = u.compute_eligibility(ep, engine, fingerprint=fp)
            assert d.eligible is None
            assert d.status == u.STATUS_UNKNOWN

    def test_empty_fingerprint_defaults_to_incomplete(self):
        assert u.Fingerprint().complete is False
        assert u.Fingerprint.from_iterable(["php"]).complete is True


# --------------------------------------------------------------------------- #
# Profil gəldikdə `unknown` qəti hala çevrilir (səbəblə)
# --------------------------------------------------------------------------- #
class TestFingerprintArrivalResolvesUnknown:
    def test_ssti_unknown_then_eligible(self):
        ep = u.analyze("http://h/page?id=1")
        incomplete = u.Fingerprint.from_iterable(["nginx"], complete=False)
        assert u.compute_eligibility(ep, "ssti",
                                     fingerprint=incomplete).status == u.STATUS_UNKNOWN

        complete = u.Fingerprint.from_iterable(["php", "nginx"], complete=True)
        d = u.compute_eligibility(ep, "ssti", fingerprint=complete)
        assert d.status == u.STATUS_ELIGIBLE
        assert d.eligible is True

    def test_ssti_unknown_then_ineligible_with_reason(self):
        ep = u.analyze("http://h/page?id=1")
        complete = u.Fingerprint.from_iterable(["react"], complete=True)
        d = u.compute_eligibility(ep, "ssti", fingerprint=complete)
        assert d.status == u.STATUS_INELIGIBLE
        assert d.eligible is False
        assert d.reason.startswith("SKIPPED")
        assert "SSTI" in d.reason
        assert d.evidence == ep.original

    def test_jwt_unknown_then_ineligible_with_reason(self):
        ep = u.analyze("http://h/login")
        complete = u.Fingerprint.from_iterable(["react", "vue"], complete=True)
        d = u.compute_eligibility(ep, "jwt", fingerprint=complete)
        assert d.status == u.STATUS_INELIGIBLE
        assert d.reason.startswith("SKIPPED")
        assert "JWT" in d.reason

    def test_jwt_unknown_then_eligible(self):
        ep = u.analyze("http://h/login")
        complete = u.Fingerprint.from_iterable(["express"], complete=True)
        d = u.compute_eligibility(ep, "jwt", fingerprint=complete)
        assert d.status == u.STATUS_ELIGIBLE
        assert d.eligible is True

    def test_library_cve_unknown_then_resolves(self):
        ep = u.analyze("http://h/app.js")
        incomplete = u.Fingerprint.from_iterable(["nginx"], complete=False)
        assert u.compute_eligibility(ep, "library_cve",
                                     fingerprint=incomplete).status == u.STATUS_UNKNOWN

        ineligible = u.Fingerprint.from_iterable(["php"], complete=True)
        d = u.compute_eligibility(ep, "library_cve", fingerprint=ineligible)
        assert d.status == u.STATUS_INELIGIBLE
        assert d.reason.startswith("SKIPPED")

        eligible = u.Fingerprint.from_iterable(["react"], complete=True)
        assert u.compute_eligibility(
            ep, "library_cve", fingerprint=eligible).status == u.STATUS_ELIGIBLE


# --------------------------------------------------------------------------- #
# URL-nümunəsinin qəti qərarı profil tərəfindən YUMŞALDILMIR
# --------------------------------------------------------------------------- #
class TestUrlPatternDecisionNotSoftened:
    def test_static_resource_stays_ineligible_even_with_matching_fingerprint(self):
        ep = u.analyze("http://h/style.css")
        complete = u.Fingerprint.from_iterable(["php"], complete=True)
        # URL özü qəti istisna edir (statik resurs) → profil bunu dəyişmir.
        for engine in ("ssti", "library_cve"):
            d = u.compute_eligibility(ep, engine, fingerprint=complete)
            assert d.status == u.STATUS_INELIGIBLE
            assert d.eligible is False

    def test_non_gated_engine_unaffected_by_fingerprint(self):
        ep = u.analyze("http://h/page?id=1")
        complete = u.Fingerprint.from_iterable(["react"], complete=True)
        # SQLi texnologiya qapısı ALTINDA DEYİL → profil qərarı dəyişmir.
        assert (u.compute_eligibility(ep, "sqli", fingerprint=complete)
                == u.evaluate(ep, "sqli"))

    def test_deferred_base_decision_preserved_when_tech_present(self):
        # SSTI üçün parametrsiz dinamik endpoint əsasda `deferred`dir; profil
        # tələbi ödəsə belə əsas qərar qalır (profil yalnız İNKAR edə bilər).
        ep = u.analyze("http://h/page")
        complete = u.Fingerprint.from_iterable(["php"], complete=True)
        d = u.compute_eligibility(ep, "ssti", fingerprint=complete)
        assert d == u.evaluate(ep, "ssti")
        assert d.status == u.STATUS_DEFERRED
