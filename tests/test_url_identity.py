"""Faza 1, §3.1 — Çox-səviyyəli URL kimliyi (`URLIdentity`).

Yoxlanılan prinsiplər (hamısı şəbəkəsiz və DETERMİNİSTİK):

  * Hər test növü ÖZ kimlik səviyyəsini işlədir; səviyyələr QARIŞDIRILMIR.
  * `infra_id` yalnız host+scheme+port → rəqəmsal ID-lər BİRLƏŞİR
    (`/user/123` ilə `/user/456` eyni infrastruktur).
  * `idor_id` isə bu ID-ləri QORUYUR → onlar AYRILIR (IDOR/BOLA üçün).
  * Metod, parametr adı/dəyəri və auth konteksti — vacib olduqda AYRILIR.
  * Orijinal URL heç bir səviyyədə SİLİNMİR (normalizasiya onu məhv etmir).
  * Hər səviyyə üçün `reason` (niyə bu birləşdirmə təhlükəsizdir) mövcuddur.
  * Geriyə uyğunluq: `task_identity()` köhnə çağırışlarda EYNİ nəticə verir.
"""
from __future__ import annotations

from qbh import urlintel as u
from qbh.tasks import task_identity


# --------------------------------------------------------------------------- #
# Metod fərqi
# --------------------------------------------------------------------------- #
class TestMethodDistinction:
    def test_same_url_different_methods_differ_in_testing_id(self):
        get = u.url_identity("http://h/api/v1/users", method="GET")
        post = u.url_identity("http://h/api/v1/users", method="POST")
        assert get.testing_id != post.testing_id

    def test_method_case_insensitive(self):
        a = u.url_identity("http://h/x", method="get")
        b = u.url_identity("http://h/x", method="GET")
        assert a.testing_id == b.testing_id
        assert a.method == "GET"

    def test_infra_id_is_host_level_only(self):
        # infra_id yalnız host → metod onu DƏYİŞMİR (infrastruktur birdir).
        get = u.url_identity("http://h/x?a=1", method="GET")
        post = u.url_identity("http://h/x?a=1", method="POST")
        assert get.infra_id == post.infra_id
        assert get.param_id != post.param_id


# --------------------------------------------------------------------------- #
# Rəqəmsal ID-lər — infra BİRLƏŞİR, idor AYRILIR
# --------------------------------------------------------------------------- #
class TestNumericIdIdentity:
    def test_same_infra_id_for_different_object_ids(self):
        a = u.url_identity("http://h/user/123")
        b = u.url_identity("http://h/user/456")
        assert a.infra_id == b.infra_id

    def test_different_idor_id_for_different_object_ids(self):
        a = u.url_identity("http://h/user/123")
        b = u.url_identity("http://h/user/456")
        assert a.idor_id != b.idor_id

    def test_uuid_object_id_preserved_in_idor(self):
        x = "http://h/orders/550e8400-e29b-41d4-a716-446655440000"
        y = "http://h/orders/550e8400-e29b-41d4-a716-446655440001"
        assert u.url_identity(x).infra_id == u.url_identity(y).infra_id
        assert u.url_identity(x).idor_id != u.url_identity(y).idor_id

    def test_object_segments_extracted_in_order(self):
        assert u._object_segments("http://h/user/12/order/99") == ("12", "99")
        assert u._object_segments("http://h/user/profile") == ()


# --------------------------------------------------------------------------- #
# Parametr fərqi
# --------------------------------------------------------------------------- #
class TestParamIdentity:
    def test_same_url_different_params_differ_in_param_id(self):
        a = u.url_identity("http://h/item?id=1")
        b = u.url_identity("http://h/item?id=2")
        assert a.param_id != b.param_id

    def test_param_order_does_not_matter(self):
        a = u.url_identity("http://h/item?a=1&b=2")
        b = u.url_identity("http://h/item?b=2&a=1")
        assert a.param_id == b.param_id

    def test_testing_id_ignores_param_values(self):
        # Ümumi test səviyyəsi parametr DƏYƏRİNİ buraxır → eyni qalır.
        a = u.url_identity("http://h/item?id=1")
        b = u.url_identity("http://h/item?id=2")
        assert a.testing_id == b.testing_id


# --------------------------------------------------------------------------- #
# Auth konteksti
# --------------------------------------------------------------------------- #
class TestAuthIdentity:
    def test_different_auth_context_differ_in_auth_id(self):
        anon = u.url_identity("http://h/profile", auth_context="anon")
        user = u.url_identity("http://h/profile", auth_context="session:user")
        assert anon.auth_id != user.auth_id

    def test_testing_id_unaffected_by_auth_context(self):
        anon = u.url_identity("http://h/profile", auth_context="anon")
        user = u.url_identity("http://h/profile", auth_context="session:user")
        assert anon.testing_id == user.testing_id

    def test_missing_auth_context_is_stable(self):
        assert (u.url_identity("http://h/profile").auth_id
                == u.url_identity("http://h/profile", auth_context="").auth_id)


# --------------------------------------------------------------------------- #
# Orijinalın qorunması + səbəblər
# --------------------------------------------------------------------------- #
class TestOriginalAndReasons:
    def test_every_identity_type_preserves_original(self):
        raw = "http://H:8080/A/../user/123?ID=1&x=%2F#frag"
        ident = u.url_identity(raw, method="post", auth_context="tok")
        assert ident.original == raw
        assert ident.preserves_original()
        # Orijinal dəyişdirilməyib — yalnız kimliklər hesablanıb.
        for level in u.IDENTITY_LEVELS:
            assert ident.get(level)

    def test_each_level_has_reason(self):
        ident = u.url_identity("http://h/x")
        for level in u.IDENTITY_LEVELS:
            assert ident.reason(level).strip(), level

    def test_ids_are_distinct_across_levels(self):
        ident = u.url_identity("http://h/user/1?id=9", auth_context="anon")
        ids = [ident.get(lv) for lv in u.IDENTITY_LEVELS]
        assert len(set(ids)) == len(ids)

    def test_unknown_level_returns_empty(self):
        ident = u.url_identity("http://h/x")
        assert ident.get("bogus") == ""
        assert ident.reason("bogus") == ""

    def test_as_dict_shape(self):
        d = u.url_identity("http://h/x").as_dict()
        assert set(d) == set(u.IDENTITY_LEVELS)

    def test_invalid_url_does_not_crash(self):
        ident = u.url_identity("not a url")
        assert ident.original == "not a url"
        assert ident.infra_id            # host boş olsa da stabil hash
        assert u.url_identity(None).original == ""


# --------------------------------------------------------------------------- #
# Geriyə uyğunluq — `task_identity`
# --------------------------------------------------------------------------- #
class TestTaskIdentityBackwardCompatibility:
    def test_default_call_unchanged(self):
        # Köhnə imza ilə eyni nəticə (heç bir identity verilmədən).
        old_style = task_identity(1, "sqli", "http://h/x", method="POST",
                                  param="id=1", test_type="t", profile="p")
        new_style = task_identity(1, "sqli", "http://h/x", method="POST",
                                  param="id=1", test_type="t", profile="p",
                                  identity_level="", identity="")
        assert old_style == new_style

    def test_default_digest_matches_legacy_formula(self):
        # Legacy formula: gözlənilən hex[:32] (regressiya qoruyucusu).
        import hashlib
        raw = "\x1f".join(["7", "xss", "http://h/a", "GET", "", "", ""])
        expected = hashlib.sha256(raw.encode()).hexdigest()[:32]
        assert task_identity(7, "xss", "http://h/a") == expected

    def test_identity_level_changes_identity(self):
        base = task_identity(1, "sqli", "http://h/x")
        with_id = task_identity(1, "sqli", "http://h/x",
                                identity_level="idor",
                                identity=u.url_identity("http://h/x").idor_id)
        assert base != with_id

    def test_identity_level_distinguishes_object_ids(self):
        a = u.url_identity("http://h/user/1")
        b = u.url_identity("http://h/user/2")
        ta = task_identity(1, "sqli", "http://h/user/1",
                           identity_level="idor", identity=a.idor_id)
        tb = task_identity(1, "sqli", "http://h/user/2",
                           identity_level="idor", identity=b.idor_id)
        assert ta != tb
