"""Scope Enforcement testləri — unit + təhlükəsizlik (bypass cəhdləri)."""
from __future__ import annotations

import pytest

from qbh.scope import (ScopeEnforcer, ScopeError, extract_host,
                       normalize_host)


def scope(in_scope, out_of_scope=()):
    return ScopeEnforcer.from_entries([
        {"domain": "x", "in_scope": list(in_scope),
         "out_of_scope": list(out_of_scope)}])


# ---------------------------------------------------------------- exact
class TestExact:
    def test_exact_match(self):
        s = scope(["example.com"])
        assert s.is_authorized("example.com")
        assert s.is_authorized("EXAMPLE.COM")     # normalize
        assert s.is_authorized("example.com.")    # trailing dot

    def test_exact_rejects_sibling(self):
        s = scope(["example.com"])
        assert not s.is_authorized("evil.com")
        assert not s.is_authorized("sub.example.com")

    def test_exact_rejects_suffix_confusion(self):
        s = scope(["example.com"])
        assert not s.is_authorized("example.com.attacker.test")
        assert not s.is_authorized("evil-example.com")
        assert not s.is_authorized("notexample.com")
        assert not s.is_authorized("example.com.evil.test")


# ---------------------------------------------------------------- wildcard
class TestWildcard:
    def test_wildcard_matches_subdomain(self):
        s = scope(["*.example.com"])
        assert s.is_authorized("a.example.com")
        assert s.is_authorized("deep.a.example.com")

    def test_wildcard_does_not_match_root(self):
        s = scope(["*.example.com"])
        assert not s.is_authorized("example.com")

    def test_wildcard_suffix_confusion(self):
        s = scope(["*.example.com"])
        # Wildcard yalnız HƏQİQİ alt-domeni qəbul edir
        assert not s.is_authorized("example.com.attacker.test")
        assert not s.is_authorized("attacker.example.com.evil.test")
        assert not s.is_authorized("notexample.com")
        assert not s.is_authorized("evilexample.com")

    def test_root_and_wildcard(self):
        s = scope(["example.com", "*.example.com"])
        assert s.is_authorized("example.com")
        assert s.is_authorized("a.example.com")


# ---------------------------------------------------------------- deny
class TestOutOfScopeDenial:
    def test_deny_wins(self):
        s = scope(["*.example.com"], ["admin.example.com"])
        assert s.is_authorized("shop.example.com")
        assert not s.is_authorized("admin.example.com")

    def test_deny_wildcard(self):
        s = scope(["*.example.com"], ["*.internal.example.com"])
        assert not s.is_authorized("db.internal.example.com")
        assert s.is_authorized("internal.example.com")  # root, not denied

    def test_denied_host_in_allow_still_rejected(self):
        s = scope(["example.com"], ["example.com"])
        assert not s.is_authorized("example.com")


# ---------------------------------------------------------------- hostnames
class TestMalformedHostnames:
    @pytest.mark.parametrize("bad", [
        "", "   ", "-bad.com", "bad-.com", "bad..com", "a b.com",
        "localhost", "example", "1.2.3.4.5.6",
        "http://exa mple.com", "a" * 300 + ".com",
    ])
    def test_normalize_rejects(self, bad):
        with pytest.raises(ScopeError):
            normalize_host(bad)

    def test_numeric_tld_rejected(self):
        with pytest.raises(ScopeError):
            normalize_host("example.123")

    def test_extract_url_host(self):
        # `extract_host` yalnız hostu ayırır; registr `normalize_host`-da
        # kanonikləşdirilir (URL formasında urlsplit hostu lowercase edir).
        assert extract_host("https://EXAMPLE.com/path?q=1").lower() == "example.com"
        assert extract_host("example.com:8443") == "example.com"
        assert extract_host("example.com") == "example.com"
        assert extract_host("[::1]:443") == "::1"


# ---------------------------------------------------------------- IP
class TestIpAuthorization:
    def test_ip_explicitly_authorized(self):
        s = scope(["203.0.113.5"])
        assert s.is_authorized("203.0.113.5")
        assert not s.is_authorized("203.0.113.6")

    def test_ip_not_authorized_by_domain_rule(self):
        s = scope(["example.com"])
        assert not s.is_authorized("203.0.113.5")

    def test_cidr_rule(self):
        s = scope(["10.0.0.0/8"])
        assert s.is_authorized("10.1.2.3")
        assert not s.is_authorized("11.1.2.3")

    def test_ipv6_loopback(self):
        s = scope(["::1"])
        assert s.is_authorized("::1")
        assert not s.is_authorized("::2")


# ---------------------------------------------------------------- IDNA
class TestUnicodeIdna:
    def test_unicode_normalized_to_punycode(self):
        assert normalize_host("münchen.de") == "xn--mnchen-3ya.de"

    def test_unicode_in_scope(self):
        s = scope(["xn--mnchen-3ya.de"])
        assert s.is_authorized("münchen.de")
        assert s.is_authorized("MÜNCHEN.de")

    def test_unicode_deny(self):
        s = scope(["*.xn--mnchen-3ya.de"])
        assert s.is_authorized("shop.münchen.de")

    def test_invalid_idna_rejected(self):
        with pytest.raises(ScopeError):
            normalize_host("xn--\u00ff\u00ff.de")


# ---------------------------------------------------------------- fail closed
class TestFailClosed:
    def test_empty_scope_denies_everything(self):
        s = ScopeEnforcer.from_entries([])
        assert s.is_empty
        assert not s.is_authorized("example.com")
        with pytest.raises(ScopeError):
            s.authorize("example.com")

    def test_authorize_returns_canonical(self):
        s = scope(["example.com"])
        assert s.authorize("EXAMPLE.COM.") == "example.com"

    def test_authorize_raises_out_of_scope(self):
        s = scope(["example.com"])
        with pytest.raises(ScopeError):
            s.authorize("evil.com")


# ---------------------------------------------------------------- redirect
class TestRedirectScope:
    def test_redirect_within_scope(self):
        s = scope(["example.com"])
        assert s.resolve_redirect("https://example.com/a", "/b") == \
            "https://example.com/b"

    def test_redirect_absolute_within_scope(self):
        s = scope(["example.com"])
        assert s.resolve_redirect(
            "https://example.com/a", "https://example.com/x") == \
            "https://example.com/x"

    def test_redirect_escape_blocked(self):
        s = scope(["example.com"])
        with pytest.raises(ScopeError):
            s.resolve_redirect("https://example.com/a", "http://evil.com/")

    def test_redirect_scheme_relative_escape_blocked(self):
        s = scope(["example.com"])
        with pytest.raises(ScopeError):
            s.resolve_redirect("https://example.com/a", "//evil.com/x")

    def test_redirect_subdomain_escape_blocked(self):
        s = scope(["example.com"])
        with pytest.raises(ScopeError):
            s.resolve_redirect("https://example.com/a",
                               "https://example.com.evil.test/x")

    def test_empty_redirect_blocked(self):
        s = scope(["example.com"])
        with pytest.raises(ScopeError):
            s.resolve_redirect("https://example.com/a", "")
