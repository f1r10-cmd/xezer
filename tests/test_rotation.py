"""İdentiklik rotasiyası (OPSEC) testləri — configurable və audit olunmuş.

Yoxlanılan prinsiplər:
  * Rotasiya qapalı olduqda davranış deterministik və sabitdir.
  * Rotasiya aktiv olduqda `rotate()` identikliyi dəyişir və audit qeydi düşür.
  * UA, başlıq və proxy rotasiyası ayrı-ayrı konfiqurasiya oluna bilər.
  * Heç bir test xarici hədəfə müraciət etmir.
"""
from __future__ import annotations

from qbh.antiblock.identity import IdentityManager
from qbh.config import RotationConfig


def _rot(**kw):
    base = dict(enabled=True, ua=False, headers=False, proxy=False, on_block=True)
    base.update(kw)
    return RotationConfig(**base)


# ---------------------------------------------------------------- deterministic
class TestDeterministic:
    def test_no_rotation_is_stable(self):
        mgr = IdentityManager("", "lo", None)
        assert mgr.can_rotate is False
        a = mgr.identity_for("example.com")
        b = mgr.identity_for("example.com")
        assert a == b
        assert mgr.rotate("example.com", "test") is False

    def test_headers_always_present(self):
        mgr = IdentityManager("", "lo", None)
        h = mgr.headers_for("example.com")
        assert "User-Agent" in h and "Accept-Language" in h


# ---------------------------------------------------------------- rotation on
class TestRotation:
    def test_ua_rotation_changes_identity(self):
        mgr = IdentityManager("", "lo", _rot(ua=True))
        assert mgr.can_rotate is True
        before = mgr.identity_for("example.com")
        assert mgr.rotate("example.com", "HTTP 429") is True
        after = mgr.identity_for("example.com")
        assert after != before
        assert after.ua != before.ua

    def test_audit_log_records_rotation(self):
        mgr = IdentityManager("", "lo", _rot(ua=True, headers=True))
        mgr.rotate("example.com", "HTTP 403")
        log = mgr.audit_log()
        assert len(log) == 1
        assert log[0]["host"] == "example.com"
        assert log[0]["reason"] == "HTTP 403"
        assert log[0]["ua_changed"] is True

    def test_on_block_false_disables_rotation(self):
        mgr = IdentityManager("", "lo", _rot(ua=True, on_block=False))
        assert mgr.can_rotate is True
        assert mgr.rotate("example.com", "x") is False
        assert mgr.audit_log() == []

    def test_proxy_rotation(self, tmp_path):
        proxy_file = tmp_path / "proxies.txt"
        proxy_file.write_text(
            "http://127.0.0.1:8080\nhttp://127.0.0.1:8081\n", encoding="utf-8")
        mgr = IdentityManager(str(proxy_file), "lo", _rot(proxy=True))
        before = mgr.proxy_for("example.com")
        assert before is not None
        assert mgr.rotate("example.com", "HTTP 429") is True
        after = mgr.proxy_for("example.com")
        assert after != before
        assert mgr.audit_log()[0]["proxy_changed"] is True

    def test_disabled_rotation_zeroes_subflags(self):
        # Config validasiyası: enabled=False → bütün alt bayraqlar sıfırlanır.
        from qbh.config import Config

        rc = Config._validate_rotation(
            {"enabled": False, "ua": True, "headers": True, "proxy": True},
            {"rotate_ua": True, "rotate_headers": True, "rotate_proxy": True},
            [])
        assert rc.enabled is False
        assert rc.ua is False and rc.headers is False and rc.proxy is False
