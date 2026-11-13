"""Faza 3.2 testi — şifrəli secret vault + `secret_replay` mühərriki.

Prinsiplər:
  * Heç bir test xarici hədəfə müraciət etmir — yalnız `127.0.0.1` fixture.
  * Düz mətn secret-in bazaya/heç yerə yazılmadığı sübut olunur.
  * Replay RoE ilə qapılıdır; qadağandırsa addım atlanır və audit yazılır.
"""
from __future__ import annotations

from qbh import db
from qbh.engines.secret_replay import SecretReplayEngine, headers_for
from qbh.vault import ENV_VAR, SecretVault, normalize_key

VALID_TOKEN = "valid-token-1234567890"
LOOPBACK_SCOPE = [{"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
                   "out_of_scope": []}]


def _fernet_key() -> str:
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()


# ------------------------------------------------------------------ vault
class TestVaultKey:
    def test_valid_fernet_key_passthrough(self):
        key = _fernet_key()
        assert normalize_key(key) == key.encode()

    def test_passphrase_is_deterministic(self):
        a, b = normalize_key("s3cr3t-pass"), normalize_key("s3cr3t-pass")
        assert a == b and len(a) == 44

    def test_empty_material(self):
        assert normalize_key("") is None
        assert normalize_key("   ") is None


class TestVault:
    def test_env_key_enables_roundtrip(self, monkeypatch):
        monkeypatch.setenv(ENV_VAR, _fernet_key())
        v = SecretVault()
        assert v.available
        tok = v.encrypt("hello-secret")
        assert tok and tok != "hello-secret"
        assert v.decrypt(tok) == "hello-secret"

    def test_key_file_enables_vault(self, tmp_path, monkeypatch):
        monkeypatch.delenv(ENV_VAR, raising=False)
        kf = tmp_path / "vault.key"
        kf.write_text(_fernet_key(), encoding="utf-8")
        assert SecretVault(key_file=str(kf)).available

    def test_missing_key_file_is_honest(self, tmp_path, monkeypatch):
        monkeypatch.delenv(ENV_VAR, raising=False)
        v = SecretVault(key_file=str(tmp_path / "nope.key"))
        assert not v.available
        assert v.encrypt("x") is None
        assert v.decrypt("x") is None
        assert v.reason  # səbəb açıq şəkildə bildirilir

    def test_no_key_anywhere_unavailable(self, monkeypatch):
        monkeypatch.delenv(ENV_VAR, raising=False)
        v = SecretVault()
        assert not v.available
        assert v.encrypt("x") is None

    def test_disabled_vault(self, monkeypatch):
        monkeypatch.setenv(ENV_VAR, _fernet_key())
        v = SecretVault(enabled=False)
        assert not v.available
        assert v.encrypt("x") is None

    def test_tampered_token_returns_none(self, monkeypatch):
        monkeypatch.setenv(ENV_VAR, _fernet_key())
        v = SecretVault()
        assert v.decrypt("not-a-valid-token") is None

    def test_from_config(self, loopback_config, monkeypatch):
        monkeypatch.setenv(ENV_VAR, _fernet_key())
        v = SecretVault.from_config(loopback_config)
        assert v.available
        assert v.summary()["available"] is True

    def test_summary_does_not_leak_key(self, monkeypatch):
        monkeypatch.setenv(ENV_VAR, "super-secret-passphrase")
        v = SecretVault()
        assert "super-secret-passphrase" not in str(v.summary())


# ------------------------------------------------------------------ db
class TestVaultDb:
    def test_value_enc_column_exists(self, tmp_db):
        cols = {r["name"] for r in
                tmp_db.get_db().execute("PRAGMA table_info(secrets)")}
        assert "value_enc" in cols

    def test_insert_with_cipher(self, tmp_db):
        hid = tmp_db.upsert_host("127.0.0.1", status_code=200)
        tmp_db.insert_secret(hid, "http://127.0.0.1:1/x.js", "JWT token",
                             "eyJ***", value_enc="TOKENVALUE")
        rows = tmp_db.secrets_with_cipher(scan_id=None)
        assert len(rows) == 1
        assert rows[0]["value_enc"] == "TOKENVALUE"

    def test_plain_secret_excluded_from_cipher(self, tmp_db):
        hid = tmp_db.upsert_host("127.0.0.1", status_code=200)
        tmp_db.insert_secret(hid, "http://127.0.0.1:1/x.js", "JWT token", "eyJ***")
        assert tmp_db.secrets_with_cipher(scan_id=None) == []


# ------------------------------------------------------------------ headers
class TestHeadersFor:
    def test_jwt_uses_bearer(self):
        assert headers_for("JWT token", "abc") == {"Authorization": "Bearer abc"}

    def test_api_key_uses_two_headers(self):
        h = headers_for("Google API Key", "abc")
        assert h["X-Api-Key"] == "abc" and h["Authorization"] == "Bearer abc"

    def test_generic_defaults(self):
        h = headers_for("Generic secret", "abc")
        assert "Authorization" in h and "X-Api-Key" in h


# ------------------------------------------------------------------ engine
class TestSecretReplayEngine:
    async def test_forbidden_by_roe_skips_and_audits(
            self, make_ctx, load_config, tmp_db, monkeypatch):
        monkeypatch.setenv(ENV_VAR, _fernet_key())
        cfg = load_config(LOOPBACK_SCOPE, extra={
            "program_rules": {"forbidden": ["secret_replay"]}})
        ctx = make_ctx(cfg=cfg)
        res = await SecretReplayEngine(ctx).run()
        assert res.skipped
        assert any(e.get("event") == "secret_replay_skipped"
                   for e in ctx.egress_audit)

    async def test_vault_unavailable_skips(
            self, make_ctx, tmp_db, monkeypatch):
        monkeypatch.delenv(ENV_VAR, raising=False)
        ctx = make_ctx()
        res = await SecretReplayEngine(ctx).run()
        assert res.skipped

    async def test_no_candidates_skips(self, make_ctx, tmp_db, monkeypatch):
        monkeypatch.setenv(ENV_VAR, _fernet_key())
        ctx = make_ctx()
        res = await SecretReplayEngine(ctx).run()
        assert res.skipped

    async def test_valid_secret_confirmed(
            self, make_ctx, tmp_db, local_server, monkeypatch):
        monkeypatch.setenv(ENV_VAR, _fernet_key())
        ctx = make_ctx()
        hid = db.upsert_host("127.0.0.1", status_code=200, scan_id=ctx.scan_id)
        enc = ctx.vault.encrypt(VALID_TOKEN)
        db.insert_secret(hid, f"{local_server['base']}/app.js", "JWT token",
                         "valid***", value_enc=enc)
        res = await SecretReplayEngine(ctx, probe_path="/secret").run()
        assert res.findings == 1
        row = db.get_db().execute(
            "SELECT status, confidence FROM findings "
            "WHERE module='secret_replay'").fetchone()
        assert row["status"] == "confirmed"

    async def test_invalid_secret_rejected(
            self, make_ctx, tmp_db, local_server, monkeypatch):
        monkeypatch.setenv(ENV_VAR, _fernet_key())
        ctx = make_ctx()
        hid = db.upsert_host("127.0.0.1", status_code=200, scan_id=ctx.scan_id)
        enc = ctx.vault.encrypt("wrong-token-0000000000")
        db.insert_secret(hid, f"{local_server['base']}/app.js", "JWT token",
                         "wrong***", value_enc=enc)
        res = await SecretReplayEngine(ctx, probe_path="/secret").run()
        assert res.findings == 0
        row = db.get_db().execute(
            "SELECT status FROM findings WHERE module='secret_replay'").fetchone()
        assert row["status"] == "rejected"

    async def test_webhook_not_replayed(
            self, make_ctx, tmp_db, monkeypatch):
        monkeypatch.setenv(ENV_VAR, _fernet_key())
        ctx = make_ctx()
        hid = db.upsert_host("127.0.0.1", status_code=200, scan_id=ctx.scan_id)
        db.insert_secret(hid, "http://127.0.0.1:1/app.js", "Slack webhook",
                         "https***", value_enc="x")
        res = await SecretReplayEngine(ctx).run()
        assert res.findings == 0
        assert any("replay edilə bilməz" in w for w in res.warnings)

    async def test_out_of_scope_skipped(
            self, make_ctx, tmp_db, monkeypatch):
        monkeypatch.setenv(ENV_VAR, _fernet_key())
        ctx = make_ctx()
        enc = ctx.vault.encrypt("some-secret-value-123456")
        hid = db.upsert_host("evil.test", status_code=200, scan_id=ctx.scan_id)
        db.insert_secret(hid, "http://evil.test/app.js", "JWT token",
                         "some***", value_enc=enc)
        res = await SecretReplayEngine(ctx).run()
        assert res.findings == 0
        assert res.warnings  # scope xarici → xəbərdarlıq
