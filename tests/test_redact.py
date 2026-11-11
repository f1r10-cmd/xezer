"""Redaction testləri — secret-lər heç vaxt açıq göstərilməməlidir."""
from __future__ import annotations

import pytest

from qbh.redact import mask_value, redact


class TestMaskValue:
    def test_masks_middle(self):
        masked = mask_value("AKIAIOSFODNN7EXAMPLE")
        assert masked.startswith("AKIA")
        assert masked.endswith("MPLE")
        assert "IOSFODNN7EXA" not in masked
        assert "*" in masked

    def test_short_value_fully_masked(self):
        assert mask_value("abc") == "***"
        assert mask_value("abcdefgh") == "*" * 8

    def test_none_and_empty(self):
        assert mask_value(None) == ""
        assert mask_value("") == ""


class TestRedact:
    @pytest.mark.parametrize("secret", [
        "AKIAIOSFODNN7EXAMPLE",
        "AIzaSyA1234567890abcdefghijklmnopqrstuv",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "xox" + "b-123456789012-abcdefghijklmn",
    ])
    def test_known_secret_patterns(self, secret):
        out = redact(f"found token {secret} here")
        assert secret not in out
        assert "<redacted>" in out

    def test_jwt(self):
        jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
               "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               "abcdefghij")
        assert jwt not in redact(f"Authorization: Bearer {jwt}")

    def test_password_assignment(self):
        out = redact("password=SuperSecret123")
        assert "SuperSecret123" not in out
        assert "password=<redacted>" in out

    def test_api_key_assignment(self):
        out = redact('api_key: "abcdef1234567890"')
        assert "abcdef1234567890" not in out

    def test_authorization_header(self):
        out = redact("Authorization: Bearer sometokenvalue")
        assert "sometokenvalue" not in out

    def test_private_key_block(self):
        pem = ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n"
               "-----END RSA PRIVATE KEY-----")
        out = redact(pem)
        assert "MIIEow" not in out
        assert "<redacted>" in out

    def test_slack_webhook(self):
        hook = "https://hooks.slack.com/services/T000/B000/XXXX"
        assert hook not in redact(f"webhook: {hook}")

    def test_plain_text_unchanged(self):
        text = "Bu adi bir cümlədir, secret yoxdur."
        assert redact(text) == text

    def test_empty_input(self):
        assert redact("") == ""
