"""Konfiqurasiya validasiyası testləri (fail-closed)."""
from __future__ import annotations

import pytest

from qbh.config import Config, ConfigError
from qbh.scope import ScopeError

GOOD = [{"domain": "example.com", "in_scope": ["example.com", "*.example.com"],
         "out_of_scope": []}]


class TestValidConfig:
    def test_loads(self, load_config):
        cfg = load_config(GOOD)
        assert cfg.program == "test"
        assert cfg.targets == ["example.com"]
        assert cfg.in_scope("a.example.com")
        assert not cfg.in_scope("evil.com")
        assert cfg.limits.requests_per_second == 50

    def test_authorize_target(self, load_config):
        cfg = load_config(GOOD)
        assert cfg.authorize_target("a.example.com") == "a.example.com"
        with pytest.raises(ScopeError):
            cfg.authorize_target("evil.com")

    def test_example_local_config_is_valid(self):
        cfg = Config.load("config/example_local.yaml")
        assert cfg.in_scope("127.0.0.1")
        assert not cfg.in_scope("8.8.8.8")


class TestFileErrors:
    def test_missing_file(self):
        with pytest.raises(ConfigError):
            Config.load("/nonexistent/does-not-exist.yaml")

    def test_bad_yaml(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("scope: [::broken", encoding="utf-8")
        with pytest.raises(ConfigError):
            Config.load(str(p))

    def test_root_not_mapping(self, tmp_path):
        p = tmp_path / "list.yaml"
        p.write_text("- a\n- b\n", encoding="utf-8")
        with pytest.raises(ConfigError):
            Config.load(str(p))


class TestScopeValidation:
    def test_empty_scope_rejected(self, load_config):
        with pytest.raises(ConfigError):
            load_config([])

    def test_scope_not_list(self, write_config):
        with pytest.raises(ConfigError):
            Config.load(write_config({"domain": "x"}))

    def test_scope_item_not_mapping(self, write_config):
        with pytest.raises(ConfigError):
            Config.load(write_config(["example.com"]))

    def test_missing_domain(self, write_config):
        with pytest.raises(ConfigError):
            Config.load(write_config([{"in_scope": ["example.com"]}]))

    def test_empty_in_scope(self, write_config):
        with pytest.raises(ConfigError):
            Config.load(write_config([{"domain": "example.com",
                                       "in_scope": []}]))

    def test_invalid_domain_rejected(self, write_config):
        with pytest.raises(ConfigError):
            Config.load(write_config([{"domain": "bad host",
                                       "in_scope": ["bad host"]}]))

    def test_non_string_rules(self, write_config):
        with pytest.raises(ConfigError):
            Config.load(write_config([{"domain": "example.com",
                                       "in_scope": [123]}]))


class TestLimitsValidation:
    def test_limits_not_mapping(self, write_config):
        with pytest.raises(ConfigError):
            Config.load(write_config(GOOD, limits="fast"))

    @pytest.mark.parametrize("key,value", [
        ("requests_per_second", "abc"),
        ("requests_per_second", 0),
        ("max_concurrency", 0),
        ("cooldown", 0),
        ("total_timeout", -3),
    ])
    def test_bad_limits(self, write_config, key, value):
        limits = {"requests_per_second": 5, key: value}
        with pytest.raises(ConfigError):
            Config.load(write_config(GOOD, limits=limits))

    def test_none_limit_is_ignored(self, write_config):
        cfg = Config.load(write_config(
            GOOD, limits={"requests_per_second": 5, "max_concurrency": None}))
        assert cfg.limits.max_concurrency == 10  # default saxlanılır

    def test_bool_is_not_number(self, write_config):
        with pytest.raises(ConfigError):
            Config.load(write_config(GOOD, limits={"max_concurrency": True}))


class TestWarnings:
    def test_unknown_key_warns(self, write_config):
        cfg = Config.load(write_config(GOOD, extra={"mystery": 1}))
        assert any("naməlum" in w for w in cfg.warnings)

    def test_deprecated_antiblock_warns(self, write_config):
        cfg = Config.load(write_config(
            GOOD, antiblock={"interface": "lo", "rotate_levels": {},
                             "credits": True}))
        joined = " ".join(cfg.warnings)
        assert "rotate_levels" in joined
        assert "credits" in joined

    def test_proxy_file_must_be_str(self, write_config):
        with pytest.raises(ConfigError):
            Config.load(write_config(GOOD, proxy_file={"a": 1}))

    def test_antiblock_wrong_type_rejected(self, write_config):
        with pytest.raises(ConfigError):
            Config.load(write_config(GOOD, antiblock=["eth0"]))
