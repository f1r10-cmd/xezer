"""Konfiqurasiya yükləmə + ciddi validasiya + scope qurulması.

Qaydalar:
  * YAML strukturu yoxlanılır.
  * Boş/xətalı scope HEÇ VAXT qəbul edilmir (fail-closed).
  * Rəqəmsal limitlər yoxlanılır; təhlükəli default yoxdur.
  * Naməlum/aşağı düşmüş açar(lar) barədə xəbərdarlıq verilir.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import yaml

from .scope import ScopeEnforcer, ScopeError, normalize_host

KNOWN_TOP_KEYS = {
    "program", "nvd_api_key", "scope", "limits", "proxy_file", "antiblock",
}
# Artefakt: evasion silindiyi üçün bu açarlar artıq istifadə olunmur.
DEPRECATED_ANTIBLOCK_KEYS = {"rotate_levels", "credits"}


class ConfigError(ValueError):
    """Konfiqurasiya etibarsızdır."""


@dataclass
class Limits:
    requests_per_second: float = 5.0
    max_subdomains_per_target: int = 500
    max_concurrency: int = 10
    connect_timeout: float = 10.0
    total_timeout: float = 30.0
    cooldown: float = 60.0


@dataclass
class Config:
    path: str
    program: str
    nvd_api_key: str
    scope: ScopeEnforcer
    limits: Limits
    proxy_file: str
    interface: str = "eth0"
    warnings: list[str] = field(default_factory=list)
    _raw: dict = field(default_factory=dict)

    # ---------------- yükləmə + validasiya ----------------
    @classmethod
    def load(cls, path: str) -> "Config":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
        except FileNotFoundError as exc:
            raise ConfigError(f"konfiq faylı tapılmadı: {path}") from exc
        except yaml.YAMLError as exc:
            raise ConfigError(f"YAML sintaksis xətası ({path}): {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError(f"konfiq kökü mapping olmalıdır: {path}")
        return cls._build(path, raw)

    @classmethod
    def _build(cls, path: str, raw: dict) -> "Config":
        warnings: list[str] = []
        for key in raw:
            if key not in KNOWN_TOP_KEYS:
                warnings.append(f"naməlum konfiq açarı: {key!r}")

        program = str(raw.get("program", "QBH"))
        nvd_key = str(raw.get("nvd_api_key") or "")

        scope_entries = cls._validate_scope(path, raw.get("scope"))
        scope = ScopeEnforcer.from_entries(scope_entries)
        if scope.is_empty:
            raise ConfigError("scope boşdur — heç bir hədəfə icazə verilmir")

        limits = cls._validate_limits(raw.get("limits"))

        proxy_file = raw.get("proxy_file") or ""
        if proxy_file and not isinstance(proxy_file, str):
            raise ConfigError("proxy_file mətn olmalıdır")

        antiblock = raw.get("antiblock") or {}
        if not isinstance(antiblock, dict):
            raise ConfigError("antiblock mapping olmalıdır")
        interface = str(antiblock.get("interface", "eth0"))
        for dep in DEPRECATED_ANTIBLOCK_KEYS & set(antiblock):
            warnings.append(
                f"antiblock.{dep} artıq istifadə olunmur (evasion silindi)")

        return cls(
            path=path, program=program, nvd_api_key=nvd_key, scope=scope,
            limits=limits, proxy_file=proxy_file, interface=interface,
            warnings=warnings, _raw=raw,
        )

    @staticmethod
    def _validate_scope(path: str, scope) -> list[dict]:
        if not isinstance(scope, list) or not scope:
            raise ConfigError("scope siyahı olmalıdır və boş ola bilməz")
        entries: list[dict] = []
        for i, item in enumerate(scope):
            if not isinstance(item, dict):
                raise ConfigError(f"scope[{i}] mapping olmalıdır")
            domain = item.get("domain")
            if not domain or not isinstance(domain, str):
                raise ConfigError(f"scope[{i}].domain tələb olunur")
            try:
                normalize_host(domain)
            except ScopeError as exc:
                raise ConfigError(f"scope[{i}].domain etibarsızdır: {exc}") from exc
            in_scope = item.get("in_scope") or []
            out_scope = item.get("out_of_scope") or []
            if not isinstance(in_scope, list) or not in_scope:
                raise ConfigError(f"scope[{i}].in_scope boş ola bilməz")
            if not all(isinstance(x, str) for x in in_scope + out_scope):
                raise ConfigError(f"scope[{i}] scope qaydaları mətn olmalıdır")
            entries.append({"domain": domain, "in_scope": in_scope,
                            "out_of_scope": out_scope})
        return entries

    @staticmethod
    def _validate_limits(limits) -> Limits:
        if limits is None:
            return Limits()
        if not isinstance(limits, dict):
            raise ConfigError("limits mapping olmalıdır")
        lim = Limits()
        for key, caster, minimum in (
            ("requests_per_second", float, 0.1),
            ("max_subdomains_per_target", int, 1),
            ("max_concurrency", int, 1),
            ("connect_timeout", float, 1.0),
            ("total_timeout", float, 1.0),
            ("cooldown", float, 1.0),
        ):
            if key in limits and limits[key] is not None:
                value = limits[key]
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ConfigError(f"limits.{key} rəqəm olmalıdır")
                value = caster(value)
                if value < minimum:
                    raise ConfigError(
                        f"limits.{key} ən azı {minimum} olmalıdır")
                setattr(lim, key, value)
        return lim

    # ---------------- köməkçilər ----------------
    @property
    def targets(self) -> list[str]:
        return [e["domain"] for e in self._raw.get("scope", [])]

    def in_scope(self, host: str) -> bool:
        return self.scope.is_authorized(host)

    def authorize_target(self, value: str) -> str:
        """CLI --targets üçün: icazəsizdirsə ScopeError."""
        return self.scope.authorize(value)

    def get(self, key, default=None):
        return self._raw.get(key, default)
