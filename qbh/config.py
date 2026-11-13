"""Konfiqurasiya yükləmə + ciddi validasiya + scope qurulması.

Qaydalar:
  * YAML strukturu yoxlanılır.
  * Boş/xətalı scope HEÇ VAXT qəbul edilmir (fail-closed).
  * Rəqəmsal limitlər yoxlanılır.
  * Naməlum açar(lar) barədə xəbərdarlıq verilir.
  * `aggressiveness` profili (passive|normal|aggressive) aktiv test, rotation
    və blok strategiyası üçün DEFAULT-ları təyin edir; YAML bunları
    fərdi olaraq override edə bilər.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import yaml

from .scope import ScopeEnforcer, ScopeError, normalize_host

KNOWN_TOP_KEYS = {
    "program", "nvd_api_key", "scope", "limits", "proxy_file", "antiblock",
    "aggressiveness", "program_rules", "rotation", "block_strategy", "chain",
    "oob", "stealth", "vault",
}

#: Faza 2 — stealth qatının strateji variantları.
PROXY_STRATEGIES = {"off", "single", "rotate", "residential", "tor"}
PACING_PROFILES = {"passive", "normal", "aggressive"}
IMPERSONATE_TARGETS = {"off", "chrome", "safari", "firefox", "edge"}

#: `antiblock` bölməsində qəbul olunan açar(lar). Digərləri (köhnə `rotate_levels`,
#: `credits`) sadəcə xəbərdarlıqla nəzərə alınmır.
KNOWN_ANTIBLOCK_KEYS = {"interface"}

# Offensive icra profilləri. Bunlar DEFAULT-dur; YAML override edə bilər.
PROFILES = {
    "passive": {
        "rate_factor": 0.5, "concurrency_factor": 0.5, "max_redirects": 5,
        "active_fuzz": False, "intrusive_templates": False,
        "rotate_ua": False, "rotate_headers": False, "rotate_proxy": False,
        "block_429": "respect", "block_403": "backoff",
    },
    "normal": {
        "rate_factor": 1.0, "concurrency_factor": 1.0, "max_redirects": 10,
        "active_fuzz": True, "intrusive_templates": False,
        "rotate_ua": True, "rotate_headers": False, "rotate_proxy": False,
        "block_429": "respect", "block_403": "backoff",
    },
    "aggressive": {
        "rate_factor": 2.0, "concurrency_factor": 2.0, "max_redirects": 20,
        "active_fuzz": True, "intrusive_templates": True,
        "rotate_ua": True, "rotate_headers": True, "rotate_proxy": True,
        "block_429": "backoff_then_rotate", "block_403": "rotate",
    },
}

BLOCK_429_STRATEGIES = {"respect", "rotate", "backoff_then_rotate"}
BLOCK_403_STRATEGIES = {"backoff", "rotate", "escalate_bypass"}

#: Proqramın istifadəsini qadağan edə biləcəyi hərəkətlər.
#: `state_changing` — state dəyişən HTTP metodları (POST/PUT/PATCH/DELETE);
#: default olaraq qadağandır və yalnız `--allow-state-changing` ilə açılır.
ALL_ACTIONS = {
    "active_fuzz", "intrusive_templates", "bypass", "cve_poc",
    "secret_replay", "param_fuzz", "race", "state_changing",
}


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
class RotationConfig:
    """İdentiklik rotasiyası (OPSEC) — configurable."""
    enabled: bool = True
    ua: bool = True
    headers: bool = True
    proxy: bool = False
    on_block: bool = True


@dataclass
class BlockStrategy:
    http_429: str = "respect"
    http_403: str = "backoff"

    def for_status(self, status: int) -> str:
        if status == 429:
            return self.http_429
        if status == 403:
            return self.http_403
        return "respect"


@dataclass
class ChainConfig:
    enabled: bool = True
    max_depth: int = 3
    max_tasks: int = 200


@dataclass
class OOBConfig:
    """Faza 1.4 — Out-of-Band geri-zəng konfiqurasiyası."""
    enabled: bool = True
    domain: str = ""             # internetdən əlçatan geri-zəng domeni
    listen_host: str = "127.0.0.1"
    listen_port: int = 0
    backend: str = "local"       # "local" | "interactsh"
    wait: float = 20.0           # callback gözləmə müddəti (saniyə)

    @property
    def active(self) -> bool:
        return bool(self.enabled and self.domain)


@dataclass
class StealthConfig:
    """Faza 2 — deteksiya azaltma konfiqurasiyası (profil-əsaslı)."""
    impersonate: str = "chrome"          # off|chrome|safari|firefox|edge
    proxy_strategy: str = "off"          # off|single|rotate|residential|tor
    pacing: str = "aggressive"           # passive|normal|aggressive
    pacing_max_overhead: float = 1.15    # bulk fazalarda maksimal yavaşlama
    waf_adapt: bool = True               # WAF aşkarlaması → bypass/rate/tamper
    tor_for_sensitive_only: bool = True  # Tor yalnız həssas fazalarda


@dataclass
class VaultConfig:
    """Faza 3.2 — şifrəli secret vault konfiqurasiyası.

    Açar ya `vault.key_file`-dan, ya da `QBH_VAULT_KEY` mühit dəyişənindən
    oxunur. Heç biri yoxdursa vault `available=False` olur və JS-dən tapılan
    secret-lər (əvvəlki kimi) YALNIZ maskalanmış saxlanılır — düz mətn HEÇ VAXT
    yazılmır.
    """

    enabled: bool = True
    key_file: str = ""


@dataclass
class ProgramRules:
    """Rules of Engagement — proqramın qadağaları."""
    forbidden: set[str] = field(default_factory=set)
    allow_wildcard_expansion: bool = True
    max_requests_per_second: float = 0.0  # 0 → profil/limits default

    def allows(self, action: str) -> bool:
        return action not in self.forbidden


@dataclass
class Config:
    path: str
    program: str
    nvd_api_key: str
    scope: ScopeEnforcer
    limits: Limits
    proxy_file: str
    interface: str = "eth0"
    aggressiveness: str = "aggressive"
    rotation: RotationConfig = field(default_factory=RotationConfig)
    block_strategy: BlockStrategy = field(default_factory=BlockStrategy)
    chain: ChainConfig = field(default_factory=ChainConfig)
    oob: OOBConfig = field(default_factory=OOBConfig)
    stealth: StealthConfig = field(default_factory=StealthConfig)
    vault: VaultConfig = field(default_factory=VaultConfig)
    program_rules: ProgramRules = field(default_factory=ProgramRules)
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
        for key in antiblock:
            if key not in KNOWN_ANTIBLOCK_KEYS:
                warnings.append(
                    f"naməlum/köhnə antiblock açarı: {key!r} (nəzərə alınmır)")
        interface = str(antiblock.get("interface", "eth0"))

        aggressiveness = str(raw.get("aggressiveness", "aggressive")).lower()
        if aggressiveness not in PROFILES:
            raise ConfigError(
                f"aggressiveness {aggressiveness!r} etibarsızdır — "
                f"{sorted(PROFILES)} olmalıdır")
        profile = cls._resolve_profile(aggressiveness)

        program_rules = cls._validate_program_rules(raw.get("program_rules"))
        if not program_rules.allows("active_fuzz") and profile["active_fuzz"]:
            warnings.append(
                "proqram qaydaları 'active_fuzz'ı qadağan edir — deaktiv edildi")
            profile["active_fuzz"] = False

        rotation = cls._validate_rotation(raw.get("rotation"), profile, warnings)
        block_strategy = cls._validate_block_strategy(
            raw.get("block_strategy"), profile)
        chain = cls._validate_chain(raw.get("chain"))
        oob = cls._validate_oob(raw.get("oob"), aggressiveness)
        stealth = cls._validate_stealth(raw.get("stealth"), aggressiveness)
        vault = cls._validate_vault(raw.get("vault"), warnings)

        return cls(
            path=path, program=program, nvd_api_key=nvd_key, scope=scope,
            limits=limits, proxy_file=proxy_file, interface=interface,
            aggressiveness=aggressiveness, rotation=rotation,
            block_strategy=block_strategy, chain=chain, oob=oob,
            stealth=stealth, vault=vault,
            program_rules=program_rules, warnings=warnings, _raw=raw,
        )

    @staticmethod
    def _resolve_profile(aggressiveness: str) -> dict:
        return dict(PROFILES[aggressiveness])

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

    @staticmethod
    def _validate_program_rules(rules) -> ProgramRules:
        if rules is None:
            return ProgramRules()
        if not isinstance(rules, dict):
            raise ConfigError("program_rules mapping olmalıdır")
        forbidden_raw = rules.get("forbidden") or []
        if not isinstance(forbidden_raw, list) or not all(
                isinstance(x, str) for x in forbidden_raw):
            raise ConfigError("program_rules.forbidden mətn siyahısı olmalıdır")
        unknown = {f.lower() for f in forbidden_raw} - ALL_ACTIONS
        known = {f.lower() for f in forbidden_raw} - unknown
        pr = ProgramRules(forbidden=known)
        if "allow_wildcard_expansion" in rules:
            val = rules["allow_wildcard_expansion"]
            if not isinstance(val, bool):
                raise ConfigError(
                    "program_rules.allow_wildcard_expansion boolean olmalıdır")
            pr.allow_wildcard_expansion = val
        if rules.get("max_requests_per_second") is not None:
            val = rules["max_requests_per_second"]
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                raise ConfigError(
                    "program_rules.max_requests_per_second rəqəm olmalıdır")
            if val < 0:
                raise ConfigError(
                    "program_rules.max_requests_per_second mənfi ola bilməz")
            pr.max_requests_per_second = float(val)
        _ = unknown  # naməlum hərəkətlər sükutla buraxılır (irəli uyğunluq)
        return pr

    @staticmethod
    def _validate_rotation(rot, profile: dict, warnings: list[str]
                           ) -> RotationConfig:
        rc = RotationConfig(
            enabled=profile["rotate_ua"] or profile["rotate_headers"]
            or profile["rotate_proxy"],
            ua=profile["rotate_ua"], headers=profile["rotate_headers"],
            proxy=profile["rotate_proxy"], on_block=True,
        )
        if rot is None:
            return rc
        if not isinstance(rot, dict):
            raise ConfigError("rotation mapping olmalıdır")
        for key in ("enabled", "ua", "headers", "proxy", "on_block"):
            if key in rot:
                if not isinstance(rot[key], bool):
                    raise ConfigError(f"rotation.{key} boolean olmalıdır")
                setattr(rc, key, rot[key])
        if not rc.enabled:
            rc.ua = rc.headers = rc.proxy = False
        return rc

    @staticmethod
    def _validate_block_strategy(bs, profile: dict) -> BlockStrategy:
        strat = BlockStrategy(http_429=profile["block_429"],
                              http_403=profile["block_403"])
        if bs is None:
            return strat
        if not isinstance(bs, dict):
            raise ConfigError("block_strategy mapping olmalıdır")
        if "http_429" in bs:
            val = str(bs["http_429"]).lower()
            if val not in BLOCK_429_STRATEGIES:
                raise ConfigError(
                    f"block_strategy.http_429 {val!r} etibarsızdır — "
                    f"{sorted(BLOCK_429_STRATEGIES)} olmalıdır")
            strat.http_429 = val
        if "http_403" in bs:
            val = str(bs["http_403"]).lower()
            if val not in BLOCK_403_STRATEGIES:
                raise ConfigError(
                    f"block_strategy.http_403 {val!r} etibarsızdır — "
                    f"{sorted(BLOCK_403_STRATEGIES)} olmalıdır")
            strat.http_403 = val
        return strat

    @staticmethod
    def _validate_chain(chain) -> ChainConfig:
        if chain is None:
            return ChainConfig()
        if not isinstance(chain, dict):
            raise ConfigError("chain mapping olmalıdır")
        cc = ChainConfig()
        if "enabled" in chain:
            if not isinstance(chain["enabled"], bool):
                raise ConfigError("chain.enabled boolean olmalıdır")
            cc.enabled = chain["enabled"]
        for key in ("max_depth", "max_tasks"):
            if key in chain:
                val = chain[key]
                if isinstance(val, bool) or not isinstance(val, int):
                    raise ConfigError(f"chain.{key} tam ədəd olmalıdır")
                if val < 0:
                    raise ConfigError(f"chain.{key} mənfi ola bilməz")
                setattr(cc, key, val)
        return cc

    @staticmethod
    def _validate_oob(oob, aggressiveness: str) -> OOBConfig:
        cfg = OOBConfig()
        if aggressiveness == "passive":
            cfg.enabled = True
        if oob is None:
            return cfg
        if not isinstance(oob, dict):
            raise ConfigError("oob mapping olmalıdır")
        if "enabled" in oob:
            if not isinstance(oob["enabled"], bool):
                raise ConfigError("oob.enabled boolean olmalıdır")
            cfg.enabled = oob["enabled"]
        if oob.get("domain") is not None:
            if not isinstance(oob["domain"], str):
                raise ConfigError("oob.domain mətn olmalıdır")
            cfg.domain = oob["domain"].strip()
        if oob.get("listen_host") is not None:
            if not isinstance(oob["listen_host"], str):
                raise ConfigError("oob.listen_host mətn olmalıdır")
            cfg.listen_host = oob["listen_host"]
        if oob.get("listen_port") is not None:
            val = oob["listen_port"]
            if isinstance(val, bool) or not isinstance(val, int) or val < 0:
                raise ConfigError("oob.listen_port qeyri-mənfi tam ədəd olmalıdır")
            cfg.listen_port = val
        if oob.get("backend") is not None:
            backend = str(oob["backend"]).lower()
            if backend not in ("local", "interactsh"):
                raise ConfigError(
                    f"oob.backend {backend!r} etibarsızdır — local|interactsh")
            cfg.backend = backend
        if oob.get("wait") is not None:
            val = oob["wait"]
            if isinstance(val, bool) or not isinstance(val, (int, float)) or val < 0:
                raise ConfigError("oob.wait qeyri-mənfi rəqəm olmalıdır")
            cfg.wait = float(val)
        return cfg

    @staticmethod
    def _validate_stealth(stealth, aggressiveness: str) -> StealthConfig:
        # Profil-əsaslı default-lar: passive → tam insan-təqlidi pacing;
        # aggressive → minimal pacing (impersonation + rotation-a güvən).
        defaults = {
            "passive": ("chrome", "off", "passive"),
            "normal": ("chrome", "off", "normal"),
            "aggressive": ("chrome", "off", "aggressive"),
        }
        imp, prox, pace = defaults[aggressiveness]
        cfg = StealthConfig(impersonate=imp, proxy_strategy=prox, pacing=pace)
        if stealth is None:
            return cfg
        if not isinstance(stealth, dict):
            raise ConfigError("stealth mapping olmalıdır")
        if stealth.get("impersonate") is not None:
            val = str(stealth["impersonate"]).lower()
            if val not in IMPERSONATE_TARGETS:
                raise ConfigError(
                    f"stealth.impersonate {val!r} etibarsızdır — "
                    f"{sorted(IMPERSONATE_TARGETS)}")
            cfg.impersonate = val
        if stealth.get("proxy_strategy") is not None:
            val = str(stealth["proxy_strategy"]).lower()
            if val not in PROXY_STRATEGIES:
                raise ConfigError(
                    f"stealth.proxy_strategy {val!r} etibarsızdır — "
                    f"{sorted(PROXY_STRATEGIES)}")
            cfg.proxy_strategy = val
        if stealth.get("pacing") is not None:
            val = str(stealth["pacing"]).lower()
            if val not in PACING_PROFILES:
                raise ConfigError(
                    f"stealth.pacing {val!r} etibarsızdır — "
                    f"{sorted(PACING_PROFILES)}")
            cfg.pacing = val
        for key in ("pacing_max_overhead",):
            if stealth.get(key) is not None:
                val = stealth[key]
                if isinstance(val, bool) or not isinstance(val, (int, float)):
                    raise ConfigError(f"stealth.{key} rəqəm olmalıdır")
                if val < 1.0:
                    raise ConfigError(f"stealth.{key} ən azı 1.0 olmalıdır")
                setattr(cfg, key, float(val))
        for key in ("waf_adapt", "tor_for_sensitive_only"):
            if stealth.get(key) is not None:
                if not isinstance(stealth[key], bool):
                    raise ConfigError(f"stealth.{key} boolean olmalıdır")
                setattr(cfg, key, stealth[key])
        return cfg

    @staticmethod
    def _validate_vault(vault, warnings: list[str]) -> VaultConfig:
        """Faza 3.2 — `vault` bölməsini validasiya edir (fail-closed deyil:
        açar yoxdursa vault sadəcə `available=False` olur)."""
        cfg = VaultConfig()
        if vault is None:
            return cfg
        if not isinstance(vault, dict):
            raise ConfigError("vault mapping olmalıdır")
        for key in vault:
            if key not in ("enabled", "key_file"):
                warnings.append(f"naməlum vault açarı: {key!r}")
        if "enabled" in vault:
            if not isinstance(vault["enabled"], bool):
                raise ConfigError("vault.enabled boolean olmalıdır")
            cfg.enabled = vault["enabled"]
        if vault.get("key_file") is not None:
            if not isinstance(vault["key_file"], str):
                raise ConfigError("vault.key_file mətn olmalıdır")
            cfg.key_file = vault["key_file"].strip()
        return cfg

    # ---------------- köməkçilər ----------------
    @property
    def targets(self) -> list[str]:
        return [e["domain"] for e in self._raw.get("scope", [])]

    @property
    def profile(self) -> dict:
        """Cari icra profili (rotation/block strategy ilə sinxronlaşdırılmış)."""
        p = self._resolve_profile(self.aggressiveness)
        p["rotate_ua"] = self.rotation.enabled and self.rotation.ua
        p["rotate_headers"] = self.rotation.enabled and self.rotation.headers
        p["rotate_proxy"] = self.rotation.enabled and self.rotation.proxy
        p["block_429"] = self.block_strategy.http_429
        p["block_403"] = self.block_strategy.http_403
        return p

    @property
    def effective_rate(self) -> float:
        """Profil faktorunu tətbiq etmiş rate (RoE limiti ilə məhdudlaşdırılmış)."""
        base = self.limits.requests_per_second
        factor = PROFILES[self.aggressiveness]["rate_factor"]
        rate = base * factor
        cap = self.program_rules.max_requests_per_second
        if cap > 0:
            rate = min(rate, cap)
        return max(0.1, rate)

    @property
    def effective_concurrency(self) -> int:
        base = self.limits.max_concurrency
        factor = PROFILES[self.aggressiveness]["concurrency_factor"]
        return max(1, int(base * factor))

    def is_allowed(self, action: str) -> bool:
        """Proqram RoE-nə görə hərəkət icazəlidir?"""
        return self.program_rules.allows(action)

    def in_scope(self, host: str) -> bool:
        return self.scope.is_authorized(host)

    def authorize_target(self, value: str) -> str:
        """CLI --targets üçün: icazəsizdirsə ScopeError."""
        return self.scope.authorize(value)

    def get(self, key, default=None):
        return self._raw.get(key, default)
