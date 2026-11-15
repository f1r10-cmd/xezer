"""Zəkalı cavab keşi (Faza 1, §3.5).

MƏQSƏD: eyni (hədəf, endpoint, metod, parametr, auth konteksti, test
strategiyası, strategiya versiyası, fingerprint halı) üçün cavabı TƏKRAR
çəkməmək — beləcə həm trafik azalır, həm də nəticələr sabit qalır.

Prinsiplər (qəti):
  * Keş YALNIZ cavab METADATA-sını saxlayır (status, başlıqlar, ölçü,
    gövdənin ilk N baytı) — TAM gövdə YOX (yaddaş partlamır).
  * Etibarsızlıq (invalidation) şərtləri: fingerprint DƏYİŞİKLİYİ,
    strategiya VERSİYASI dəyişikliyi, auth KONTEKSTİ dəyişikliyi, TTL bitməsi.
    Keş KEYİ bu komponentləri ehtiva edir → komponent dəyişdikdə keş MISS olur
    (köhnə cavab yanlış tətbiq OLUNMUR).
  * **TARİXİ TAPINTILAR VƏ DƏLİLLƏR HEÇ VAXT SİLİNMİR** — `prune()` yalnız
    vaxtı keçmiş cavab metadata-sını təmizləyir; `findings` keş müddətindən
    ASILI DEYİL və `prune()`/`invalidate()` onlara TOXUNMUR.
  * Bu modul HTTP sorğusu YARATMIR — yalnız qərar/anbar qatıdır.
  * `CacheManager` `HttpPolicy`-yə OPSİONAL qoşulur (`HttpPolicy(cache=...)`);
    keş verilmədikdə və ya sorğu metadata-sı verilmədikdə davranış ƏVVƏLKİ
    kimidir (geriyə uyğun).
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field

#: Bu keş sxeminin versiyası. Dəyişdikdə köhnə qeydlər etibarsız sayılır.
STRATEGY_VERSION = "1"

#: Gövdədən saxlanılan maksimum bayt (tam gövdə SAXLANILMIR).
DEFAULT_BODY_HEAD = 2048

#: Default TTL (saniyə).
DEFAULT_TTL = 300.0


@dataclass(frozen=True)
class CacheEntry:
    """Keşlənmiş cavab METADATA-sı (tam gövdə deyil)."""

    key: str
    status: int
    headers: dict
    size: int
    body_head: str
    content_type: str
    expires_at: float
    fingerprint_state: str = ""
    strategy_version: str = STRATEGY_VERSION
    auth_context: str = ""
    meta: dict = field(default_factory=dict)

    @property
    def truncated(self) -> bool:
        return self.size > len(self.body_head)


def _token(value) -> str:
    """Kanınkallaşdırılmış, sabit uzunluqlu komponent tokeni."""
    if value is None:
        return ""
    if isinstance(value, dict):
        items = sorted(f"{k}={v}" for k, v in value.items())
        value = "&".join(items)
    elif isinstance(value, (list, tuple, set)):
        value = "&".join(str(x) for x in value)
    return str(value)


def cache_key(*, target: str = "", endpoint: str = "", method: str = "GET",
              params="", auth_context: str = "", test_strategy: str = "",
              strategy_version: str = STRATEGY_VERSION,
              fingerprint_state: str = "") -> str:
    """Keş açarı — BÜTÜN relevant komponentlər daxildir (deterministik).

    Komponentlərdən biri dəyişdikdə açar dəyişir → keş MISS olur (səhv cavab
    tətbiq olunmur).
    """
    parts = [
        _token(target).lower(),
        _token(endpoint),
        (method or "GET").upper(),
        _token(params),
        _token(auth_context),
        _token(test_strategy),
        _token(strategy_version),
        _token(fingerprint_state),
    ]
    raw = "\x1f".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


class CacheManager:
    """Cavab keşi + etibarsızlıq qaydaları (şəbəkəsiz, deterministik)."""

    def __init__(self, *, ttl: float = DEFAULT_TTL,
                 body_head: int = DEFAULT_BODY_HEAD, clock=None):
        self.ttl = float(ttl)
        self.body_head = max(0, int(body_head))
        self._clock = clock or time.monotonic
        self.strategy_version = STRATEGY_VERSION
        self._entries: dict[str, CacheEntry] = {}
        #: TARİXİ TAPINTILAR — keşdən AYRI, HEÇ VAXT silinmir.
        self.findings: list = []
        self.hits = 0
        self.misses = 0
        self.stores = 0
        self.expirations = 0
        self.invalidations = 0

    # ------------------------------------------------------------------ lookup
    def lookup(self, *, target: str = "", endpoint: str = "", method: str = "GET",
               params="", auth_context: str = "", test_strategy: str = "",
               strategy_version: str | None = None,
               fingerprint_state: str = "") -> CacheEntry | None:
        """Keşə baxır. MISS/TTL bitib/komponent uyğunsuzdursa `None`."""
        key = cache_key(
            target=target, endpoint=endpoint, method=method, params=params,
            auth_context=auth_context, test_strategy=test_strategy,
            strategy_version=(self.strategy_version if strategy_version is None
                              else strategy_version),
            fingerprint_state=fingerprint_state)
        entry = self._entries.get(key)
        if entry is None:
            self.misses += 1
            return None
        if entry.expires_at <= self._clock():
            self.expirations += 1
            self.misses += 1
            del self._entries[key]           # YALNIZ metadata silinir
            return None
        self.hits += 1
        return entry

    # ------------------------------------------------------------------- store
    def store(self, *, target: str = "", endpoint: str = "", method: str = "GET",
              params="", auth_context: str = "", test_strategy: str = "",
              strategy_version: str | None = None, fingerprint_state: str = "",
              response=None, status: int | None = None, headers=None,
              body: str = "", ttl: float | None = None,
              meta: dict | None = None) -> CacheEntry:
        """Cavab metadata-sını saxlayır (tam gövdə YOX — yalnız ilk N bayt).

        `response` verilərsə ondan `status`/`headers`/`text` götürülür.
        """
        if response is not None:
            status = getattr(response, "status", status)
            headers = getattr(response, "headers", headers)
            body = getattr(response, "text", body) or ""
        text = body or ""
        head = text[:self.body_head] if self.body_head else ""
        ctype = _header(headers, "Content-Type")
        sv = self.strategy_version if strategy_version is None else strategy_version
        key = cache_key(
            target=target, endpoint=endpoint, method=method, params=params,
            auth_context=auth_context, test_strategy=test_strategy,
            strategy_version=sv, fingerprint_state=fingerprint_state)
        entry = CacheEntry(
            key=key,
            status=int(status) if status is not None else 0,
            headers=dict(headers or {}),
            size=len(body or ""),
            body_head=head,
            content_type=ctype,
            expires_at=self._clock() + (self.ttl if ttl is None else float(ttl)),
            fingerprint_state=fingerprint_state,
            strategy_version=sv,
            auth_context=auth_context,
            meta=_with_identity(meta, target, endpoint),
        )
        self._entries[key] = entry
        self.stores += 1
        return entry

    # ------------------------------------------------------------ invalidation
    def invalidate(self, *, target=None, endpoint=None, auth_context=None,
                   fingerprint_state=None, strategy_version=None) -> int:
        """Filtrə uyğun cavab metadata-sını silir (tapıntılara TOXUNMUR)."""
        removed = 0
        for key, entry in list(self._entries.items()):
            if endpoint is not None and entry.meta.get("endpoint") != endpoint:
                continue
            if auth_context is not None and entry.auth_context != auth_context:
                continue
            if (fingerprint_state is not None
                    and entry.fingerprint_state != fingerprint_state):
                continue
            if (strategy_version is not None
                    and entry.strategy_version != strategy_version):
                continue
            if target is not None and entry.meta.get("target") != target:
                continue
            del self._entries[key]
            removed += 1
        self.invalidations += removed
        return removed

    def invalidate_fingerprint(self, target: str, current_state: str) -> int:
        """Fingerprint dəyişdi → `target`-ın köhnə fingerprint qeydləri silinir."""
        removed = 0
        for key, entry in list(self._entries.items()):
            if (entry.meta.get("target") == target
                    and entry.fingerprint_state != current_state):
                del self._entries[key]
                removed += 1
        self.invalidations += removed
        return removed

    def set_strategy_version(self, version: str) -> int:
        """Strategiya versiyasını dəyişir və KÖHNƏ versiyalı qeydləri silir."""
        self.strategy_version = str(version)
        return self.invalidate_strategy(self.strategy_version)

    def invalidate_strategy(self, version: str) -> int:
        """Verilmiş versiyadan FƏRQLİ bütün qeydləri silir."""
        removed = 0
        for key, entry in list(self._entries.items()):
            if entry.strategy_version != str(version):
                del self._entries[key]
                removed += 1
        self.invalidations += removed
        return removed

    def invalidate_auth(self, auth_context: str) -> int:
        """Bir auth kontekstinə aid qeydləri silir (kontekst dəyişdi)."""
        return self.invalidate(auth_context=auth_context)

    def prune(self) -> int:
        """Vaxtı keçmiş cavab metadata-sını təmizləyir.

        TAPINTILAR VƏ DƏLİLLƏR HEÇ VAXT SİLİNMİR — `findings` toxunulmaz qalır.
        """
        now = self._clock()
        removed = 0
        for key, entry in list(self._entries.items()):
            if entry.expires_at <= now:
                del self._entries[key]
                removed += 1
        self.expirations += removed
        return removed

    # ---------------------------------------------------------------- findings
    def record_finding(self, finding) -> None:
        """Tarixi tapıntını qeyd edir — `prune()`/`invalidate()` onu SİLMİR."""
        self.findings.append(finding)

    # ------------------------------------------------------------------- stats
    def stats(self) -> dict:
        return {
            "entries": len(self._entries),
            "hits": self.hits,
            "misses": self.misses,
            "stores": self.stores,
            "expirations": self.expirations,
            "invalidations": self.invalidations,
            "findings": len(self.findings),
            "strategy_version": self.strategy_version,
            "ttl": self.ttl,
        }


def _header(headers, name: str) -> str:
    """Başlığı registrə həssas olmayan şəkildə oxuyur."""
    if not headers:
        return ""
    target = name.lower()
    for k, v in headers.items():
        if str(k).lower() == target:
            return str(v)
    return ""


def _with_identity(meta, target: str, endpoint: str) -> dict:
    """Keş qeydinin `meta`sına hədəf/endpoint əlavə edir (invalidation üçün)."""
    out = dict(meta or {})
    out.setdefault("target", target)
    out.setdefault("endpoint", endpoint)
    return out

