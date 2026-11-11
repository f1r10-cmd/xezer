"""Mərkəzləşdirilmiş Scope Enforcement.

Bütün hədəf yoxlamaları BURADAN keçir. Fail-closed prinsipi:
scope boş və ya qeyri-müəyyəndirsə — hər şey RƏDD edilir.

Qarşısı alınan ssenarilər:
  * suffix confusion  → example.com.attacker.test, evil-example.com
  * wildcard sui-istifadə → *.example.com yalnız həqiqi alt-domenə uyğun gəlir
  * malformed hostname → boşluq, slash, yolverilməz simvol
  * unicode / IDNA → xn--... formasına çevrilir və o formada yoxlanılır
  * IP ünvanı → yalnız konfiqdə AÇIQ şəkildə göstərilibsə icazəlidir
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

# RFC 1123-ə uyğun hostname etiketi: hərf/rəqəm/defis, defislə başlamaz/bitməz
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

MAX_HOST_LEN = 253


class ScopeError(ValueError):
    """Scope pozuntusu və ya etibarsız host daxil edildi."""


def extract_host(value: str) -> str:
    """URL, host:port və ya sadə host daxil edildikdə yalnız hostu qaytarır."""
    if value is None:
        raise ScopeError("host boşdur")
    s = str(value).strip()
    if not s:
        raise ScopeError("host boşdur")
    if "://" in s:
        host = urlsplit(s).hostname or ""
    else:
        s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if s.startswith("["):  # IPv6 literal: [::1]:443
            end = s.find("]")
            host = s[1:end] if end != -1 else s
        elif s.count(":") == 1:
            host = s.rsplit(":", 1)[0]
        else:
            host = s
    return host


def normalize_host(value: str) -> str:
    """Hostu kanonik ASCII formasına gətirir; etibarsızdırsa ScopeError atır."""
    host = extract_host(value)
    host = host.strip().lower().rstrip(".")
    if not host:
        raise ScopeError("host boşdur")
    if len(host) > MAX_HOST_LEN:
        raise ScopeError(f"host çox uzundur: {host!r}")
    # Unicode → IDNA (punycode)
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ScopeError(f"IDNA çevrilməsi alınmadı: {value!r}") from exc

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    labels = host.split(".")
    if len(labels) < 2:
        raise ScopeError(f"tam domen adı deyil: {host!r}")
    for lab in labels:
        if not _LABEL_RE.match(lab):
            raise ScopeError(f"etibarsız hostname etiketi: {host!r}")
    if labels[-1].isdigit():
        raise ScopeError(f"rəqəmsal TLD qadağandır: {host!r}")
    return host


@dataclass(frozen=True)
class _Rule:
    kind: str          # "exact" | "wildcard" | "ip" | "net"
    value: object      # str (host) | ipaddress.IPv4Address | ipaddress.IPv4Network

    def matches(self, host: str, ip) -> bool:
        if self.kind == "exact":
            return ip is None and host == self.value
        if self.kind == "wildcard":
            base = self.value
            return (ip is None and host != base and host.endswith("." + base))
        if self.kind == "ip":
            return ip is not None and ip == self.value
        if self.kind == "net":
            return ip is not None and ip in self.value
        return False


def _parse_rule(pattern: str) -> _Rule:
    raw = str(pattern).strip().lower()
    if not raw:
        raise ScopeError("boş scope qaydası")
    # CIDR?
    if "/" in raw and not raw.startswith("*"):
        try:
            return _Rule("net", ipaddress.ip_network(raw, strict=False))
        except ValueError as exc:
            raise ScopeError(f"etibarsız CIDR: {pattern!r}") from exc
    # Wildcard?
    if raw.startswith("*."):
        base = normalize_host(raw[2:])
        return _Rule("wildcard", base)
    # IP?
    try:
        return _Rule("ip", ipaddress.ip_address(raw))
    except ValueError:
        pass
    return _Rule("exact", normalize_host(raw))


@dataclass
class ScopeEnforcer:
    """Bütün scope qərarları üçün vahid giriş nöqtəsi."""

    allow: list[_Rule] = field(default_factory=list)
    deny: list[_Rule] = field(default_factory=list)

    @classmethod
    def from_entries(cls, entries: list[dict]) -> "ScopeEnforcer":
        enforcer = cls()
        for entry in entries or []:
            for pat in entry.get("in_scope", []) or []:
                enforcer.allow.append(_parse_rule(pat))
            for pat in entry.get("out_of_scope", []) or []:
                enforcer.deny.append(_parse_rule(pat))
        return enforcer

    @property
    def is_empty(self) -> bool:
        return not self.allow

    def is_authorized(self, value: str) -> bool:
        """Host/URL/IP scope daxilindədir? Fail-closed."""
        if self.is_empty:
            return False
        try:
            host = normalize_host(value)
        except ScopeError:
            return False
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if any(r.matches(host, ip) for r in self.deny):
            return False
        return any(r.matches(host, ip) for r in self.allow)

    def authorize(self, value: str) -> str:
        """Uğurlu olduqda kanonik hostu qaytarır, əks halda ScopeError atır."""
        if self.is_empty:
            raise ScopeError("scope konfiqurasiyası boşdur — icra dayandırılır")
        host = normalize_host(value)  # ScopeError yuxarı ötürülür
        ip = None
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            pass
        if any(r.matches(host, ip) for r in self.deny):
            raise ScopeError(f"out-of-scope (deny qaydası): {host}")
        if not any(r.matches(host, ip) for r in self.allow):
            raise ScopeError(f"out-of-scope: {host}")
        return host

    def authorize_url(self, url: str) -> str:
        """URL-i yoxlayır və eyni URL-i qaytarır; kənardırsa ScopeError."""
        self.authorize(extract_host(url))
        return url

    def resolve_redirect(self, base_url: str, location: str) -> str:
        """Redirect hədəfini mütləq URL-ə çevirir və scope-unu yoxlayır.

        Scope xaricindədirsə ScopeError atır (redirect escape-in qarşısı).
        """
        if not location:
            raise ScopeError("boş redirect hədəfi")
        target = urljoin(base_url, location)
        self.authorize_url(target)
        return target
