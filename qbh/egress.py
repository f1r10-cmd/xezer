"""Subprocess egress idarəsi — Faza 0.2 (KRİTİK).

**Problem.** Native HTTP mühərrikləri `HttpPolicy`-dən keçir, lakin subprocess
alətləri (nuclei, feroxbuster, ffuf, schemathesis, katana, kiterunner ...) öz
şəbəkə trafikini özləri idarə edir. Ona görə də alt-prosesə verilən hədəflərin
scope-a uyğun olduğunu ƏVVƏLCƏDƏN təsdiqləmək və prosesi lazım gəldikdə bütöv
proses qrupu ilə öldürmək vacibdir.

**Tək giriş nöqtəsi.**

    tset = await egress.authorize_process_targets(targets)

`tset` YALNIZ scope-daxili hostları/URL-ləri ehtiva edir; hər host üçün DNS
IP-ləri həll olunub və `ctx.resolved_ips`-ə audit üçün yazılır (DNS pinning).
Scope xarici hədəflər RƏDD edilir və `tset.rejected`-də qeyd olunur — onlar
HEÇ VAXT alt-prosesə verilmir.

**Ləğv/halt.** Bütün alt-proseslər `adapters.base.run_process` vasitəsilə
işə düşür; o, `start_new_session=True` ilə ayrı proses qrupu yaradır və
timeout/ləğv (və ya `cancel_event`) zamanı qrupu SIGKILL edir.

**Dürüst məhdudiyyət (docs/STEALTH.md).** Bu, tam per-request egress nəzarəti
DEYİL. Alt-proses öz DNS-ini yenidən həll edə və ya redirect izləyə bilər; tam
nəzarət üçün OS səviyyəli sandbox (firejail / network namespace) tələb olunur
ki, bu da opsional/konfiqurasiya edilə biləndir. Tətbiq olunan praqmatik
sərhəd: (1) giriş hədəflərinin scope yoxlaması, (2) DNS pinning/audit,
(3) ləğv/halt zamanı proses qrupunun SIGKILL edilməsi, (4) audit qeydi.
"""
from __future__ import annotations

import asyncio
import os
import socket
import tempfile
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .scope import ScopeError, extract_host, normalize_host

DEFAULT_TTL = 300.0          # DNS nəticəsinin keçərlilik müddəti (saniyə)


def system_resolver(host: str) -> list[str]:
    """Host adını OS resolver-i ilə IP-lərə çevirir (bloklayan; executor-da)."""
    infos = socket.getaddrinfo(host, None)
    seen: set[str] = set()
    out: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def classify_target(token: str) -> tuple[str, str]:
    """Xam token-i ("url"|"host", dəyər) cütünə çevirir.

    URL → olduğu kimi; əks halda host hissəsi (port/path/query təmizlənir).
    Boş token → ("", "").
    """
    t = (token or "").strip()
    if not t:
        return "", ""
    if "://" in t or t.startswith("//"):
        return "url", t
    return "host", t.split("/", 1)[0]


@dataclass
class ProcessTargetSet:
    """`authorize_process_targets` nəticəsi — yalnız icazəli hədəflər."""

    hostnames: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    resolved: dict[str, tuple[str, ...]] = field(default_factory=dict)
    rejected: list[tuple[str, str]] = field(default_factory=list)

    @property
    def ips(self) -> list[str]:
        out: list[str] = []
        for ips in self.resolved.values():
            for ip in ips:
                if ip not in out:
                    out.append(ip)
        return out

    def is_empty(self) -> bool:
        return not (self.hostnames or self.urls)

    def target_file(self, *, urls: bool = False) -> str:
        """İcazəli hədəfləri müvəqqəti fayla yazır (çağıran silməlidir)."""
        entries = self.urls if urls else (self.hostnames or self.urls)
        fd, path = tempfile.mkstemp(prefix="qbh_egress_", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(entries))
        return path


class EgressController:
    """Subprocess hədəf validasiyası + DNS pinning + audit."""

    def __init__(self, authorization, *, resolver: Callable[[str], list[str]] | None = None,
                 ttl: float = DEFAULT_TTL, clock: Callable[[], float] | None = None,
                 resolved_store: dict | None = None,
                 audit: list | None = None):
        self.auth = authorization
        self._resolver = resolver or system_resolver
        self.ttl = float(ttl)
        self._clock = clock or time.monotonic
        self.resolved_store = resolved_store if resolved_store is not None else {}
        self.audit: list = audit if audit is not None else []

    # ----------------------------------------------------------- əsas giriş
    async def authorize_process_targets(self, targets: Iterable[str]) -> ProcessTargetSet:
        """Hədəfləri scope-a yoxlayır, DNS pinning edir, audit yazır.

        Yalnız icazəli hədəflər qaytarılır; rədd edilənlər `rejected`-də.
        """
        tset = ProcessTargetSet()
        seen: set[str] = set()
        for raw in targets:
            kind, value = classify_target(raw)
            if not kind:
                continue
            try:
                if kind == "url":
                    self.auth.authorize_url(value)
                    host = normalize_host(extract_host(value))
                    if value not in tset.urls:
                        tset.urls.append(value)
                else:
                    host = self.auth.authorize_host(value)
            except ScopeError as exc:
                tset.rejected.append((value, str(exc)))
                continue
            if host not in seen:
                seen.add(host)
                tset.hostnames.append(host)
            await self._resolve_pinned(host, tset)
        self._record(tset)
        return tset

    async def _resolve_pinned(self, host: str, tset: ProcessTargetSet) -> None:
        """Host-u TTL-ə uyğun həll edir (keşlənmiş → yenidən soruşmadan)."""
        now = self._clock()
        cached = self.resolved_store.get(host)
        if cached and (now - cached[1]) < self.ttl:
            tset.resolved[host] = tuple(cached[0])
            return
        ips = await self._resolve(host)
        if ips:
            self.resolved_store[host] = (tuple(ips), now)
        tset.resolved[host] = tuple(ips)

    async def _resolve(self, host: str) -> list[str]:
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, self._resolver, host)
        except (OSError, socket.gaierror):
            return []
        except Exception:  # noqa: BLE001 - resolver xətası skanı dayandırmasın
            return []

    def _record(self, tset: ProcessTargetSet) -> None:
        if tset.rejected:
            self.audit.append({
                "event": "egress_rejected",
                "targets": [u for u, _ in tset.rejected],
                "at": time.time(),
            })
        if tset.resolved:
            self.audit.append({
                "event": "egress_pinned",
                "hosts": list(tset.resolved.keys()),
                "ips": tset.ips,
                "at": time.time(),
            })


async def authorize_process_targets(authorization, targets: Iterable[str], *,
                                    resolver=None, ttl: float = DEFAULT_TTL,
                                    resolved_store: dict | None = None):
    """Rahatlıq funksiyası: yeni `EgressController` ilə hədəfləri yoxlayır."""
    controller = EgressController(
        authorization, resolver=resolver, ttl=ttl,
        resolved_store=resolved_store)
    return await controller.authorize_process_targets(targets)
