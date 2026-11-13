"""Subprocess egress idarəsi — Faza 0.2 + Faza 1.2 (KRİTİK).

**Problem.** Native HTTP mühərrikləri `HttpPolicy`-dən keçir, lakin subprocess
alətləri (nuclei, feroxbuster, ffuf, schemathesis, katana, kiterunner, dnstwist,
gowitness ...) öz şəbəkə trafikini özləri idarə edir. Ona görə də alt-prosesə
verilən hədəflərin scope-a uyğun olduğunu ƏVVƏLCƏDƏN təsdiqləmək və prosesi
lazım gəldikdə bütöv proses qrupu ilə öldürmək vacibdir.

**Tək məcburi giriş nöqtəsi (Faza 1.2).**

    proc = await ctx.egress.run(cmd, targets=[...])   # mühərriklər üçün

Əlavə olaraq qapı proses başlatma nöqtəsinin ÖZÜNDƏ — `adapters.base.run_process`
daxilində — ikinci qat kimi tətbiq olunur:

    with egress.activate():          # Conductor skan boyu bunu edir
        await run_process(cmd)       # açıq targets + cmd içindəki URL-lər yoxlanır

Beləliklə HEÇ BİR mühərrik (dnstwist, gowitness, semgrep ...) egress yoxlamasını
keçə bilmir: qapı həm `egress.run()`, həm də birbaşa `run_process()` çağırışında
işləyir.

**Fail-closed DNS pinning.** Hər icazəli host üçün IP-lər indi həll olunur və
`ctx.resolved_ips`-ə audit üçün yazılır. Scope xarici hədəf YAXUD həll olunmayan
(DNS uğursuz) hədəf varsa alt-proses HEÇ BAŞLADILMIR (`ProcResult(blocked=True)`)
və hadisə audit jurnalına düşür.

**OS səviyyəli sərhəd (opsional, Linux).** `QBH_EGRESS_SANDBOX=firejail` (və ya
firejail avtomatik aşkarlanarsa) alt-proses `firejail --hosts-file=<pin>` ilə
işə salınır: pin olunmuş host→IP cədvəli uşağa YALNIZ bu fayl vasitəsilə verilir
(DNS pinning faktiki tətbiq olunur). `--netfilter` + `--net` verildikdə yalnız
pin olunmuş IP-lərə çıxışa icazə verən nftables/iptables allowlist yazılır.
firejail yoxdursa bu qat sakitcə atlanır və auditə `egress_sandbox_unavailable`
yazılır (`docs/SECURITY_VERIFICATION.md`).

**Dürüst məhdudiyyət (docs/STEALTH.md).** Sandbox aktiv olmadıqda bu, tam
per-request egress nəzarəti DEYİL: alt-proses öz DNS-ini yenidən həll edə və ya
redirect izləyə bilər. Tətbiq olunan praqmatik sərhəd: (1) giriş hədəflərinin
scope + DNS yoxlaması (fail-closed), (2) DNS pinning/audit, (3) opsional firejail
(DNS pin + IP allowlist), (4) ləğv/halt zamanı proses qrupunun SIGKILL edilməsi.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import socket
import tempfile
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .adapters.base import (ProcResult, derive_targets, reset_process_guard,
                            run_process, set_process_guard)
from .scope import ScopeError, extract_host, normalize_host

DEFAULT_TTL = 300.0          # DNS nəticəsinin keçərlilik müddəti (saniyə)
DEFAULT_SANDBOX = "auto"     # auto | off | firejail
SANDBOX_ENV = "QBH_EGRESS_SANDBOX"


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
                 audit: list | None = None,
                 sandbox: str | None = None):
        self.auth = authorization
        self._resolver = resolver or system_resolver
        self.ttl = float(ttl)
        self._clock = clock or time.monotonic
        self.resolved_store = resolved_store if resolved_store is not None else {}
        self.audit: list = audit if audit is not None else []
        self.sandbox = sandbox
        self._sandbox_warned = False

    # -------------------------------------------------- aktiv qapı (Faza 1.2)
    @contextlib.contextmanager
    def activate(self):
        """Bu controller-i cari kontekst üçün MƏCBURİ egress qapısı edir.

        Aktiv olduqda `adapters.base.run_process` hər alt-prosesi bu qapıdan
        keçirir — mühərrik `egress.run()` çağırmasa belə bypass mümkün deyil.
        """
        token = set_process_guard(self)
        try:
            yield self
        finally:
            reset_process_guard(token)

    async def prepare_process(self, cmd: list[str],
                              targets: Iterable[str] | None) -> tuple[ProcResult | None, dict | None]:
        """`run_process` qapısı: (blok_nəticəsi|None, əlavə_env|None) qaytarır.

        Açıq `targets` ilə command içindəki URL-lər birləşdirilir; heç biri
        yoxdursa (lokal alət) qapı heç nə etmir. Scope xarici və ya DNS-i
        həll olunmayan hədəf varsa proses bloklanır (fail-closed) + audit.
        """
        candidates: list[str] = []
        for raw in list(targets or []):
            if raw:
                candidates.append(raw)
        candidates.extend(derive_targets(cmd))
        if not candidates:
            return None, None
        tset = await self.authorize_process_targets(candidates)
        if tset.rejected:
            denied = [u for u, _ in tset.rejected]
            self.audit.append({"event": "egress_blocked", "reason": "scope",
                               "targets": denied, "at": time.time()})
            return ProcResult(-1, stderr=b"egress: out-of-scope target blocked",
                              blocked=True), None
        unresolved = [h for h in tset.hostnames if not tset.resolved.get(h)]
        if unresolved:
            self.audit.append({"event": "egress_blocked", "reason": "dns",
                               "hosts": unresolved, "at": time.time()})
            return ProcResult(-1, stderr=b"egress: DNS resolution failed (fail-closed)",
                              blocked=True), None
        return None, None

    async def run(self, cmd: list[str], *, targets: Iterable[str] = (),
                  stdin: bytes | None = None, timeout: float = 600,
                  cancel_event: "asyncio.Event | None" = None) -> ProcResult:
        """Mühərriklər üçün TƏK icazəli alt-proses başlatma nöqtəsi.

        Qapını (scope + fail-closed DNS) tətbiq edir, mümkünsə firejail
        sandbox-u (DNS pin + IP allowlist) ilə işə salır və audit yazır.
        """
        target_list = [t for t in targets if t]
        prefix, cleanup = await self._sandbox_prefix(target_list)
        real_cmd = list(prefix) + list(cmd) if prefix else list(cmd)
        try:
            with self.activate():
                return await run_process(real_cmd, stdin=stdin, timeout=timeout,
                                         cancel_event=cancel_event,
                                         targets=target_list)
        finally:
            for path in cleanup:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    # ------------------------------------------------------ OS sandbox (opsional)
    def _sandbox_mode(self) -> str:
        mode = (self.sandbox or os.environ.get(SANDBOX_ENV)
                or DEFAULT_SANDBOX).strip().lower()
        if mode == "auto":
            return "firejail" if shutil.which("firejail") else "off"
        return mode if mode in ("off", "firejail") else "off"

    async def _sandbox_prefix(self, targets: list[str]) -> tuple[list[str], list[str]]:
        """Firejail prefiksini + müvəqqəti faylları hazırlayır (varsa)."""
        mode = self._sandbox_mode()
        if mode != "firejail":
            return [], []
        if not targets:
            return [], []
        if shutil.which("firejail") is None:
            if not self._sandbox_warned:
                self._sandbox_warned = True
                self.audit.append({"event": "egress_sandbox_unavailable",
                                   "sandbox": "firejail", "at": time.time()})
            return [], []
        tset = await self.authorize_process_targets(targets)
        pinned = {h: tset.resolved.get(h, ()) for h in tset.hostnames}
        if not any(pinned.values()):
            return [], []
        hosts_path = _write_temp("\n".join(
            f"{ip} {host}" for host, ips in pinned.items() for ip in ips) + "\n")
        cleanup = [hosts_path]
        prefix = ["firejail", "--quiet", "--noprofile",
                  f"--hosts-file={hosts_path}"]
        iface = os.environ.get("QBH_EGRESS_IFACE", "").strip()
        if iface:
            nf_path = _write_temp(_netfilter_rules(tset.ips))
            cleanup.append(nf_path)
            prefix += [f"--net={iface}", f"--netfilter={nf_path}"]
        self.audit.append({"event": "egress_sandbox", "sandbox": "firejail",
                           "hosts": list(pinned), "ips": tset.ips,
                           "netfilter": bool(iface), "at": time.time()})
        return prefix, cleanup

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


def _write_temp(content: str) -> str:
    """Məzmunu müvəqqəti fayla yazır və yolunu qaytarır (çağıran silir)."""
    fd, path = tempfile.mkstemp(prefix="qbh_egress_", suffix=".conf")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def _netfilter_rules(ips: Iterable[str]) -> str:
    """Yalnız pin olunmuş IP-lərə (və loopback-a) çıxışa icazə verən allowlist.

    firejail `--netfilter=` faylı üçün iptables-restore sintaksisi.
    Default politika DROP → scope xarici istənilən IP bağlanır.
    """
    lines = ["*filter", ":INPUT DROP [0:0]", ":FORWARD DROP [0:0]",
             ":OUTPUT DROP [0:0]",
             "-A OUTPUT -o lo -j ACCEPT",
             "-A INPUT -i lo -j ACCEPT"]
    for ip in ips:
        fam = "-4" if ":" not in ip else "-6"
        lines.append(f"-A OUTPUT {fam} -d {ip} -j ACCEPT")
    lines.append("COMMIT")
    return "\n".join(lines) + "\n"


async def authorize_process_targets(authorization, targets: Iterable[str], *,
                                    resolver=None, ttl: float = DEFAULT_TTL,
                                    resolved_store: dict | None = None):
    """Rahatlıq funksiyası: yeni `EgressController` ilə hədəfləri yoxlayır."""
    controller = EgressController(
        authorization, resolver=resolver, ttl=ttl,
        resolved_store=resolved_store)
    return await controller.authorize_process_targets(targets)
