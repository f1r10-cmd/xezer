"""Tool adapterləri — təhlükəsiz subprocess idarəsi.

Heç bir yerdə shell istifadə olunmur (shell=True yoxdur) → command injection
mümkün deyil. Timeout və ləğvetmə (cancellation) zamanı proses mütləq öldürülür.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import signal
import tempfile
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Sequence

#: Cari asyncio kontekstində aktiv egress qapısı (Faza 1.2).
#:
#: `EgressController.activate()` bunu qurur; `run_process` hər alt-proses
#: başlatmazdan ƏVVƏL qapıdan keçir. Beləliklə heç bir mühərrik (dnstwist,
#: gowitness, semgrep ...) egress yoxlamasını keçə bilməz — qapı proses
#: başlatma nöqtəsinin ÖZÜNDƏ tətbiq olunur.
_process_guard: ContextVar[Any] = ContextVar("qbh_process_guard", default=None)

#: Alt-proses arqumentlərində URL-ləri (derived target) aşkarlayır.
_URL_TOKEN_RE = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.\-]*://|//)")


def current_process_guard() -> Any:
    """Cari egress qapısını qaytarır (yoxdursa `None`)."""
    return _process_guard.get()


def set_process_guard(guard: Any):
    """Egress qapısını aktivləşdirir və geri-qaytarma token-i verir."""
    return _process_guard.set(guard)


def reset_process_guard(token) -> None:
    """`set_process_guard` nəticəsini geri qaytarır."""
    _process_guard.reset(token)


def derive_targets(cmd: Sequence[str]) -> list[str]:
    """Command arqumentlərindən URL formalı hədəfləri çıxarır.

    Yalnız AÇIQ sxemli (`scheme://`, `//`) token-lər — host adları və ya
    fayl yolları səhvən hədəf sayılmır (JWT token-ləri, wordlist yolları ...).
    """
    out: list[str] = []
    for arg in cmd:
        if isinstance(arg, str) and _URL_TOKEN_RE.match(arg.strip()):
            out.append(arg.strip())
    return out


def limited_wordlist(path: str, cap: int) -> tuple[str, str | None]:
    """Wordlist-i `cap` sətirlə məhdudlaşdırır.

    Fayl `cap`-dan kiçikdirsə (yol, None) qaytarır. Böyükdürsə yalnız ilk
    `cap` sətri ehtiva edən müvəqqəti fayl yaradır → (yol, temp_path).
    Çağıran tərəf temp_path-i (varsa) silməlidir.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return path, None
    if len(lines) <= cap:
        return path, None
    fd, tmp = tempfile.mkstemp(prefix="qbh_wl_", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines[:cap]))
    except BaseException:
        # `os.fdopen`/write uğursuz olsa fayl deskriptoru açıq qala bilər və
        # müvəqqəti fayl yerində qalır. Çağıran `tmp`-i HƏLƏ almamışdır →
        # təmizləməni BURADA etmək lazımdır (əks halda sızma olur).
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return tmp, tmp


@dataclass
class ProcResult:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    missing: bool = False
    blocked: bool = False

    @property
    def ok(self) -> bool:
        return (self.returncode == 0 and not self.timed_out
                and not self.missing and not self.blocked)


#: Timeout/ləğvdən sonra natamam çıxışın yığılması üçün grace müddəti (saniyə).
_PARTIAL_DRAIN_GRACE = 5.0


def _cancel_task(task: "asyncio.Future") -> None:
    """Asılı qalmış reader task-ını ləğv edir (təmizləmə ən yaxşı səy)."""
    try:
        task.cancel()
    except Exception:  # noqa: BLE001 - təmizləmə heç vaxt atmasın
        pass


async def _drain_partial(comm: "asyncio.Future") -> tuple[bytes, bytes]:
    """Öldürülmüş prosesdən sonra ƏLÇATAN natamam çıxışı yığır.

    `comm` — `Process.communicate()` task-ıdır. Proses (qrupu) öldürüldükdən
    sonra kanallar bağlanır və task NATAMAM stdout/stderr ilə tamamlanır →
    qismən nəticə İTİRİLMİR. Uşaq proses kanalı açıq saxlayıbsa
    `_PARTIAL_DRAIN_GRACE` saniyə sonra task ləğv olunur (asılı qalma yoxdur).
    """
    try:
        out, err = await asyncio.wait_for(asyncio.shield(comm),
                                         _PARTIAL_DRAIN_GRACE)
        return out or b"", err or b""
    except asyncio.TimeoutError:
        _cancel_task(comm)
        return b"", b""
    except asyncio.CancelledError:
        _cancel_task(comm)
        raise
    except Exception:  # noqa: BLE001 - natamam çıxış ən yaxşı səy
        return b"", b""


def kill_process_group(proc: asyncio.subprocess.Process,
                       sig: int | None = None) -> None:
    """Prosesi və BÜTÖV proses qrupunu öldürür (Faza 0.2).

    `start_new_session=True` ilə başladılmış alt-proseslər üçün `killpg`
    istifadə olunur ki, alətin özü açdığı uşaq proseslər də dayansın.
    Qrup mövcud deyilsə sadəcə `proc.kill()`.

    Default siqnal RUNTIME-da hesablanır (`SIGKILL` Windows-da yoxdur) —
    import zamanı AttributeError-un qarşısı alınır.
    """
    if sig is None:
        sig = getattr(signal, "SIGKILL", signal.SIGTERM)
    # Windows-da proses qrupları (`os.getpgid`/`os.killpg`) YOXDUR → dürüst
    # şəkildə tək prosesə düşülür (AttributeError atılmır).
    getpgid = getattr(os, "getpgid", None)
    killpg = getattr(os, "killpg", None)
    if getpgid is not None and killpg is not None:
        try:
            killpg(getpgid(proc.pid), sig)
            return
        except (ProcessLookupError, PermissionError, OSError):
            pass
    try:
        proc.kill()
    except (ProcessLookupError, OSError):
        pass


async def run_process(cmd: list[str], *, stdin: bytes | None = None,
                      timeout: float = 600,
                      cancel_event: "asyncio.Event | None" = None,
                      env: dict | None = None,
                      targets: Sequence[str] | None = None) -> ProcResult:
    """Təhlükəsiz async subprocess. Shell yoxdur; cancel/timeout → proses qrupu öldürülür.

    `cancel_event` verildikdə proses ayrı monitor vasitəsilə izlənir və
    event set olan kimi bütöv proses qrupu SIGKILL edilir (Guardian/Conductor
    halt qərarı).

    Egress qapısı (Faza 1.2): cari kontekstdə `EgressController.activate()`
    ilə qapı aktivdirsə, alt-proses başladılmazdan ƏVVƏL həm açıq şəkildə
    verilən `targets`, həm də command içindəki URL-lər scope + DNS pinning
    yoxlamasından keçir. Fail-closed: scope xarici və ya həll olunmayan
    hədəf varsa proses HEÇ BAŞLADILMIR (`ProcResult(blocked=True)`).
    """
    guard = _process_guard.get()
    extra_env: dict | None = None
    if guard is not None:
        blocked, extra_env = await guard.prepare_process(cmd, targets)
        if blocked is not None:
            return blocked

    child_env: dict | None = None
    if env is not None or extra_env is not None:
        child_env = dict(os.environ)
        if env:
            child_env.update(env)
        if extra_env:
            child_env.update(extra_env)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin is not None
            else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=child_env,
            start_new_session=True)
    except FileNotFoundError:
        return ProcResult(-1, missing=True)
    except OSError:
        return ProcResult(-1, missing=True)

    killer: asyncio.Task | None = None
    if cancel_event is not None:
        async def _watch():
            await cancel_event.wait()
            kill_process_group(proc)
        killer = asyncio.create_task(_watch())

    # `communicate` AYRI task kimi işlədilir və `shield` ilə qorunur: timeout və
    # ya ləğv zamanı bu task ləğv OLUNMUR → proses (qrupu) öldükdən sonra kanallar
    # bağlanır və task NATAMAM stdout/stderr ilə tamamlanır. Beləliklə qismən
    # çıxış İTİRİLMİR (əvvəlki `wait_for(proc.communicate(...))` onu atırdı).
    comm = asyncio.ensure_future(proc.communicate(stdin))
    try:
        out, err = await asyncio.wait_for(asyncio.shield(comm), timeout)
    except asyncio.TimeoutError:
        kill_process_group(proc)
        await proc.wait()
        out, err = await _drain_partial(comm)
        return ProcResult(-1, out, err, timed_out=True)
    except asyncio.CancelledError:
        kill_process_group(proc)
        try:
            await proc.wait()
        except asyncio.CancelledError:
            pass
        # Ən yaxşı səy: natamam çıxışı yığ, sonra ləğvi ötür.
        try:
            await _drain_partial(comm)
        except BaseException:  # noqa: BLE001 - əsas ləğv siqnalı aşağı ötürülür
            _cancel_task(comm)
        raise
    finally:
        if killer is not None:
            killer.cancel()
            # Watcher task-ın FAKTİKİ bitməsini gözlə — "Task was destroyed
            # but it is pending" sızmasının qarşısını alır. Burada bizim
            # tətiklədiyimiz ləğv udulur; cari task ləğv olunursa `gather`
            # yenə `CancelledError` qaldırır → yuxarı ötürülür (udulmur).
            await asyncio.gather(killer, return_exceptions=True)
    return ProcResult(proc.returncode or 0, out or b"", err or b"")


class AsyncTool:
    name = "base"

    def __init__(self, name: str | None = None, extra_args: list | None = None):
        if name:
            self.name = name
        self.log = logging.getLogger(f"qbh.{self.name}")
        self.extra_args = extra_args or []

    async def run(self, args: list, timeout: int = 600,
                  parse_json: bool = True) -> list:
        res = await run_process(args + self.extra_args, timeout=timeout)
        if res.missing:
            self.log.error("%s tapılmadı — installer işə sal", self.name)
            return []
        if res.timed_out:
            self.log.warning("%s timeout (%ds)", self.name, timeout)
            return []
        if res.returncode != 0 and not res.stdout:
            self.log.warning("%s qeyri-sıfır çıxış kodu: %s",
                             self.name, res.returncode)
            return []

        lines = res.stdout.decode(errors="ignore").splitlines()
        if not parse_json:
            return [ln for ln in lines if ln.strip()]

        results = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results
