"""Tool adapterləri — təhlükəsiz subprocess idarəsi.

Heç bir yerdə shell istifadə olunmur (shell=True yoxdur) → command injection
mümkün deyil. Timeout və ləğvetmə (cancellation) zamanı proses mütləq öldürülür.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from dataclasses import dataclass


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
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines[:cap]))
    return tmp, tmp


@dataclass
class ProcResult:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    missing: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.missing


async def run_process(cmd: list[str], *, stdin: bytes | None = None,
                      timeout: float = 600) -> ProcResult:
    """Təhlükəsiz async subprocess. Shell yoxdur; cancel/timeout → kill."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin is not None
            else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError:
        return ProcResult(-1, missing=True)
    except OSError:
        return ProcResult(-1, missing=True)

    try:
        out, err = await asyncio.wait_for(proc.communicate(stdin), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return ProcResult(-1, timed_out=True)
    except asyncio.CancelledError:
        proc.kill()
        await proc.wait()
        raise
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
