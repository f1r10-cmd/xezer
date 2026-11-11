"""Race Condition Engine — YALNIZ lokal fixture (NON-DESTRUCTIVE).

Bu mühərrik artıq real hədəflərə qarşı "blast" etmir. Yalnız istifadəçi
`--race-fixture` ilə AÇIQ şəkildə göstərdiyi LOKAL test serverinə (loopback)
qarşı işləyir. Beləliklə dağıdıcı race testi default olaraq tamamilə
deaktivdir və yalnız nəzarətli, təkrarlana bilən mühitdə mümkündür.

Məhdudiyyətlər:
  * fixture loopback (127.0.0.1 / ::1 / localhost) olmalıdır;
  * sorğu sayı SABİTDİR (`--race-count`, default 10, maks 20);
  * concurrency SƏRT məhduddur (default 4, maks 5);
  * nəticə yalnız "potential" kimi qeyd olunur, manual təsdiq tələb edir.
"""
from __future__ import annotations

import asyncio
import ipaddress
from urllib.parse import urlsplit

import aiohttp

from .. import db
from ..results import EngineResult

DEFAULT_COUNT = 10
MAX_COUNT = 20
DEFAULT_CONCURRENCY = 4
MAX_CONCURRENCY = 5
TIMEOUT = 10.0

_LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


def _is_loopback(url: str) -> bool:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return False
    if not host:
        return False
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class RaceEngine:
    name = "race"

    def __init__(self, ctx):
        self.ctx = ctx
        self.args = ctx.args

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        fixture = self.ctx.race_fixture
        if not fixture:
            return res.skip(
                "race testi deaktivdir — yalnız `--race-fixture "
                "http://127.0.0.1:PORT/...` ilə lokal fixture üzərində mümkündür")

        if not _is_loopback(fixture):
            res.fail(f"race fixture loopback olmalıdır (verilən: {fixture}) — "
                     f"xarici hədəfə race testi QADAĞANDIR")
            return res

        count = min(MAX_COUNT, max(2, int(getattr(self.args, "race_count",
                                                  DEFAULT_COUNT) or DEFAULT_COUNT)))
        concurrency = min(MAX_CONCURRENCY, max(1, int(
            getattr(self.args, "race_concurrency", DEFAULT_CONCURRENCY)
            or DEFAULT_CONCURRENCY)))
        print(f"[═══ RACE (lokal fixture) ═══] {fixture} · "
              f"{count} sorğu · concurrency={concurrency}")

        sem = asyncio.Semaphore(concurrency)

        async def hit(session):
            async with sem:
                try:
                    async with session.get(
                            fixture, timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                            allow_redirects=False) as r:
                        body = (await r.text(errors="ignore"))[:2000]
                        return r.status, body
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    return 0, ""

        async with aiohttp.ClientSession() as session:
            results = await asyncio.gather(*[hit(session) for _ in range(count)])

        ok_200 = sum(1 for s, _ in results if s == 200)
        distinct_bodies = {b for s, b in results if s == 200}

        res.data.update({"fixture": fixture, "count": count,
                         "http_200": ok_200,
                         "distinct_bodies": len(distinct_bodies)})

        if ok_200 > 1 and len(distinct_bodies) > 1:
            db.insert_finding(
                self._fixture_host_id(fixture, self.ctx.scan_id),
                "race", "low",
                f"Race simptomu (lokal fixture): {fixture}",
                f"Lokal fixture-də {count} paralel sorğunun {ok_200}-i HTTP 200 "
                f"aldı və {len(distinct_bodies)} fərqli cavab gövdəsi müşahidə "
                f"olundu. Bu YALNIZ HEURISTIK siqnaldır — manual təsdiq tələb "
                f"olunur. Xarici hədəflərə race testi aparılmır.",
                evidence=f"http_200={ok_200}, distinct_bodies={len(distinct_bodies)}",
                confidence=0.3, status="potential", source="race-local")
            res.findings += 1
            res.warn("race: heuristik siqnal — manual təsdiq tələb olunur")
        else:
            print(f"[+] Race siqnalı yoxdur ({ok_200}/{count} HTTP 200)")
        return res

    @staticmethod
    def _fixture_host_id(fixture: str, scan_id=None) -> int:
        """Lokal fixture üçün host qeydi yaradır (yalnız lokal saxlanış)."""
        host = urlsplit(fixture).hostname or "127.0.0.1"
        return db.upsert_host(host, scan_id, status_code=200,
                              source="race-local")
