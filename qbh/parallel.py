"""Məhdud (bounded) paralel işçi köməkçisi (Faza 1, §7).

Məqsəd: bir-birindən MÜSTƏQİL host-lar üzərində işləri (hər host öz sorğu
axınına malikdir) məhdud sayda paralel işlədərək skan ötürmə qabiliyyətini
artırmaq — L AKİN hədəfə gedən trafik ARTIRILMIR: hər sorğu `HttpPolicy`-dən
(scope + host RPS + host/qlobal concurrency + cooldown) keçir.

Prinsiplər:
  * Yalnız `min(limit, len(items))` işçi tapşırığı yaradılır — hər element
    üçün ayrı tapşırıq YARADILMIR → "limitsiz tapşırıq yaradılması" yoxdur.
  * Nəticələr `items` sırası ilə saxlanılır → deterministik aqreqasiya.
  * Bir elementin exception-u DİGƏR elementləri DAYANDIRMIR; həmin element
    üçün nəticə yerinə exception saxlanılır (çağıran onu yoxlayır).
  * `asyncio.CancelledError` udulmur — bütün işçilərə yayılır.
  * `ContextVar` (məs. egress proses qapısı) işçi tapşırıqlarına ötürülür,
    beləcə alt-proses EgressController yoxlamaları qorunur.
"""
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def concurrency_limit(cfg, n: int, *, default: int = 4) -> int:
    """Konfiqurasiya olunmuş QLOBAL concurrency-dən böyük olmayan host tavanı.

    Host paralelliyi heç vaxt qlobal concurrency tavanını aşmamalıdır — daha
    çox işçi yaratmağın mənası yoxdur, çünki `HttpPolicy` qlobal slotları
    onsuz da məhdudlaşdırır. Konfiq oxunmazsa mühafizəkar default istifadə
    olunur (partlamır).
    """
    try:
        ceiling = int(cfg.effective_concurrency)
    except Exception:  # noqa: BLE001 - konfiq yoxdursa mühafizəkar default
        ceiling = default
    return max(1, min(ceiling, max(1, n)))


async def run_bounded(
    items: Iterable[T],
    worker: Callable[[T], Awaitable[R]],
    *,
    limit: int,
) -> list[R | BaseException]:
    """`items` üzərində ən çoxu `limit` paralel `worker(item)` icra edir.

    Qaytarır: `items` sırasına uyğun nəticə siyahısı. Uğursuz element üçün
    həmin yerdə exception saxlanılır (digərləri təsirlənmir).
    """
    seq = list(items)
    n = len(seq)
    if n == 0:
        return []
    concurrency = max(1, min(int(limit), n))
    results: list[R | BaseException] = [None] * n  # type: ignore[list-item]

    cursor = 0

    async def _consume() -> None:
        nonlocal cursor
        while True:
            # `cursor` oxu/artım arasında `await` YOXDUR → atomikdir.
            index = cursor
            cursor += 1
            if index >= n:
                return
            try:
                results[index] = await worker(seq[index])
            except asyncio.CancelledError:
                raise
            except BaseException as exc:  # noqa: BLE001 - digər hostları dayandırma
                results[index] = exc

    workers = [asyncio.create_task(_consume()) for _ in range(concurrency)]
    try:
        await asyncio.gather(*workers)
    except asyncio.CancelledError:
        for task in workers:
            task.cancel()
        raise
    return results
