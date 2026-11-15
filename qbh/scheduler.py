"""Mərkəzləşdirilmiş, məhdud (bounded) tapşırıq planlaşdırıcısı (Faza 4).

Məqsəd: mühərriklərin İÇİNDƏ limitsiz tapşırıq yaratmağın qarşısını almaq və
iş yükünü MƏRKƏZİ şəkildə, məhdud növbə + prioritet + ədalətlə idarə etmək.

Prinsiplər:
  * **Məhdud növbə + backpressure** — növbə doyduqda `submit()` `False`
    qaytarır (səssizcə yaddaş partlamır); doyma sayı ölçülür.
  * **Prioritet-şüurlu** — yüksək prioritetli tapşırıq əvvəl seçilir.
  * **Host və endpoint-ailəsi ədaləti** — növbədəki açar `(host, ailə)` üzrə
    ROUND-ROBIN seçilir → bir host bütün işçiləri işğal edə BİLMƏZ və
    yüksək prioritetli tapşırıq seli digər endpoint-ləri AÇ QOYMAZ.
  * **İki səviyyəli concurrency** — qlobal + host (+ mühərrik) semaforları.
  * **İzolyasiya** — bir tapşırığın xətası işçi dövrəsini DAYANDIRMIR.
  * **Ləğv yayılması** — `aclose()` bütün işçiləri ləğv edir və FAKTİKİ
    bitməsini gözləyir (Task sızması yoxdur).
  * Mövcud `HttpPolicy`/`Guardian`/rate limitləri KEÇMİR — bu planlaşdırıcı
    yalnız "nə vaxt hansı işi başlatmaq" qərarını verir; faktiki HTTP trafiki
    yenə `Guardian`/`HttpPolicy`-dən keçir və RPS ARTIRILMIR.

İDEMPOTENTLİK MÜQAVİLƏSİ (F-04 — TƏK həqiqət mənbəyi)
-----------------------------------------------------
Planlaşdırıcı özü qəbul (admission) üçün `TaskLedger`-ə MÜRACİƏT ETMİR.
Yeganə həqiqət mənbəyi **`TaskLedger`-dir** və müqavilə belədir:

  1. ÇAĞIRAN `TaskLedger.consider(identity)` ilə icazə ALMALIDIR.
     Yalnız `decision.create is True` olduqda tapşırıq `submit()` edilir.
  2. `Scheduler` yalnız HƏYAT DÖVRÜNÜ (`ledger.mark`) yazır — icra
     `running → completed|failed|timed_out|cancelled` keçidlərini qeyd edir.
  3. Planlaşdırıcıya icazəsiz (dəftərdə `queued`/`running`/terminal olan)
     eyni kimlikli tapşırıq VERİLMƏMƏLİDİR — deduplikasiya tək yerdə,
     `TaskLedger`-də baş verir. İki paralel həqiqət mənbəyi YARADILMIR.

Ədalət açarları (F-06): URL-səviyyəli tapşırıqlar üçün REAL `(host, ailə)`
`url_fair_key()` ilə alınır; hostları əhatə edən (qlobal) mərhələ
tapşırıqları üçün isə sənədləşdirilmiş `HOST_GLOBAL` sentinelindən istifadə
olunur — uydurma host dəyəri YAZILMIR.
"""
from __future__ import annotations

import asyncio
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from .tasks import (STATE_CANCELLED, STATE_COMPLETED, STATE_FAILED,
                    STATE_QUEUED, STATE_RUNNING, STATE_TIMED_OUT)

DEFAULT_QUEUE_LIMIT = 512

#: Backpressure zamanı gözləmə parametrləri (SONSUZ gözləmə YOXDUR).
DEFAULT_SUBMIT_ATTEMPTS = 64
DEFAULT_SUBMIT_DELAY = 0.02

#: Host-üzrə scope-u OLMAYAN (bütün hostları əhatə edən) mərhələ tapşırıqları
#: üçün SƏNƏDLƏŞDİRİLMİŞ ədalət açarı (F-06). Belə tapşırıqların tək hostu
#: yoxdur → `host=""` yerinə bu sentinel "qlobal əhatə"ni bildirir; `family`
#: isə mərhələnin adıdır. Nəticədə hər mərhələ AYRI ədalət səbətinə düşür və
#: uzun sürən bir mərhələ digərlərini AÇ QOYMASIN (round-robin).
HOST_GLOBAL = "*"


def url_fair_key(url: str, *, host: str = "") -> tuple[str, str]:
    """URL-səviyyəli tapşırıq üçün REAL ədalət açarı `(host, ailə)` (F-06).

    `host`/`ailə` UYDURULMUR — `urlintel`-in deterministik normalizasiyasından
    alınır (`endpoint_family`). Beləcə çox-hostlu, çox-ailəli iş yükü üzərində
    round-robin ədaləti FAKTİKİ metadata ilə işləyir və eyni marşrutun
    endpoint-ləri bir-birini AÇ QOYMASIN.

    Normalizasiya mümkün olmadıqda host/ailə boş qalır (uydurma dəyər yox).
    """
    from . import urlintel

    fam = urlintel.endpoint_family(url)
    if not host:
        norm = urlintel.normalize_url(url)
        if norm:
            from urllib.parse import urlsplit
            host = urlsplit(norm).hostname or ""
    return (host or "", fam or "")


async def submit_with_backpressure(sched: "Scheduler", task: SchedTask, *,
                                   attempts: int = DEFAULT_SUBMIT_ATTEMPTS,
                                   delay: float = DEFAULT_SUBMIT_DELAY) -> bool:
    """`submit()` backpressure-ını MƏHDUD gözləmə ilə idarə edir.

    Növbə doyduqda (`submit()` `False`) qısa müddət gözləyib YENİDƏN cəhd edir
    — bu müddətdə işçilər növbəni boşaldır. `attempts` tükənərsə `False`
    qaytarır: çağıran bunu AÇIQ şəkildə qeyd etməlidir (mərhələ SƏSSİZCƏ
    itirilmir). SONSUZ gözləmə/cəhd YOXDUR və bu funksiya HEÇ BİR HTTP sorğusu
    yaratmır — yalnız növbə axınını idarə edir (RPS artırılmır).
    """
    for _ in range(max(1, int(attempts))):
        if await sched.submit(task):
            return True
        await asyncio.sleep(max(0.0, float(delay)))
    return False


@dataclass
class SchedTask:
    """Planlaşdırılan məntiqi iş vahidi."""

    identity: str
    engine: str
    host: str
    run: Callable[[], Awaitable[Any]]
    family: str = ""
    priority: int = 0
    status: str = STATE_QUEUED
    result: Any = None
    error: str = ""
    meta: dict = field(default_factory=dict)

    @property
    def fair_key(self) -> tuple:
        return (self.host or "", self.family or "")


class _Slot:
    """Qlobal + host (+ mühərrik) semaforlarını birlikdə götürən kontekst."""

    def __init__(self, sched: "Scheduler", task: SchedTask):
        self.sched = sched
        self.task = task
        self._held: list = []

    async def __aenter__(self):
        for sem in self.sched._sems_for(self.task):
            await sem.acquire()
            self._held.append(sem)
        # Sayğac YALNIZ bütün semaforlar alındıqdan sonra artır → ölçülən
        # concurrency həqiqi icra concurrency-sidir (tavanı aşa bilməz).
        self.sched._enter_slot(self.task)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        for sem in reversed(self._held):
            sem.release()
        self._held.clear()
        self.sched._exit_slot(self.task)
        return False


class Scheduler:
    """Bounded, prioritet-şüurlu, ədalətli tapşırıq planlaşdırıcısı."""

    def __init__(self, *, workers: int = 4, queue_limit: int | None = None,
                 global_limit: int = 0, per_host_limit: int = 0,
                 engine_limits: dict | None = None, ledger=None, metrics=None):
        self.workers = max(1, int(workers))
        self.queue_limit = (DEFAULT_QUEUE_LIMIT if queue_limit is None
                            else int(queue_limit))
        self.global_limit = max(0, int(global_limit))
        self.per_host_limit = max(0, int(per_host_limit))
        self.engine_limits = {k: max(1, int(v))
                              for k, v in (engine_limits or {}).items()}
        self.ledger = ledger
        self.metrics = metrics

        self._buckets: dict[int, OrderedDict] = {}
        self._cond: asyncio.Condition | None = None
        self._global_sem: asyncio.Semaphore | None = None
        self._host_sems: dict[str, asyncio.Semaphore] = {}
        self._engine_sems: dict[str, asyncio.Semaphore] = {}
        self._workers: list[asyncio.Task] = []
        self._stopping = False
        self._started = False

        self._queued = 0            # növbədə gözləyən
        self._outstanding = 0       # qəbul olunan, hələ bitməyən (queued+running)
        self._active = 0            # hazırda slot tutmuş
        self.submitted = 0
        self.executed = 0
        self.completed = 0
        self.failed = 0
        self.cancelled = 0
        #: Backpressure səbəbilə RƏDD OLUNMUŞ submit CƏHDLƏRİ (cəhdlər).
        #: `submit_with_backpressure` məhdud təkrar cəhd etdiyi üçün bir
        #: tapşırıq bir neçə dəfə burada sayıla bilər — bu, tapşırıq İTKİSİ
        #: DEYİL. `accepted` (submitted) ilə birlikdə submit SƏRHƏDİNİN
        #: nəticəsini ölçür (niyyət/icra qarışmır; tapşırığın YEKUN taleyi
        #: TaskLedger vəziyyətində saxlanılır).
        self.rejected = 0
        self.peak_queue = 0
        self.peak_concurrency = 0
        self.engine_runs: dict[str, int] = {}
        self.host_runs: dict[str, int] = {}

    # ------------------------------------------------------------------ setup
    def _ensure(self) -> None:
        if self._cond is None:
            self._cond = asyncio.Condition()
        if self.global_limit and self._global_sem is None:
            self._global_sem = asyncio.Semaphore(self.global_limit)

    def _sems_for(self, task: SchedTask):
        sems = []
        if self._global_sem is not None:
            sems.append(self._global_sem)
        if self.per_host_limit:
            sems.append(self._host_sems.setdefault(
                task.host or "", asyncio.Semaphore(self.per_host_limit)))
        limit = self.engine_limits.get(task.engine)
        if limit:
            sems.append(self._engine_sems.setdefault(
                task.engine, asyncio.Semaphore(limit)))
        return sems

    def _enter_slot(self, task: SchedTask) -> None:
        self._active += 1
        if self._active > self.peak_concurrency:
            self.peak_concurrency = self._active
        if self.metrics is not None:
            self.metrics.record_concurrency(self._active)

    def _exit_slot(self, task: SchedTask) -> None:
        if self._active > 0:
            self._active -= 1

    # ----------------------------------------------------------------- submit
    @property
    def queue_size(self) -> int:
        return self._queued

    @property
    def outstanding(self) -> int:
        return self._outstanding

    async def submit(self, task: SchedTask) -> bool:
        """Tapşırığı növbəyə əlavə edir. Doymuşsa `False` (backpressure)."""
        self._ensure()
        if self.queue_limit and self._queued >= self.queue_limit:
            self.rejected += 1
            if self.metrics is not None:
                self.metrics.record_backpressure()
            return False
        bucket = self._buckets.setdefault(task.priority, OrderedDict())
        dq = bucket.get(task.fair_key)
        if dq is None:
            dq = deque()
            bucket[task.fair_key] = dq
        dq.append(task)
        self._queued += 1
        self._outstanding += 1
        self.submitted += 1
        if self._queued > self.peak_queue:
            self.peak_queue = self._queued
        if self.metrics is not None:
            self.metrics.record_queue_depth(self._queued)
        async with self._cond:
            self._cond.notify_all()
        return True

    def _pop(self) -> SchedTask | None:
        for priority in sorted(self._buckets, reverse=True):
            bucket = self._buckets[priority]
            if not bucket:
                continue
            key = next(iter(bucket))
            dq = bucket[key]
            task = dq.popleft()
            if dq:
                bucket.move_to_end(key)     # round-robin: host/ailə ədaləti
            else:
                del bucket[key]
            if not bucket:
                del self._buckets[priority]
            self._queued -= 1
            return task
        return None

    async def _next(self) -> SchedTask | None:
        assert self._cond is not None
        async with self._cond:
            while True:
                task = self._pop()
                if task is not None:
                    return task
                if self._stopping:
                    return None
                await self._cond.wait()

    # ------------------------------------------------------------------ workers
    def start(self) -> None:
        self._ensure()
        if self._started:
            return
        self._started = True
        self._workers = [asyncio.create_task(self._worker(i))
                         for i in range(self.workers)]

    async def _worker(self, index: int) -> None:
        while True:
            task = await self._next()
            if task is None:
                return
            await self._run(task)

    async def _run(self, task: SchedTask) -> None:
        task.status = STATE_RUNNING
        if self.ledger is not None:
            self.ledger.mark(task.identity, STATE_RUNNING, "işçi başladı")
        try:
            async with _Slot(self, task):
                self.executed += 1
                task.result = await task.run()
        except asyncio.CancelledError:
            task.status = STATE_CANCELLED
            self.cancelled += 1
            if self.ledger is not None:
                self.ledger.mark(task.identity, STATE_CANCELLED, "ləğv edildi")
            raise
        except asyncio.TimeoutError:
            task.status = STATE_TIMED_OUT
            self.failed += 1
            if self.ledger is not None:
                self.ledger.mark(task.identity, STATE_TIMED_OUT, "timeout")
        except Exception as exc:                       # noqa: BLE001 - izolyasiya
            task.status = STATE_FAILED
            task.error = f"{type(exc).__name__}: {exc}"
            self.failed += 1
            if self.ledger is not None:
                self.ledger.mark(task.identity, STATE_FAILED, task.error)
        else:
            task.status = STATE_COMPLETED
            self.completed += 1
            self.engine_runs[task.engine] = self.engine_runs.get(task.engine, 0) + 1
            self.host_runs[task.host] = self.host_runs.get(task.host, 0) + 1
            if self.ledger is not None:
                self.ledger.mark(task.identity, STATE_COMPLETED, "tamamlandı")
        finally:
            await self._finish(task)

    async def _finish(self, task: SchedTask) -> None:
        """Tamamlanma sayğacını azaldır və gözləyənlərə xəbər verir."""
        self._outstanding = max(0, self._outstanding - 1)
        if self._cond is not None:
            async with self._cond:
                self._cond.notify_all()

    # -------------------------------------------------------------------- loop
    async def drain(self) -> None:
        """Qəbul olunmuş BÜTÜN tapşırıqlar bitənə qədər gözləyir."""
        self._ensure()
        async with self._cond:
            while self._outstanding > 0:
                await self._cond.wait()

    async def join(self) -> None:
        """`drain()` ilə eyni — mövcud çağırışlar üçün saxlanılır."""
        await self.drain()

    async def run(self) -> None:
        """Növbəni boşaldır və işçiləri bağlayır (submit-lərdən SONRA)."""
        self.start()
        try:
            await self.drain()
        finally:
            await self.aclose()

    def stop(self) -> None:
        self._stopping = True
        if self._cond is not None:
            asyncio.create_task(self._notify())

    async def _notify(self) -> None:
        async with self._cond:
            self._cond.notify_all()

    async def aclose(self) -> None:
        """Bütün işçiləri ləğv edir və FAKTİKİ bitməsini gözləyir."""
        self._stopping = True
        if self._cond is not None:
            async with self._cond:
                self._cond.notify_all()
        for w in self._workers:
            w.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers = []
        self._started = False

    async def __aenter__(self) -> "Scheduler":
        self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        await self.aclose()
        return False

    # ------------------------------------------------------------------- stats
    def snapshot(self) -> dict:
        return {
            "submitted": self.submitted,
            "executed": self.executed,
            "completed": self.completed,
            "failed": self.failed,
            "cancelled": self.cancelled,
            "rejected_backpressure": self.rejected,
            "pending": self._queued,
            "outstanding": self._outstanding,
            "peak_queue": self.peak_queue,
            "peak_concurrency": self.peak_concurrency,
            "workers": self.workers,
            "queue_limit": self.queue_limit,
            "host_runs": dict(sorted(self.host_runs.items())),
            "engine_runs": dict(sorted(self.engine_runs.items())),
        }
