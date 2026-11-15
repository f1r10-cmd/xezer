"""Skan-scoped HTTP metrikləri (Faza 0).

Məqsəd: performans əsasını **ÖLÇMƏK** — uydurma rəqəm deyil. Bu kollektor
`HttpPolicy`-nin hər fiziki HTTP cəhdində yenilənir və yalnız BİR skana aiddir
(`Conductor` hər skan üçün təzə nüsxə yaradır).

Prinsiplər:
  * **Bounded yaddaş** — fərdi ölçmələrin limitsiz siyahısı SAXLANILMIR;
    latensiya/gözləmə vaxtları sabit ölçülü reservoir nümunəsi ilə toplanır
    (Vitter Alqoritm R), host-əsaslı sayğaclar isə yumşaq üst hədlə məhdudlanır.
  * **Həssas məlumat YOX** — cavab gövdələri, cookie, `Authorization`,
    credential və sorğu parametrləri saxlanılmır; tam URL YAZILMIR (yalnız host).
  * **Deterministik** — reservoir sabit toxumla işləyir → eyni yük eyni nəticəni
    verir (təkrar istehsal oluna bilən benchmark üçün).
  * **Yüngül** — `HttpPolicy.metrics is None` olduqda heç bir ölçmə aparılmır.
"""
from __future__ import annotations

import random
from collections import Counter

#: Reservoir nümunəsinin sabit ölçüsü (bounded memory).
DEFAULT_SAMPLE_CAP = 1024

#: Host-əsaslı sayğaclar üçün yumşaq üst hədd; artıqlar bir səbətdə toplanır.
DEFAULT_HOST_CAP = 512

#: Üst hədd aşıldıqda istifadə olunan birləşdirici açar.
OVERFLOW_KEY = "__other__"

#: Reservoir toxumu — sabit → eyni yük eyni P50/P95 verir.
_RESERVOIR_SEED = 20240101


class _Reservoir:
    """Sabit ölçülü, sabit toxumlu reservoir (P50/P95 təxmini, bounded)."""

    __slots__ = ("_cap", "_rng", "samples", "count", "total", "maximum")

    def __init__(self, cap: int = DEFAULT_SAMPLE_CAP, seed: int = _RESERVOIR_SEED):
        self._cap = max(1, int(cap))
        self._rng = random.Random(seed)
        self.samples: list[float] = []
        self.count = 0
        self.total = 0.0
        self.maximum = 0.0

    def add(self, value: float) -> None:
        v = max(0.0, float(value))
        self.count += 1
        self.total += v
        if v > self.maximum:
            self.maximum = v
        if len(self.samples) < self._cap:
            self.samples.append(v)
            return
        # Vitter Alqoritm R: hər yeni element bərabər ehtimalla seçilir.
        j = self._rng.randint(0, self.count - 1)
        if j < self._cap:
            self.samples[j] = v

    def percentile(self, pct: float) -> float:
        if not self.samples:
            return 0.0
        ordered = sorted(self.samples)
        rank = int(round(len(ordered) * max(0.0, min(100.0, pct)) / 100.0 + 0.5))
        idx = min(len(ordered) - 1, max(0, rank - 1))
        return ordered[idx]

    def to_dict(self, *, scale: float = 1000.0, unit: str = "_ms") -> dict:
        return {
            "count": self.count,
            f"total{unit}": round(self.total * scale, 3),
            f"max{unit}": round(self.maximum * scale, 3),
            f"p50{unit}": round(self.percentile(50) * scale, 3),
            f"p95{unit}": round(self.percentile(95) * scale, 3),
        }


class ScanMetrics:
    """Bir skan üçün HTTP metrikaları (bounded, həssas məlumatsız)."""

    def __init__(self, *, sample_cap: int = DEFAULT_SAMPLE_CAP,
                 host_cap: int = DEFAULT_HOST_CAP):
        self._host_cap = max(1, int(host_cap))
        self._known_hosts: set[str] = set()

        self.requests_total = 0
        self.by_host: Counter = Counter()
        self.by_status: Counter = Counter()
        self.timeouts = 0
        self.connection_errors = 0

        self.latency = _Reservoir(sample_cap)
        self.global_sem_wait = _Reservoir(sample_cap)
        self.host_sem_wait = _Reservoir(sample_cap)

        self.max_global_concurrency = 0
        self.max_host_concurrency: dict[str, int] = {}
        self.sessions_created = 0
        self.sessions_closed = 0
        self.transport_requests = 0
        self.aiohttp_requests = 0

        self._global_active = 0
        self._host_active: dict[str, int] = {}

    # ------------------------------------------------------------- host bucket
    def _key(self, host: str) -> str:
        """Host üçün bounded açar (üst hədd aşılırsa birləşdirici səbət)."""
        h = host or ""
        if h in self._known_hosts:
            return h
        if len(self._known_hosts) < self._host_cap:
            self._known_hosts.add(h)
            return h
        return OVERFLOW_KEY

    # ---------------------------------------------------------------- requests
    def record_request(self, host: str, status: int, elapsed: float, *,
                       transport: bool = False) -> None:
        self.requests_total += 1
        self.by_host[self._key(host)] += 1
        self.by_status[int(status)] += 1
        self.latency.add(elapsed)
        if transport:
            self.transport_requests += 1
        else:
            self.aiohttp_requests += 1

    def record_error(self, kind: str) -> None:
        """`kind`: `timeout` və ya `connection`."""
        if kind == "timeout":
            self.timeouts += 1
        else:
            self.connection_errors += 1

    # ------------------------------------------------------------ concurrency
    def enter_global(self) -> None:
        self._global_active += 1
        if self._global_active > self.max_global_concurrency:
            self.max_global_concurrency = self._global_active

    def exit_global(self) -> None:
        if self._global_active > 0:
            self._global_active -= 1

    def enter_host(self, host: str) -> None:
        k = self._key(host)
        n = self._host_active.get(k, 0) + 1
        self._host_active[k] = n
        if n > self.max_host_concurrency.get(k, 0):
            self.max_host_concurrency[k] = n

    def exit_host(self, host: str) -> None:
        k = self._key(host)
        n = self._host_active.get(k, 0)
        if n > 0:
            self._host_active[k] = n - 1

    # --------------------------------------------------------------- waiting
    def record_global_wait(self, seconds: float) -> None:
        self.global_sem_wait.add(seconds)

    def record_host_wait(self, seconds: float) -> None:
        self.host_sem_wait.add(seconds)

    # --------------------------------------------------------------- sessions
    def record_session_created(self) -> None:
        self.sessions_created += 1

    def record_session_closed(self) -> None:
        self.sessions_closed += 1

    # --------------------------------------------------------------- snapshot
    def snapshot(self) -> dict:
        """JSON-a yazıla bilən xülasə (həssas məlumat YOX, tam URL YOX)."""
        return {
            "requests_total": self.requests_total,
            "requests_by_host": dict(sorted(self.by_host.items())),
            "requests_by_status": {str(k): v for k, v in
                                   sorted(self.by_status.items())},
            "timeouts": self.timeouts,
            "connection_errors": self.connection_errors,
            "latency": self.latency.to_dict(),
            "global_sem_wait": self.global_sem_wait.to_dict(),
            "host_sem_wait": self.host_sem_wait.to_dict(),
            "max_global_concurrency": self.max_global_concurrency,
            "max_host_concurrency": dict(sorted(
                self.max_host_concurrency.items())),
            "sessions_created": self.sessions_created,
            "sessions_closed": self.sessions_closed,
            "aiohttp_requests": self.aiohttp_requests,
            "transport_requests": self.transport_requests,
        }


# --------------------------------------------------------------------------- #
# Orkestrasiya metrikaları (Faza 6) — URL / tapşırıq / zəncir / mühərrik
# --------------------------------------------------------------------------- #
#: Tapşırıq metrikalarının sabit açar dəsti (boş dəyərlər də göstərilir).
#:
#: F-05: NIYYƏT (planlama) və FAKTİKİ İCRA AYRI anlayışlardır. Hər açarın
#: VAHİD mənası var və heç bir açar iki mənbədən cəmlənmir (ikiqat sayma yox):
#:   discovered    — URL Intelligence-ın kəşf etdiyi UNIKAL URL-lər (mənbə: URL).
#:   considered    — `TaskLedger.consider()` çağırışları (niyyət).
#:   eligible      — uyğun (`eligible`) mühərrik-URL cütlərinin cəmi (mənbə: uyğunluq).
#:   queued        — dəftərdə YENİ yaradılıb növbəyə alınan tapşırıqlar (niyyət).
#:   accepted      — planlaşdırıcıya QƏBUL olunan (submit=TRUE) tapşırıqlar (icra).
#:   deduplicated  — idempotentlik üzrə TƏKRAR rədd edilənlər (niyyət).
#:   rejected      — planlaşdırıcı backpressure ilə rədd edilənlər (icra).
#:   started       — icraya BAŞLANAN (ledger `running`) tapşırıqlar.
#:   executed      — FAKTİKİ icra olunan tapşırıqlar (planlaşdırıcı işçisi çalışdı).
#:   completed     — uğurla tamamlanan (icra realm-i).
#:   partial       — qismən tamamlanan.
#:   failed        — uğursuz.
#:   timed_out     — vaxt aşımı.
#:   cancelled     — ləğv edilən.
#:   skipped       — şüurlu atlanan (dəstəklənməyən/qadağan).
#:   retried       — bounded təkrar cəhdə icazə verilənlər.
#:   deferred      — təxirə salınan (mənbə: uyğunluq).
#:   pending       — hələ bitməyən (queued+running).
TASK_KEYS = (
    "discovered", "considered", "eligible", "queued", "accepted",
    "deduplicated", "rejected", "started", "executed", "completed",
    "partial", "failed", "timed_out", "cancelled", "skipped", "retried",
    "deferred", "pending",
)

#: Zəncir metrikalarının sabit açar dəsti.
CHAIN_KEYS = ("emitted", "received", "duplicate", "conditions_rejected",
              "cyclic", "scheduled", "scheduled_tasks", "suppressed")


class OrchestrationMetrics:
    """Skan- və mühərrik-əsaslı orkestrasiya sayğacları.

    Uydurma faiz/qalan-vaxt YOXDUR — yalnız FAKTİKİ saylar. Bütün sahələr
    bounded-dır (Counter/dict); URL gövdələri və ya tam URL saxlanılmır.
    """

    def __init__(self):
        # --- URL metrikaları ---
        self.urls_raw = 0
        self.urls_unique = 0
        self.urls_duplicate = 0
        self.endpoint_families = 0
        self.urls_by_category: Counter = Counter()

        # --- uyğunluq (mühərrik-əsaslı) ---
        self.eligible: Counter = Counter()
        self.excluded: Counter = Counter()
        self.deferred: Counter = Counter()
        self.exclusion_reasons: Counter = Counter()
        #: F-07: təxirə salınmış endpoint-lərin yenidən baxışı — YENİ dəlil
        #: əsasında uyğun hala keçənlər və hələ də deferred qalanlar.
        self.reconsidered: Counter = Counter()
        self.remained_deferred: Counter = Counter()
        #: Faza 2: cavab metadata-sı əsaslı təsnifat dəqiqləşdirmələri —
        #: tətbiq olunan və uyğunluğu dəyişəcəyi üçün RƏDD edilənlər.
        self.refined_applied = 0
        self.refined_refused = 0

        # --- tapşırıq ---
        self.tasks: Counter = Counter({k: 0 for k in TASK_KEYS})
        #: F-05: xam mənbələr AYRI saxlanılır — niyyət (ledger) vs FAKTİKİ
        #: icra (scheduler). Beləliklə iki vəziyyət həmişə ayırd edilə bilər.
        self.tasks_ledger: dict = {}
        self.tasks_scheduler: dict = {}
        #: Hər açarın mənbəyi: "ledger" | "scheduler" | "urls" | "eligibility" |
        #: "unavailable" (uydurma YOX — əlçatmaz metrika açıq işarələnir).
        self.tasks_sources: dict = {k: "unavailable" for k in TASK_KEYS}
        self.peak_queue = 0
        self.peak_concurrency = 0
        self.backpressure_events = 0

        # --- zəncir ---
        self.chain: Counter = Counter({k: 0 for k in CHAIN_KEYS})

        # --- mühərrik ---
        self.engines: dict[str, dict] = {}

    # ------------------------------------------------------------------- URL
    def record_url_intake(self, intake) -> None:
        """`urlintel.UrlIntake` nəticəsini qeyd edir (TƏK çağırış)."""
        self.urls_raw = int(intake.raw)
        self.urls_unique = int(intake.unique)
        self.urls_duplicate = int(intake.duplicates)
        self.endpoint_families = int(intake.families)
        self.urls_by_category = Counter(intake.by_category)

    # -------------------------------------------------------------- eligibility
    def record_plan(self, plan) -> None:
        """`urlintel.UrlPlan` (mühərrik planı) nəticəsini qeyd edir."""
        eng = plan.engine or "?"
        self.eligible[eng] += int(plan.eligible)
        self.excluded[eng] += int(plan.excluded)
        self.deferred[eng] += int(plan.deferred)
        for d in plan.excluded_details:
            self.exclusion_reasons[d.reason] += 1

    def record_reconsider(self, engine: str, *, promoted: int = 0,
                          remained: int = 0) -> None:
        """F-07: deferred endpoint yenidən baxışının nəticəsini qeyd edir.

        `promoted` — yeni dəlil sayəsində `deferred`-dən `eligible`-a keçənlər;
        `remained` — hələ də deferred qalanlar. Heç bir uydurma yoxdur.
        """
        self.reconsidered[engine] += int(promoted)
        self.remained_deferred[engine] += int(remained)

    def record_refinement(self, *, applied: bool) -> None:
        """Faza 2: cavab metadata-sı ilə təsnifat dəqiqləşdirməsini qeyd edir.

        `applied=True` — uyğunluğu dəyişməyən dəqiqləşdirmə tətbiq olundu.
        `applied=False` — mühərrik uyğunluğunu dəyişəcəyi üçün RƏDD olundu
        (evasion/əhatə genişlənməsinin qarşısı). Uydurma say yoxdur.
        """
        if applied:
            self.refined_applied += 1
        else:
            self.refined_refused += 1

    # -------------------------------------------------------------- queue
    def record_queue_depth(self, depth: int) -> None:
        if depth > self.peak_queue:
            self.peak_queue = int(depth)

    def record_concurrency(self, current: int) -> None:
        if current > self.peak_concurrency:
            self.peak_concurrency = int(current)

    def record_backpressure(self) -> None:
        self.backpressure_events += 1

    # -------------------------------------------------------------- tasks/chain
    def record_task_stats(self, ledger: dict | None = None,
                          scheduler: dict | None = None) -> None:
        """Tapşırıq metrikalarını İKİ AYRI mənbədən sinxronlaşdırır (F-05).

        * `ledger` — `TaskLedger.snapshot()`: NIYYƏT/planlama (nəyi nəzərdən
          keçirdik, nə qədərini növbəyə aldıq, nə qədərini dedup etdik).
        * `scheduler` — `Scheduler.snapshot()` (və ya toplanmış saylar): FAKTİKİ
          İCRA (nə qədəri həqiqətən işçi tərəfindən çalışdı).

        Prinsiplər:
          * `executed` YALNIZ faktiki icradan (scheduler) götürülür — adaptive
            niyyətlər və ya sadəcə `consider()` çağırışları onu ŞİŞİRTMİR.
          * Ledger və scheduler sayları AYRI saxlanılır (`tasks_ledger`,
            `tasks_scheduler`) → iki vəziyyət həmişə ayırd edilir.
          * Scheduler məlumatı yoxdursa, faktiki-icra metrikləri UYDURULMUR —
            `0` yazılır və mənbə `unavailable` kimi işarələnir.
          * Heç bir açar iki mənbədən CƏMLƏNMİR (ikiqat sayma yoxdur).
        """
        led = dict(ledger or {})
        sch = dict(scheduler or {})
        self.tasks_ledger = led
        self.tasks_scheduler = sch
        t = self.tasks
        src = self.tasks_sources

        def put(key: str, value, source: str) -> None:
            t[key] = int(value)
            src[key] = source

        # --- URL / uyğunluq səviyyəli (eyni kollektor, toplama yox) ---
        put("discovered", self.urls_unique, "urls")
        put("eligible", sum(int(v) for v in self.eligible.values()),
            "eligibility")
        put("deferred", sum(int(v) for v in self.deferred.values()),
            "eligibility")

        # --- NIYYƏT / planlama (ledger) ---
        put("considered", led.get("considered", 0), "ledger")
        put("queued", led.get("queued", 0), "ledger")
        put("deduplicated", led.get("deduplicated", 0), "ledger")
        put("retried", led.get("retried", 0), "ledger")
        put("skipped", led.get("skipped", 0), "ledger")
        put("pending", led.get("pending", 0), "ledger")
        # `started` — ledger-səviyyəli "running"-ə keçid (icraya BAŞLAMA).
        put("started", led.get("started", led.get("executed", 0)), "ledger")
        put("partial", led.get("partial", 0), "ledger")
        put("timed_out", led.get("timed_out", 0), "ledger")

        # --- FAKTİKİ İCRA (scheduler) ---
        if sch:
            put("accepted", sch.get("submitted", 0), "scheduler")
            put("executed", sch.get("executed", 0), "scheduler")
            put("rejected", sch.get("rejected_backpressure", 0), "scheduler")
            put("completed", sch.get("completed", 0), "scheduler")
            put("failed", sch.get("failed", 0), "scheduler")
            put("cancelled", sch.get("cancelled", 0), "scheduler")
        else:
            # Scheduler məlumatı YOXDUR: faktiki-icra metrikası UYDURULMUR.
            for key in ("accepted", "executed", "rejected"):
                put(key, 0, "unavailable")
            # Terminal saylar yalnız ledger-dən (icra realm-i DEYİL).
            put("completed", led.get("completed", 0), "ledger")
            put("failed", led.get("failed", 0), "ledger")
            put("cancelled", led.get("cancelled", 0), "ledger")

    def record_chain_stats(self, stats: dict) -> None:
        for key in CHAIN_KEYS:
            if key in stats:
                self.chain[key] = int(stats[key])

    # -------------------------------------------------------------- engine
    def record_engine(self, name: str, **counters) -> None:
        """Mühərrik sayğaclarını TOPLAYIR (input, eligible, skipped, requests...)."""
        bucket = self.engines.setdefault(name, {
            "input_urls": 0, "eligible_urls": 0, "skipped_urls": 0,
            "deferred_urls": 0, "params_processed": 0, "requests": 0,
            "findings": 0, "validated": 0, "duration": 0.0,
        })
        for key, value in counters.items():
            if key == "duration":
                bucket["duration"] = round(bucket["duration"] + float(value), 3)
            else:
                bucket[key] = bucket.get(key, 0) + int(value)

    # --------------------------------------------------------------- snapshot
    def snapshot(self) -> dict:
        return {
            "urls": {
                "raw": self.urls_raw,
                "unique": self.urls_unique,
                "duplicate": self.urls_duplicate,
                "families": self.endpoint_families,
                "by_category": dict(sorted(self.urls_by_category.items())),
            },
            "eligibility": {
                "eligible": dict(sorted(self.eligible.items())),
                "excluded": dict(sorted(self.excluded.items())),
                "deferred": dict(sorted(self.deferred.items())),
                "exclusion_reasons": dict(sorted(self.exclusion_reasons.items())),
            },
            # F-07: deferred → eligible keçidləri (yeni dəlil əsaslı).
            "reconsideration": {
                "promoted": dict(sorted(self.reconsidered.items())),
                "remained_deferred": dict(sorted(self.remained_deferred.items())),
            },
            # Faza 2: cavab metadata-sı ilə təsnifat dəqiqləşdirmələri.
            "response_refinement": {
                "applied": self.refined_applied,
                "refused": self.refined_refused,
            },
            "tasks": dict(sorted(self.tasks.items())),
            # F-05: mənbələr AYRI — niyyət (ledger) vs faktiki icra (scheduler).
            "tasks_ledger": dict(sorted(self.tasks_ledger.items())),
            "tasks_scheduler": dict(sorted(self.tasks_scheduler.items())),
            "tasks_sources": dict(sorted(self.tasks_sources.items())),
            "queue": {
                "peak_queue": self.peak_queue,
                "peak_concurrency": self.peak_concurrency,
                "backpressure_events": self.backpressure_events,
            },
            "chain": dict(sorted(self.chain.items())),
            "engines": {k: dict(v) for k, v in sorted(self.engines.items())},
        }
