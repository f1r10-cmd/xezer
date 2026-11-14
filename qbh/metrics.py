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
