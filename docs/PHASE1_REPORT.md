# PHASE 1 — BASELINE, INTELLIGENT NORMALIZATION, AND COVERAGE-PRESERVING OPTIMIZATION

> Bu sənəd XEzer "Stateful Intelligence & Coverage-Preserving Optimization" direktivinin
> **Faza 1** (§3.0–§3.6) nəticələridir. Bütün ölçmələr yalnız `127.0.0.1` loopback
> fixture-i üzərində aparılmışdır — heç bir xarici şəbəkə trafiki YOXDUR.
> Fəlsəfə qorunub: **qeyri-müəyyənlik → TEST ET (skip etmə), nəticə PRODUCE et.**

---

## 1. Xülasə

| Sahə | Vəziyyət |
|---|---|
| §3.0 Deterministik baseline benchmark | **PASS** |
| §3.1 Çoxsəviyyəli URL identity | **PASS** |
| §3.2 4-hallı uyğunluq (eligible/ineligible/deferred/unknown) | **PASS** |
| §3.3 ResponseClassifier (403/404/405/500 saxlanır) | **PASS** |
| §3.4 Adaptiv per-host concurrency | **PASS** |
| §3.5 Zəkalı cavab keşi + invalidation | **PASS** |
| §3.6 Qəbul meyarları (acceptance criteria) | **PASS (11/11)** |

**Nəticə:** Bütün Faza 1 tələbləri yerinə yetirildi. Heç bir optimizasiya əhatəni
(coverage) və ya tapıntı sayını AZALTMAYIB — `regressions: []`.

---

## 2. Baseline vs After (əhatə və tapıntı müqayisəsi)

Ölçmə: `tests/benchmarks/run_baseline.py` (deterministik sintetik yük, 12×10 nümunə,
8 worker, global limit 8, per-host limit 4). Referans: `tests/benchmarks/baseline.json`.

| Metrika | Baseline | After | Fərq |
|---|---|---|---|
| unique_endpoints | 53 | 53 | **SAME** |
| unique_endpoint_param_combos | 53 | 53 | **SAME** |
| eligible_total | 384 | 384 | **SAME** |
| executed | 236 | 236 | **SAME** |
| evidence_records (tapıntılar) | 36 | 36 | **SAME** |
| findings_by_severity | `{medium: 36}` | `{medium: 36}` | **SAME** |
| failed_tasks | 0 | 0 | **SAME** |
| skipped_tasks | 612 | 612 | **SAME** |
| deferred_tasks | 324 | 324 | **SAME** |
| total_http_requests | 236 | 236 | **SAME** |
| concurrency_peak | 4 | 4 | **SAME** |
| total_duration (s) | 0.0738 | 0.0726 | ~SAME |

**Regressiya yoxdur** (`compare()["regressions"] == []`) — heç bir mühərrikin `executed`
sayı azalmadı. Optimizasiya əhatəni SİNƏQ EDİLMƏDƏN həyata keçirildi (§1.16 qadağasına uyğun).

---

## 3. Edilən dəyişikliklər

### §3.0 — Deterministik baseline benchmark

- **Yaradıldı:** `tests/benchmarks/run_baseline.py` — loopback aiohttp fixture üzərində
  sintetik skan; nəticəni `baseline.json`-a yazır və `compare()` ilə əhatə/tapıntı
  reqressiyasını yoxlayır.
- **Yaradıldı:** `tests/benchmarks/baseline.json` (referans nəticə).
- **Yaradıldı:** `tests/test_benchmark_baseline.py` — (a) təkrarlanabilirlik (iki dəfə
  işlədildikdə eyni `bench_metrics`), (b) saxlanılan baseline-a qarşı reqressiyasız olma.

### §3.1 — Çoxsəviyyəli URL identity

- **Dəyişdirildi:** `qbh/urlintel.py` — `IDENTITY_LEVELS = ("infra", "testing",
  "param", "idor", "auth")`, `URLIdentity` dataclass (`get`, `reason`,
  `preserves_original`, `as_dict`) və `url_identity(url, *, method, auth_context)`.
  - `infra` yalnız host səviyyəsindədir (metod fərqi ona təsir etmir).
  - Rəqəmsal ID/UUID/HASH seqmentləri `_object_segments` ilə çıxarılır → `idor`
    səviyyəsi obyekt kimliyini AYIRIR, `infra` isə birləşdirir.
  - `normalize_url`/`normalize_path`/`normalize_query` **dəyişməyib**.
- **Dəyişdirildi:** `qbh/tasks.py` — `task_identity(...)` geriyə uyğun genişləndirildi
  (`identity_level`/`identity` verilmədikdə açar ƏVVƏLKİ kimidir).
- **Test:** `tests/test_url_identity.py` (23 test) — metod fərqi, rəqəmsal ID, parametr,
  auth identity, orijinalın qorunması və legacy `task_identity` regressiya qoruyucusu.

### §3.2 — 4-hallı uyğunluq (eligibility)

- **Dəyişdirildi:** `qbh/urlintel.py` — `STATUS_ELIGIBLE/INELIGIBLE/DEFERRED/UNKNOWN`,
  `Fingerprint` dataclass (`technologies`, `complete`, `source`) və
  `compute_eligibility(ep, engine, *, fingerprint=None)`.
  - Natamam fingerprint → `unknown` (test edilir, ATILMIR; səbəb "UNKNOWN..." ilə başlayır).
  - Bütöv fingerprint texnologiyanı İNKAR edərsə → `ineligible` (səbəblə).
  - `evaluate()` **dəyişməyib** (geriyə uyğun).
- **Test:** `tests/test_eligibility_states.py` (28 test) — fingerprint=None üçün
  `evaluate` ilə eynilik, unknown-un ineligible sayılmaması, fingerprint gəlişi ilə
  həll, statik-resurs qərarının YUMŞALDILMAMASI.

### §3.3 — ResponseClassifier

- **Yaradıldı:** `qbh/response_classifier.py` — `ResponseClass` + `ResponseClassifier`.
  - 403 → `auth_required` (+ `suggests_bypass`), 404 → `soft_not_found` (prioritet > 0),
    405 → `method_mismatch` (+ `try_methods`, `Allow` başlığından), 500 →
    `server_error` (prioritet yüksək), 429 → `rate_limited` (testable=False → Guardian-a
    buraxılır). HEAD heç vaxt GET-ə bərabər sayılmır.
  - **Guardian ƏVƏZ EDİLMƏDİ** — Guardian rate/block idarəsini saxlayır, ResponseClassifier
    yalnız test-əhəmiyyətini qiymətləndirir.
  - Content-Type testability-ni dəyişmir → **bypass/evasion qapısı YOXDUR** (§1.4ə uyğun).
  - `observe_block=False` mexanizmi pozulmadı (mövcud testlər keçir).
- **Test:** `tests/test_response_classifier.py` (20 test).

### §3.4 — Adaptiv per-host concurrency

- **Dəyişdirildi:** `qbh/scheduler.py` — `HostLimit` sinfi (ceiling/limit, async
  `acquire`/`release`, `throttle` = yarıya endir, `recover` = +1 ceiling-ə qədər) və
  `Scheduler.observe(host, status, *, retry_after=None)`.
  - 429 → yalnız həmin host üçün limit azaldılır + qısa cooldown.
  - Ardıcıl sağlam (2xx/3xx) cavablar → limit tədricən bərpa olunur.
  - Cooldown bitməmiş recover OLUNMUR; planlaşdırıcı HEÇ VAXT gözləmir (Retry-After
    `HttpPolicy`-də hörmət olunur, planlaşdırıcı onu OVERRIDE ETMİR).
  - Guardian-ın blok/cooldown məlumatı REUSE edilir (`guardian.halted` → limit 1).
    Dublikat vəziyyət saxlanılmır.
  - Retry storm yoxdur — `TaskLedger.max_attempts` qüvvədədir.
  - `snapshot()`-a `host_limits`, `host_throttles`, `host_recoveries` əlavə olundu.
- **Test:** `tests/test_adaptive_scheduling.py` (16 test) — throttle/recover primitivi,
  429-un yalnız həmin hosta təsiri, Retry-After hörməti, Guardian re-use, retry storm
  olmaması və geriyə uyğunluq.

### §3.5 — Zəkalı cavab keşi

- **Yaradıldı:** `qbh/cache.py` — `CacheManager`, `CacheEntry`, `cache_key(...)`.
  - Açar: `(target, endpoint, method, params, auth_context, test_strategy,
    strategy_version, fingerprint_state)` → SHA-256[:32] (deterministik).
  - Keş YALNIZ cavab METADATA-sını saxlayır: `status`, `headers`, `size`,
    gövdənin ilk `DEFAULT_BODY_HEAD=2048` baytı, `content_type`; tam gövdə YOX.
  - Etibarsızlıq: fingerprint dəyişikliyi (`invalidate_fingerprint`), strategiya
    versiyası dəyişikliyi (`set_strategy_version`/`invalidate_strategy`), auth konteksti
    dəyişikliyi (`invalidate_auth`), TTL bitməsi (`prune`/`lookup`).
  - **TARİXİ TAPINTILAR VƏ DƏLİLLƏR HEÇ VAXT SİLİNMİR** — `findings` keşdən AYRI
    saxlanılır; `prune()` və `invalidate*()` YALNIZ cavab metadata-sına toxunur.
- **Dəyişdirildi:** `qbh/http_policy.py` — `HttpPolicy(..., cache=None)` və
  `request(..., cache_meta=None)`. Keş scope yoxlamasından SONRA, `acquire`-dən ƏVVƏL
  yoxlanır (yalnız GET); cavab 403/429 olmadıqda keşə yazılır.
  Keş/`cache_meta` verilmədikdə davranış ƏVVƏLKİ kimidir (geriyə uyğun).
- **Test:** `tests/test_cache.py` (24 test) — HIT/MISS, yalnız-metadata saxlanması,
  TTL, fingerprint/versiya/auth invalidation, **tapıntıların keş müddəti bitəndə
  SİLİNMƏMƏSİ**, scope-un keşdən ÜSTÜN olması, POST-un keşlənməməsi və geriyə uyğunluq.

---

## 4. §3.6 Qəbul meyarları (acceptance criteria)

| # | Meyar | Vəziyyət | Sübut |
|---|---|---|---|
| 1 | `baseline.json` mövcud və təkrarlanabilir | **PASS** | `test_benchmark_baseline.py::test_reproducible` (iki icra eyni `bench_metrics`) |
| 2 | URL identity səviyyələri; mövcud dedup dəyişməyib | **PASS** | `test_url_identity.py` (23) + mövcud `test_tasks.py` keçir |
| 3 | 4-hallı uyğunluq | **PASS** | `test_eligibility_states.py` (28) |
| 4 | ResponseClassifier 403/404/405/500-ü atmır | **PASS** | `test_response_classifier.py` (20) |
| 5 | Per-host adaptiv concurrency | **PASS** | `test_adaptive_scheduling.py` (16) |
| 6 | Düzgün invalidation-lı cavab keşi | **PASS** | `test_cache.py` (24) |
| 7 | Bütün mövcud testlər keçir | **PASS** | `1130 passed, 2 skipped` (0 fail) |
| 8 | Tapıntı sayı baseline-dan AŞAĞI deyil | **PASS** | 36 → 36 (SAME) |
| 9 | Endpoint əhatəsi baseline-dan AŞAĞI deyil | **PASS** | 53 → 53 (SAME) |
| 10 | Lint və compile keçir | **PASS** | ruff `All checks passed!`; compileall exit 0 |
| 11 | Yeni funksionallıq üçün yeni testlər | **PASS** | 6 yeni test faylı, **+113 test** |
| 12 | Əhatə səssizcə azaldılmayıb (§1.16) | **PASS** | `compare()["regressions"] == []` |

---

## 5. Doğrulama icrası

| Addım | Əmr | Nəticə |
|---|---|---|
| Lint | `python -m ruff check qbh tests --select E4,E7,E9,F,B,W` | **All checks passed!** |
| Compile | `python -m compileall -q qbh tests` | **exit 0** |
| Testlər | `python -m pytest` | **1130 passed, 2 skipped** (227 s) |
| Baseline | `run_baseline.compare(baseline.json, cari)` | **regressions: []** |

Test sayı: baseline 1017 keçən → **1130 keçən** (**+113 yeni test**), 2 skip dəyişməyib.

---

## 6. Geriyə uyğunluq və qadağalara uyğunluq

- **BYPASS/evasion yoxdur** (§1.4): ResponseClassifier yalnız test-əhəmiyyətini
  qiymətləndirir; Content-Type testability-ni dəyişmir; keş yalnız TƏKRAR trafikini azaldır.
- **Secret sızması yoxdur**: keş yalnız metadata saxlayır; auth konteksti açarın
  komponentidir, dəyəri log-a yazılmır.
- **Dağıdıcı əməliyyat yoxdur** (§1.10); yalnız `127.0.0.1` fixture (§1.11).
- **Commit/push EDİLMƏYİB** (§1.16).
- **Geriyə uyğunluq:** `evaluate()`, `normalize_*`, `task_identity` (identitiesiz çağırış),
  `HttpPolicy` (keşsiz çağırış) — hamısı ƏVVƏLKİ davranışı qoruyur; mövcud testlər keçir.

---

## 7. Faza 1 — Status

**TAMAMLANDI (PASS).** Direktiv §16-ya uyğun olaraq **STOP** — növbəti fazaya
(PHASE 2 — Durable Execution and Recovery) keçməzdən əvvəl istifadəçi təsdiqi gözlənilir.
