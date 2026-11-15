# PHASE 0 — ARCHITECTURE AUDIT (Audit-only)

> Bu sənəd XEzer "Stateful Intelligence & Coverage-Preserving Optimization" direktivinin
> Faza 0 tələbidir. **Kod dəyişikliyi EDİLMƏMİŞDİR** — yalnız yoxlama və qeyd.

---

## 1. Cari vəziyyət (2.1)

| Yoxlama | Nəticə |
|---|---|
| `git branch --show-current` | `main` |
| `git rev-parse HEAD` | `770dafd833eac4a8615aaedf9ebaea4355531f74` ("son dəyişikliklər") |
| §0.2 ilə uyğunluq | **UYĞUNDUR** (direktivdəki commit ilə eyni) |
| `git status --short` | yalnız `?? Untitled-1.md` (bu direktiv faylının özü); başqa dəyişiklik yox |
| `python -m compileall -q qbh main.py` | **təmiz** (exit 0) |
| `python -m ruff check --select E4,E7,E9,F,B,W .` | **All checks passed!** (exit 0) |
| `python -m pytest -q --tb=no` | **1019 yığıldı → 1017 keçdi, 2 skip** (exit 0) |
| Virtual mühit | **`.venv/` YOXDUR** → `python` / `python -m pytest` istifadə olunur |

**Qeyd:** Direktivdəki `.venv/bin/python` yolu Linux üçündür; bu repoda `.venv` yoxdur,
sistem `python` (3.10.11) istifadə olunur. Test sayı (1017 keçdi / 2 skip) §0.2 ilə tam uyğundur.

---

## 2. İnteqrasiya nöqtələri (2.2) — təsdiq

| Yoxlama | Fayl / yer | Nəticə |
|---|---|---|
| STAGE_MAP tamlığı | `qbh/conductor.py:84` | **TƏSDİQ.** 25 mərhələ: `deep_enum, recon, bbot, waymore, dnstwist, gowitness, fingerprint, wafdetect, takeover, vuln, js, content, ferox, api_enum, sqli, xss, ssti, ssrf, jwt, sourcecode, race, cve_intel, library_cve, validation, chain`. Hər biri `prereq/scope/subprocess/network/findings/klass` ilə. |
| Scheduler istifadəsi | `qbh/conductor.py:516` | **TƏSDİQ.** Yalnız `vuln, js, content, ferox` `_run_parallel` ilə `Scheduler`-dən keçir. `Scheduler(` yalnız `conductor.py:395`-də bir dəfə yaradılır. |
| TaskLedger davamlılığı | `qbh/tasks.py` | **TƏSDİQ (RAM-only).** `tasks.py` yalnız `hashlib/dataclasses/datetime` import edir; `db` importu YOXDUR → heç bir SQLite yazısı yoxdur. |
| EventLedger davamlılığı | `qbh/tasks.py` | **TƏSDİQ (RAM-only).** *Düzəliş:* `EventLedger` `chain.py`-də DEYİL, `tasks.py`-dədir (`event_identity` @76, `EventLedger` class ~297). `chain.py` onu import edir. |
| AdaptiveController nəticələri | `qbh/adaptive.py:171` | **TƏSDİQ.** `record_outcome()` mövcuddur; real çağırış `chain.py:405` (`_dispatch_one`) daxilindədir və `conductor._run_chain()` → `ChainPipeline.run()` vasitəsilə tetiklenir (dolayı yolla conductor-dan). |
| URL Intelligence mühərrikləri | `qbh/urlintel.py:501` (`evaluate`) | **TƏSDİQ.** `sqli/xss/ssti/ssrf` → `offensive.candidate_urls`; `jsanalysis/library_cve/param_enum` → `plan_rows(engine=...)`; `content` yalnız refinement produсeri. `api_enum/jwt/api_fuzz/bypass` İSTİFADƏ ETMİR. |
| Scheduler növbə limitləri | `qbh/scheduler.py` | **TƏSDİQ.** Məhdud növbə (`queue_limit`), prioritet (`priority`), ədalət (`fair_key` = host+family), backpressure (`submit()`→`bool`, `rejected`, `submit_with_backpressure`). Lakin **429-əsaslı adaptiv concurrency YOXDUR**. |
| DB sxema | `qbh/db.py:19` | **TƏSDİQ.** `SCHEMA_VERSION = 6`. Cədvəllər: `schema_meta, scans, hosts, urls, findings, evidence, cve_matches, secrets, stage_status, validated` + indekslər. Miqrasiya: `ALTER TABLE ADD COLUMN` + `hosts` yenidən qurulması. |
| Metrikalar split | `qbh/metrics.py:337` | **TƏSDİQ (`record_task_stats`).** `executed` YALNIZ scheduler-dən; ledger (niyyət) vs scheduler (faktiki icra) ayrı saxlanılır (`tasks_ledger`/`tasks_scheduler`, `tasks_sources`). |
| Hesabat sırası | `qbh/conductor.py:697` | **TƏSDİQ.** `finish_scan(status)` (L697) → `generate_report()` (L698). Skan statusu hesabatdan ƏVVƏL yazılır. |
| CLI əlavələri (Faza 3/4) | `main.py` | **YOXDUR.** `--import-har`, `--list-imported`, `--request-graph`, `--test-plan`, `--pending-followups`, `--resume`, `--compare-scans`, `--findings` bayraqları hələ əlavə olunmayıb. |

---

## 3. Boşluqların təsdiqi (2.3)

| # | §0.5-dəki boşluq | Hökm | Dəlil |
|---|---|---|---|
| 1 | TaskLedger/EventLedger/AdaptiveController RAM-only — davamlılıq/çökmə bərpası yoxdur | **CONFIRMED** | `tasks.py` `db` import etmir; üçü də yalnız yaddaşda (dataclass/lists). |
| 2 | URL Intelligence SQLi/XSS/SSTI/SSRF/JS/LibraryCVE/ParamEnum ilə inteqrasiyalı, amma api_enum/content/jwt/api_fuzz/bypass DEYİL | **CONFIRMED** (qismən yenilənib) | Yuxarıdaki §2 cədvəli. *Əlavə:* `content` mühərriki Faza-2 refinement hook-u üçün urlintel-ə yazır, lakin **eligibility** filtri tətbiq etmir. |
| 3 | Yalnız 4 mühərrik mərkəzi Scheduler istifadə edir | **CONFIRMED** | `conductor.py:516-521` (vuln/js/content/ferox); qalan mərhələlər `_run_stage` ilə ardıcıl/öz mexanizmi ilə. |
| 4 | Real-world end-to-end validasiya yoxdur (yalnız loopback) | **CONFIRMED** | `tests/conftest.py` yalnız `127.0.0.1` istifadə edir; xarici hədəf skan artefaktı yoxdur. |
| 5 | Sənədləşmə kodla uyğun deyil (ARCHITECTURE.md 562 test yazır) | **CONFIRMED** | `docs/ARCHITECTURE.md:73`, `docs/TESTING.md:31,63`, `docs/CHANGELOG.md:49` → "562 test"; faktiki 1017. |
| 6 | Request relationship model, auth context model, HAR ingestion yoxdur | **CONFIRMED** | `qbh/ingest/`, `qbh/brain/`, `qbh/brain/auth_state.py` YOXDUR; uyğun CLI bayraqları yoxdur. |

---

## 4. Faza 1 üçün prioritetli siyahı

1. **§3.0 — Deterministik baseline benchmark** (`tests/benchmarks/`): referans `baseline.json`.
   *Əvvəlcə bu* — heç bir optimallaşdırmadan əvvəl ölçmə bazası olmalıdır.
2. **§3.2 — 4-hallı uyğunluq (`unknown`)**: hazırda `evaluate()` yalnız
   `eligible/ineligible/deferred` qaytarır (`urlintel.py:501-591`; `None`=deferred).
   `unknown` ayrı haldır və YOXDUR. Fingerprint olmadıqda test ATILMAMALIDIR.
3. **§3.1 — `URLIdentity` çox-identiklik modeli** (`infra_id/testing_id/param_id/idor_id/auth_id`),
   `task_identity()` geriyə-uyğun genişləndirmə ilə.
4. **§3.3 — `ResponseClassifier`** (403/404/405/500 məhv edilməsin; HEAD≠GET).
   `bypass`-ın `observe_block=False` mexanizmi POZULMAMALIDIR.
5. **§3.4 — Scheduler-də per-host adaptiv concurrency** (429 → host slotlarının azaldılması,
   sağlam cavablarla bərpa). Guardian-ın cooldown/ladder məlumatı TƏKRAR istifadə edilməlidir.
6. **§3.5 — Cavab keşi** (`qbh/cache.py`): `http_policy.py`/`db.py`-də keş YOXDUR.

---

## 5. Asan qazanclar (low-hanging fruit)

- **Sənəd yeniləməsi (boşluq #5):** `docs/ARCHITECTURE.md`, `docs/TESTING.md`,
  `docs/CHANGELOG.md` daxilində "562 test" → faktiki say (1017 keçdi / 2 skip). Kiçik, təhlükəsiz.
- **`unknown` vəziyyətinin kiçik miqyasda telə salınması:** `urlintel.evaluate()`-də
  fingerprint olmadıqda `None`/`deferred` yerinə açıq `unknown` qaytarmaq — izolyasiyalı dəyişiklik.
- **Guardian cooldown → Scheduler backoff:** məlumat artıq mövcuddur
  (`guardian.py` — `EscalationLadder`, `on_block`, `_on_host_success`), yalnız oxunub istifadə olunmalıdır.

---

## 6. Faza 0 qəbul meyarları

- [x] Compile keçir (`compileall` təmiz)
- [x] Lint keçir (`ruff` təmiz)
- [x] Bütün mövcud testlər keçir (1017 keçdi, 2 skip)
- [x] `docs/PHASE0_AUDIT.md` yaradıldı
- [x] Kod dəyişikliyi edilmədi (yalnız audit)
