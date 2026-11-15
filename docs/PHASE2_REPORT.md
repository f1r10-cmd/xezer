# PHASE 2 — DURABLE EXECUTION AND RECOVERY

> Bu sənəd XEzer "Stateful Intelligence & Coverage-Preserving Optimization"
> direktivinin **Faza 2** (§4.1–§4.4) nəticələridir. Bütün ölçmələr yalnız
> `127.0.0.1` loopback fixture-i üzərində aparılmışdır — heç bir xarici şəbəkə
> trafiki YOXDUR. Fəlsəfə qorunub: **qeyri-müəyyənlik → TEST ET (skip etmə),
> nəticə PRODUCE et.** Heç bir optimizasiya əhatəni (coverage) və ya tapıntı
> sayını AZALTMAYIB.

---

## 1. Xülasə

| Sahə | Vəziyyət |
|---|---|
| §4.1 Mövcud persistence auditi | **PASS** |
| §4.2 Davamlı saxlama (yeni cədvəllər + SCHEMA_VERSION bump) | **PASS** |
| §4.3 Bərpa davranışı (`--resume`, dedup, scope re-verify) | **PASS** |
| §4.4 Testlər (real proses kill + bərpa) | **PASS (35/35)** |
| Phase 2 acceptance checklist | **PASS (6/6)** |

**Nəticə:** Bütün Faza 2 tələbləri yerinə yetirildi. Bərpa mexanizmi `completed`
işi TƏKRAR İCRA ETMİR, çökmüş (`running`) işi yenidən növbəyə alır, scope-u
YENİDƏN yoxlayır və skan izolyasiyasını qoruyur.

---

## 2. §4.1 — Mövcud persistence auditi

Faza 0/1 vəziyyətində bütün icra vəziyyəti YALNIZ RAM-da saxlanılırdı:

| Komponent | Fayl | Faza 2-dən əvvəl |
|---|---|---|
| `TaskLedger` (task identity, həyat dövrü, attempts) | `qbh/tasks.py` | RAM-only (`self.tasks` dict) |
| `EventLedger` (zəncir hadisə idempotentliyi) | `qbh/tasks.py` | RAM-only (`self.events` dict) |
| `AdaptiveController` gözləyən follow-up-lar | `qbh/adaptive.py` | RAM-only (`self.followups`) |
| Retry/deferred vəziyyəti | `qbh/tasks.py` | RAM-only |

Nəticə: proses çökdükdə (SIGKILL/TerminateProcess) bütün icra vəziyyəti
İTİRİLİRDİ — `--resume` mümkün deyildi və yarımçıq skan ən başından təkrarlanmalı
olurdu (əhatə itkisi riski).

---

## 3. §4.2 — Davamlı saxlama (durable persistence)

### 3.1 Yeni cədvəllər (`qbh/db.py`) — ƏLAVƏDİ (additive)

`SCHEMA_VERSION` **6 → 7** bump edildi. Yeni cədvəllər mövcud sxemin YANINDA
yaradılır; in-memory dəftərləri ƏVƏZ ETMİR — baza yalnız bərpa üçün yazılır.

```sql
CREATE TABLE IF NOT EXISTS task_state (
  task_id TEXT PRIMARY KEY, scan_id INTEGER NOT NULL,
  identity_hash TEXT NOT NULL, status TEXT NOT NULL,
  engine TEXT NOT NULL DEFAULT '', endpoint TEXT, method TEXT, params TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  attempts INTEGER DEFAULT 0, last_error TEXT, result_data TEXT,
  FOREIGN KEY (scan_id) REFERENCES scans(id));

CREATE TABLE IF NOT EXISTS event_state (
  event_id TEXT PRIMARY KEY, scan_id INTEGER NOT NULL,
  event_type TEXT NOT NULL DEFAULT '', payload TEXT, processed_at TEXT,
  followup_task_ids TEXT, FOREIGN KEY (scan_id) REFERENCES scans(id));

CREATE TABLE IF NOT EXISTS followup_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
  trigger_finding_id INTEGER, proposed_action TEXT NOT NULL,
  prerequisite_hash TEXT, status TEXT DEFAULT 'pending',
  created_at TEXT NOT NULL, executed_at TEXT,
  FOREIGN KEY (scan_id) REFERENCES scans(id));
```

İndekslər: `idx_task_state_scan`, `idx_task_state_status`,
`idx_event_state_scan`, `idx_followup_scan`.

Yeni API (`qbh/db.py`): `upsert_task_state`, `load_task_state`,
`upsert_event_state`, `load_event_state`, `insert_followup`,
`set_followup_status`, `load_followups`, `running_scans`, `get_scan`,
`latest_running_scan`, həmçinin `TASK_STATES` / `FOLLOWUP_STATUSES`
sabitləri. Dəstəkləyici mühit dəyişəni: **`QBH_DB_PATH`** (baza yolunu
override edir — test/bərpa üçün).

### 3.2 `TaskLedger` davamlılığı (`qbh/tasks.py`)

- `TaskRecord`-a `result_data: dict` sahəsi əlavə olundu. Bu, mərhələnin
  nəticə datasını (`StageResult.data`) bərpada QORUYUR ki, aşağı mərhələlər
  (məs. `deep_enum` → `recon`) İTİRİLMİŞ kəşfi TƏKRAR ETMƏDƏN əhatəni
  azaltmasın.
- `persist_to_db(identity=None, *, last_error="", result_data=None)` — hər
  state keçidindən sonra çağırılır (in-memory əməliyyatı ƏVƏZ ETMİR).
- `restore(records)` — davamlı vəziyyəti RAM dəftərinə yükləyir:
  `running` → `cancelled` (retryable, "bərpa: proses çökdü → yenidən növbəyə");
  `queued`/`cancelled`/`failed`/`timed_out`/`partial` → yenidən növbəyə;
  `completed`/`skipped`/digər terminal → OLDUĞU KİMİ qalır (TƏKRAR İCRA YOX).
  `attempts` / `reason` tarixçəsi QORUNUR.

### 3.3 `EventLedger` davamlılığı (`qbh/tasks.py`)

- `persist_to_db()` — qəbul edilmiş hər zəncir hadisəsi (`event_id`,
  `event_type`, `payload`, `followup_task_ids`) yazılır.
- `restore(events)` — hadisə idempotentliyini bərpa edir (təkrar emal YOX).

### 3.4 `AdaptiveController` davamlılığı (`qbh/adaptive.py`)

- Konstruktora `store=None` əlavə olundu (mövcud çağırışlar pozulmur).
- `_persist_followup(identity, actions, *, status)` — gözləyən davam testləri
  `followup_queue`-ya yazılır; status `pending`→`executed`/`skipped`/`failed`
  kimi yenilənir.
- `restore_followups(records)` — bərpadan sonra gözləyən davam testlərini
  yenidən qeydiyyata alır.

### 3.5 `DurableStore` adapteri (`qbh/recovery.py`)

SQLite-ı `TaskLedger`/`EventLedger`/`AdaptiveController` üçün vahid interfeysə
bağlayır: `persist_task`, `persist_event`, `persist_followup`,
`mark_followup`. Beləliklə dəftərlər DB-yə birbaşa asılı deyil.

---

## 4. §4.3 — Bərpa davranışı

### 4.1 `qbh/recovery.py`

- `task_records(scan_id)` / `event_records(scan_id)` /
  `followup_records(scan_id, status="pending")` — davamlı vəziyyəti oxuyur.
- `build_resume_plan(scan_id, *, program="", mode="", authorize=None)`:
  - `ResumePlan` qurur (`requeue` = terminal olmayan, `terminal` = bitmiş).
  - `authorize` verilərsə hər tapşırığın host-u **YENİDƏN yoxlanılır**;
    scope-dan kənar hədəf AÇIQ `skipped` edilir → icra OLUNMUR (fail-closed).
- `pending_scans()` / `latest_pending_scan()` — çökmüş (`running`) skanları tapır.
- `resume_mode(scan_id)` — rejimi davamlı `scans` cədvəlindən oxuyur.
- `_result_data(raw)` — `task_state.result_data` JSON sətrini təhlükəsiz
  `dict`-ə çevirir (xətalı/boş → `{}`).

### 4.2 `Conductor` bərpası (`qbh/conductor.py`)

- `_mode_body(mode)` — yeni skan və bərpa üçün ORTAQ icra gövdəsi.
- `_restore_durable()` — dəftərləri bərpa edir və scope-u yenidən yoxlayır:
  `task_ledger.restore` + `event_ledger.restore` + `adaptive.restore_followups`.
- `resume(scan_id=None)` — `scan_id=None` → ən son `running` skan; YENİ skan
  sətri YARADILMIR (eyni `scan_id` davam edir). Scope `resolve_targets()` ilə
  YENİDƏN yoxlanılır (bərpa avtorizasiyanı KEÇMİR).

### 4.3 Mərhələ dedup-ı (`_run_stage` ledger-əsaslı)

`completed` tapşırığın TƏKRAR İCRA OLUNMAMASI `TaskLedger.consider()` ilə
təmin olunur. Sahiblik (ownership) iki yolla müəyyən edilir:

- **Paralel yol** — `_submit_stage` tapşırığı `Scheduler`-ə verir; Scheduler
  `task.run()`-dan ƏVVƏL dəftərdə `running` işarələyir → `_run_stage` ikinci
  dəfə `consider` ETMİR (tək həqiqət mənbəyi), yalnız `result_data`-nı saxlayır.
- **Birbaşa yol** — boru xətləri (`run_recon`/`run_vuln`) `_run_stage`-i birbaşa
  çağırır → qərar `consider` ilə ALINIR; `create=False` olduqda mərhələ
  `_record_dedup` ilə AÇIQ `skipped`/`ok` kimi qeyd olunur (səssizcə İTMİR).

`_persist_stage(identity, sr, owned)` mərhələnin `result_data`-sını dəftərə
yazır; `owned=True` olduqda həyat dövrünü də işarələyir.

---

## 5. §4.4 — Testlər

`tests/test_durable_recovery.py` — **35 test** (hamısı KEÇİR). Sinfə görə:

| Sinf | Nə yoxlanır |
|---|---|
| `TestSchemaPhase2` | v7 cədvəlləri, indekslər, geriyə uyğun miqrasiya |
| `TestDurableStore` | `DurableStore` CRUD (task/event/followup) |
| `TestTaskLedgerDurable` | `persist_to_db` + `restore` (running→cancelled, terminal qorunur, attempts qorunur, `result_data` bərpası) |
| `TestEventLedgerDurable` | hadisə davamlılığı + idempotent bərpa |
| `TestAdaptiveDurable` | gözləyən follow-up-ların davamlılığı |
| `TestResumePlan` | `build_resume_plan` (requeue/terminal scope re-verify, scan izolyasiyası) |
| `TestCrashRecovery` | **real `subprocess` proses kill** → `--resume` pending bərpa, `completed` TƏKRAR İCRA OLUNMUR, attempts QORUNUR |
| `TestPendingFollowupsCli` | `--pending-followups` CLI |

Ən vacib test: `TestCrashRecovery::test_kill_then_resume_recovers_state` —
mid-scan `proc.kill()` (real SIGKILL/TerminateProcess), sonra `--resume` ilə
bərpa; `idempotentlik: artıq uğurla tamamlanıb` işarəsi `completed`
mərhələnin təkrarlanmadığını sübut edir.

---

## 6. CLI əlavələri (§14)

| Flag | Təsvir |
|---|---|
| `--resume [SCAN_ID]` | yarımçıq (çökmüş) skanı davam etdirir; ID verilməzsə ən son `running` skan |
| `--pending-followups` | gözləyən davam testlərini (`followup_queue`) göstərir |
| `--scan-id SCAN_ID` | əməliyyatı konkret skana tətbiq edir |

---

## 7. Phase 2 acceptance checklist (§4)

| # | Tələb | Vəziyyət | Sübut |
|---|---|---|---|
| 1 | Yeni cədvəllər + miqrasiya (SCHEMA_VERSION bump, data qorunur) | **PASS** | `tests/test_scan_isolation.py::TestMigrationV5` (v4→v7, data/id-lər qorunur); `TestSchemaPhase2` |
| 2 | `TaskLedger`/`EventLedger`/`Adaptive` DB-yə yazır | **PASS** | `TestTaskLedgerDurable`, `TestEventLedgerDurable`, `TestAdaptiveDurable` |
| 3 | `--resume` yarımçıq skanlar üçün işləyir | **PASS** | `TestCrashRecovery`, `TestPendingFollowupsCli` |
| 4 | Crash recovery REAL proses kill ilə test olunub | **PASS** | `TestCrashRecovery::test_kill_then_resume_recovers_state` |
| 5 | Bütün mövcud testlər keçir | **PASS** | `1165 passed, 2 skipped` |
| 6 | Miqrasiya geriyə uyğundur (köhnə DB data itkisi olmadan açılır) | **PASS** | `TestMigrationV5` (id/data qorunur) |

---

## 8. Doğrulama (verification)

| Yoxlama | Nəticə |
|---|---|
| `python -m pytest -q` | **1165 passed, 2 skipped** (Faza 2: +35 test) |
| `python -m ruff check --select E4,E7,E9,F,B,W qbh main.py tests` | **All checks passed!** |
| `python -m compileall -q qbh main.py` | **OK** |
| `python main.py --help` | `--resume`, `--pending-followups`, `--scan-id` görünür |

---

## 9. Əhatə-nin qorunması (§1.16)

- `result_data` davamlı saxlanması aşağı mərhələlərin bərpada İTİRİLMİŞ kəşfi
  TƏKRAR ETMƏSİNİ təmin edir → əhatə ARTIRILIR, azaldılmır.
- `_record_dedup` mərhələni heç vaxt SƏSSİZCƏ atmır — AÇIQ `skipped`/`ok` kimi
  yazır (səbəblə) ki, hesabatda/metrikalarda görünsün.
- Bərpa scope-u KEÇMİR (§4.3) — fail-closed avtorizasiya qorunur.
- Heç bir `BYPASS`/`evasion` yoxdur; yalnız pacing/dedup/prioritet.
- **Heç bir commit/push edilməyib** (§1.16).

---

## 10. Dəyişdirilmiş fayllar

| Fayl | Dəyişiklik |
|---|---|
| `qbh/db.py` | v7 sxem (`task_state`, `event_state`, `followup_queue`) + indekslər + API |
| `qbh/tasks.py` | `TaskRecord.result_data`; `TaskLedger.persist_to_db`/`restore`; `EventLedger.persist_to_db`/`restore` |
| `qbh/adaptive.py` | `store=` + `_persist_followup` + `restore_followups` |
| `qbh/recovery.py` | `DurableStore`, `build_resume_plan`, `ResumePlan`, `pending_scans`, `latest_pending_scan`, `resume_mode` |
| `qbh/conductor.py` | `_mode_body`, `_restore_durable`, `resume`, `_stage_identity`, ledger-əsaslı `_run_stage`/`_persist_stage`/`_record_dedup` |
| `main.py` | `--resume`, `--pending-followups`, `--scan-id` |
| `tests/test_durable_recovery.py` | **YENİ** — 35 test |
| `tests/test_lifecycle.py` | sxem versiyası testi → v7 |
| `tests/test_scan_isolation.py` | miqrasiya testi → cari versiya + Faza 2 cədvəlləri |
