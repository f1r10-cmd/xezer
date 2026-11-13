# Arxitektura — QBH v2.1 "Xəzər"

Bu sənəd QBH-ın faktiki implementasiyasını təsvir edir. Burada yalnız
mövcud və yoxlanılmış davranış əks olunur.

## Baxış

QBH asinxron (asyncio) Python platformasıdır. Tək CLI giriş nöqtəsi
(`main.py`) konfiqurasiyanı yükləyir, `Conductor` mühərrikləri orkestrləşdirir,
bütün HTTP trafiki `HttpPolicy` üzərindən keçir və nəticələr SQLite bazasında
saxlanılır.

```
main.py  (CLI)
   └── Conductor            — mərhələlərin orkestrləşdirilməsi
         ├── Context        — mühərriklərə ötürülən paylaşılan vəziyyət
         ├── Guardian       — scope + rate + cooldown/circuit-breaker + audit
         │     └── HttpPolicy — vahid HTTP sorğu siyasəti
         ├── Engines[]      — recon / vuln / api / cve / validation
         ├── installer.py   — tool aşkarlama + quraşdırma
         ├── db.py          — SQLite qatı
         └── report/generator.py — Markdown + JSON hesabat
```

## Qovluq strukturu

```
qbh-xazar/
├── main.py                     # CLI giriş nöqtəsi
├── requirements.txt
├── pytest.ini
├── config/
│   ├── examples/               # git-də saxlanılan təhlükəsiz nümunələr
│   │   ├── example_local.yaml  # yalnız 127.0.0.1 (loopback nümunə)
│   │   └── targets.example.yaml# real scope şablonu
│   ├── targets.yaml            # yerli real scope (git-ignore)
│   ├── proxies.txt             # (git-ignore)
│   └── strategies/*.yaml       # fingerprint strategiyaları
├── qbh/
│   ├── config.py               # YAML yükləmə + profillər/RoE + ciddi validasiya
│   ├── scope.py                # ScopeEnforcer, normalize_host, extract_host
│   ├── authorization.py        # vahid scope/RoE qərar mərkəzi (fail-closed)
│   ├── http_policy.py          # HttpPolicy, TargetBlocked, parse_retry_after
│   ├── payloads.py             # WAF/filter bypass matrisi (path/header/verb)
│   ├── chain.py                # ChainPipeline — tapıntı zəncirləmə
│   ├── context.py              # Context dataclass
│   ├── results.py              # EngineResult, StageResult
│   ├── redact.py               # secret maskalama
│   ├── db.py                   # SQLite sxem (v4) + miqrasiya + dedup + evidence
│   ├── installer.py            # tool aşkarlama/quraşdırma
│   ├── conductor.py            # orkestrasiya
│   ├── antiblock/
│   │   ├── guardian.py         # blok/cooldown + adaptiv strategiya nəzarəti
│   │   ├── identity.py         # configurable identiklik + rotasiya audit
│   │   ├── proxymanager.py     # off / single / rotate
│   │   └── ua_rotator.py       # UA hovuzu (rotasiya profilə görə)
│   ├── engines/                # bütün mühərriklər
│   ├── adapters/base.py        # shell-siz subprocess icrası
│   └── report/                 # generator + HackerOne exporters
├── tests/                      # pytest dəsti (242 test)
└── docs/
```

## Əsas komponentlər

### 1. CLI (`main.py`)

- `argparse` əsaslı; `build_parser()` / `run(args)` / `main(argv)`.
- `Config.load(args.config)` ilə konfiq yükləyir (bu, əvvəlki buqlu
  `Config(...)` çağırışını əvəz edir).
- Çıxış kodları: `0` uğur, `1` mərhələ xətası / pipeline abort,
  `2` istifadə və ya konfiq xətası, `130` Ctrl+C.
- `KeyboardInterrupt` → yarımçıq nəticələr saxlanılır, hesabat yenə yazılır.

### 2. Conductor (`qbh/conductor.py`)

- `resolve_targets()` — CLI `--targets` və konfiq hədəflərini
  `Config.authorize_target` ilə süzür (fail-closed). Heç bir icazəli hədəf
  qalmazsa `PipelineAbort`.
- `_run_stage(stage, target, factory)` — mərhələni `factory` (callable →
  korutin) vasitəsilə icra edir. `factory` sayəsində əvvəlki mərhələ uğursuz
  olsa lazımsız korutin yaradılmır. `_run_stage` **heç vaxt `None`
  qaytarmır** — həmişə `StageResult`.
- Tool yoxlaması YALNIZ BİR DƏFƏ (`_ensure_tools`, `_tools_checked` bayrağı).
- `_pipeline(mode, body)` — `finally` blokunda hesabat yaradılır və skan
  `done` kimi bağlanır; `CancelledError` halında da.
- `failed_stages` — uğursuz mərhələlərin siyahısı (çıxış kodu üçün).

### 3. Context (`qbh/context.py`)

Mühərriklərə ötürülən paylaşılan vəziyyət: `cfg`, `args`, `guardian`,
`scan_id`, `rate`, `limits`, `scope`, `active_fuzz`, `race_fixture`,
`in_scope(host)` köməkçisi.

### 4. Nəticə kontraktları (`qbh/results.py`)

- `EngineResult(stage, ok, skipped, findings, hosts, urls, warnings, errors,
  data)` + `warn()` / `fail()` / `skip()`.
- `StageResult(stage, status, started_at, completed_at, duration, target,
  findings_count, errors, warnings, data)` + `to_dict()`.
- `status` dəyərləri: `ok` · `failed` · `skipped` · `cancelled`.

### 5. Mühərriklər (`qbh/engines/`)

Hər mühərrik `(ctx)` qəbul edir və `run(...) -> EngineResult` təmin edir.
Bütün HTTP əməliyyatları Guardian/HttpPolicy üzərindən keçir; subprocess
icrası `adapters/base.run_process` vasitəsilə (`shell=False`) aparılır.
Subprocess hədəfləri əvvəlcə `qbh/egress.EgressController`-dən keçir
(scope validasiyası + DNS pinning + proses qrupu SIGKILL + audit).

### 6. Baza (`qbh/db.py`)

- Açıq sxem + `SCHEMA_VERSION` (hazırda 4) + `_migrate()` ilə təhlükəsiz
  sütun əlavələri (mövcud data silinmir).
- `init_db()` sırası: **cədvəllər → `_migrate` → indekslər**. İndekslər
  `fingerprint` sütunundan asılıdır və köhnə bazalarda bu sütun sonradan
  əlavə olunur.
- UNIQUE məhdudiyyətləri → təkrar tapıntıların qarşısı.
- `insert_finding()` `ON CONFLICT(fingerprint) DO UPDATE ... RETURNING id`
  istifadə edir → təkrar halda **həqiqi** `id` qaytarır.

### 7. Hesabat (`qbh/report/generator.py`)

- Markdown + JSON çıxışı (`reports/qbh_<zaman>.md|.json`).
- Secret-lər `redact()` ilə maskalanır; etibarsız məzmun Markdown/HTML üçün
  escape olunur.
- `verified`/`confirmed` tapıntılar `potential` olanlardan ayrı göstərilir.
- Mərhələ xətaları və atlanan addımlar hesabata daxil edilir; bəzi
  mühərriklər uğursuz olsa da hesabat yazılır.

## Məlumat axını (full mode)

```
resolve_targets() → deep_enum → recon → fingerprint
  → [vuln | js | content | ferox] (paralel)
  → api_enum → api_fuzz → param_enum → race → cve_intel → validation
  → generate_report() → finish_scan()
```
