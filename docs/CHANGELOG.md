# Dəyişikliklər — QBH "Xəzər"

Bu sənəd audit, hardening və offensive genişləndirmə işləri zamanı edilmiş
əhəmiyyətli arxitektura və davranış dəyişikliklərini qeyd edir.

## [3.0.1] — Faza 4: bitirmə və cilalama (feature-complete)

v3.0-ın funksional imkanları genişləndirilmədi — mövcud kod real bug bounty
axınında uçdan-uca işləyəcək səviyyəyə gətirildi. **Yeni xarici imkan yoxdur**;
sənəd/kod uyğunluğu, dürüst raportlaşdırma və zəncir həyat dövrünün bağlanması
əsas işdir.

### 4.1 Sənəd unifikasiyası

- Bütün sənədlər faktiki v3.0 davranışına uyğunlaşdırıldı; köhnə "evasion
  qadağandır" və oxşar bayat ifadələr təmizləndi.

### 4.2 "Tool missing" dürüst raportlaşdırma

- Çatışmayan alət artıq uydurma tapıntı yaratmır — aid olduğu mərhələ `skipped`
  kimi qeyd olunur və hesabatda **dürüst** göstərilir. Recon rate konfiqdən
  düzgün bağlanır.

### 4.3 Uçdan-uca inteqrasiya testi

- `tests/test_e2e_hunt.py` + `conftest.vuln_app` — loopback "zəiflikli tətbiq"
  üzərində `--mode hunt` tam dövrəti (recon→…→hesabat). Heç bir xarici trafik yox.
- `wafdetect` şəbəkə xətasında (`ClientError`/`OSError`) mərhələni "failed"
  etmək yerinə dürüst `warn` verir.

### 4.4 Zəncir keyfiyyəti — tapıntı həyat dövrünün bağlanması

- Hesabat (H1 ixracı daxil) yazıldıqdan SONRA təsdiqlənmiş tapıntılar
  `reported` işarələnir: `candidate → confirmed → reported` tamamlanır.
- Mühərriklər yekunlaşmış (`confirmed`/`reported`) hədəfləri **YENİDƏN skan
  etmir** — `docs/STEALTH.md` prinsipi indi `bypass` mühərrikində tətbiq olunur.
- **Bug:** `bypass._record` `insert_finding` çağırışında `scan_id` ötürmürdü →
  tapıntılar `LEGACY_SCAN_ID (0)` altına düşür və cari skanda görünmürdü.
  Düzəldildi və regressiya testi ilə qorundu.

### 4.5 CI və sənəd

- CI `--cov-fail-under=70` (coverage floor); cari coverage **77%**.
- README-yə "Məlum məhdudiyyətlər" bölməsi; TESTING.md sayları yeniləndi.

### Versiya və baza

- `qbh.__version__` → `3.0.1`; `SCHEMA_VERSION` `6` olaraq qalır.
- Test dəsti **562 test** (561 keçir, 1 POSIX-only skip).

## [3.0] — Faza 3: secret vault, takeover, real zəncir, hunter, stealth

Faza 2-nin offensive əsası üzərində qurulub. Bütün yeni imkanlar **eyni
toxunulmaz sərhəd** altındadır: avtorizasiya scope-u (fail-closed) və
`program_rules.forbidden` (RoE). Qadağan olunan addım icra olunmur, atlanır
və audit loquna yazılır.

### 3.1 State-dəyişən əməliyyat qapısı

- `--allow-state-changing` bayrağı və `Authorization`-a `state_changing`
  əməliyyatı əlavə olundu. Profil/RoE bunu qadağan edərsə, state-dəyişən
  addımlar fail-closed şəkildə atlanır.

### 3.2 Şifrəli secret vault + `secret_replay`

- `qbh/vault.py` — JS-də tapılan xam secret-lər **Fernet** (`cryptography`)
  ilə şifrələnərək saxlanılır; açar konfiqdən (`vault`) və ya mühit
  dəyişənindən götürülür.
- `qbh/engines/secret_replay.py` — tapılan secret-i hədəfə qarşı yoxlayır;
  RoE `secret_replay` qadağan edirsə **atla + audit** (trafik göndərilmir).
- Hesabat/loq üçün extradan `redact`/`mask_value` istifadə olunur — xam
  secret heç vaxt açıq yazılmır.

### 3.3 CNAME takeover detektoru

- `qbh/engines/takeover.py` — `dnspython` ilə dangling CNAME aşkarlayır,
  zəif provayder imzaları ilə uyğunlaşdırır və təsdiq mərhələsi ilə
  yanlış-pozitivi azaldır.

### 3.4 Zəncir addımlarının real icrası

- `qbh/chain.py` — əvvəl `delegated` kimi yalnız planlaşdırılan
  `param_fuzz`, `hidden_param_detect`, `schemathesis_fuzz` addımları indi
  `ChainPipeline` daxilində **birbaşa** və RoE qapılarından keçməklə icra
  olunur.

### 3.5 Hunter orkestratoru

- `qbh/hunter.py` + `--mode hunt` — avtomatik zəncir: subdomain → canlı
  yoxlama → fingerprint → JS → secret/param → fuzz → CVE → confirm → PoC →
  hesabat. 401/403 hallarında bypass matrisi; yüksək dəyərli endpoint-lər
  (admin/login/upload) üçün dərin zəncirlər.

### 3.6 Stealth & low-detection (adaptiv)

- Yeni `qbh/stealth/humanize.py` (`Humanizer`) — real mobil+masaüstü UA
  hovuzu, brauzer başlıq setləri (`Sec-Fetch-*`, `Accept-Language`),
  təsadüfi jitter (0.5–3 s).
- Yeni `qbh/stealth/policy.py` (`StealthPlan`, `build_plan`) — WAF
  aşkarlamasını **tək qərara** çevirir və real alət parametrlərinə bağlayır.
- `StealthStack.plan()` və audit qeydi (`stealth_plan`).
- **Adaptiv qaydalar:** WAF var → rate ≤ 3 rps, concurrency ≤ 5, UA rotasiyası
  ON, geniş template istisnası (`-exclude-tags`); WAF yox → ≤ 10 rps;
  `waf_adapt=False` → dəyişmir (səbəb auditdə).
- Mühərriklər plana qoşuldu: `nuclei` (`-rl`/`-c`/`-H`), `ffuf`
  (`-rate`/`-t`), `feroxbuster` (`--rate-limit`/`-t`), `httpx`
  (`-rate-limit`), `naabu` (`-rate`).
- Sənəd: `docs/STEALTH.md` (A→F workflow, adaptiv cədvəl, humanization, alət
  bayrağı dürüst qeydləri).

### Versiya və baza

- `qbh.__version__` → `3.0.0`; `SCHEMA_VERSION` → `6`.
- Test dəsti **550 test** (549 keçir, 1 POSIX-only skip); `tests/test_vault.py`,
  `tests/test_takeover.py`, `tests/test_hunter.py`, `tests/test_stealth.py`
  əlavə olundu.

## [2.2] — Offensive bug bounty maksimallaşdırma

Fəlsəfə dəyişdi: **"topla, sonra süz" → "tap, sonra təsdiqlə"**.
**Yeganə toxunulmaz sərhəd — avtorizasiya scope-u.** Scope daxilində əvvəl
qadağan olan texnikalar indi icazəlidir.

### İcazəli (əvvəl qadağan idi)

- Aktiv fuzzinq (Schemathesis, state-dəyişən) — profil default-u **ON**;
  `--no-active-fuzz` ilə söndürülür. Proqram qaydası həmişə qalib gəlir.
- Nuclei intrusiv/exploit template-ləri — yalnız `aggressive` profildə;
  zərərli kateqoriyalar (`dos`, `brute-force`, `creds-stuffing`) həmişə xaric.
- İdentiklik/UA/başlıq/proxy rotasiyası (`rotation`) — legitim OPSEC, audit olunur.
- WAF/filter bypass matrisi (path/header/verb) — 401/403-da `bypass` engine.
- Adaptiv blok strategiyası (`block_strategy`) — `respect | rotate |
  backoff_then_rotate | escalate_bypass`.
- Agressiv redirect izləmə (`max_redirects` profilə görə 20-yə qədər).
- CVE təsdiqi PoC-a qədər (`confirm` engine).

### Yeni konfiqurasiya bölmələri (`qbh/config.py`)

- `aggressiveness` (`passive | normal | aggressive`, default `aggressive`) —
  rate/concurrency/redirect/rotation/blok default-larını təyin edir.
- `program_rules` — `forbidden` siyahısı (`active_fuzz`, `intrusive_templates`,
  `bypass`, `cve_poc`, `secret_replay`, `param_fuzz`, `race`),
  `allow_wildcard_expansion`, `max_requests_per_second`.
- `rotation` — `enabled`, `ua`, `headers`, `proxy`, `on_block`.
- `block_strategy` — `http_429`, `http_403`.
- `chain` — `enabled`, `max_depth`, `max_tasks`.

### Zəncirləmə (`qbh/chain.py`)

- Yeni `ChainPipeline`: kəşfləri növbəti addıma bağlayır (subdomain → canlı
  yoxlama → fingerprint/JS; JS → endpoint/secret; param → fuzz; OpenAPI →
  schemathesis; CVE → confirm; 401/403 → bypass; nuclei medium+ →
  `boost_confidence`). Hər addım `ctx.authorization`-dan keçir; qadağan olunan
  addım atlanır və audit olunur.

### Tapıntı həyat dövrü və sübut (`qbh/db.py`)

- **Breaking:** `SCHEMA_VERSION = 3`. Statuslar yenidən adlandırıldı:
  `potential → candidate`, `verified → confirmed`, `false-positive → rejected`;
  köhnə dəyərlər `normalize_status` ilə avtomatik çevrilir.
- Yeni `evidence` cədvəli (`http_response | marker | callback | data | note`)
  və `confidence` sahəsi; `db.upsert_host`/`insert_finding`/`set_finding_status`/
  `add_evidence` API-ləri.

### Hesabat (`qbh/report/`)

- `report/exporters.py` — **HackerOne** formatı (`reports/qbh_<ts>.h1.json`):
  severity → `severity_rating`, CVSS balı, CWE təklifi, remediasiya, confidence.
- `report/generator.py` — MD + JSON + H1; rotasiya auditini hesabata daxil edir;
  secret-lər `redact` ilə maskalanır.

### HTTP / Guardian (`qbh/http_policy.py`, `qbh/antiblock/`)

- `HttpPolicy` 403/429-da `block_strategy`-yə görə rotate/backoff/escalate qərarı
  verir; `TargetBlocked(suggest_bypass=True)` `escalate_bypass` üçün.
- `Guardian`/`Identity` — rotasiya (`ua`/`headers`/`proxy`) audit loqu ilə.
- Bypass engine xam probe (`observe_block=False`) göndərir.

### CLI (`main.py`)

- Yeni bayraqlar: `--aggressiveness`, `--no-active-fuzz`.
- `--proxy` `off|single` (OPSEC rejimi). `--active-fuzz` profil default-u ON.
- Banner `v2.2`; profil/rate/concurrency loqda göstərilir.

### Testlər / CI

- Test dəsti **242 test**-ə çatdı; `tests/test_bypass.py`, `tests/test_chain.py`,
  `tests/test_lifecycle.py`, `tests/test_rotation.py` əlavə olundu.
- `requirements-dev.txt`, `.github/workflows/ci.yml` (lint + test matrix +
  secret-scan), `.gitleaks.toml` əlavə olundu.
- Ruff (`E4,E7,E9,F,B,W`) təmiz; bütün 11 lint xətası düzəldildi.

### Sənədləşdirmə

- Yeni: `docs/OFFENSIVE_PLAYBOOK.md`, `docs/REMEDIATION_REPORT.md`,
  `docs/SECURITY_VERIFICATION.md`.
- `README.md` v2.2 davranışına uyğun yeniləndi (köhnə "evasion qadağandır"
  ifadələri silindi).

## [2.1] — Hardening və funksional tamamlama

### Təhlükəsizlik (BREAKING)

- **Scope enforcement mərkəzləşdirildi** (`qbh/scope.py`).
  `ScopeEnforcer` fail-closed işləyir; boş/xətalı scope heç bir hədəfə icazə
  vermir. Suffix confusion, wildcard sui-istifadəsi, malformed hostname,
  rəqəmsal TLD, tək-etiketli ad və IDNA halları yoxlanılır. `deny`
  (`out_of_scope`) `allow`-dan üstündür.
- **Redirect escape qarşısı alındı.** Redirect-lər `allow_redirects=False` ilə
  özümüz idarə edilir; hər addım `resolve_redirect` vasitəsilə scope
  yoxlanılır.
- **`--targets` avtorizasiyanı keçə bilmir.** Bütün CLI hədəfləri
  `Config.authorize_target` ilə süzülür.
- **Identiklik evasion TAMAMİLƏ silindi:**
  - MAC rotasiyası silindi,
  - IP rotasiyası silindi,
  - UA rotasiyası (blok aşma) silindi — indi hər hosta sabit UA,
  - proxy rotasiyası silindi (`--proxy` yalnız `off|single`),
  - "credit" əsaslı sürət artırma sistemi silindi,
  - 403/429 artıq evasion siqnalı deyil → **cooldown + circuit breaker**.
- **Cloudflare/CDN origin-IP bypass modulu (`qbh/cfp/`) SİLİNDİ.**
- **Non-destructive siyasət:** race yalnız lokal fixture üzərində, API fuzz
  yalnız `--active-fuzz` ilə (GET-only), nuclei yalnız təhlükəsiz
  template-lərlə.
- **Subprocess təhlükəsizliyi:** bütün alət çağırışları `shell=False` ilə.

### Core arxitektura

- **`qbh/conductor.py`** — `_safe()` (nəticə qaytarmayan, xətanı udan metod)
  `_run_stage(stage, target, factory)` ilə əvəz olundu. `_run_stage` həmişə
  `StageResult` qaytarır (`ok`/`failed`/`skipped`/`cancelled`), müddət və
  status izləyir. `factory` sayəsində lazımsız korutin yaradılmır. Tool
  aşkarlanması yalnız bir dəfə aparılır. Hesabat `finally` blokunda bəzi
  mərhələlər uğursuz olsa da yazılır. Ctrl+C halında yarımçıq nəticələr
  saxlanılır.
- **`qbh/results.py`** — `EngineResult` və `StageResult` kontraktları
  (`stage_name`, `status`, `started_at`, `completed_at`, `duration`,
  `findings_count`, `errors`, `warnings`).
- **`main.py`** — yenidən yazıldı:
  - Bug: `Config(args.config)` → düzgün `Config.load(args.config)`.
  - Çıxış kodları (0/1/2/130), Ctrl+C idarəsi, yeni bayraqlar
    (`--dry-run`, `--active-fuzz`, `--race-fixture`, `--race-count`,
    `--race-concurrency`).
  - `--proxy` choices `off|single` (əvvəlki `rotate` silindi).

### Baza (`qbh/db.py`)

- **Bug (miqrasiya sırası):** `init_db()` indeksləri `fingerprint` sütunu
  əlavə olunmadan ƏVVƏL yaratmağa çalışırdı →
  `sqlite3.OperationalError: no such column: fingerprint`. Sxem
  `SCHEMA_TABLES` + `SCHEMA_INDEXES`-ə bölündü; sıra: cədvəllər → `_migrate`
  → indekslər.
- **Bug (dedup id):** `insert_finding()` təkrar halda `cur.lastrowid` ilə
  səhv `id` qaytarırdı. `ON CONFLICT(fingerprint) DO UPDATE ... RETURNING id`
  ilə düzəldildi.
- Sxem versiyası (`SCHEMA_VERSION = 2`), UNIQUE məhdudiyyətləri, indekslər,
  WAL, parametrləşdirilmiş SQL və vahid ISO-8601 UTC zaman formatı.

### Hesabat (`qbh/report/generator.py`)

- **Bug:** JSON çıxışında redaction yerinə yetirilmirdi
  (`[self_redacted for self_redacted in kept]`). Başlıq, təsvir, sübut və
  `curl_repro` üçün real `redact()` tətbiq edildi.
- Markdown/HTML escape, `verified`/`confirmed` və `potential` ayrımı,
  mərhələ xətaları/atlanan addımlar və məhdudiyyətlər bölməsi.

### Konfiqurasiya (`qbh/config.py`)

- Ciddi validasiya: YAML strukturu, scope qaydaları, rəqəmsal limitlər.
- Boş scope qəbul edilmir. Naməlum açarlar və silinmiş evasion açarları
  (`rotate_levels`, `credits`) barədə xəbərdarlıq.
- Yeni nümunə: `config/example_local.yaml` (yalnız `127.0.0.1`).

### Quraşdırıcı (`qbh/installer.py`)

- Tool aşkarlama və quraşdırma ayrıldı; dry-run rejimi.
- `go` mövcudluğu/versiyası yoxlanılır; quraşdırma çıxış kodları nəzərə
  alınır; **hər quraşdırmadan sonra binari yenidən yoxlanılır**.
- Avtomatik `sudo`, shell profili və PATH dəyişikliyi YOXDUR.
- Manual tool-lar üçün yalnız tövsiyə. Nəticə hesabatı (ad, versiya,
  məcburi/istəyə bağlı, status, xəta, manual tövsiyə).

### Mühərriklər

- `deep_enum` — dedup, normalizasiya, maksimum limit, hər nəticənin scope
  yoxlaması, mənbə (provenance) qeydi.
- `recon` — CF origin-IP bypass silindi; nəticələr scope-dan keçir.
- `race` — dağıdıcı "blast" silindi; yalnız lokal loopback fixture, sabit
  say, sərt concurrency.
- `api_fuzz` — yalnız `--active-fuzz`, GET-only.
- `cve_intel` — `match_type` (`confirmed`/`possible`), mənbə atribusiyası,
  keş, timeout.
- `validation` — sübut yoxlaması, confidence, false-positive sinfi;
  heuristika "confirmed" kimi təqdim olunmur.

### Testlər

- Yeni pytest dəsti: **151 test** (scope 40, config 25, engines 33, db 20,
  http_policy 18, redact 15). Bütün testlər xarici şəbəkəyə çıxmır.
- `pytest.ini` və `tests/conftest.py` (izolyasiyalı baza + lokal HTTP
  fixture).

### Python 3.14 uyğunluğu

- `aiohttp 3.14`-də `ClientResponse.get_encoding()` stream oxunmuş gövdə
  üçün `RuntimeError` atır. `HttpPolicy._read_body` bunu tutub UTF-8
  fallback istifadə edir.

### Sənədləşdirmə

- `README.md` faktiki davranışa uyğun yenidən yazıldı (köhnə evasion
  iddiaları silindi).
- Yeni: `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/TESTING.md`,
  `docs/CHANGELOG.md`, `docs/AUDIT_REPORT.md`.
