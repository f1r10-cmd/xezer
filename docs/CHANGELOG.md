# Dəyişikliklər — QBH v2.1 "Xəzər"

Bu sənəd audit və hardening işləri zamanı edilmiş əhəmiyyətli arxitektura və
davranış dəyişikliklərini qeyd edir.

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
