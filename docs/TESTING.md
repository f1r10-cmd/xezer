# Testinq — QBH v2.1 "Xəzər"

## İşə salma

```bash
# Virtual mühit (bir dəfə)
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install pytest pytest-asyncio

# Bütün testlər
.venv/bin/python -m pytest -q

# Konkret fayl / test
.venv/bin/python -m pytest tests/test_scope.py -q
.venv/bin/python -m pytest tests/test_db.py::TestFindings -q
```

Konfiqurasiya: [`pytest.ini`](../pytest.ini) — `asyncio_mode = auto`,
`testpaths = tests`.

## Prinsiplər

- **Xarici şəbəkəyə müraciət YOXDUR.** Bütün HTTP testləri
  `127.0.0.1`-də qalxan lokal aiohttp fixture üzərində aparılır.
- Xarici alətlər (nuclei, ffuf, subfinder ...) testlərdə çağırılmır; mühərrik
  kontraktları boş baza və scope-xarici girişlərlə yoxlanılır.
- Heç bir test real hədəfə skan etmir.
- Nəticələr uydurulmur — yalnız real icra əsasında.

## Dəst (151 test)

| Fayl | Test sayı | Əhatə |
|---|---|---|
| `tests/test_scope.py` | 40 | exact / wildcard / kök domen / out-of-scope / redirect escape / malformed / IP avtorizasiyası / IDNA / fail-closed / suffix confusion / CIDR |
| `tests/test_config.py` | 25 | valid konfiq, fayl xətaları, scope validasiyası, limitlər, xəbərdarlıqlar, `example_local.yaml` |
| `tests/test_engines.py` | 33 | mühərrik kontraktı (`EngineResult`), boş baza davranışı, race/api_fuzz təhlükəsizlik qapıları, scope sərhədi |
| `tests/test_db.py` | 20 | sxem, miqrasiya (data itkisi yoxdur), hosts/urls/findings, dedup regressiyası, CVE, secret, validated, scans/stages, parametrləşdirilmiş SQL |
| `tests/test_http_policy.py` | 18 | Retry-After parse, sorğudan əvvəl scope, 403 cooldown, 429 hörmət, circuit breaker, redirect scope, body truncation, rate limit, concurrency, cancellation |
| `tests/test_redact.py` | 15 | maskalama (AWS/Google/GitHub/Slack/JWT/parol/api_key/Authorization/private key/webhook) |

Ümumi: **151 test, hamısı keçir.**

## Fixture-lər (`tests/conftest.py`)

| Fixture | Təyinat |
|---|---|
| `tmp_db` | İzolyasiyalı müvəqqəti SQLite bazası (`db.DB_PATH` monkeypatch) |
| `write_config` / `load_config` | YAML konfiq yazan/yükləyən köməkçi |
| `loopback_config` | Yalnız `127.0.0.1`-ə icazə verən konfiq |
| `local_server` | Lokal aiohttp fixture (`/`, `/403`, `/429`, `/escape`, `/inside`, `/final`, `/big`, `/500`, `/slow`, `/count`, `/conc`) |
| `make_ctx` | Real `Context` + `Guardian` + `HttpPolicy` (şəbəkəsiz) |

## Test kateqoriyaları

### Unit
- Konfiqurasiya validasiyası, scope enforcement, rate limiting, circuit
  breaker, identiklik siyasəti, baza əməliyyatları, tapıntı normalizasiyası,
  hesabat generasiyası, mühərrik nəticə kontraktları.

### İnteqrasiya
- Conductor boru xətti, baza davamlılığı, tool aşkarlama, subprocess xəta
  idarəsi, HTTP sorğu siyasəti.

### Təhlükəsizlik
- Scope bypass cəhdləri, redirect escape, command injection (subprocess
  `shell=False`), malformed URL, gizli məlumatların maskalanması.

### Regressiya
- `test_db.py::TestFindings::test_dedup_returns_original_id_after_other_inserts`
  — `insert_finding` təkrar halda həqiqi `id` qaytarmalıdır.
- `test_db.py::TestMigration` — `fingerprint` sütunu olmayan köhnə baza
  miqrasiya olunmalı və indeks yaradıla bilməlidir (data itkisi olmadan).

## Nəticə formatı

`pytest.ini` `-q` rejimini default edir. Uğurlu icra:

```
........................................................................ [ 47%]
........................................................................ [ 95%]
.......                                                                  [100%]
```

## Yeni test əlavə edərkən

1. Xarici şəbəkəyə çıxma — lazımdırsa `local_server` fixture-indən istifadə et.
2. Xarici alət çağırışı lazımdırsa, `adapters.base.run_process`-i monkeypatch et.
3. İzolyasiya üçün `tmp_db` və `make_ctx` fixture-lərindən istifadə et.
4. Hər yeni düzəliş üçün regressiya testi yaz.
