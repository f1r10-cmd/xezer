# Testinq — QBH v3.0 "Xəzər"

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

## Dəst (562 test)

| Fayl | Test sayı | Əhatə |
|---|---|---|
| `tests/test_scope.py` | 40 | exact / wildcard / kök domen / out-of-scope / redirect escape / malformed / IP avtorizasiyası / IDNA / fail-closed / suffix confusion / CIDR |
| `tests/test_conductor.py` | 43 | Conductor boru xətti, `resolve_targets`, mərhələ icrası, `_ensure_tools`, `failed_stages`, hesabat bağlanması (confirmed→reported keçidi) |
| `tests/test_engines.py` | 35 | mühərrik kontraktı (`EngineResult`), boş baza davranışı, race/api_fuzz təhlükəsizlik qapıları, scope sərhədi, vuln template profili |
| `tests/test_installer.py` | 29 | tool aşkarlama / quraşdırma, versiya yoxlaması, platforma qolları |
| `tests/test_config.py` | 26 | valid konfiq, fayl xətaları, scope validasiyası, limitlər, xəbərdarlıqlar, profillər/RoE, `example_local.yaml` |
| `tests/test_chain.py` | 25 | trigger-lər, emit qapısı, discovery, lokal icra (`bypass`/`confirm`/`boost_confidence`), param/openapi addımları |
| `tests/test_authorization.py` | 24 | vahid scope/RoE qərar mərkəzi, `authorize_url`, ləğv/deadline |
| `tests/test_vault.py` | 24 | şifrəli secret vault (Fernet), açar idarəsi, `secret_replay` engine, RoE qapısı |
| `tests/test_egress.py` | 23 | subprocess egress: proses hədəfləri, target faylı, DNS pinning, proses qrupu SIGKILL, fail-closed |
| `tests/test_generator.py` | 22 | Markdown/JSON hesabat generasiyası, escape, mərhələ xətaları |
| `tests/test_http_policy.py` | 22 | Retry-After parse, sorğudan əvvəl scope, 403 cooldown, 429 hörmət, circuit breaker, redirect scope, body truncation, rate limit, concurrency, cancellation |
| `tests/test_api_fuzz.py` | 21 | OpenAPI `effective_servers`, server validasiyası, engine scope qapısı |
| `tests/test_offensive_engines.py` | 20 | hücum mühərrikləri (param/endpoint/hidden param) kontrakt + təhlükəsizlik qapıları |
| `tests/test_db.py` | 21 | sxem, miqrasiya (data itkisi yoxdur), hosts/urls/findings, dedup regressiyası, CVE, secret, validated, scans/stages, parametrləşdirilmiş SQL |
| `tests/test_lifecycle.py` | 18 | tapıntı həyat dövrü, `evidence`, status normalizasiyası, miqrasiya |
| `tests/test_oob.py` | 14 | out-of-band callback qeydiyyatı/korrelyasiya |
| `tests/test_scan_isolation.py` | 15 | skan izolyasiyası, `LEGACY_SCAN_ID`, engine sorğu yolları, v3→v4 miqrasiyası |
| `tests/test_redact.py` | 15 | maskalama (AWS/Google/GitHub/Slack/JWT/parol/api_key/Authorization/private key/webhook) |
| `tests/test_takeover.py` | 12 | CNAME takeover detektoru (dangling CNAME + provayder imzaları + təsdiq) |
| `tests/test_bypass.py` | 12 | WAF/filter bypass matrisi (path/header/verb), settled hədəfin yenidən skan olunmaması |
| `tests/test_exporters.py` | 8 | MD/JSON/HackerOne export forması, severity xəritəsi, secret maskalama, `exclude rejected`, `min_severity` |
| `tests/test_rotation.py` | 7 | rotasiya determinizmi (UA/başlıq/proxy), audit, `on_block=False`, validasiya |
| `tests/test_tool_missing.py` | 7 | çatışmayan alətin dürüst raportlaşdırılması (mərhələ `skipped`), uydurma tapıntı yoxdur |
| `tests/test_smoke.py` | 6 | başdan-sona minimal skan |
| `tests/test_hunter.py` | 4 | Hunter orkestratoru (`--mode hunt`) |
| `tests/test_e2e_hunt.py` | 2 | loopback "zəiflikli tətbiq" üzərində `--mode hunt` tam dövrəti (recon→…→hesabat) |
| `tests/test_stealth.py` | 67 | stealth stack, WAF aşkarlama/adaptasiya planı, humanizer (UA/başlıq seti/jitter), `build_plan`, adaptiv alət parametrləri |

Ümumi: **562 test (561 keçir, 1 POSIX-only skip).**

## Fixture-lər (`tests/conftest.py`)

| Fixture | Təyinat |
|---|---|
| `tmp_db` | İzolyasiyalı müvəqqəti SQLite bazası (`db.DB_PATH` monkeypatch) |
| `write_config` / `load_config` | YAML konfiq yazan/yükləyən köməkçi |
| `loopback_config` | Yalnız `127.0.0.1`-ə icazə verən konfiq |
| `local_server` | Lokal aiohttp fixture (`/`, `/403`, `/429`, `/escape`, `/inside`, `/final`, `/big`, `/500`, `/slow`, `/count`, `/conc`) |
| `vuln_app` | Loopback "zəiflikli tətbiq" (JWT/`/admin` XFF/yalançı secret/openapi) — `test_e2e_hunt` üçün |
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
