<!-- coderabbit-ai-generated:v1 -->

# XEzer — Fazalar 3–8 yekun yoxlama hesabatı

## Ümumi qərar: PARTIAL — v4.0.0 buraxılmayıb

16 noyabr 2026. Fazalar 3–8 ardıcıllıqla implementasiya və regressiya yoxlamasından
keçib. Son lokal dəst **1280 passed**, **85.33% coverage**; benchmark qorunub.
Buna baxmayaraq production-ready/feature-complete iddiası verilmir: external
CLI-lərin daxili path/method/technique sorğularını və cooldown davranışını mövcud
native HTTP sərhədi idarə etmir. Bu, Non-Negotiable §1.2/§1.7/§1.9 üçün açıq
release maneəsidir. Tag yalnız bütün qapılar keçəndə yaradıla bilər; **v4.0.0 yoxdur**.
`main`-ə merge edilməyib. Phase 9 implementasiya edilməyib.

## Hər fazanın qəbul meyarları

| Meyar | Vəziyyət | İşlədilmiş sübut |
|---|---|---|
| 3.1 HAR request/response/timing, JSON/form/multipart, binary reference | PASS | `tests/test_har_import.py`; full suite daxilində |
| 3.1 Dedup, malformed entry report, occurrence/provenance | PASS | Eyni suite: duplicate, malformed content, response preservation |
| 3.2 Additive DB, mövcud state qorunması | PASS | `tests/test_durable_recovery.py`, `tests/test_har_import.py`; schema 12 son vəziyyət |
| 3.3 Graph API, confidence/provenance, chronology dependency deyil | PASS | HAR graph və scan-isolation testləri; E2E captured traffic graph assertions |
| 3.4 Redaction/vault, açar yoxdursa blocked/retryable | PASS | HAR/vault tests; real public sample offline socket guard |
| 3.5–3.6 CLI və sıfır import target trafiki | PASS | HAR CLI tests; E2E import zamanı Guardian request trap |
| 4.1 Bütün 12 classification, confidence/evidence refs | PASS | `tests/test_request_classifier.py` |
| 4.2 Bütün 15 data-only knowledge faylı | PASS | `tests/test_knowledge_base.py` |
| 4.3 Plugin discovery və iki işlək strategy | PASS | `tests/test_strategy_interface.py`, real Chain/Scheduler testi; IDOR active, JWT offline |
| 4.4 ContextBuilder: HAR/graph/auth/URL/finding/schema/fingerprint | PASS | Classifier/context/strategy/planner tests |
| 4.5 İzah edilə bilən planlar və davamlı rejection | PASS | `tests/test_brain_planner.py`, E2E bütün 15 sinifdə reason |
| 5 Status/header/type/JSON/ownership/body/error/redirect müqayisəsi | PASS | `tests/test_diff_engine.py`; ilkin ayrıca DiffEngine coverage 98% |
| 5 Normalization fərqi gizlətmir; timing etibarlılığı | PASS | Volatile/type/presence/ownership və repeated timing testləri |
| 5 Fərq confirmed vulnerability deyil | PASS | DiffResult interpretations/false-positive tests, IDOR negative controls |
| 6 ENV/vault auth, cookie/origin/path/expiry ayrılığı | PASS | `tests/test_auth_state.py` |
| 6 İki fərqli kimliklə planted IDOR, secure/public false positive yoxdur | PASS | Auth full-planner testləri və E2E3/4/5/7 birləşmiş axın |
| 6 Səlahiyyətsiz hesab yaradılmır | PASS | Yalnız fixture daxilində synthetic users; kənar hesab yaradılmayıb |
| 6 Bütün engine-lərdə explicit request restrictions | PARTIAL | Native Authorization/HttpPolicy/Conductor/Chain tests PASS; external subprocess daxili sorğu nəzarəti yoxdur |
| 7 Yeni HAR/auth/finding evidence, əlaqəli hash | PASS | `tests/test_feedback_loop.py`; unrelated evidence hash-i dəyişmir |
| 7 EventLedger dedup, bounded rounds, restart və RoE təkrar yoxlaması | PASS | Feedback/Chain/durable recovery/planner tests |
| 7 Failed/deferred test yalnız dəyişmiş prerequisite ilə təkrarlanır | PASS | Persisted reconsideration və result-history tests |
| 8 Existing JS engine + AST/fallback, route/API/permission/flag | PASS | `tests/test_js_intelligence.py`; unsupported syntax limitation saxlanır |
| 8 Source maps, secret pattern reuse, internal refs/HAR correlation | PASS | Encrypted observation, inline map və real loopback JS/map flow tests |
| 8 Discovered secret xarici servisə avtomatik göndərilmir | PASS | Xarici reference retention və fetch boundary tests |

Graph avtomatik olaraq session continuation və endpoint family infer edir;
auth_flow/parameter_progression açıq graph API ilə əlavə edilə bilər. JS AST
ECMAScript 2017 ilə məhduddur; fallback qeyd olunur. Bütün 15 sinif üçün yeni
executor yaradıldığı iddia edilmir: iki plugin var, qalan mövcud engine-lər qorunur
və missing-plugin planları görünən deferred səbəbi saxlayır.

## Son lokal yoxlamalar

İş qovluğu repository root; Ubuntu 26.04.1, Python 3.14.4, repo `.venv`.
`requirements.txt` daxilində esprima==4.0.1; digər dependency versiyaları
sandbox-un hazırlanmış mühitindən istifadə edir. Yoxlamalar synthetic loopback və
müvəqqəti SQLite üzərindədir; ictimai HAR hostlarına scan göndərilməyib.

| Yoxlama | Faktiki nəticə |
|---|---|
| `.venv/bin/python -m compileall -q qbh main.py` | PASS, exit 0 |
| `.venv/bin/python -m ruff check --select E4,E7,E9,F,B,W .` | PASS, exit 0 |
| Full pytest + `--cov=qbh --cov-report=term-missing --cov-fail-under=70` | **1280 passed in 71.84s**, exit 0, **85.33%** |
| `.venv/bin/python -m pytest tests/e2e -o addopts='' -q --tb=short` | **7 passed in 0.81s**, exit 0 |
| Benchmark `_amain(write=False)` iki dəfə, `compare`, `bench_metrics` equality | PASS, regressions=[]; iki nəticə eyni |
| Session ownership audit, bütün 1280 test | **0 unclosed ClientSession** |
| `git diff --check` | PASS, exit 0 |
| Isolated venv `python -m pip check` | PASS, exit 0 |

Full suite scratch audit plugin-i ilə işlədilib: hər testin yaratdığı sessiyalar
teardown-da yoxlanıb. İlkin audit **20** açıq sessiya tapmışdı (14 fingerprint/WAF,
6 takeover); `make_ctx` fixture-i öz Context-lərini `aclose()` ilə bağlamaqla
səbəb düzəldilib. Son audit heç bir leak qeydi yaratmayıb. CI-da eyni kod standart
pytest ilə ayrıca yoxlanır.

İlkin release full cəhdində **1273 pass / 2 fail** idi. Bunlar category-only
exclusion köhnə gözləntiləri idi; yeni deferred müqaviləsi və uyğun fingerprint
ilə testlər düzəldildi. Məqsədli son pass-lar **82** və **164** testdir.
JWT `alg:none`/`accepted` mətninin server acceptance olmadan confirmed yaratması
düzəldilib; candidate sayı və müşahidə saxlanır. Installer qeyri-sıfır çıxışı
verified saymır; bunu missing/timeout/nonzero regressiyaları yoxlayır.

## Benchmark qorunması

| Metrika | Saxlanmış baseline | Son nəticə |
|---|---:|---:|
| Tentative evidence | 36 | 36 |
| Unikal endpoint | 53 | 53 |
| Endpoint/parametr kombinasiyası | 53 | 53 |
| Eligible qiymətləndirmə | 384 | 384 |
| Faktiki task icrası | 236 | 236 |

`tests/benchmarks/baseline.json` dəyişdirilməyib. Hər fazanın hesabatında eyni
minimumlar qorunub. Benchmark özü bütün external tool-ların real production scan-ı
və ya 36 confirmed zəiflik demək deyil.

## E2E qəbul xəritəsi

| Ssenari | Vəziyyət və sübutun həddi |
|---|---|
| E2E-1 | PARTIAL: real loopback benchmark coverage qorunur; bütün real external alətlərlə tam production scan yoxlanmayıb |
| E2E-2 | PASS: real subprocess kill, CLI resume, completed dedup və interrupted state qorunması |
| E2E-3 | PASS: fixture-dən götürülən real HTTP response-larla HAR, offline import, graph provenance; content parsing ayrıca HAR suite-də |
| E2E-4 | PASS: import→durable feedback; hash/round məhdudiyyətləri feedback suite-də |
| E2E-5 | PASS: user A/B, planted IDOR confirmed, secure counterpart confirmed deyil |
| E2E-6 | PASS: Diff interpretations/false-positive considerations və ownership fərqi; normalization ayrıca Diff suite-də |
| E2E-7 | PARTIAL: 15 sinif reason ilə qiymətləndirilir; bütün imkanların external request səviyyəsində enforcement-i tamam deyil |
| E2E-8 | PASS — istifadəçinin düzəltdiyi müqavilə: harmless permission simulation allowed; destructive=True və forbidden state_changing blocked; target dağıdıcı əməliyyatı icra edilməyib |
| E2E-9 | PASS — məhdud sübut: real CLI full axın missing subprocess ilə tamamlanıb nonempty report yaradıb; tam tool fidelity iddiası yoxdur |
| E2E-10 | PARTIAL: real clean venv, real auto-install, 7/7 required və 11 optional verified; 10 optional çatışmır |

7 pytest case bəzi əlaqəli ssenariləri bir testdə birləşdirir. Ssenari sayı
pytest test sayı kimi göstərilmir.

## Real təcrid olunmuş quraşdırma

`/tmp/xezer-clean-install` ayrıca venv yaradılıb və `pip install -r requirements-dev.txt`
real icra edilib. Go sandbox-da distro paketi ilə ayrıca hazırlanıb; tətbiq installer-i
sudo işlətməyib. Alətlər ayrıca GOBIN/GOPATH/GOCACHE altında quraşdırılıb.
İlk `--dry-run` required tool-lar olmadığı üçün exit 1 verdi. Son düzəldilmiş
`--dry-run` və `--auto-install` **exit 0** verdi; bu yalnız required gate-dir.

`QBH_HTTPX_BIN=/tmp/xezer-install-tools/bin/httpx` Python httpx CLI toqquşmasını
həll etmək üçün mövcud documented override kimi istifadə edildi.

| Doğrulanan alətlər | Versiya |
|---|---|
| subfinder / dnsx / httpx | 2.17.0 / 1.3.1 / 1.12.0 |
| naabu / katana / nuclei / ffuf | 2.7.0 / 1.8.0 / 3.11.1 / 2.1.0 |
| alterx / gau / dalfox | 0.1.0 / 2.2.4 / 2.13.0 |
| schemathesis / semgrep / gowitness / interactsh-server | 4.33.4 / 1.185.0 / 3.2.2 / 1.4.1 |
| jsluice / arjun / git-dumper / waymore / dnstwist | Binary probe keçib; etibarlı versiya çıxarılmayıb |

| Çatışmayan alət | Real nəticə | Manual remediation |
|---|---|---|
| x8 | failed: Cargo yoxdur | Rust/Cargo qurun, `cargo install x8`, Cargo bin-i PATH-a əlavə edin |
| ghauri | pip install exit 1 | Dəstəklənən Python mühitində `python -m pip install ghauri`; əvvəl error çıxışını yoxlayın |
| kr | go install exit 1 | `go install github.com/assetnote/kiterunner/cmd/kr@latest`; build error-u yoxlayın |
| bbot | pip install exit 1 | Dəstəklənən Python mühitində `python -m pip install bbot`; dependency error-u yoxlayın |
| feroxbuster | manual, icra edilməyib | `cargo install feroxbuster` |
| amass | manual, icra edilməyib | `sudo apt install amass` |
| nmap | manual, icra edilməyib | `sudo apt install nmap` |
| sqlmap | manual, icra edilməyib | `sudo apt install sqlmap` |
| sstimap | manual, icra edilməyib | `git clone https://github.com/vladko312/SSTImap`; upstream setup |
| jwt_tool | manual, icra edilməyib | `git clone https://github.com/ticarpi/jwt_tool`; upstream setup |

Uğursuz qurulumun yalnız exit code-u saxlanıb; səbəbin konkret dependency olduğu
iddia edilmir. Siyahı manual tövsiyədir, işlədilmiş əmrlərin nəticəsi deyil.
Alətin binary probe-u target scan fidelity yoxlaması sayılmır.

## Commit və CI sübutları

| Faza | Commit | GitHub CI |
|---|---|---|
| 4 | 14021d7e0e376b048ed84d0fdf415594ae86a68c | [43828104133 — success](https://github.com/f1r10-cmd/xezer/actions/runs/43828104133) |
| 5 | 5aa1ece8afd4ad1caca592f4540674d7ebee5ff4 | [43828896014 — success](https://github.com/f1r10-cmd/xezer/actions/runs/43828896014) |
| 6 | 81d1e0fbe0cc1c9648342b34430e106044f677af | [43832112450 — success](https://github.com/f1r10-cmd/xezer/actions/runs/43832112450) |
| 7 | 52703fd390b6946baa6f90e603cf0ccd36023672 | [43832823558 — success](https://github.com/f1r10-cmd/xezer/actions/runs/43832823558) |
| 8 | efc2cca621f04fae3a73f2f257347a7926750bc2 | [43833413796 — success](https://github.com/f1r10-cmd/xezer/actions/runs/43833413796) |

Son release-hardening diff-i üçün uzaq CI nəticəsi push-dan sonra əlavə ediləcək;
yuxarıdakı tarixi success-lər yeni diff-in CI nəticəsi sayılmır. Yeni matrix:
Python 3.10/3.11/3.12/3.13/3.14, compile, coverage≥70%, iki benchmark, ruff,
gitleaks və loopback smoke. `main`-ə merge istifadəçiyə saxlanır.

## Qalan maneə və tələb olunan qərar

1. External tool-lar üçün request-aware enforcement tələb olunur. Mövcud
   `EgressController.prepare_process` tool/target/DNS yoxlayır, binary-nin daxili
   HTTPS əməliyyatlarını idarə etmir. Native testlərin keçməsi bu zəmanəti vermir.
2. Uyğun mediation olmayan external engine-i path/method məhdudiyyəti olan scope-da
   reason ilə blocked saxlamaq təhlükəsizdir, amma istifadəçinin icazəli imkanları
   daraltmamaq qaydası ilə ziddiyyət yaradır. Bu istisna istifadəçi tərəfindən
   təsdiqlənmədən tətbiq edilməyib. Alternativ hər tool üçün etibarlı request-aware
   adapter/proxy və onun loopback integration suite-inin hazırlanmasıdır.
3. Optional alətlərin hamısının quraşdırılması təsdiqlənməyib. Uğursuzluqlar yuxarıda
   qeyd olunub; heç biri installed kimi təqdim edilmir.

Bu maneələrə görə final commit mesajında “feature-complete/all release gates green”
yazılmır və v4.0.0 tag-i yaradılmır. Bloklanmayan CLI, sənədlər, lokal validation,
benchmark qorunması və CI yenilənməsi tamamlanır.
