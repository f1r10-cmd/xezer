# Remediation Report — QBH Xəzər v2.1 → v2.2

**Tarix:** 2026-11-12
**Mühit:** Kali Linux x86_64 · Python 3.14.8 · SQLite · aiohttp
**Əhatə:** `/home/kali/Desktop/cf-hunter/qbh-xazar/`

Bu hesabat **yalnız real, yoxlanılmış** dəyişiklikləri əks etdirir. Heç bir
nəticə uydurulmamışdır; yerinə yetirilməmiş işlər açıq şəkildə göstərilir.

---

## 1. Kontekst

v2.1 təhlükəsizlik baxımından möhkəm idi, lakin **offensive** baxımdan
həddindən artıq məhdudlaşdırılmışdı (bax: `docs/OFFENSIVE_BASELINE.md`).
v2.2-nin məqsədi: **scope daxilində maksimum tapıntı** çıxarmaq — zəncirləmə
pipeline, aktiv testlər, adaptiv blok idarəsi, rotasiya və bounty-ready
hesabat.

Yeganə toxunulmaz sərhəd: **avtorizasiya scope-u**.

---

## 2. A: v2.1-in offensive məhdudiyyətləri → v2.2 həlləri

| # | v2.1 məhdudiyyəti | v2.2 həlli | Fayl(lar) | Status |
|---|---|---|---|---|
| A1 | Aktiv fuzz default **bağlı** (`--active-fuzz`) | Aggressiveness profilləri; `aggressive`/`normal` profildə `active_fuzz=true` | `config.py`, `conductor.py` | ✅ FIXED |
| A2 | Vahid authorization yox idi; scope əsasən `cfg.in_scope` | Vahid `ctx.authorization.authorize_url()` + RoE + deadline/cancel | `authorization.py`, `context.py` | ✅ FIXED |
| A3 | Kəşflər testə çevrilmirdi (JS-secret, param, CVE, 403) | Zəncirləmə pipeline (`TRIGGERS` + `ACTION_EXEC`) | `chain.py` | ⚠️ PARTIAL (bax §3) |
| A4 | Tapıntı statusu yalnız `potential/verified/false-positive` | `candidate→confirmed→rejected→reported` lifecycle + `evidence` cədvəli | `db.py`, `chain.py` | ✅ FIXED |
| A5 | Blokda yalnız cooldown ("əyləc pedalı") | Adaptiv `Guardian` + `block_strategy` (respect/rotate/backoff_then_rotate/escalate_bypass) | `antiblock/guardian.py`, `http_policy.py` | ✅ FIXED |
| A6 | Kimlik sabit idi (rotasiya silinmişdi) | Configurable UA/başlıq/proxy rotasiyası + audit | `antiblock/identity.py`, `config.py` | ✅ FIXED |
| A7 | Bypass texnikaları yox idi | WAF/filter bypass payload matrisi + `BypassEngine` | `payloads.py`, `engines/bypass.py` | ✅ FIXED |
| A8 | CVE uyğunluğu təsdiqlənmirdi | `ConfirmEngine` (imza/versiya əsaslı decisive yoxlama) | `engines/confirm.py` | ✅ FIXED |
| A9 | HackerOne/JSON export yox idi | Markdown + JSON + HackerOne export | `report/exporters.py`, `report/generator.py` | ✅ FIXED |
| A10 | Intrusive Nuclei template-ləri default xaric | `intrusive_templates` profil açarı (aggressive-də ✓) | `engines/vuln.py`, `config.py` | ✅ FIXED |
| A11 | Wildcard subdomain auto-expansion yox idi | `allow_wildcard_expansion` (configurable) | `authorization.py`, `config.py` | ✅ FIXED |
| A12 | `evidence` ayrı struktur deyildi | `evidence` cədvəli (`http_response/marker/callback/data/note`) | `db.py` | ✅ FIXED |

---

## 3. B: v2.2 işi zamanı aşkarlanan defektlər və düzəlişlər

| # | Defekt | Fayl | Ciddilik | Düzəliş | Regressiya testi |
|---|---|---|---|---|---|
| B1 | Bypass mühərriki 403-ü görə bilmirdi: `HttpPolicy` 403-ü `record()` edib hostu cooldown-a salır və `TargetBlocked` atırdı → matris heç vaxt sınanmırdı | `http_policy.py`, `engines/bypass.py` | Yüksək | `request()`-a `observe_block: bool = True` parametri; bypass probe sorğuları `observe_block=False` göndərir (xam status, cooldown yox) | `tests/test_bypass.py::test_successful_bypass_is_confirmed` |
| B2 | **Yalançı bypass**: path variantları (`#/403`, `/403/%2e%2e/`) **yarl**-ın URL normallaşdırmasından sonra kökə (`/`) çökür və 200 cavabı "bypass" kimi qeyd olunurdu | `payloads.py` | Yüksək | (1) `_encoded_variants` başlanğıc `/`-i qoruyur; (2) `_candidate` netloc + `path=="/"` yoxlayır; (3) `_effective_raw_path()` yarl-ın `raw_path`-ini ground-truth kimi istifadə edir | `tests/test_bypass.py::test_failed_bypass_no_finding` |
| B3 | `conductor.run_recon` dövr dəyişənlərini (`deep`, `recon`) lambda-da bağlamırdı (B023) → potensial səhv closure | `conductor.py` | Orta | `lambda t=t, deep=deep: ...` şəklində dəyişənlər bağlandı | mövcud recon testləri |
| B4 | `zip()` `strict` parametrsiz (B905) | `engines/deep_enum.py` | Aşağı | `strict=False` əlavə edildi | mövcud testlər |
| B5 | `raise ... ` `except` daxilində `from`-sız (B904) | `http_policy.py` | Aşağı | `raise ScopeError(...) from exc` | `tests/test_http_policy.py` |
| B6 | İstifadəsiz import/dəyişən (F401/F841) | `engines/api_fuzz.py`, `http_policy.py`, testlər | Aşağı | Təmizləndi | ruff |
| B7 | Ambiguous dəyişən adı `l` (E741) | `tests/test_bypass.py` | Aşağı | `lbl`-ə dəyişdirildi | ruff |

### 3.1 B1 + B2-nin mahiyyəti (ən vacib düzəlişlər)

Bunlar "yalançı tapıntı" və "itirilmiş tapıntı" sinfinə aiddir — bug bounty
üçün **kritikdir**:

- **B1** olmadan bypass mühərriki 403 səbəbindən heç vaxt işləmirdi →
  real authorization-bypass tapıntıları **itirilirdi**.
- **B2** olmadan path trick-ləri kökə çökür və **uydurma** "bypass"
  tapıntıları yaranırdı → hesabat keyfiyyəti sıfıra düşürdü.

Hər ikisi regressiya testi ilə qorunur və **lokal loopback** fixture üzərində
işləyir (xarici trafik yoxdur).

---

## 4. C: Əlavə gücləndirmə — `boost_confidence`

Baseline §3.3 ("Nuclei medium+ hit → sübut tutulur, amma severity confidence
artırılmır") buraxılışını bağlamaq üçün zəncirə **lokal** `boost_confidence`
addımı əlavə edildi (`chain.py`):

- nuclei `medium|high|critical` kandidatlarına mövcud siqnal **sübut** kimi
  bağlanır;
- confidence ən azı 0.75-ə qaldırılır;
- **status `candidate` qalır** — təsdiq uydurulmur.

Regressiya testi: `tests/test_chain.py::test_boost_confidence_attaches_evidence`.

---

## 5. D: Həyata keçirilməyən / qismən işlər (dürüst)

| # | İş | Səbəb | Status |
|---|---|---|---|
| D1 | JS-də tapılan secret-lərin birbaşa **replay-i** (`test_secret_endpoints`) | Bazada yalnız **maskalanmış** secret saxlanılır (`mask_value`); xam dəyər mövcud deyil | ❌ NOT DONE |
| D2 | OpenAPI **server URL-lərinin** ayrıca canlı scope yoxlaması (`scope_validate`) | Schemathesis mərhələsi Conductor boru xəttində icra olunur; ayrıca lokal addım yoxdur | ⚠️ PARTIAL |
| D3 | Zəncir addımlarının bir qismi (`param_fuzz`, `schemathesis_fuzz`, `hidden_param_detect`) | Bunlar Conductor-un planlaşdırdığı mərhələlər kimi icra olunur (`delegated`), zəncir tərəfindən təkrar icra edilmir | ⚠️ DELEGATED |
| D4 | `secret_replay` RoE qapısı | Qapı mövcuddur, lakin real replay engine-i yoxdur (D1 ilə bağlı) | ⚠️ PARTIAL |
| D5 | Dnspython əsaslı **CNAME takeover** aşkarlanması | Faza 4-də nəzərdə tutulmuşdu; `deep_enum` subdomain toplayır, lakin dangling-CNAME yoxlaması ayrıca yoxdur | ❌ NOT DONE |

Bu məhdudiyyətlər **gizlədilmir** və `docs/SECURITY_VERIFICATION.md`-də
PARTIAL/NOT DONE kimi işarələnib.

---

## 6. Yoxlama nəticələri (icra edilmiş)

```
$ .venv/bin/python -m compileall -q qbh main.py
COMPILE_OK

$ .venv/bin/python -m ruff check --select E4,E7,E9,F,B,W .
All checks passed!

$ .venv/bin/python -m pytest
234 passed

$ .venv/bin/python -m pytest --cov=qbh --cov-report=term-missing
TOTAL  3512  1750  50%
```

Testlər **yalnız** `127.0.0.1`/`localhost` loopback fixture-larına qarşı
işləyir — xarici hədəfə trafik göndərilmir.

---

## 7. Nəticə

- v2.1-in 12 əsas offensive məhdudiyyətindən **11-i tam**, **1-i qismən**
  həll olundu.
- v2.2 işi zamanı aşkarlanan **4 əsas defekt** (B1–B4) və **3 kiçik** lint
  defekti (B5–B7) düzəldildi; hər biri testlə qorunur.
- 5 iş (D1–D5) **həyata keçirilməyib/qismən**dir və açıq şəkildə göstərilib.
