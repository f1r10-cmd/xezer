# Security Verification — QBH Xəzər v2.2

**Tarix:** 2026-11-12
**Metod:** yalnız **icra edilmiş** yoxlamalar və **real** test nəticələri.
Heç bir sətir "implementasiya olundu" iddiası ilə PASS sayılmır — `PASS`
YALNIZ həm **implementasiya olunduqda**, həm də **test edildikdə** verilir.

```
$ .venv/bin/python -m compileall -q qbh main.py   → COMPILE_OK
$ .venv/bin/python -m ruff check --select E4,E7,E9,F,B,W .  → All checks passed!
$ .venv/bin/python -m pytest                      → 242 passed
$ .venv/bin/python -m pytest --cov=qbh            → TOTAL 51%
```

Bütün testlər **yalnız** `127.0.0.1`/`localhost` loopback fixture-larına qarşı
işləyir — **CI heç bir xarici hədəfə trafik göndərmir**.

---

## 1. Əsas yoxlama cədvəli

| Sahə | Status | Sübut (test) | Qeyd |
|---|---|---|---|
| **Scope enforcement** | ✅ **PASS** | `test_authorization.py::TestAuthorizeUrl` (in/out, boş scope fail-closed, etibarsız URL, wildcard, deny-wins), `test_scope.py` (exact/wildcard/IP/CIDR/IDNA/malformed), `test_config.py::test_authorize_target` | Fail-closed; `authorize_url` YALNIZ kənarı rədd edir |
| **Chaining** | ⚠️ **PARTIAL** | `test_chain.py` (TestTriggers, TestEmitGate, TestDiscovery, TestRun, `test_boost_confidence_attaches_evidence`, TestFindingStore, TestConfirmEngine), `test_bypass.py::TestBypassEngine` | Mexanizm PASS; JS→secret replay (`test_secret_endpoints`) **implementasiya olunmayıb** |
| **Rotation** | ✅ **PASS** | `test_rotation.py` (TestDeterministic, TestRotation: UA/başlıq/proxy, audit, `on_block=False`, `_validate_rotation`) | Determinizm + audit yoxlanılır |
| **Adaptive rate handling** | ✅ **PASS** | `test_http_policy.py`: `test_403_triggers_cooldown_not_evasion`, `test_403_rotate_strategy_rotates_identity`, `test_403_escalate_bypass_sets_flag`, `test_403_rotate_impossible_falls_to_cooldown`, `test_429_rotate_strategy_rotates`, `test_429_honours_retry_after`, `test_repeated_blocks_grow_cooldown_capped` | 4 strategiya (respect/rotate/backoff_then_rotate/escalate_bypass) sınanır |
| **Egress control** | ✅ **PASS** | `test_http_policy.py::test_request_out_of_scope_blocked`, `test_scope_check_happens_before_any_request`, `test_redirect_within_scope_followed`, `test_redirect_escape_blocked`; `test_scope.py` redirect escape testləri | Hər sorğu + hər redirect addımı yenidən avtorizasiya olunur; scope yoxlaması sorğudan ƏVVƏL |
| **Cancellation** | ✅ **PASS** | `test_authorization.py::TestCancellationAndDeadline` (cancel, canceller Event, deadline keçmiş/gələcək, summary); `test_http_policy.py::test_cancellation_propagates` | `ensure_active()` uzun əməliyyatlardan əvvəl çağırılır |
| **DB migration** | ✅ **PASS** | `test_lifecycle.py::TestMigration` (köhnə `potential/verified/false-positive` bazası → v3), `TestNormalizeStatus` (`SCHEMA_VERSION==3`), `test_db.py` | Cədvəl → `_migrate` → indeks sırası; məlumat itmir |

---

## 2. Əlavə acceptance yoxlamaları

| Sahə | Status | Sübut (test) | Qeyd |
|---|---|---|---|
| Aktiv fuzz default ON (profil) | ✅ **PASS** | `test_authorization.py::test_passive_profile_disables_active_fuzz`, `test_aggressive_profile_enables_active_fuzz`; `test_engines.py::test_api_fuzz_requires_active_flag` | Proqram qadağası profildən üstündür |
| Intrusive nuclei templates (profilə bağlı) | ✅ **PASS** | `test_engines.py::TestVulnTemplateProfile`, `test_authorization.py::test_passive_profile_disables_intrusive_templates`, `test_aggressive_profile_enables_intrusive_templates` | `aggressive` → yalnız zərərli tag-lar xaric |
| Findings lifecycle + evidence | ✅ **PASS** | `test_lifecycle.py::TestFindingLifecycle`, `TestEvidence`; `test_chain.py::TestFindingStore` | `candidate→confirmed→rejected→reported`, sübut cascade |
| Bounty-ready export (MD/JSON/H1) | ✅ **PASS** | `test_exporters.py` (shape, severity mapping, secret redaction, exclude rejected, min_severity) | HackerOne struktur + remediasiya + confidence |
| Hər engine `EngineResult` qaytarır | ✅ **PASS** | `test_engines.py::TestEngineContract` (parametrized, 12 mühərrik) | Boş bazada xətasız `skipped` |
| `shell=True` yoxdur | ✅ **PASS** | `adapters/base.py` (`asyncio.create_subprocess_exec`); ruff/grep | Command injection mümkün deyil |
| CI (lint + test + secret scan) | ✅ **PASS** | `.github/workflows/ci.yml`, `.gitleaks.toml`, `requirements-dev.txt` | Yalnız loopback testləri |
| "Tool missing" dürüst raportu | ⚠️ **PARTIAL** | `adapters/base.py` `proc.missing`; engine-lərdə `res.warn("... tapılmadı")` | Mexanizm mövcuddur, lakin ayrıca avtomatik testi **yoxdur** |

---

## 3. PARTIAL / NOT DONE — açıq izah

Aşağıdakılar **gizlədilmir**; `docs/REMEDIATION_REPORT.md` (D1–D5) ilə
uzlaşır.

### 3.1 Chaining — PARTIAL

**İşləyən (test edilir):**

- trigger-lərin DB-dən çıxarılması (`_discover_triggers`);
- RoE qapısı (`emit` → `_gate` → `allows`) və `skipped` audit;
- **lokal** icra: `bypass_matrix` (403→bypass), `confirm_template` (CVE→confirm),
  `boost_confidence` (nuclei medium+ → sübut + confidence);
- `audit()` / `delegated` çıxışı.

**Çatışmır:**

- `test_secret_endpoints` — JS-də tapılan secret-lərin birbaşa testi.
  Səbəb: bazada yalnız **maskalanmış** secret saxlanılır (`mask_value`), xam
  dəyər mövcud deyil → replay mümkün deyil.
- `scope_validate` (OpenAPI server-lərinin ayrıca canlı scope yoxlaması) —
  Schemathesis mərhələsi Conductor boru xəttində icra olunur.
- `param_fuzz` / `schemathesis_fuzz` / `hidden_param_detect` — Conductor-un
  planlaşdırdığı mərhələlər kimi (`delegated`) icra olunur.

### 3.2 "Tool missing" raportu — PARTIAL

`run_process()` `missing=True` qaytarır və hər engine `res.warn(...)` ilə
dürüst xəbərdarlıq verir; lakin bu davranışın **avtomatik testi yoxdur**
(CI-da xarici alət quraşdırılmır).

### 3.3 Konfiqurasiya qeydi

`config/*.yaml`-da `intrusive_templates` və `active_fuzz` yalnız profillə
idarə olunur; proqram qaydası (`program_rules.forbidden`) onlardan üstündür
(`config.py` `_build` validasiyası).

---

## 4. Nəticə

- 7 əsas sahədən **6-sı PASS**, **1-i PARTIAL** (Chaining).
- Əlavə 8 acceptance sahəsindən **7-si PASS**, **1-i PARTIAL**.
- Heç bir PASS sətri test olmadan verilməmişdir.
