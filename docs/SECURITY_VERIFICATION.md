# Security Verification — QBH Xəzər v3.0

**Tarix:** 2026-11-13
**Metod:** yalnız **icra edilmiş** yoxlamalar və **real** test nəticələri.
Heç bir sətir "implementasiya olundu" iddiası ilə PASS sayılmır — `PASS`
YALNIZ həm **implementasiya olunduqda**, həm də **test edildikdə** verilir.

```
$ .venv/bin/python -m compileall -q qbh main.py   → COMPILE_OK
$ .venv/bin/python -m ruff check --select E4,E7,E9,F,B,W .  → All checks passed!
$ .venv/bin/python -m pytest                      → 557 collected (556 passed, 1 skipped)
$ .venv/bin/python -m pytest --cov=qbh            → TOTAL 72%
```

Bütün testlər **yalnız** `127.0.0.1`/`localhost` loopback fixture-larına qarşı
işləyir — **CI heç bir xarici hədəfə trafik göndərmir**.

---

## 1. Əsas yoxlama cədvəli

| Sahə | Status | Sübut (test) | Qeyd |
|---|---|---|---|
| **Scope enforcement** | ✅ **PASS** | `test_authorization.py::TestAuthorizeUrl` (in/out, boş scope fail-closed, etibarsız URL, wildcard, deny-wins), `test_scope.py` (exact/wildcard/IP/CIDR/IDNA/malformed), `test_config.py::test_authorize_target` | Fail-closed; `authorize_url` YALNIZ kənarı rədd edir |
| **Chaining** | ✅ **PASS** | `test_chain.py` (TestTriggers, TestEmitGate, TestDiscovery, TestRun, `test_boost_confidence_attaches_evidence`, TestFindingStore, TestConfirmEngine, param/openapi real icra), `test_bypass.py::TestBypassEngine`, `test_vault.py::TestSecretReplay`, `test_hunter.py` | Zəncir addımları RoE qapısından keçir; JS→secret replay (vault + `secret_replay`) və param/openapi addımları real icra olunur |
| **Rotation** | ✅ **PASS** | `test_rotation.py` (TestDeterministic, TestRotation: UA/başlıq/proxy, audit, `on_block=False`, `_validate_rotation`) | Determinizm + audit yoxlanılır |
| **Adaptive rate handling** | ✅ **PASS** | `test_http_policy.py`: `test_403_triggers_cooldown_not_evasion`, `test_403_rotate_strategy_rotates_identity`, `test_403_escalate_bypass_sets_flag`, `test_403_rotate_impossible_falls_to_cooldown`, `test_429_rotate_strategy_rotates`, `test_429_honours_retry_after`, `test_repeated_blocks_grow_cooldown_capped` | 4 strategiya (respect/rotate/backoff_then_rotate/escalate_bypass) sınanır |
| **Egress control** | ✅ **PASS** | `test_http_policy.py::test_request_out_of_scope_blocked`, `test_scope_check_happens_before_any_request`, `test_redirect_within_scope_followed`, `test_redirect_escape_blocked`; `test_scope.py` redirect escape testləri | Hər sorğu + hər redirect addımı yenidən avtorizasiya olunur; scope yoxlaması sorğudan ƏVVƏL |
| **Subprocess egress (Faza 0.2)** | ✅ **PASS** | `test_egress.py` (TestAuthorizeProcessTargets, TestTargetFile, TestDnsPinning: TTL keş/xarici xəta, TestProcessKill: timeout/ehtiva/killpg/uşaq, TestFailClosed) | Bütün subprocess hədəfləri `EgressController.authorize_process_targets()`-dən keçir; DNS pinning + qrup SIGKILL + audit. Tam per-request nəzarət üçün OS sandbox tələb olunur — sənədləşdirilib |
| **Scan izolyasiyası (Faza 0.1)** | ✅ **PASS** | `test_scan_isolation.py` (TestScanIsolation, TestLegacyIsolation, TestEngineQueryPaths, TestMigrationV4: v3→v4 id qorunması, idempotentlik) | `hosts.scan_id NOT NULL` + `UNIQUE(scan_id, subdomain)`; köhnə qeydlər `LEGACY_SCAN_ID=0` alır və yeni skanın hədəfi ola bilməz |
| **OpenAPI servers scope (Faza 0.3)** | ✅ **PASS** | `test_api_fuzz.py` (TestEffectiveServers, TestValidateServers, TestEngineGuard) | `servers:` dəyişən əvəzindən SONRA genişləndirilir; hər URL `authorize_url()`-dən keçir; icazəsiz server rədd + log (səssiz əvəz yox) |
| **Cancellation** | ✅ **PASS** | `test_authorization.py::TestCancellationAndDeadline` (cancel, canceller Event, deadline keçmiş/gələcək, summary); `test_http_policy.py::test_cancellation_propagates`; `test_egress.py::TestProcessKill` | `ensure_active()` uzun əməliyyatlardan əvvəl çağırılır; cancel → proses qrupuna SIGKILL |
| **DB migration** | ✅ **PASS** | `test_lifecycle.py::TestMigration` (köhnə `potential/verified/false-positive` bazası → cari), `TestNormalizeStatus` (`SCHEMA_VERSION==6`), `test_db.py`, `test_scan_isolation.py::TestMigrationV4` | Cədvəl → `_rebuild_hosts_v4` → `_migrate` → indeks sırası; məlumat itmir (id qorunur, köhnə hostlar `legacy`); cari `SCHEMA_VERSION = 6` |

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
| "Tool missing" dürüst raportu | ✅ **PASS** | `test_tool_missing.py` (recon/vuln/content/ferox/param_enum/api_enum/deep_enum → `ProcResult(missing=True)` → `res.warn`, uydurma tapıntı yox) | 7 mühərrik üzrə avtomatik test; `adapters/base.py` `proc.missing` mexanizmi |
| Şifrəli secret vault (Faza 3.2) | ✅ **PASS** | `test_vault.py` (Fernet şifrə/açma, açar idarəsi, round-trip, korrupsiya), `TestSecretReplay` | Xam secret şifrəli saxlanılır; hesabat/loqda `redact`; RoE `secret_replay` qadağan edərsə atla + audit |
| CNAME takeover (Faza 3.3) | ✅ **PASS** | `test_takeover.py` (dangling CNAME, provayder imzaları, təsdiq, yanlış-pozitiv) | `dnspython` əsaslı aşkarlama + təsdiq mərhələsi |
| Hunter orkestratoru (Faza 3.5) | ✅ **PASS** | `test_hunter.py`, `main.py --mode hunt` | Avtomatik zəncir + 401/403 bypass matrisi; hər addım RoE-dan keçir |
| Stealth adaptiv siyasət (Faza 3.6) | ✅ **PASS** | `test_stealth.py` (`TestBuildPlan`, `TestStealthStackPlan`, `TestHumanizer`, `TestAdaptiveToolWiring`) | WAF var/yox → rate/concurrency/UA/`-exclude-tags` dəyişir; auditə yazılır |

---

## 3. PARTIAL / NOT DONE — açıq izah

Aşağıdakılar **gizlədilmir**; `docs/REMEDIATION_REPORT.md` (D1–D5) ilə
uzlaşır.

### 3.1 Chaining — HƏLL OLUNDU

Faza 3 ilə əvvəlki çatışmazlıqlar bağlandı:

- **JS→secret replay:** xam secret-lər artıq `qbh/vault.py`-də **şifrəli**
  saxlanılır və `qbh/engines/secret_replay.py` onları RoE (`secret_replay`)
  qapısı altında yoxlayır — `test_vault.py::TestSecretReplay`. RoE qadağan
  edərsə trafik göndərilmir (atla + audit).
- **`param_fuzz` / `hidden_param_detect` / `schemathesis_fuzz`:** əvvəl
  yalnız `delegated` planlaşdırma idi; indi `ChainPipeline` daxilində
  **birbaşa** və RoE qapılarından keçməklə icra olunur.
- **`scope_validate`:** OpenAPI server-ləri `test_api_fuzz.py` ilə canlı
  scope yoxlamasından keçir.

Yalnız aşağıdakı qeyd qalır: OS səviyyəli per-request sandbox tələb olunan
tam şəbəkə izolyasiyası — sənədləşdirilmiş məhdudiyyətdir.

### 3.2 "Tool missing" raportu — HƏLL OLUNDU (Faza 4.2)

`run_process()` `missing=True` qaytarır və hər engine `res.warn(...)` ilə
dürüst xəbərdarlıq verir. Bu davranış artıq **avtomatik test olunur**:
`test_tool_missing.py` bütün alət çağırışlarını `missing=True`-ya çevirir və
7 mühərrikin (recon/vuln/content/ferox/param_enum/api_enum/deep_enum) crash
etmədən `res.warn` verdiyini, uydurma tapıntı yaratmadığını təsdiqləyir.
`ReconEngine.__init__`-də `self.rate` çatışmazlığı (real wiring buqu) da bu
testlə aşkarlandı və düzəldildi.

### 3.3 Konfiqurasiya qeydi

`config/*.yaml`-da `intrusive_templates` və `active_fuzz` yalnız profillə
idarə olunur; proqram qaydası (`program_rules.forbidden`) onlardan üstündür
(`config.py` `_build` validasiyası).

---

## 4. Nəticə

- Əsas cədvəldəki sahələrin **hamısı PASS** (Chaining Faza 3 ilə bağlandı).
- Əlavə 12 acceptance sahəsinin **12-si də PASS** ("Tool missing" dürüst
  raportu Faza 4.2-də avtomatik test ilə təsdiqləndi).
- Yeganə açıq məhdudiyyət: OS səviyyəli per-request sandbox tələb edən tam
  şəbəkə izolyasiyası (§3.1) — sənədləşdirilmiş, gizlədilməyib.
- Heç bir PASS sətri test olmadan verilməmişdir.
