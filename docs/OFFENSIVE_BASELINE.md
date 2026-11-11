# Offensive Baseline — QBH Xəzər (v2.1 → v2.2 keçid auditi)

**Tarix:** 2026-11-12
**Repo:** `/home/kali/Desktop/cf-hunter/qbh-xazar/`
**Məqsəd:** v2.1-in hazırkı vəziyyətini xəritələmək və **daha çox bug tapmağa
mane olan** məhdudiyyətləri açıq şəkildə göstərmək.

> v2.1 təhlükəsizlik baxımından möhkəm idi, lakin **offensive** baxımdan
> həddindən artıq məhdudiyyətli idi: aktiv testlər default bağlı, kəşflər
> avtomatik testə çevrilmirdi, tapıntılar `potential` statusunda "ölürdü".

---

## 1. Arxitektura xəritəsi

```
main.py → Conductor → { deep_enum, recon, fingerprint, vuln, jsanalysis,
                        content, ferox, api_enum, api_fuzz, param_enum,
                        race, cve_intel, validation }
              ↓
          Guardian → HttpPolicy → aiohttp
              ↓
          db.py (SQLite)  →  report/generator.py
```

- Hər mühərrik `(ctx) -> EngineResult` kontraktına malikdir (**bu yaxşıdır**).
- Scope qapısı `Config.in_scope` / `authorize_target` + `HttpPolicy`-də hər
  sorğu və hər redirect addımında işləyir.
- Subprocess: `adapters/base.run_process` (`shell=False`).

## 2. Mühərrik inventarı və hazırkı vəziyyət

| Mühərrik | Giriş | Hazırkı rejim | Offensive boşluq |
|---|---|---|---|
| `deep_enum` | `domain` | aktiv (subfinder/amass/crt.sh/alterx) | OK, lakin nəticələr yalnız host kimi yazılır |
| `recon` | `domain`, subdomain-lər | aktiv (httpx/naabu/katana/gau) | URL-lər toplanır, **test olunmur** |
| `fingerprint` | DB hostlar | aktiv | versiya → CVE zənciri yoxdur |
| `vuln` (nuclei) | DB hostlar | aktiv, təhlükəsiz template-lər | intrusive template-lər **default xaric** |
| `jsanalysis` | DB JS URL-lər | aktiv | secret tapılır, **test olunmur** |
| `content` (ffuf) | DB hostlar | aktiv, flat | recursive yoxdur |
| `ferox` | DB hostlar | aktiv, recursive | — |
| `api_enum` | DB hostlar | aktiv (OpenAPI/Swagger/kiterunner) | tapılan sxem → **aktiv fuzz yoxdur** |
| `api_fuzz` (schemathesis) | OpenAPI sənədi | **GATED** (`--active-fuzz`) | default bağlıdır |
| `param_enum` | DB URL-lər | aktiv (arjun/x8, GET-only) | tapılan parametr → **fuzz yoxdur** |
| `race` | lokal fixture | **GATED** (loopback-only) | dağıdıcı olduğu üçün qalır |
| `cve_intel` | fingerprint + banner | aktiv (NVD/OSV/KEV/EPSS) | uyğunluq → **PoC təsdiqi yoxdur** |
| `validation` | high/critical tapıntılar | aktiv | yalnız cavab müqayisəsi, sübut zəifdir |

## 3. Sistemi geri saxlayan məhdudiyyətlər

### 3.1 Passiv-olan / gated mühərriklər
- `api_fuzz` default bağlıdır (`active_fuzz` bayrağı).

### 3.2 Toplanan, lakin test olunmayan kəşflər
- **JS-də tapılan endpoint-lər** → heç bir testə düşmür.
- **JS-də tapılan secret-lər** → yalnız maskalanıb saxlanılır, **heç vaxt
  yoxlanılmır**.
- **param_enum-un tapdığı gizli parametrlər** → fuzz olunmur.
- **api_enum-un tapdığı OpenAPI sənədi** → aktiv fuzz-a ötürülmür.
- **fingerprint versiyası → CVE** → təsdiq (PoC) addımı yoxdur.
- **401/403 olan maraqlı yollar** (login/admin/upload) → bypass matrisi yoxdur.

### 3.3 Tapıntıların sükutla öldüyü yerlər
- `status` yalnız `potential|verified|false-positive`; **`candidate → confirmed
  → reported` lifecycle yoxdur**.
- Sübut (evidence) ayrıca strukturdur — **`evidence` cədvəli yoxdur**;
  sübut `findings.evidence` mətninə sıxılır.
- Nuclei medium+ hit → sübut tutulur, amma severity confidence artırılmır.

### 3.4 Manual addımlar (avtomatlaşdırıla bilər)
- Blok (403/429) → yalnız cooldown; **adaptiv cavab yoxdur** (rotate/escalate).
- Kimlik sabitdir; real bug bounty-da UA/başlıq/proxy rotasiyası OPSEC-dir.
- Bypass texnikaları (encoding, verb tampering, path tricks) **ümumiyyətlə yoxdur**.

### 3.5 Zəif tapıntı keyfiyyəti
- CVSS/CWE yoxdur.
- Reproduction (curl) bəzən boşdur.
- HackerOne formatında export yoxdur.
- Confidence hesablanır, lakin lifecycle və sübut zənciri ilə bağlanmır.

## 4. v2.2 hədəfləri (bu baseline-a cavab)

1. **Vahid authorization** (`ctx.auth.authorize_url`) + proqram RoE.
2. **Aggressiveness profilləri** (`passive|normal|aggressive`, default aggressive).
3. **Zəncirləmə pipeline** (`chain.py`): kəşf → test → təsdiq → PoC.
4. **Tapıntı lifecycle + sübut** (`candidate|confirmed|rejected|reported` + `evidence`).
5. **Adaptiv Guardian**: 403/429 → respect / rotate / backoff_then_rotate /
   escalate_bypass.
6. **Rotation**: UA + başlıq + proxy (configurable OPSEC).
7. **WAF bypass matrisi** (`payloads.py`).
8. **Bounty-ready export**: Markdown + JSON + HackerOne.
9. **CI + testlər** (yalnız lokal fixture).
