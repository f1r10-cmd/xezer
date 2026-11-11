# Offensive Playbook — QBH Xəzər v2.2

**Məqsəd:** İcazəli hədəfdə *maksimum tapıntı* çıxarmaq üçün zəncirləmə
pipeline-ının necə işlədiyini və necə konfiqurasiya olunduğunu göstərmək.

> **Yeganə toxunulmaz sərhəd — avtorizasiya scope-u.** Scope daxilində hər şey
> (aktiv fuzz, bypass, rotasiya, PoC) icazəlidir. Scope xaricində heç nə.

---

## 1. Fəlsəfə: "topla, sonra süz" → "tap, sonra təsdiqlə"

v2.1 kəşfləri toplayır, lakin onları **test etmirdi** — tapıntılar `potential`
statusunda ölürdü. v2.2-də hər kəşf avtomatik növbəti addıma **zəncirlənir**:

```
Recon → Discover → Enrich → Test → Confirm → PoC → Report
```

---

## 2. Zəncirləmə cədvəli (`qbh/chain.py`)

| Trigger | Avtomatik davam | İcra |
|---|---|---|
| Subdomain kəşfi | canlı-yoxlama; canlıdırsa fingerprint + JS analizi | delegasiya |
| JS faylı | endpoint + secret çıxarışı | delegasiya |
| Yeni parametr | gizli parametr aşkarlanması → fuzz | delegasiya |
| OpenAPI sənədi | server-ləri scope-a yoxla → Schemathesis aktiv fuzz | delegasiya |
| Maraqlı endpoint (login/upload/admin) | hədəfli fuzz / SQLi-yönlü yoxlama | delegasiya + **bypass** (lokal) |
| Fingerprint-dən CVE uyğunluğu | təsdiq template-i / skript PoC | **lokal** (`confirm_template`) |
| 401/403 maraqlı yolda | bypass matrisi (`payloads.build_matrix`) | **lokal** (`bypass_matrix`) |
| Nuclei medium+ hit | sübut toplama, confidence artırımı | **lokal** (`boost_confidence`) |

**Lokal** = `ChainPipeline.run()` həmin addımı birbaşa icra edir.
**Delegasiya** = addım Conductor-un planlaşdırdığı mərhələ kimi icra olunur
(bu, audit-də `delegated` siyahısında qeyd olunur — heç bir iş ikiqat
icra olunmur).

### 2.1 Necə oxunmalıdır

`ChainPipeline.run()` DB-dən trigger-ləri çıxarır (`_discover_triggers`),
sonra:

1. **`bypass_matrix`** — maraqlı endpoint-lərdə 401/403 aşkar edilərsə
   `payloads.build_matrix` ilə path/header/verb matrisi sınanır; ilk uğurlu
   cəhd `confirmed` tapıntı + sübut kimi qeyd olunur (`engines/bypass.py`).
2. **`confirm_template` / `poc`** — CVE və exposure kandidatları canlı cavabla
   yoxlanılır; uyğun gələrsə `confirmed`, 404 olarsa `rejected`
   (`engines/confirm.py`).
3. **`boost_confidence`** — nuclei medium+ kandidatlarına mövcud siqnal sübut
   kimi bağlanır və confidence 0.75-ə qaldırılır. **Status `candidate` qalır** —
   təsdiq uydurulmur.

Hər addım `ctx.authorization`-dan keçir:

- `authorize_url()` / `cfg.in_scope()` — scope qapısı;
- `allows(action)` — proqramın qadağaları (RoE);
- `ensure_active()` — ləğv və deadline.

Qadağan olunmuş addım **atlanır** və `skipped` siyahısında audit olunur.

---

## 3. Aggressiveness profilləri

`config/*.yaml` → `aggressiveness: passive | normal | aggressive` (default
`aggressive`). Profil rate, concurrency, redirect dərinliyi və rotasiyanın
default-larını təyin edir:

| Parametr | passive | normal | aggressive |
|---|---|---|---|
| `rate_factor` | 0.5 | 1.0 | 2.0 |
| `concurrency_factor` | 0.5 | 1.0 | 2.0 |
| `max_redirects` | 5 | 10 | 20 |
| `active_fuzz` | ✗ | ✓ | ✓ |
| `intrusive_templates` | ✗ | ✗ | ✓ |
| `rotate_ua` | ✗ | ✓ | ✓ |
| `rotate_headers` | ✗ | ✗ | ✓ |
| `rotate_proxy` | ✗ | ✗ | ✓ |
| `block_429` | respect | respect | backoff_then_rotate |
| `block_403` | backoff | backoff | rotate |

Profil yalnız **aşağı salına** bilər — proqram qaydası `active_fuzz`-ı
qadağan edərsə, profil `aggressive` olsa belə deaktiv olunur (`config.py`).

### 3.1 Proqramın qadağaları (`program_rules.forbidden`)

İstifadəçi/proqram aşağıdakı hərəkətləri qadağan edə bilər:

`active_fuzz`, `intrusive_templates`, `bypass`, `cve_poc`, `secret_replay`,
`param_fuzz`, `race`.

Qadağan edilmiş hərəkət zəncir addımında və engine daxilində hörmətlə
atlanır (uydurma nəticə yoxdur).

---

## 4. Adaptiv blok idarəetməsi (403/429)

`Guardian` "əyləc pedalı" deyil — **adaptiv** engine-dir:

| Strategiya | 429 | 403 |
|---|---|---|
| `respect` | `Retry-After`/cooldown gözlə | (403 → backoff) |
| `rotate` | identikliyi dəyiş | identikliyi dəyiş |
| `backoff_then_rotate` | əvvəl gözlə, sonra dəyiş | — |
| `escalate_bypass` | — | bypass matrisi üçün işarə qaldır |

Bypass mühərriki 403-ü görmək üçün **xam** probe sorğuları göndərir
(`observe_block=False`) — beləliklə host cooldown-a düşməzdən əvvəl matris
eyni yol üzərində sınanır. Normal mühərriklər üçün adaptiv blok qalır.

---

## 5. OPSEC rotasiyası (configurable)

`rotation` bölməsi: `enabled`, `ua`, `headers`, `proxy`, `on_block`.

- **UA rotasiyası** — UA hovuzundan deterministik (hosta görə) seçim.
- **Başlıq rotasiyası** — `Accept-Language`, benign `Sec-Fetch-*` başlıqları.
- **Proxy rotasiyası** — `config/proxies.txt` varsa rotasiya.
- `on_block: true` — blok zamanı `Guardian.rotate()` identikliyi dəyişir.

Hər rotasiya `identity.audit_log()`-da audit olunur. Rotasiya söndürüldükdə
davranış **deterministikdir** (test edilir: `tests/test_rotation.py`).

---

## 6. Tapıntı həyat dövrü və sübut

- **Statuslar:** `candidate → confirmed → reported` (və `rejected`).
- **Sübut (`evidence` cədvəli):** `http_response | marker | callback | data | note`.
- **Confidence:** hər tapıntı üçün hesablanır; `confirm` mərhələsi onu
  qaldırır, `reject` isə 0.1-ə salır.
- Köhnə adlar (`potential`, `verified`, `false-positive`) migrasiya ilə
  avtomatik çevrilir (`db.py :: normalize_status`, `SCHEMA_VERSION = 3`).

---

## 7. Bounty-ready hesabat

`report/generator.py` yazır:

- `reports/qbh_<ts>.md` — əsas Markdown hesabat,
- `reports/qbh_<ts>.json` — strukturlaşdırılmış JSON,
- `reports/qbh_<ts>.h1.json` — **HackerOne** uyğun format
  (`report/exporters.py`: severity → `severity_rating`, CVSS balı, CWE
  təklifi, remediasiya, confidence). Rədd edilmiş və aşağı severity-li
  tapıntılar ixrac olunmur; secret-lər `redact` ilə maskalanır.

---

## 8. Nümunə konfiqurasiya (aggressive, RoE ilə)

```yaml
program: "Acme Bounty"
aggressiveness: aggressive
scope:
  - domain: "*.acme.com"
  - domain: "acme.com"
program_rules:
  forbidden: []            # proqram heç nəyi qadağan etmir
  allow_wildcard_expansion: true
rotation:
  enabled: true
  ua: true
  headers: true
  proxy: false             # proxy yoxdursa belə UA/başlıq rotasiyası işləyir
  on_block: true
block_strategy:
  http_429: backoff_then_rotate
  http_403: rotate
chain:
  enabled: true
  max_depth: 3
  max_tasks: 200
```

Proqram qaydası ilə məhdudlaşdırılmış nümunə:

```yaml
program_rules:
  forbidden: ["cve_poc", "race"]   # PoC və race qadağandır → atlanır
```

---

## 9. İşə salma

```bash
python main.py --mode full --config config/targets.yaml
python main.py --mode full --config config/targets.yaml --targets acme.com
python main.py --mode report    # mövcud baza üzərindən hesabat
```

`--targets` **heç vaxt** avtorizasiyanı keçmir — hər hədəf `authorize_target`
ilə fail-closed yoxlanılır.

---

## 10. Açıq məhdudiyyətlər (dürüst)

Bu playbook "hər şey hazırdır" demir. Aşağıdakılar **hələ tam deyil** və
`docs/SECURITY_VERIFICATION.md`-də PARTIAL kimi işarələnib:

- JS-dən çıxarılan **secret-lərin birbaşa replay-i** (`test_secret_endpoints`)
  həyata keçirilməyib — bazada yalnız **maskalanmış** secret saxlanılır, ona
  görə xam dəyər mövcud deyil.
- OpenAPI **server-lərinin canlı scope yoxlaması** ayrıca lokal addım kimi
  yoxdur; Schemathesis mərhələsi Conductor boru xəttində icra olunur.
- `secret_replay` və bəzi zəncir addımları RoE qapısından keçir, lakin
  hazırda yalnız `bypass`, `cve_poc` və `active_fuzz` üçün real engine
  tətbiqi var.

Bunlar gizlədilmir — `docs/SECURITY_VERIFICATION.md` cədvəlinə baxın.
