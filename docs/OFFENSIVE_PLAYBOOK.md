# Offensive Playbook — QBH Xəzər v3.0

**Məqsəd:** İcazəli hədəfdə *maksimum tapıntı* çıxarmaq üçün zəncirləmə
pipeline-ının necə işlədiyini və necə konfiqurasiya olunduğunu göstərmək.

> **Yeganə toxunulmaz sərhəd — avtorizasiya scope-u.** Scope daxilində hər şey
> (aktiv fuzz, bypass, rotasiya, PoC) icazəlidir. Scope xaricində heç nə.

---

## 1. Fəlsəfə: "topla, sonra süz" → "tap, sonra təsdiqlə"

v2.1 kəşfləri toplayır, lakin onları **test etmirdi** — tapıntılar `potential`
statusunda ölürdü. v2.2-də hər kəşf avtomatik növbəti addıma **zəncirlənirdi**;
v3.0-da isə zəncirin yerli addımları (bypass, confirm, **secret replay**,
parametr/OpenAPI fuzzinqi) real mühərriklərlə **icra olunur**, `--mode hunt` isə
yüksək dəyərli URL-lər üzərində əlavə dərin pass qoşur:

```
Recon → Discover → Enrich → Test → Confirm → PoC → Report
```

---

## 2. Zəncirləmə cədvəli (`qbh/chain.py`)

| Trigger | Avtomatik davam | İcra |
|---|---|---|
| Subdomain kəşfi | canlı-yoxlama; canlıdırsa fingerprint + JS analizi | delegasiya |
| JS faylı | endpoint + secret çıxarışı → eyni hostda yoxlama + **secret replay** | delegasiya + **lokal** (`secret_replay`) |
| Yeni parametr | gizli parametr aşkarlanması → fuzz | **lokal** (`hidden_param_detect`, `param_fuzz`) |
| OpenAPI sənədi | server-ləri scope-a yoxla → Schemathesis aktiv fuzz | delegasiya + **lokal** (`schemathesis_fuzz`) |
| CNAME dangling (takeover) | domen iddiası yoxlanılır → `confirmed` | **lokal** (`qbh/engines/takeover.py`) |
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
3. **`secret_replay`** — JS-dən çıxarılmış secret-lər şifrəli vault-dan
   (`qbh/vault.py`) açılır və eyni hostda yönləndirilmiş endpoint-lərə
   **replay olunur** (`engines/secret_replay.py`). RoE (`secret_replay`
   qadağası) və scope qapısı tətbiq olunur; uğurlu replay `confirmed` sayılır,
   secret-lər hər zaman maskalanır.
4. **`hidden_param_detect` / `param_fuzz`** — parametrli URL-lər üçün gizli
   parametr aşkarlanması + (aktiv fuzz icazəlidirsə) parametr fuzzinqi
   (`engines/param_enum.py`).
5. **`schemathesis_fuzz`** — OpenAPI sxemi üzərində yalnız GET metodları ilə
   property-test (`engines/api_fuzz.py`).
6. **`boost_confidence`** — nuclei medium+ kandidatlarına mövcud siqnal sübut
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
`param_fuzz`, `race`, `state_changing`.

`state_changing` (POST/PUT/PATCH/DELETE) **default olaraq qadağandır** və yalnız
`--allow-state-changing` bayrağı ilə açılır; proqram RoE-si həmişə qalib gəlir.

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
  avtomatik çevrilir (`db.py :: normalize_status`, cari `SCHEMA_VERSION = 6`).

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
python main.py --mode hunt --config config/targets.yaml   # tam zəncir + dərin pass
python main.py --mode full --config config/targets.yaml --targets acme.com
python main.py --mode report    # mövcud baza üzərindən hesabat
```

`--targets` **heç vaxt** avtorizasiyanı keçmir — hər hədəf `authorize_target`
ilə fail-closed yoxlanılır.

---

## 10. Vəziyyət və açıq məhdudiyyətlər (dürüst)

Bu playbook "hər şey hazırdır" demir, lakin v3.0 Faza 3 ilə əvvəlki boşluqları
bağladı. **Real olan**:

- JS-dən çıxarılan **secret-lərin replay-i** (`test_secret_endpoints` /
  `secret_replay`) **həyata keçirilmişdir** — secret-lər `qbh/vault.py`-də
  Fernet ilə şifrələnmiş saxlanılır, icazə verildikdə açılıb replay olunur
  (`engines/secret_replay.py`).
- **CNAME dangling takeover** aşkarlanması real mühərriklə işləyir
  (`engines/takeover.py`, Faza 3.3).
- Zəncirin parametr/OpenAPI addımları **real icra** olunur (`param_enum.py`,
  `api_fuzz.py`, Faza 3.4).
- `--mode hunt` (Faza 3.5) avtomatik tam zənciri + yüksək dəyərli URL-lər
  üzərində dərin pass-ı birləşdirir.
- Adaptiv stealth (Faza 3.6): WAF aşkarlamasına görə rate/concurrency/template
  uyğunlaşdırılır və humanization tətbiq olunur (`qbh/stealth/`).

**Hələ məhdud olan** (gizlədilmir — `docs/SECURITY_VERIFICATION.md`-ə baxın):

- Subprocess alətlərinin (nuclei, ffuf, ...) öz daxili DNS/redirect davranışı
  üzərində tam egress nəzarəti yalnız **OS səviyyəli sandbox** ilə mümkündür;
  layihə scope qapısı və `EgressController` tətbiq edir, lakin proses daxili
  hər paketi qarantiyalaya bilmir.
- Heuristik siqnallar (banner, başlıq) tək başına sübut DEYİL — `candidate`
  statusunda qalır və manual təsdiq tələb edir.
- Real hədəf üzərində canlı validasiya hələ aparılmayıb (yalnız loopback
  fixture E2E testində işlədilib).

Bunlar gizlədilmir — `docs/SECURITY_VERIFICATION.md` cədvəlinə baxın.
