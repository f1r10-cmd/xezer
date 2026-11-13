# 🎯 QBH — Qarabug Autonomous Hunter v3.0 "Xəzər"

Bug bounty hədəfləri üzərində **maksimum tapıntı** çıxaran, **yalnız icazəli
scope daxilində** işləyən offensive recon və zəiflik aşkarlama platforması.

> ⚠️ **Yeganə toxunulmaz sərhəd — avtorizasiya scope-u.** Scope daxilində hər şey
> (aktiv fuzzinq, WAF/filter bypass, rotasiya, PoC) **icazəlidir və təşviq
> olunur**. Scope xaricində heç bir trafik mümkün deyil — `--targets` bayrağı
> avtorizasiyanı **heç vaxt** keçə bilmir (fail-closed).

---

## Quraşdırma

```bash
# 1. Python asılılıqları
python -m venv .venv
.venv/bin/pip install -r requirements.txt

# 2. (İnkişaf/test üçün) test və lint asılılıqları
.venv/bin/pip install -r requirements-dev.txt

# 3. Tool-ların vəziyyətini yoxla (heç nə quraşdırmır)
python main.py --mode install --dry-run

# 4. Çatışmayan tool-ları təhlükəsiz üsulla quraşdır (yoxlama ilə)
python main.py --mode install --auto-install
```

Quraşdırıcı **avtomatik `sudo` işlətmir**, shell profillərini dəyişmir və
PATH-ı özbaşına redaktə etmir. Yalnız `go install` / `pip install` kimi
idempotent əməliyyatlar icra edir və **hər quraşdırmadan sonra binari-ni
yenidən yoxlayır**. Manual tool-lar (`feroxbuster`, `amass`, `nmap`) üçün
yalnız tövsiyə göstərilir.

### Tələblər

- Python 3.10+ (inkişaf/test mühiti: **Python 3.14**, Kali Linux x86_64)
- `aiohttp>=3.9`, `PyYAML>=6.0`, `packaging>=23.0`, `dnspython>=2.4.0`
- Testlər üçün: `requirements-dev.txt` (`pytest`, `pytest-asyncio`,
  `pytest-cov`, `ruff`)
- Tool-lar (bax: [Tool asılılıqları](#tool-asılılıqları))

---

## Konfiqurasiya

Konfiqurasiya YAML faylıdır. Nümunələr:

| Fayl | Təyinat |
|---|---|
| [config/examples/example_local.yaml](config/examples/example_local.yaml) | Yalnız `127.0.0.1` üçün təhlükəsiz nümunə |
| [config/examples/targets.example.yaml](config/examples/targets.example.yaml) | Real proqram scope-u (şablon) |

> Real konfiqi şablondan kopyala: `cp config/examples/targets.example.yaml
> config/targets.yaml` və `scope`-u öz avtorizasiya etdiyin proqramla əvəz et.
> `config/targets.yaml` git-ignore olunur (yalnız yerli).

```yaml
program: "Qarabug"
nvd_api_key: ""                 # istəyə bağlı (NVD rate limitini artırır)
aggressiveness: aggressive      # passive | normal | aggressive (default)

scope:
  - domain: example.com
    in_scope:
      - example.com             # kök domen
      - "*.example.com"         # bütün alt domenlər
    out_of_scope:
      - "admin.example.com"     # açıq şəkildə istisna

limits:
  requests_per_second: 5        # host başına rate limit
  max_subdomains_per_target: 500
  max_concurrency: 10
  connect_timeout: 10
  total_timeout: 30
  cooldown: 60                  # 403/429 sonrası hədəf cooldown-u (saniyə)

proxy_file: ""                  # rotasiya üçün proxy siyahısı (OPSEC)

# Proqramın qadağaları (RoE) — verilən hərəkət atlanır və audit olunur
program_rules:
  forbidden: []                 # məs.: ["cve_poc", "race"]
  allow_wildcard_expansion: true
  max_requests_per_second: 0    # 0 → profil/limits default

# İdentiklik rotasiyası (OPSEC; profil default-larını override edir)
rotation:
  enabled: true
  ua: true
  headers: true
  proxy: false
  on_block: true

# Adaptiv blok strategiyası
block_strategy:
  http_429: backoff_then_rotate  # respect | rotate | backoff_then_rotate
  http_403: rotate               # backoff | rotate | escalate_bypass

chain:
  enabled: true
  max_depth: 3
  max_tasks: 200

antiblock:
  interface: "eth0"
```

**Validasiya qaydaları:** boş/xətalı `scope` HEÇ VAXT qəbul edilmir; rəqəmsal
limitlər aralıq yoxlanılır; `aggressiveness` yalnız `passive|normal|aggressive`
ola bilər; naməlum açarlar və silinmiş köhnə evasion açarları (`rotate_levels`,
`credits`) barədə xəbərdarlıq verilir.

### Aggressiveness profilləri

Profil rate, concurrency, redirect dərinliyi və rotasiyanın **default-larını**
təyin edir (default → `aggressive`):

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

Profil yalnız **aşağı salına** bilər: proqram qaydası (`program_rules.forbidden`)
`active_fuzz`-ı qadağan edərsə, `aggressive` olsa belə deaktiv olunur. Ətraflı:
[docs/OFFENSIVE_PLAYBOOK.md](docs/OFFENSIVE_PLAYBOOK.md).

### Scope idarəetməsi

Dəstəklənən qaydalar: dəqiq domen, wildcard (`*.example.com`), kök domen,
IP ünvan, CIDR blok. Domenlər kanonikləşdirilir (lowercase, IDNA/punycode).
Suffix-confusion (`example.com.attacker.test`), malformed hostname, rəqəmsal
TLD və tək-etiketli adlar rədd olunur. Redirect-lər özümüz idarə olunur və
hər addım scope yoxlanılır — **redirect escape mümkün deyil**.

---

## CLI istifadəsi

```bash
# Tam skan (recon + vuln + zəncirləmə) — konfiqdəki bütün icazəli hədəflər
python main.py --config config/targets.yaml --mode full

# Hunter rejimi — tam zəncir + yüksək dəyərli URL-lər üzərində dərin pass
python main.py --config config/targets.yaml --mode hunt

# Yalnız recon / yalnız vuln / yalnız hesabat
python main.py --mode recon
python main.py --mode vuln
python main.py --mode report

# İcra profilini override et
python main.py --mode full --aggressiveness passive

# Tool-ların vəziyyəti / quraşdırma
python main.py --mode install --dry-run
python main.py --mode install --auto-install

# Yalnız göstərilən hədəflər — scope-dan KƏNARA ÇIXA BİLMƏZ
python main.py --targets example.com,www.example.com --mode recon

# Hesabatda minimum severity
python main.py --mode full --severity high
```

| Bayraq | Təsvir |
|---|---|
| `--config PATH` | YAML konfiq (default: `config/targets.yaml`) |
| `--mode {full,recon,vuln,hunt,report,install}` | İcra rejimi (`hunt`: tam zəncir + dərin pass) |
| `--aggressiveness {passive,normal,aggressive}` | İcra profili (konfiqdəki dəyəri override edir) |
| `--targets d1,d2` | Yalnız bu hədəflər (scope yoxlaması ilə) |
| `--rate N` | Saniyədə sorğu limiti (effektiv profildən yuxarı ola bilməz) |
| `--severity {low,medium,high,critical}` | Hesabat filtri |
| `--proxy {off,single}` | Proxy rejimi (OPSEC rotasiyası, scope daxilində) |
| `--active-fuzz` | Aktiv fuzzinqi MƏCBURİ yandır (profil default-u ON) |
| `--no-active-fuzz` | Aktiv fuzzinqi söndür (passive yoxlama rejimi) |
| `--allow-state-changing` | POST/PUT/PATCH/DELETE-ə icazə ver (default OFF; RoE qalib gəlir) |
| `--auto-install` | Çatışmayan tool-ları quraşdır (yoxlama ilə) |
| `--dry-run` | Heç nə icra etmə, yalnız planı göstər |
| `--race-fixture URL` | Race testi üçün YALNIZ lokal loopback fixture |
| `--race-count N` | Race fixture sorğu sayı (default 10, maks 20) |
| `--race-concurrency N` | Race concurrency (default 4, maks 5) |

**Çıxış kodları:** `0` uğur · `1` mərhələ xətası/pipeline abort · `2` istifadə
və ya konfiq xətası · `130` Ctrl+C. Ctrl+C zamanı yarımçıq nəticələr
saxlanılır və hesabat yenə yazılır.

---

## Təhlükəsiz sınaq (lokal)

Xarici hədəfə ehtiyac olmadan bütün pipeline-ı yoxlamaq üçün:

```bash
python main.py --config config/examples/example_local.yaml --mode full
```

Bu konfiq yalnız `127.0.0.1`-ə icazə verir. Testlər də yalnız lokal HTTP
fixture istifadə edir və heç bir xarici şəbəkəyə müraciət etmir:

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check --select E4,E7,E9,F,B,W qbh tests main.py
```

---

## Modullar

| Modul | Vəzifə |
|---|---|
| M1+ Deep Enum | subfinder + amass + crt.sh + alterx → dedup + scope + provenance |
| M1 Recon | httpx + naabu + katana + gau |
| M2 Fingerprint | Başlıq/HTML/imza ilə texnologiya + versiya (confidence ilə) |
| M3 Vuln | Nuclei — profilə uyğun template dəsti (aggressive → intrusiv; yalnız zərərli tag-lar həmişə istisna) |
| M4 JS Analiz | JS-də endpoint + secret (maskalanır) |
| M5 Content | ffuf (flat) + feroxbuster (recursive), wordlist limiti |
| API Enum | OpenAPI/Swagger kəşfi + kiterunner (yalnız GET parse) |
| API Fuzz | Schemathesis property-test (profil default ON; GET-only) |
| Param Enum | Arjun + x8 gizli parametr (yalnız GET) |
| Race | **YALNIZ lokal fixture** — sabit say, sərt concurrency |
| M6+ CVE İntel | NVD + OSV + GitHub Advisory + CISA KEV + EPSS (mənbə atribusiyası) |
| Validation / Confirm | Sübut yoxlaması, CVE/exposure təsdiqi, confidence |
| Bypass | 401/403 matrisi (path/header/verb) — aggressiv profildə |
| Secret Vault | JS secret-lərini şifrəli (Fernet) saxlayır; yalnız replay üçün açır |
| Secret Replay | Vault secret-lərini yalnız RoE + scope daxilində endpoint-lərə replay edir |
| Takeover | CNAME dangling aşkarlanması |
| Stealth | WAF aşkarlaması → adaptiv rate/concurrency/template + humanization (`qbh/stealth/`) |
| Hunter | `--mode hunt` orkestratoru (tam zəncir + dərin pass) |
| Chain | Kəşfləri avtomatik növbəti addıma zəncirləyir (`qbh/chain.py`) |
| Guardian | Scope + rate + adaptiv blok strategiyası + rotasiya audit |

---

## Zəncirləmə pipeline-ı

`recon → discover → enrich → test → confirm → poc → report`. Hər kəşf (subdomain,
JS endpoint, secret, parameter, CVE uyğunluğu, 401/403 yol) avtomatik növbəti
yoxlama addımına bağlanır. Cədvəl və detallar:
[docs/OFFENSIVE_PLAYBOOK.md](docs/OFFENSIVE_PLAYBOOK.md#2-zəncirləmə-cədvəli-qbhchainpy).

Hər addım `ctx.authorization`-dan keçir: `authorize_url()` (scope) və
`allows(action)` (proqram RoE). Qadağan olunmuş addım **atlanır** və audit
olunur — uydurma tapıntı YARADILMIR.

---

## Blok idarəetməsi (adaptiv Guardian)

`Guardian` "əyləc pedalı" deyil — **adaptiv** engine-dir. 403/429 cavabında
`block_strategy`-yə görə qərar verir:

| Strategiya | 429 | 403 |
|---|---|---|
| `respect` | `Retry-After`/cooldown gözlə | (403 → `backoff`) |
| `rotate` | identikliyi dəyiş | identikliyi dəyiş |
| `backoff_then_rotate` | əvvəl gözlə, sonra dəyiş | — |
| `escalate_bypass` | — | bypass matrisi üçün işarə qaldır |

**OPSEC rotasiyası** (`rotation`: `ua`, `headers`, `proxy`, `on_block`)
configurable-dir və hər rotasiya `identity.audit_log()`-da qeyd olunur.
Bypass mühərriki 403-ü görmək üçün xam probe sorğuları göndərir
(`observe_block=False`) ki, host cooldown-a düşməzdən əvvəl matris sınansın.

---

## Etik qaydalar və scope siyasəti

**Yeganə sərhəd — avtorizasiya scope-u.** Scope daxilində offensive texnikalar
(aktiv fuzzinq, bypass, rotasiya, PoC) icazəlidir. Scope-dan asılı olmayaraq
yalnız **zərərli** kateqoriyalar həmişə istisna edilir:

- Denial-of-Service (DoS) template-ləri/tag-ları
- Credential stuffing və auth brute-force
- İstehsalat (production) datasının dağıdılması

Race testı yalnız açıq göstərilən **lokal loopback fixture** üzərində işləyir.
Heuristik siqnallar (banner, başlıq) tək başına zəiflik sübutu DEYİL —
`candidate` kimi qeyd olunur və manual təsdiq tələb edir.

---

## Hesabat

`qbh/report/generator.py` üç formatda yazır:

- `reports/qbh_<ts>.md` — Markdown hesabat,
- `reports/qbh_<ts>.json` — strukturlaşdırılmış JSON,
- `reports/qbh_<ts>.h1.json` — **HackerOne** uyğun format (severity →
  `severity_rating`, CVSS balı, CWE təklifi, remediasiya, confidence).

Secret-lər hər formatda `redact` ilə maskalanır. Tapıntı həyat dövrü:
`candidate → confirmed → reported` (və `rejected`) + `evidence` cədvəli.

---

## Tool asılılıqları

| Tool | Məcburi | Quraşdırma |
|---|---|---|
| subfinder, dnsx, httpx, naabu, katana, nuclei, ffuf | ✅ | `go install` (avtomatik) |
| alterx, gau, jsluice, x8 | ➖ | `go install` (avtomatik) |
| arjun, schemathesis | ➖ | `pip install` (avtomatik) |
| feroxbuster | ➖ | `cargo install feroxbuster` (manual) |
| amass, nmap | ➖ | `sudo apt install amass nmap` (manual) |

Çatışmayan tool-lar skanı dayandırmır — aid olduğu mərhələ `skipped`
kimi qeyd olunur və hesabatda göstərilir.

---

## Troubleshooting

| Simptom | Həll |
|---|---|
| `scope boşdur` | Konfiqdə ən azı bir `scope` qeydi olmalıdır |
| `scope xaricində rədd edildi` | Hədəf konfiqdəki `in_scope` ilə uyğun deyil |
| `aggressiveness ... etibarsızdır` | Yalnız `passive\|normal\|aggressive` |
| Çatışmayan tool xəbərdarlığı | `python main.py --mode install --auto-install` |
| `go tapılmadı` | Go quraşdırın, sonra `--mode install` təkrarlayın |
| Hədəf cooldown-a düşdü | `block_strategy`-yə baxın; `rotate` rejimində identiklik dəyişir |
| Hesabat yaradılmadı | `[!] Hesabat yaradıla bilmədi` loquna baxın |

---

## Sənədləşdirmə

- [docs/OFFENSIVE_PLAYBOOK.md](docs/OFFENSIVE_PLAYBOOK.md) — offensive zəncirləmə, profillər, rotasiya
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — arxitektura və modul təsviri
- [docs/STEALTH.md](docs/STEALTH.md) — deteksiya-azaltma (stealth/OPSEC) qatı
- [docs/SECURITY.md](docs/SECURITY.md) — təhlükəsizlik modeli və siyasətlər
- [docs/SECURITY_VERIFICATION.md](docs/SECURITY_VERIFICATION.md) — dürüst PASS/PARTIAL yoxlaması
- [docs/REMEDIATION_REPORT.md](docs/REMEDIATION_REPORT.md) — v2.1→v2.2 remediasiya hesabatı
- [docs/TESTING.md](docs/TESTING.md) — test dəsti və işə salma
- [docs/CHANGELOG.md](docs/CHANGELOG.md) — dəyişikliklər tarixçəsi
- [docs/AUDIT_REPORT.md](docs/AUDIT_REPORT.md) — audit və remediasiya hesabatı

---

## Məlum məhdudiyyətlər

- Yalnız konfiqurasiyada AÇIQ icazə verilmiş scope daxilində işləyir.
- Subprocess alətlərinin öz daxili DNS/redirect davranışı üzərində tam nəzarət
  yalnız **OS səviyyəli sandbox** ilə mümkündür (layihə scope + egress qapısı
  tətbiq edir; bax [docs/STEALTH.md](docs/STEALTH.md)).
- Heuristik siqnallar manual təsdiq tələb edir.
- Tool çatışmazlığı, timeout və şəbəkə xətaları əhatəni azalda bilər.
- Race testi yalnız `--race-fixture` ilə **lokal loopback** fixture üzərində.
- Real hədəf üzərində canlı validasiya hələ aparılmayıb — Faza 4 yalnız loopback
  "vulnerable app" fixture üzərində uçdan-uca yoxlanılıb.
