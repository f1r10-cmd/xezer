# 🎯 QBH — Qarabug Autonomous Hunter v2.1 "Xəzər"

Bug bounty hədəfləri üzərində **yalnız icazəli scope daxilində** işləyən,
modul-əsaslı recon və zəiflik aşkarlama platforması.

> ⚠️ **Təhlükəsizlik prinsipi:** QBH yalnız konfiqurasiyada AÇIQ şəkildə
> icazə verilmiş hədəflərə qarşı işləyir. `--targets` bayrağı bu
> avtorizasiyanı **heç vaxt** keçə bilmir (fail-closed). Xarici hədəflərə
> icazəsiz skan qadağandır.

---

## Quraşdırma

```bash
# 1. Python asılılıqları
python -m venv .venv
.venv/bin/pip install -r requirements.txt

# 2. Tool-ların vəziyyətini yoxla (heç nə quraşdırmır)
python main.py --mode install --dry-run

# 3. Çatışmayan tool-ları təhlükəsiz üsulla quraşdır (yoxlama ilə)
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
- Testlər üçün: `pytest`, `pytest-asyncio`
- Tool-lar (bax: [Tool asılılıqları](#tool-asılılıqları))

---

## Konfiqurasiya

Konfiqurasiya YAML faylıdır. Nümunələr:

| Fayl | Təyinat |
|---|---|
| [config/example_local.yaml](config/example_local.yaml) | Yalnız `127.0.0.1` üçün təhlükəsiz nümunə |
| [config/targets.yaml](config/targets.yaml) | Real proqram scope-u (şablon) |
| [config/test_targets.yaml](config/test_targets.yaml) | Test nümunəsi |

```yaml
program: "Qarabug"
nvd_api_key: ""                 # istəyə bağlı (NVD rate limitini artırır)
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
proxy_file: ""                  # açıq routing üçün (blok aşma DEYİL)
antiblock:
  interface: "eth0"
```

**Validasiya qaydaları:** boş/xətalı `scope` HEÇ VAXT qəbul edilmir; rəqəmsal
limitlər aralıq yoxlanılır; naməlum açarlar və silinmiş evasion açarları
(`rotate_levels`, `credits`) barədə xəbərdarlıq verilir.

### Scope idarəetməsi

Dəstəklənən qaydalar: dəqiq domen, wildcard (`*.example.com`), kök domen,
IP ünvan, CIDR blok. Domenlər kanonikləşdirilir (lowercase, IDNA/punycode).
Suffix-confusion (`example.com.attacker.test`), malformed hostname, rəqəmsal
TLD və tək-etiketli adlar rədd olunur. Redirect-lər özümüz idarə edilir və
hər addım scope yoxlanılır — **redirect escape mümkün deyil**.

---

## CLI istifadəsi

```bash
# Tam skan (recon + vuln) — konfiqdəki bütün icazəli hədəflər
python main.py --config config/targets.yaml --mode full

# Yalnız recon / yalnız vuln / yalnız hesabat
python main.py --mode recon
python main.py --mode vuln
python main.py --mode report

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
| `--mode {full,recon,vuln,report,install}` | İcra rejimi |
| `--targets d1,d2` | Yalnız bu hədəflər (scope yoxlaması ilə) |
| `--rate N` | Saniyədə sorğu limiti (konfiq limitindən yuxarı ola bilməz) |
| `--severity {low,medium,high,critical}` | Hesabat filtri |
| `--proxy {off,single}` | Açıq routing (blok aşma DEYİL) |
| `--auto-install` | Çatışmayan tool-ları quraşdır (yoxlama ilə) |
| `--dry-run` | Heç nə icra etmə, yalnız planı göstər |
| `--active-fuzz` | Aktiv/state-dəyişən API fuzzinqi (**default: deaktiv**) |
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
python main.py --config config/example_local.yaml --mode full
```

Bu konfiq yalnız `127.0.0.1`-ə icazə verir. Testlər də yalnız lokal HTTP
fixture istifadə edir və heç bir xarici şəbəkəyə müraciət etmir:

```bash
.venv/bin/python -m pytest -q
```

---

## Modullar

| Modul | Vəzifə |
|---|---|
| M1+ Deep Enum | subfinder + amass + crt.sh + alterx → dedup + scope + provenance |
| M1 Recon | httpx + naabu + katana + gau (origin-IP bypass YOXDUR) |
| M2 Fingerprint | Başlıq/HTML/imza ilə texnologiya + versiya (confidence ilə) |
| M3 Vuln | Nuclei — yalnız təhlükəsiz seçilmiş template-lər |
| M4 JS Analiz | JS-də endpoint + secret (maskalanır) |
| M5 Content | ffuf (flat) + feroxbuster (recursive), wordlist limiti |
| API Enum | OpenAPI/Swagger kəşfi + kiterunner (yalnız GET parse) |
| API Fuzz | Schemathesis property-test (**yalnız `--active-fuzz`, GET-only**) |
| Param Enum | Arjun + x8 gizli parametr (yalnız GET) |
| Race | **YALNIZ lokal fixture** — sabit say, sərt concurrency |
| M6+ CVE İntel | NVD + OSV + GitHub Advisory + CISA KEV + EPSS (mənbə atribusiyası) |
| Validation | Sübut yoxlaması, confidence, false-positive sinfi |
| Guardian | Scope + rate + cooldown/circuit-breaker + audit (**evasion yoxdur**) |

---

## Blok idarəetməsi (Guardian)

QBH bloklanmanı **identiklik dəyişməklə aşmır**. Bu, açıq şəkildə
qadağandır.

- Hər host üçün rate limit və concurrency tətbiq olunur.
- Hər hosta **sabit** realist UA və `Accept-Language` istifadə olunur.
- **403/429** alındıqda hədəf **cooldown**-a salınır (eksponensial, maksimumla
  məhdud). `429` üçün `Retry-After` başlığı hörmətlə qarşılanır.
- Blok hadisələri audit üçün qeyd olunur; skan həmin hədəfdə dayandırılır və
  səbəb aydın şəkildə loqa yazılır.
- MAC rotasiyası, IP rotasiyası, UA rotasiyası və "credit" sürətləndirmə
  mexanizmi **tamamilə silinmişdir**.

---

## Etik qaydalar və non-destructive siyasət

Default icra siyasəti aşağıdakıları **istisna edir**:

- Denial-of-Service (DoS) testləri
- Dağıdıcı race-condition testləri (yalnız lokal fixture istisna)
- Data extraction
- Credential stuffing və auth brute-force
- İcazəsiz hesab yaratma və state-dəyişən əməliyyatlar
- İstehsalat (production) datasının dəyişdirilməsi

Heuristik siqnallar (banner, başlıq, sənəd aşkarlanması) tək başına zəiflik
sübutu DEYİL — `potential` kimi qeyd olunur və manual təsdiq tələb edir.

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
| Çatışmayan tool xəbərdarlığı | `python main.py --mode install --auto-install` |
| `go tapılmadı` | Go quraşdırın, sonra `--mode install` təkrarlayın |
| Hədəf cooldown-a düşdü | 403/429 cavabı — gözləyin, identiklik dəyişdirilmir |
| Hesabat yaradılmadı | `[!] Hesabat yaradıla bilmədi` loquna baxın |

---

## Sənədləşdirmə

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — arxitektura və modul təsviri
- [docs/SECURITY.md](docs/SECURITY.md) — təhlükəsizlik modeli və siyasətlər
- [docs/TESTING.md](docs/TESTING.md) — test dəsti və işə salma
- [docs/CHANGELOG.md](docs/CHANGELOG.md) — dəyişikliklər tarixçəsi
- [docs/AUDIT_REPORT.md](docs/AUDIT_REPORT.md) — audit və remediasiya hesabatı

---

## Məlum məhdudiyyətlər

- Yalnız konfiqurasiyada AÇIQ icazə verilmiş scope daxilində işləyir.
- Dağıdıcı testlər (DoS, state-dəyişən) default olaraq deaktivdir.
- Race testi yalnız `--race-fixture` ilə **lokal loopback** fixture üzərində.
- Heuristik siqnallar manual təsdiq tələb edir.
- Tool çatışmazlığı, timeout və şəbəkə xətaları əhatəni azalda bilər.
- Cloudflare/CDN origin-IP bypass **dəstəklənmir** (icazəsiz texnikadır).
