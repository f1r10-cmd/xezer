# Təhlükəsizlik modeli — QBH v2.1 "Xəzər"

QBH **avtorizə edilmiş** bug bounty və təhlükəsizlik qiymətləndirməsi üçün
nəzərdə tutulmuşdur. Təhlükəsizlik modeli üç sütun üzərində qurulur:
**scope enforcement**, **proqnozlaşdırıla bilən sorğu davranışı** və
**non-destructive testinq**.

## 1. Scope enforcement (fail-closed)

Bütün hədəf yoxlamaları [`qbh/scope.py`](../qbh/scope.py) içindəki
`ScopeEnforcer`-dən keçir.

- **Fail-closed:** scope boş, xətalı və ya qeyri-müəyyəndirsə — hər şey rədd
  olunur. `is_empty` olduqda `is_authorized()` həmişə `False`, `authorize()`
  həmişə `ScopeError` atır.
- **Normalizasiya:** host lowercase edilir, sondakı nöqtə silinir, Unicode →
  IDNA (punycode) çevrilir.
- **Qayda növləri:** `exact` (dəqiq domen), `wildcard` (`*.example.com`),
  `ip` (dəqiq IP), `net` (CIDR). `deny` (`out_of_scope`) `allow`-dan ÜSTÜN
  tutulur.
- **Suffix confusion qarşısı:** `example.com.attacker.test` uyğun gəlmir,
  çünki wildcard `host.endswith("." + base)` yoxlayır və `exact` tam bərabərlik
  tələb edir.
- **Malformed input:** boşluq, slash, yolverilməz simvol, rəqəmsal TLD,
  tək-etiketli ad (`localhost`) rədd olunur.
- **IP avtorizasiyası:** yalnız konfiqdə AÇIQ şəkildə göstərilibsə icazəlidir.
- **Redirect:** `resolve_redirect()` hər redirect addımını `urljoin` +
  `authorize_url` ilə yoxlayır → **redirect escape mümkün deyil**.

### Tətbiq nöqtələri (hər mühərrikin icra sərhədi)

1. `Conductor.resolve_targets()` — CLI `--targets` daxil olmaqla hər hədəf.
2. `HttpPolicy.request()` — hər HTTP sorğusundan ƏVVƏL host avtorizasiyası.
3. Hər mühərrik (`DeepEnumEngine.run`, `ReconEngine.run`, ...) — giriş
   yoxlaması və nəticələrin süzülməsi.
4. `resolve_redirect()` — hər redirect addımı.

**`--targets` avtorizasiyanı heç vaxt keçmir** — o, yalnız konfiq hədəflərini
əvəz edir, scope yoxlaması isə eyni qalır.

## 2. HTTP sorğu siyasəti

Bütün mühərriklər eyni [`qbh/http_policy.py`](../qbh/http_policy.py)
`HttpPolicy`-dən istifadə edir:

- **Rate limit:** host başına token-bucket.
- **Concurrency:** `asyncio.Semaphore` ilə məhdudlaşdırılır.
- **Timeout:** connect və total timeout ayrıca tətbiq olunur.
- **Retry:** yalnız `aiohttp.ClientError` / timeout üçün, məhdud eksponensial
  backoff ilə.
- **Retry-After:** `429` cavabında rəqəm və HTTP-date formatı parse olunur və
  hörmətlə qarşılanır.
- **Body limiti:** cavab gövdəsi `max_body` qədər oxunur (truncation
  qeyd olunur) — yaddaş və zəhərli cavab qarşısı.
- **Graceful cancellation:** `asyncio.CancelledError` yuxarı ötürülür; heç bir
  sorğu yarımçıq vəziyyətdə "udulmur".

## 3. Blok davranışı — adaptiv (configurable)

v2.2-də blok idarəsi **"əyləc pedalı" deyil, adaptiv engine**-dir. Yeganə
toxunulmaz sərhəd avtorizasiya scope-udur; identiklik rotasiyası legitim
OPSEC-dir və **audit olunur**.

`block_strategy` 403/429 cavabını idarə edir:

| Strategiya | 429 | 403 |
|---|---|---|
| `respect` | `Retry-After`/cooldown gözlə | (403 → `backoff`) |
| `rotate` | identikliyi dəyiş | identikliyi dəyiş |
| `backoff_then_rotate` | əvvəl gözlə, sonra dəyiş | — |
| `escalate_bypass` | — | bypass matrisi üçün işarə qaldır |

- **Cooldown:** `respect`/`backoff` strategiyalarında hədəf eksponensial
  cooldown-a salınır (`max_cooldown`-la məhdud); `429` üçün `Retry-After`
  hörmətlə qarşılanır.
- **Circuit breaker:** uğurlu cavab (`2xx`/`3xx`) blok sayğacını sıfırlayır.
- **Rotasiya (`rotation`):** `ua`, `headers`, `proxy`, `on_block` — profil və
  YAML ilə configurable. Hər rotasiya `identity.audit_log()`-da qeyd olunur.
- **Audit:** hər blok hadisəsi (`BlockEvent`) tarix, status və tətbiq olunan
  strategiya ilə qeyd olunur.
- **Qadağan qalanlar:** MAC/IP səviyyəsində spoofing və "credit" əsaslı sürət
  artırma mexanizmi YOXDUR — bunlar scope-dan kənar texnikalardır.

## 4. Non-destructive testinq

Scope-dan asılı olmayaraq yalnız **zərərli** kateqoriyalar həmişə istisna
edilir:

- Denial-of-Service (DoS) template-ləri/tag-ları
- Credential stuffing və auth brute-force
- Production data modifikasiyası / data extraction
- İcazəsiz hesab yaratma

Əlavə qapılar:

- **Race** yalnız `--race-fixture` ilə **lokal loopback** fixture üzərində
  mümkündür; sorğu sayı sabitdir (maks 20), concurrency sərt məhduddur
  (maks 5). Loopback olmayan fixture `fail` ilə rədd olunur.
- **API Fuzz** profil default-una görə ON-dur (`--no-active-fuzz` ilə söndürülür);
  yalnız GET metodları yoxlanır.
- **Param Enum** yalnız GET istifadə edir.
- **Nuclei** profilə uyğun template dəsti ilə işləyir: `aggressive` profildə
  intrusive/exploit template-ləri də işlədilir; yalnız zərərli kateqoriyalar
  (`dos`, `brute-force`, `creds-stuffing`) həmişə istisna edilir. Xaricdən
  yüklənmiş ixtiyari template icra olunmur.
- **Bypass** (401/403 matrisi) və **PoC** yalnız scope daxilində və proqram
  qaydaları (`program_rules.forbidden`) icazə verdikdə işə düşür.
- **CF/CDN origin-IP bypass** funksionallığı silinmişdir (icazəsiz texnika).

## 5. Subprocess təhlükəsizliyi

- Bütün alət çağırışları `adapters/base.run_process` vasitəsilə aparılır.
- `shell=False` (arqument siyahısı) — **command injection mümkün deyil**.
- Timeout tətbiq olunur; geri qaytarılan nəticə parse edilərkən yoxlanılır.

## 6. Gizli məlumatların idarəsi

- [`qbh/redact.py`](../qbh/redact.py) secret/token/parol nümunələrini
  (AWS, Google, GitHub, Slack, JWT, private key, `Authorization` başlığı və s.)
  maskalayır.
- **JS analizdə tapılan secret-lər** yalnız maskalanmış formada saxlanır;
  onlardan İSTİFADƏ EDİLMİR.
- Hesabatda (Markdown və JSON) başlıq, təsvir, sübut və `curl_repro` redact
  olunur.
- Etibarsız məzmun Markdown/HTML üçün escape olunur → **report injection /
  XSS mümkün deyil**.

## 7. Quraşdırma təhlükəsizliyi

- Avtomatik `sudo` icra olunmur.
- Shell profilləri və PATH özbaşına dəyişdirilmir.
- Yalnız verified `go install` / `pip install` əməliyyatları; remote shell
  skriptləri icra olunmur.
- Hər quraşdırmadan sonra binari yenidən yoxlanılır; uğursuzluq "uğur" kimi
  raportlanmır.
- Nuclei template-ləri adi skan zamanı avtomatik yenilənmir.

## 8. Məlum məhdudiyyətlər

- Heuristik siqnallar (banner, başlıq) tək başına zəiflik sübutu DEYİL —
  `potential` statusu ilə qeyd olunur.
- Scope yalnız konfiqurasiya dəqiq və tam olduqda qoruyucudur.
- Üçüncü tərəf CVE mənbələri (NVD, OSV, KEV, EPSS) xarici API-lərdir; onlar
  skan hədəfi DEYİL və onlara hədəf scope-u tətbiq olunmur.
