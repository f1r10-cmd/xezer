# Stealth & Low-Detection rejimi — QBH v3.0 "Xəzər"

Bu sənəd deteksiya-azaltma (OPSEC) qatını təsvir edir. Məqsəd: **sakit
tədqiqatçı** kimi skan etmək — ucadan qışqıran skaner kimi deyil. Bu, yalnız
**avtorizasiya olunmuş** testlərdə və scope daxilində legitimdir.

> **Dürüstlük.** Bu qat deteksiyanı AZALDIR, "görünməzlik" VƏD ETMİR.
> CAPTCHA avtomatik həll OLUNMUR. Subprocess alətləri üçün tam egress
> nəzarəti OS səviyyəli sandbox tələb edir (bax: aşağıda "Məhdudiyyətlər").

## Konfiqurasiya (`config.yaml`)

```yaml
stealth:
  impersonate: chrome          # off | chrome | safari | firefox | edge (curl_cffi)
  proxy_strategy: off          # off | single | rotate | residential | tor
  pacing: aggressive           # passive | normal | aggressive
  pacing_max_overhead: 1.15    # bulk fazalarda maksimal yavaşlama (sürət qorunur)
  waf_adapt: true              # WAF aşkarlaması → bypass/rate/template uyğunlaşması
  tor_for_sensitive_only: true # Tor YALNIZ həssas fazalarda (bulk sürəti qorunur)
```

`stealth` bloku default olaraq **aktivdir**. `proxy_strategy: tor` seçilsə də,
Tor bulk fazalarda (`recon`, `content`, `ferox`, `fuzz`, `param_enum` ...)
avtomatik `direct`-ə düşür — gecikmə sürəti məhv etməsin.

## Workflow (A → F)

| Mərhələ | Alət(lər) | Stealth parametrləri |
|---|---|---|
| **A. Passiv** | subfinder/amass, gau, katana | merge + dedup; hər host egress scope qapısından keçir |
| **B. WAF barmaq izi** | httpx (`-random-agent -rate-limit N`), `wafdetect` (aiohttp) | ilk təmas təmkinli; nəticə `ctx.waf_name`-ə yazılır |
| **C. Adaptiv aktiv** | (WAF nəticəsinə görə) | `build_plan` → rate/concurrency/UA/template seçimi |
| **D. Portlar** | naabu (`-rate N`) | WAF varsa `-rate` azaldılır (≤3), yoxsa ≤10 |
| **E. Vulnerabilities** | nuclei (`-severity medium,high,critical -tags cve,exposure,misconfig -rl N -c M -exclude-tags dos,brute-force,...`) | WAF varsa `-rl ≤3`, `-c ≤5`, geniş `-exclude-tags`, UA rotasiyası ON |
| **F. Content** | ffuf (`-ac -rate N -t M`), arjun/x8 (param), feroxbuster | `-rate`/`-t` plana görə; insan-təqlidi başlıqlar |

WAF aşkarlaması **E/F-dən ƏVVƏL** baş verir (`Conductor.run_vuln`: `fingerprint`
→ `wafdetect` → ... → `vuln`/`content`/`ferox`), ona görə adaptiv qərar aktiv
fazalara real tətbiq olunur.

## Adaptiv qaydalar (`qbh/stealth/policy.py`)

`build_plan(waf_name, base_rate, base_concurrency, waf_adapt)`:

| Vəziyyət | rate | concurrency | UA rotasiyası | template |
|---|---|---|---|---|
| WAF aşkarlanmadı | `min(base, 10)` | `base` | OFF | profilə görə |
| WAF aşkarlandı | `min(base × faktor, 3)` | `min(base, 5)` | ON | mühafizəkar (geniş `-exclude-tags`) |
| `waf_adapt: false` | `min(base, 10)` | `base` | OFF | dəyişmir |

- `faktor = rate_factor_for(waf)` → cloudflare/akamai 0.5, imperva/aws 0.4,
  fastly/sucuri 0.7, modsecurity/generic 0.6, naməlum 0.75.
- Hər qərar `audit`-ə `{"event": "stealth_plan", ...}` kimi yazılır →
  hansı sürətin nə üçün dəyişdiyi sonradan izlənə bilər.
- `429` → Guardian nərdivanı `respect_retry_after` → `rotate_identity` →
  `waf_adapt_backoff` → `stealth_mode` → `defer_intrusive` (Retry-After hörmət
  olunur; intrusiv fazalar müvəqqəti təxirə salınır).

## İnsan-təqlidi (humanization) — `qbh/stealth/humanize.py`

- **UA hovuzu**: 9 real UA (masaüstü + mobil), dövrəli rotasiya (sabit deyil).
- **Başlıq dəstləri**: brauzer ailəsinə uyğun `Sec-Fetch-Dest/Mode/Site`,
  `Accept-Language`, `Accept`, `Accept-Encoding`, `Upgrade-Insecure-Requests`.
- **Jitter**: sorğular arasında `0.5–3.0 s` dəyişkən fasilə (sabit inter-arrival
  YOX). Deterministik `rng` ilə — testlər flaky deyil.

## Alət bayraqları — dürüst qeydlər

Bəzi bayraqların dəqiq semantikası alət versiyasından asılıdır. Şübhə olduqda
**təhlükəsiz (aşağı sürət) variant** seçilmişdir:

- `httpx -rate-limit <n>` və `-random-agent` — ProjectDiscovery httpx-də
  mövcuddur (saniyədə maks. sorğu; daxili random UA). `-random-agent` bizim
  rotasiya ilə konflikt yaratmasın deyə httpx-ə manual `-H User-Agent`
  verilmir.
- `nuclei -rl <n>` (rate-limit), `-c <n>` (concurrency), `-H` (başlıq).
- `ffuf -rate <n>` (saniyədə sorğu), `-t <n>` (paralel), `-ac` (autocalibrate).
- `feroxbuster --rate-limit <n>`, `-t <n>`.
- `naabu -rate <n>` — SYN paket sürəti (HTTP rps-dən fərqlidir, lakin WAF
  halında yenə azaldılır — təhlükəsiz default).
- **nmap** default olaraq `-f` (fragment) və `-D` (decoy) İSTİFADƏ OLUNMUR;
  tövsiyə olunan salam varyantı `-sT -T2 --max-rate 50 --max-retries 2
  --version-light`-dir. Bu layihədə port taraması naabu ilə aparılır.

## Səs-küyün azaldılması

- URL/host dedup; `scan_id` üzrə DB nəticələrinin təkrar istifadəsi.
- Təsdiqlənmiş (confirmed) tapıntı heç vaxt yenidən skan edilmir.
- Wordlist ölçüsü məhdudlaşdırılır (`limited_wordlist`).

## Məhdudiyyətlər (dürüst)

- `curl_cffi` yoxdursa TLS təqlidi (`impersonate`) mövcud deyil — `HttpPolicy`
  şəffaf şəkildə aiohttp-a düşür və bunu gizlətmir.
- Subprocess alətlərinin öz DNS/redirect davranışı üçün tam nəzarət yalnız
  OS səviyyəli sandbox (namespace/firejail) ilə mümkündür; layihə egress
  qapısı ilə hədəf validasiyası edir, lakin alət daxili redirect-lərə tam
  nəzarət edə bilməz.
- Proxy rotasiyası `config/proxies.txt` varsa istifadə olunur; credential-lar
  yalnız lokal konfiqurasiyada saxlanılır — heç bir secret commit olunmur.
