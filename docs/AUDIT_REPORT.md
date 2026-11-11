# Audit və remediasiya hesabatı — QBH v2.1 "Xəzər"

**Tarix:** 2026-11-12
**Mühit:** Kali Linux x86_64 · Python 3.14.8 · SQLite · aiohttp 3.14.5
**Əhatə:** `/home/kali/Desktop/cf-hunter/qbh-xazar/`

Bu hesabat yalnız **real yoxlanılmış** nəticələri əks etdirir. Heç bir nəticə
uydurulmamışdır.

---

## 1. Metodologiya

Fazalar ardıcıl icra olundu:

1. **Repo auditi** — bütün Python, YAML, README və test faylları oxundu;
   defektlər kod üzərində müəyyən edildi.
2. **Təhlükəsizlik əsası** — scope enforcement, HTTP policy, cooldown.
3. **Core arxitektura** — Conductor, nəticə kontraktları, konfiq, baza.
4. **Quraşdırıcı** — aşkarlama/quraşdırma ayrılması, dry-run, verify.
5. **Mühərrik remediasiyası** — hər mühərrik ayrıca.
6. **Hesabat** — redaction və escape.
7. **Avtomatlaşdırılmış testlər** — 151 test.
8. **Sənədləşdirmə** — README + `docs/`.
9. **Yekun yoxlama** — import, sintaksis, CLI smoke, pytest.

## 2. Aşkarlanmış defektlər və düzəlişlər

| # | Defekt | Fayl | Ciddilik | Düzəliş |
|---|---|---|---|---|
| 1 | CLI konfiqi səhv yükləyirdi (`Config(args.config)` — `Config.load` yerinə) | `main.py` | Yüksək | `Config.load(args.config)`; xəta idarəsi və çıxış kodları əlavə edildi |
| 2 | `_safe()` istisnanı tutur, lakin **nəticə qaytarmırdı** → aşağı axın `None` alırdı | `conductor.py` | Yüksək | `_run_stage()` — həmişə `StageResult` qaytarır; `factory` əsaslı çağırış |
| 3 | `init_db()` indeksləri sütundan əvvəl yaradırdı → `no such column: fingerprint` | `db.py` | Yüksək (baza açılmırdı) | `SCHEMA_TABLES`/`SCHEMA_INDEXES` bölündü; sıra: cədvəl → `_migrate` → indeks |
| 4 | `insert_finding()` təkrar halda `lastrowid` ilə səhv `id` qaytarırdı | `db.py` | Orta | `ON CONFLICT ... RETURNING id` |
| 5 | JSON hesabatında redaction placeholder idi (`[self_redacted for ...]`) | `report/generator.py` | Yüksək (secret sızması) | title/description/evidence/curl_repro üçün real `redact()` |
| 6 | MAC/IP/UA/proxy rotasiyası və "credit" sürətləndirmə (blok aşma) | `antiblock/*` | Kritik (etik/texniki) | Hamısı SİLİNDİ; yerinə cooldown + circuit breaker |
| 7 | 403/429 evasion siqnalı kimi qiymətləndirilirdi | `http_policy.py` | Kritik | 403/429 → cooldown; `Retry-After` hörmətlə qarşılanır |
| 8 | Race mühərriki real hədəflərə "blast" edirdi | `engines/race.py` | Kritik | Yalnız lokal loopback fixture; sabit say; sərt concurrency |
| 9 | API fuzz default aktiv idi | `engines/api_fuzz.py` | Orta | Yalnız `--active-fuzz`; GET-only |
| 10 | CF/CDN origin-IP bypass modulu | `qbh/cfp/` | Kritik (icazəsiz) | Modul SİLİNDİ |
| 11 | Konfiq boş/xətalı scope-u qəbul edə bilirdi | `config.py` | Yüksək | Fail-closed validasiya; boş scope rədd |
| 12 | Redirect-lər otomatik izlənilirdi (scope yoxlaması yox) | `http_policy.py` | Yüksək | `allow_redirects=False` + hər addımda `resolve_redirect` |
| 13 | Quraşdırma binari yoxlamadan "uğur" raport edə bilirdi | `installer.py` | Orta | Hər quraşdırmadan sonra yenidən yoxlama |
| 14 | `aiohttp 3.14` — stream oxunmuş gövdə üçün `get_encoding()` `RuntimeError` atırdı | `http_policy.py` | Orta | Try/except + UTF-8 fallback |

## 3. Tətbiq edilmiş təhlükəsizlik zəmanətləri

- **Scope:** fail-closed; exact/wildcard/IP/CIDR; IDNA; suffix confusion və
  malformed hostname rədd; redirect hər addımda yoxlanılır; `--targets`
  avtorizasiyanı keçmir.
- **HTTP:** rate limit, concurrency, connect/total timeout, məhdud backoff,
  `Retry-After`, body limiti, graceful cancellation — hamısı vahid policy-də.
- **Blok:** 403/429 → cooldown + circuit breaker + audit; **evasion yoxdur**.
- **Non-destructive:** DoS, race (lokal istisna), data extraction, credential
  hücumu, state-dəyişən əməliyyatlar default olaraq deaktivdir.
- **Subprocess:** `shell=False` — command injection mümkün deyil.
- **Gizlilik:** secret maskalama; Markdown/HTML escape; heuristika
  "confirmed" kimi təqdim olunmur.

## 4. Yoxlama nəticələri (icra edilmiş)

### 4.1 Sintaksis və importlar

```
$ .venv/bin/python -m compileall -q qbh main.py
COMPILEALL OK

$ .venv/bin/python -c "import <29 modul + main>"
ALL IMPORTS OK: 29 modullar
cfp mövcuddur? False
```

### 4.2 Avtomatlaşdırılmış testlər

```
$ .venv/bin/python -m pytest -q
... 151 test keçdi (0 uğursuz)
```

| Fayl | Keçən test |
|---|---|
| `tests/test_scope.py` | 40 |
| `tests/test_engines.py` | 33 |
| `tests/test_config.py` | 25 |
| `tests/test_db.py` | 20 |
| `tests/test_http_policy.py` | 18 |
| `tests/test_redact.py` | 15 |
| **Cəmi** | **151** |

Testlər xarici şəbəkəyə müraciət etmir.

### 4.3 CLI smoke testləri

| Ssenari | Gözlənilən | Nəticə |
|---|---|---|
| `--help` | 0 | ✅ 0 |
| Mövcud olmayan konfiq | 2 + aydın xəta | ✅ `exit=2`, `Konfiqurasiya xətası: konfiq faylı tapılmadı` |
| Scope xarici `--targets` | 1 + rədd | ✅ `[⛔] scope xaricində rədd edildi`, `Pipeline dayandırıldı` |
| `--mode install --dry-run` | Hesabat, `sudo` yoxdur | ✅ Tool hesabatı (OS/Go versiya, present/skipped) |
| `--mode report` | Hesabat faylı | ✅ `reports/qbh_*.md` + `.json` |

Quraşdırma hesabatı (dry-run, cari mühit): Go 1.27.3 mövcud; `subfinder`,
`httpx`, `katana`, `nuclei`, `ffuf`, `feroxbuster`, `amass`, `nmap` present;
`dnsx`, `naabu`, `alterx`, `gau`, `jsluice`, `x8`, `arjun`, `schemathesis`
skipped (tövsiyə ilə). `sudo` işlədilmədi.

## 5. Qalan məhdudiyyətlər

- İki məcburi tool (`dnsx`, `naabu`) cari mühitdə quraşdırılmayıb; quraşdırma
  üçün `--mode install --auto-install` tələb olunur (bu auditdə **sistem
  paketi quraşdırmaq icazəsi olmadığı üçün** icra olunmadı).
- `--mode full` tam boru xətti real alətlərlə şəbəkə trafiki yaradır; audit
  daxilində xarici hədəflərə skan **aparılmadı**.
- Heuristik siqnallar manual təsdiq tələb edir.
- Üçüncü tərəf CVE mənbələri xarici API-lərdir və onlara hədəf scope-u tətbiq
  olunmur.
