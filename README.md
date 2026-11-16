<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:6d38409435fe84d9ba81da2679e8ed0ee2bad553a4c991ea80f8091cd398c3f9 -->

# XEzer — avtomatlaşdırılmış təhlükəsizlik yoxlamaları

XEzer (`qbh/`) Python 3.10+ üzərində recon, zəiflik mühərrikləri, HAR idxalı,
sübut korrelyasiyası və davamlı skan bərpasını birləşdirir. Core LLM tələb etmir.
Mövcud Nuclei və digər mühərriklər saxlanılıb; Brain onların yerini tutmur.

**v4.0.0 hazırlığı: PARTIAL.** Fazalar 3–8 implementasiya edilib, lakin xarici
CLI-lərin daxili sorğularında path/method məhdudiyyətlərinin və cooldown-un tam
icrası təsdiqlənməyib. Buraxılış tag-i yaradılmayıb. Dəqiq nəticələr və qalan
meyarlar [yekun hesabatdadır](docs/FINAL_REPORT.md). CLI banner-indəki v3.0
əvvəlki versiya mətnidir, yeni release təsdiqi deyil.

## Lokal quraşdırma

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
cp config/examples/example_local.yaml config/targets.yaml
.venv/bin/python main.py --mode install --dry-run
.venv/bin/python main.py --mode install --auto-install
```

`config/targets.yaml` əsas konfiqurasiyadır və Git tərəfindən nəzərə alınmır.
Nümunə yalnız loopback scope verir. Real scope və credential-ları commit etməyin.
Quraşdırıcı `sudo` işlətmir, PATH dəyişmir; Go/pip/Cargo quraşdırmalarından sonra
binary-ni yoxlayır. Çatışmayan alət və manual addımlar ayrıca göstərilir.
`--dry-run` burada installer üçündür; bütün skan rejimləri üçün offline zəmanəti deyil.
ProjectDiscovery `httpx` ilə Python `httpx` toqquşduqda `QBH_HTTPX_BIN` istifadə edin.

## Əsas axınlar

```bash
.venv/bin/python main.py --mode full
.venv/bin/python main.py --resume 1
.venv/bin/python main.py --import-har traffic.har
.venv/bin/python main.py --list-imported --scan-id 1
.venv/bin/python main.py --request-graph --scan-id 1
.venv/bin/python main.py --test-plan --scan-id 1
.venv/bin/python main.py --test-plan --scan-id 1 --approve
.venv/bin/python main.py --pending-followups --scan-id 1
.venv/bin/python main.py --findings --scan-id 1 --severity high
.venv/bin/python main.py --compare-scans 1 2
```

HAR idxalı offline-dır. Əvvəlcə `QBH_VAULT_KEY` və ya `vault.key_file` vasitəsilə
şəxsi vault açarı qurulmalıdır; açar yoxdursa girişlər blocked/retryable saxlanır.
HAR-da görünən host skan icazəsi yaratmır. Plan baxışı login yaratmır;
`--approve` təhlükəsiz, icazəli və ilkin şərtləri ödənən testləri icra edə bilər.
Normal Chain axını da bu testləri ayrıca interaktiv təsdiqsiz icra edir.

## Davranış müqaviləsi

- Scope/RoE qərarları `qbh/authorization.py`-dədir. Açıq qadağa olmayan
  texnika scope daxilindəki bütün uyğun yollara tətbiq edilə bilər.
- Kateqoriya təkbaşına endpoint-i atmır: bounded applicability GET probe,
  ilkin şərtlər və büdcə səbəbləri saxlanır. Büdcə bütün endpoint-lərin bir
  keçiddə tamamlanacağına zəmanət vermir.
- Native HTTP 429 cavabında `Retry-After` və cooldown qorunur; rate limit-i
  keçmək üçün identity/proxy rotasiyası edilmir.
- Candidate və fərqli cavab confirmed zəiflik deyil. IDOR üçün iki fərqli
  yoxlanmış subject, owner-only siyasət, qorunan obyekt və negative control tələb olunur.
- Genuinely destructive əməliyyatlar bloklanır. `allow_destructive` köhnə
  flag adı saxlanıb, yalnız qeyri-zərərli intrusive template seçimini dəyişir.
- External tool daxilindəki trafik üçün native HTTP zəmanətini genişləndirmirik;
  bu, hazırkı release maneəsidir.

## Yoxlama və sənədlər

```bash
.venv/bin/python -m compileall -q qbh main.py
.venv/bin/python -m ruff check --select E4,E7,E9,F,B,W .
.venv/bin/python -m pytest --cov=qbh --cov-report=term-missing --cov-fail-under=70
.venv/bin/python -m pytest tests/e2e -q
```

Saxlanmış benchmark: **36 tentative evidence, 53 endpoint, 53 parametr
kombinasiyası, 236 icra**. Bunlar confirmed vulnerability sayı deyil.
Baseline faylı dəyişdirilmədən iki müqayisəli keçid CI-da işləyir.

- [Arxitektura](docs/ARCHITECTURE.md)
- [Konfiqurasiya və T&R](docs/CONFIG.md)
- [CLI və iki istifadəçili lokal ssenari](docs/USAGE.md)
- [Dəyişikliklər](CHANGELOG.md)
- [Qəbul meyarları və yoxlama sübutları](docs/FINAL_REPORT.md)


<!-- /coderabbit-ai-generated:v1 -->