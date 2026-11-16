<!-- coderabbit-ai-generated:v1 -->

# XEzer istifadə qaydası

Əmrləri repository root-da, hazırlanmış `.venv` ilə işlədin. Default konfiqurasiya
`config/targets.yaml`-dır; nümunəni `--config config/examples/example_local.yaml`
ilə seçmək olar. Default skan rejimi `full`-dur.

## Mövcud rejimlər

| `--mode` | Məqsəd |
|---|---|
| full | Recon, mühərriklər, validation, Chain, hesabat |
| recon | Kəşf mərhələləri |
| vuln | Mövcud target məlumatları üzərində zəiflik mərhələləri |
| hunt | Avtomatik zəncir və əlavə pass-lar |
| report | DB-dən MD/JSON/HackerOne hesabatı |
| install | Tool detection və açıq tələb edilərsə quraşdırma |

`--targets`, `--aggressiveness`, `--rate`, `--proxy`, `--active-fuzz`,
`--no-active-fuzz`, `--allow-state-changing`, `--race-fixture`, `--race-count`,
`--race-concurrency` əvvəlki CLI müqaviləsi ilə saxlanır. `--help` tam siyahını verir.
Proxy rate limit-dən yayınmaq üçün istifadə edilmir.

## HAR və Brain

```bash
.venv/bin/python main.py --import-har traffic.har
.venv/bin/python main.py --import-har traffic.har --scan-id 1
.venv/bin/python main.py --list-imported --scan-id 1
.venv/bin/python main.py --request-graph --scan-id 1
.venv/bin/python main.py --test-plan --scan-id 1
.venv/bin/python main.py --test-plan --scan-id 1 --approve
.venv/bin/python main.py --test-plan --scan-id 1 --approve PLAN_ID
.venv/bin/python main.py --test-plan --scan-id 1 --reject PLAN_ID --reason 'lokal ssenari üçün rədd'
```

`PLAN_ID` əvəzinə plan çıxışındakı ID yazılır. HAR import offline parse, graph və
feedback plan yenilənməsidir; import zamanı login və target sorğusu yoxdur.
Pozulmuş giriş ayrıca invalid/reason kimi saxlanır. Vault olmadıqda blocked
entry-lər üçün açarı bərpa edib faylı yenidən idxal edin. Duplicate request-in
fərqli response occurrence-i itmir. Graph inference confidence/provenance
əsasında yoxlanır; ardıcıllıq dependency sübutu deyil.

İki yeni strategy IDOR və JWT-dir. Digər bilik sinifləri də qiymətləndirilir,
çatışmayan executor/prerequisite reason ilə görünür. `--approve` nəticəni confirmed
etmir; yalnız təkrar yoxlamadan keçən təhlükəsiz icraya seçim bildirir.

## Davamlılıq və nəticələr

```bash
.venv/bin/python main.py --resume 1
.venv/bin/python main.py --pending-followups --scan-id 1
.venv/bin/python main.py --findings --scan-id 1 --severity high
.venv/bin/python main.py --compare-scans 1 2
.venv/bin/python main.py --mode report
```

`--resume` ID-siz son running skanı seçir. Completed task-lar təkrarlanmır,
interrupted task-lar yenidən növbəyə alınır; scope yenidən yoxlanır.
`--findings` minimum severity üzrə maskalanmış metadata verir (default low).
`--compare-scans` host/module/title/template/status və multiplicity əsasında
added/removed/unchanged sayır; vulnerability-nin həqiqətən düzəldiyini sübut etmir.
CLI banner-dən sonra JSON çıxışı verir; bütöv stdout tək JSON sənədi deyil.

## Təkrarlana bilən iki istifadəçili ssenari

```bash
.venv/bin/python -m pytest tests/e2e -q
.venv/bin/python -m pytest tests/test_auth_state.py tests/test_js_intelligence.py -q
```

Testlər ephemeral loopback tətbiqi yaradır; kənar hesab yaratmır. `user_a` və
`user_b` ENV credential-ları ilə login olur. `/vulnerable/7` səhvən digər
istifadəçiyə protected JSON qaytarır; `/secure/7` düzgün 403 verir. HAR real
fixture cavablarından qurulur, sonra offline idxal edilir. Bütün 15 sinif üzrə
səbəbli planlar, graph provenance, auth confirmation və negative control yoxlanır.
JS/map fixture-i API route, frontend permission və HAR əlaqələrini yoxlayır.
Fixture portları test tərəfindən seçilir; sənəddəki 8080 avtomatik service deyil.

## Quraşdırma nəticələrinin şərhi

```bash
.venv/bin/python main.py --mode install --dry-run
.venv/bin/python main.py --mode install --auto-install
```

`present/installed` binary probe-nun keçdiyini göstərir; target-a qarşı həmin
alətin bütün imkanlarının doğrulanması deyil. `failed`, `manual`, `skipped`
uğurlu quraşdırma sayılmır. Exit 0 yalnız required alətlər baxımından uğurlu
ola bilər; optional sətirləri də oxuyun. Real isolated install nəticələri və
manual remediation [FINAL_REPORT](FINAL_REPORT.md)-dadır.
