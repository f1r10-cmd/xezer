<!-- coderabbit-ai-generated:v1 -->

# Faza 4 — Brain və izah edilə bilən planlaşdırma

## Qəbul meyarları

| Meyar | Vəziyyət | Sübut |
|---|---|---|
| Request Classifier: 12 kateqoriya, confidence, evidence_refs | PASS | `tests/test_request_classifier.py`: multi-label, unknown, struktur/JS/schema/auth və finding reference testləri |
| 15 data-only vulnerability knowledge faylı | PASS | `tests/test_knowledge_base.py`: sxem, ilkin şərtlər, təhlükəsizlik və təsdiq meyarları |
| Yeni strategy üçün mərkəzi reyestr dəyişmir | PASS | `test_plugin_discovery_does_not_need_central_registration` |
| IDOR və JWT işlək plugin-lər | PASS — müşahidə və ilkin analiz | `tests/test_strategy_interface.py`: loopback cross-identity GET, scope rəddi; offline JWT candidate |
| ContextBuilder | PASS | HAR, graph references, auth references, URL Intelligence, əvvəlki findings/tests, müşahidə edilmiş OpenAPI və fingerprint toplanır |
| Mövcud Chain/Scheduler inteqrasiyası | PASS | `test_real_chain_routes_brain_through_scheduler`: 15 plan, 1 icra, mövcud finding/evidence cədvəllərində candidate |
| İzah edilə bilən davamlı planlar və rədd | PASS | `tests/test_brain_planner.py`: restart, rejection, dəyişmiş prerequisites, budget, scan isolation və CLI |
| Scope/RoE təkrar yoxlanır | PASS | Hazırlamadan sonra `jwt` qadağası əlavə edilərək icranın bloklanması yoxlanılıb |

## İcra və məlumat müqaviləsi

- Sxem **v9**: `test_plans`, `test_plan_events`. v8 HAR cədvəlləri və Phase 2 davamlı state qorunur. Sabit sxem-versiya gözləntiləri 9-a yenilənib; durable behavior testləri dəyişdirilməyib.
- `TestStrategy.execute_test` async-dir: mövcud Guardian/Scheduler asyncio müqaviləsinə uyğunlaşdırılıb. Bilik fayllarında icra kodu yoxdur.
- Hər müşahidə edilən request üçün bütün 15 sinif qiymətləndirilir. Plugin və ya ilkin şərt çatışmırsa plan səbəblə `deferred` qalır. Kateqoriya təkbaşına testdən kənarlaşdırmır.
- Task admission yalnız `TaskLedger`, bounded execution isə mövcud `Scheduler` ilə edilir. Conductor faktiki scheduler saylarını ümumi metrikalara əlavə edir.
- İcra başlamazdan əvvəl rejection, ilkin şərtlər və authorization yenidən yoxlanır. `--approve` RoE-ni üstələmir; `--reject <id> --reason ...` davamlı qərar yaradır.
- Plugin nəticələri vault-da şifrələnir. CLI plan, reason, classification confidence və evidence reference göstərir; token və response body göstərmir. Candidate tapıntısı mövcud `findings` və `evidence` cədvəllərinə bağlanır.

## Uyğunluq dəyişiklikləri

Əvvəl `program_rules.forbidden` yalnız səkkiz sabit action adını tanıyır, qalanlarını səssizcə atırdı. İstifadəçinin təsdiq etdiyi dəyişikliklə engine, plugin, knowledge class və installer tool adları tanınır; naməlum adlar warning-də görünür və icazəli testə təsir etmir. Conductor və Chain named-engine qərarlarını, shared egress qapısı isə tool qərarlarını `authorization.py` vasitəsilə yoxlayır.

İlk full regression keçidində `_run_chain()` string qaytaran test adapterinə `.data` tətbiq etdiyi üçün bir test uğursuz oldu. Əvvəlki nəticəni olduğu kimi qaytarma müqaviləsi bərpa edildi; original test qorundu.

## Yoxlamalar

- Seçilmiş integration suite: **124 passed**.
- Brain/egress/authorization/config: **87 passed**.
- Conductor/Brain: **59 passed**.
- Brain/Chain/authorization: **60 passed**.
- Son classifier/context/plugin/planner yoxlamaları: **20 passed**.
- Compile, ruff (`E4,E7,E9,F,B,W`), `git diff --check`, `pip check`: PASS.
- Benchmark: `_amain(write=False)` + `compare`; **36 tentative evidence, 53 endpoint, 53 parametr kombinasiyası, 236 icra**, regression yoxdur; baseline faylı qorunub.
<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:e9aec1aaacf70feb468cd7bb5843747aa0e2983197347b7ee75193ef97f7165a -->

- Yekun `.venv/bin/python -m pytest -o addopts='' -q --tb=short`: **1198 passed in 72.52s**, exit 0 (`/tmp/xezer-phase4-release.log`).

<!-- /coderabbit-ai-generated:v1 -->

## Dəqiq məhdudiyyətlər və sonrakı mərhələlər

- IDOR iki registered identity ilə read-only müşahidə toplayır; eyni `200` və ya body zəiflik təsdiqi deyil. DiffEngine və yoxlanılmış ownership/negative-control əsasında confirmation Phase 5–6 işidir.
- Digər 13 sinif üçün yeni Brain plugin-i yoxdur; mövcud mühərriklər saxlanır və işləməyə davam edir. Brain-də çatışmayan plugin açıq prerequisite kimi göstərilir.
- CLI `--test-plan` plan yaradır/göstərir; `--approve [id]` icranı təkrar yoxlamadan keçirir. Normal Chain axınında uyğun təhlükəsiz planlar ayrıca interaktiv təsdiq istəmir.
- GitHub workflow dispatch əvvəlki cəhddə HTTP 403 ilə bloklanıb; yeni branch commit üçün uzaq CI hələ təsdiqlənməyib.
- Scope/path/method YAML genişləndirilməsi, köhnə category-only exclusions, 429 rotation və session diaqnostikaları yekun buraxılışdan əvvəl ayrıca tamamlanacaq.
- Bu hesabat v4.0.0 buraxılış hazırlığı iddiası deyil.
