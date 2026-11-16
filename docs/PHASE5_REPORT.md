<!-- coderabbit-ai-generated:v1 -->

# Faza 5 — Differential Analysis Engine

## Vəziyyət: PASS

`qbh/brain/diff_engine.py` HTTP cavabları arasında fərqləri izah edir. `DiffResult` zəiflik təsdiqi deyil; confidence müşahidə edilən fərqin etibarlılığına aiddir. Nəticə `difference_summary`, `relevant_evidence`, `confidence`, `possible_interpretations`, `false_positive_considerations`, `recommended_next_verification` sahələrini qaytarır.

## Qəbul meyarları və sübut

| Meyar | Yoxlama |
|---|---|
| Status, headers, content-type, redirect və error davranışı | `test_status_headers_redirect_errors_have_separate_evidence` |
| JSON structure, seçilmiş semantic fields, list order | `test_selected_semantics_and_list_order_are_preserved` |
| Ownership və sensitive-data göstəriciləri | `test_sensitive_presence_and_ownership_still_visible_when_bodies_match` |
| Body similarity və tam body fingerprint | `test_limits_never_claim_full_equality_or_silently_drop_evidence` |
| Timestamp/request ID/CSRF/nonce normalization | `test_normalization_keeps_raw_changes_and_real_ownership_difference`, `test_only_volatile_fields_still_appear_in_evidence` |
| Normalization type/presence/ownership fərqini gizlətmir | Parametrli type/presence testləri və explicit randomized-path testi |
| Yalnız müqayisə edilə bilən təkrar timing ölçmələri | `test_timing_needs_repeated_comparable_finite_samples` |
| Secret-lər output-a çıxmır | Header/query secret, sensitive JSON key və field value testləri |
| Ambiguous JSON və binary references | Duplicate-key/NaN və binary-reference testləri |
| Mövcud IDOR plugin consumer | `tests/test_strategy_interface.py`: Guardian ilə loopback müşahidəsi və DiffResult evidence inteqrasiyası |

## Davranış müqaviləsi

- `ResponseSnapshot`, mövcud `HttpResponse` və HAR/dict cavab formaları qəbul edilir. Status etibarlı tam ədəd olmalıdır.
- Bütün header dəyərləri və JSON scalar dəyərləri evidence-də fingerprint ilə göstərilir. Naməlum JSON key/header adları da maskalanmış identifikatorla göstərilir. Xam secret-lər log və CLI üçün çıxarılmır.
- Normalization yalnız məhdud volatile adlara və ya açıq verilmiş randomized JSON paths-a tətbiq olunur. Field əlavə/silmə, type dəyişməsi, ownership/security sahələri normallaşdırılmır. Volatile dəyişikliklər ayrıca evidence olaraq qalır.
- JSON duplicate keys və NaN/Infinity standart semantik müqayisəyə qəbul edilmir. Body fərqi və parse-behavior fərqi saxlanır.
- Tam body fingerprint həmişə fərqi qeyd edir. Similarity böyük cavablarda başlanğıc/orta/son hissələrdən bounded sample istifadə edir; bu vəziyyət `sampled` ilə göstərilir.
- JSON node/depth/size və evidence limitləri açıq `limitations` və `omitted_evidence_count` ilə göstərilir. Truncated response əsasında tam equality iddiası edilmir.
- Timing üçün hər tərəfdə ən azı üç finite, qeyri-mənfi sample və eyni measurement context tələb olunur. Sadə `elapsed` qiymətləri timing sübutu sayılmır. Overlap/jitter false-positive considerations-da qalır.
- Eyni status/body və ya təkcə fərqli cavab IDOR deyil. Mövcud IDOR plugin-i müşahidələri DiffEngine-dən keçirir və hələ `inconclusive` qaytarır; müstəqil ownership və negative-control confirmation Phase 6 işidir.

## İcra edilmiş yoxlamalar

İş qovluğu repository root; Python 3.14.4, mövcud dependency dəsti. Yeni dependency yoxdur.

- `.venv/bin/python -m pytest tests/test_diff_engine.py tests/test_strategy_interface.py tests/test_brain_planner.py -o addopts='' -q --tb=short`: **34 passed in 0.64s**, exit 0.
- `.venv/bin/python -m pytest tests/test_diff_engine.py --cov=qbh.brain.diff_engine --cov-report=term-missing -o addopts='' -q`: **18 passed**, **98% DiffEngine coverage**, exit 0.
- `.venv/bin/python -m pytest -o addopts='' -q --tb=short`: **1216 passed in 73.68s**, exit 0.
- Compile, ruff (`E4,E7,E9,F,B,W`) və `git diff --check`: PASS. İlk lint keçidində trailing whitespace tapılıb düzəldildi; yekun lint təmizdir.
- Benchmark `_amain(write=False)` + `compare` + regression assert: **36 tentative evidence, 53 endpoint, 53 parametr kombinasiyası, 236 icra**; azalma yoxdur. Saxlanmış baseline dəyişməyib.
- [Phase 4 GitHub CI](https://github.com/f1r10-cmd/xezer/actions/runs/43828104133) bütün job-larla **success** tamamlanıb. Phase 5 commit-in CI nəticəsi push-dan sonra ayrıca yoxlanılacaq.

## Buraxılış statusu

Phase 5 lokal qəbul meyarları keçir. Auth State Machine, feedback loop, JavaScript intelligence, qalan təhlükəsizlik uyğunlaşdırmaları və yekun E2E/install/release qapıları hələ tamamlanmayıb. v4.0.0 tag yaradılmayıb.
