<!-- coderabbit-ai-generated:v1 -->

# Faza 3 — HAR idxalı

## Vəziyyət: PASS (lokal funksional yoxlamalar)

- `qbh/ingest/har_importer.py`: offline HAR parser, JSON/form/multipart, binary reference, `task_identity` deduplication. Hər girişin statusu və səbəbi `import_entries` cədvəlindədir. Təkrar sorğunun fərqli cavabı ayrıca şifrəli occurrence sübutunda qalır.
- Sxem v8: `imported_requests`, `import_entries`, `request_graph_edges`; mövcud cədvəllər qorunur. İki sxem testi əvvəlki sabit v7 gözləntisindən v8-ə keçirilib; durable recovery davranış testləri saxlanılıb.
- Sorğu və cavabın tam mətn metadata-sı vault-da şifrələnir; CLI maskalanmış görünüş verir. Vault olmadıqda giriş bloklanır və səbəb təkrar idxal üçün qeyd edilir. Binary məzmun üçün hash/reference saxlanır.
- Graph: eyni origin və credential üçün `session_continuation`; eyni parent path üçün `same_endpoint_family`. Hər əlaqə confidence və provenance saxlayır. Ardıcıllıq təkbaşına əlaqə yaratmır. `get_auth_context_chains` əlaqəli komponentləri qaytarır, təsdiqlənmiş login ardıcıllığı iddiası etmir.
- CLI: `--import-har`, `--list-imported`, `--request-graph`, mövcud `--scan-id`. İdxal heç vaxt trafikdəki hostları skan etmir.

## İcra edilmiş yoxlamalar

İş qovluğu: repository root; Python 3.14.4.

| Yoxlama | Nəticə |
|---|---|
| `.venv/bin/python -m compileall -q qbh main.py` | PASS, exit 0 |
| `.venv/bin/python -m ruff check --select E4,E7,E9,F,B,W .` | PASS, exit 0 |
<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:c73a834e469cdd0c7631249b480421ec5e030780701662641ab94768d205b7e4 -->

| `.venv/bin/python -m pytest -o addopts='' -q --tb=short` | Yekun keçid: 1175 passed, 72.19s, exit 0 |

<!-- /coderabbit-ai-generated:v1 -->
| Son parser əlavəsindən sonra `.venv/bin/python -m pytest tests/test_har_import.py -o addopts='' -q` | 8 passed, exit 0; tam suite-dən sonra əlavə edilmiş bir test daxildir |
| Benchmark `_amain(write=False)` + `compare` | 36 tentative evidence, 53 endpoint, 53 parametr kombinasiyası, 236 icra; regressions=[] |
| İctimai HAR + socket yaradılmasını rədd edən yoxlama | 8 import, 0 invalid, 6 graph edge; şəbəkə cəhdi yoxdur |

İlk phase regression cəhdində köhnə v7 gözləntisinə görə 2 test uğursuz oldu; düzəlişdən sonra tam dəst keçdi. Saxlanmış benchmark dəyişdirilməyib.

## İctimai nümunənin mənşəyi

[HAR Viewer nümunəsi](https://github.com/JanOdvarko/harviewer/blob/master/webapp/examples/inline-scripts-block.har), [BSD lisenziyası](https://github.com/JanOdvarko/harviewer/blob/master/webapp/license.txt). Fayl yalnız müvəqqəti qovluğa endirilib, repoya əlavə edilməyib. SHA-256: `0a1c158158e04931057b67884c05a9a295e44e267dbc701484491179d8ec0788`. Xarici hostların heç biri skan edilməyib.

## Məhdudiyyətlər

- Bütün HAR məzmunu potensial həssas sayıldığı üçün idxal vault açarı tələb edir. Standart görünüşdə path və query dəyərləri gizlədilir; tam request yalnız vault vasitəsilə açılır.
- `auth_flow` və `parameter_progression` əlaqələri açıq API ilə əlavə edilə bilər; avtomatik infer hazırda session və endpoint family ilə məhduddur.
- Phase 7 feedback inteqrasiyası sonrakı mərhələyə aiddir.
- Başlanğıc suite-dəki 6 session diaqnostikasının səbəbi hələ düzəldilməyib; növbəti suite-də görünməməsi düzəliş sübutu deyil.
- Bu hesabat v4.0.0 buraxılış hazırlığı iddiası deyil.
