<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:2b3886f2d51ed2a2f78d76146491e66e90f7c265c801380b27a57acac168eaa0 -->

# Faza 8 — JavaScript Intelligence

## İcra

Mövcud `qbh/engines/jsanalysis.py` genişləndirilib. Secret pattern-ləri, vault və mövcud mühərrik saxlanılıb.

- Esprima 4.0.1 ilə offline AST: fetch/axios/router çağırışları, route obyektləri, frontend role/permission işarələri, feature flag-lər və service reference-ləri.
- Mövcud regex çıxarışı həmişə saxlanır. Qəbul edilməyən sintaksis açıq fallback səbəbi verir. Esprima-nın ECMAScript 2017 sərhədi [upstream sənəddə](https://github.com/Kronuz/esprima-python) göstərilir.
- Source map linkləri, inline map-lər və embedded sources işlənir. Xarici source URL-lər avtomatik yüklənmir. Remote map sorğusu scope/RoE qapısından keçir, redirect izləmir; credential/query olan map review üçün saxlanır.
- Bir JS faylı üçün 5 map, hər map üçün 20 embedded source analiz büdcəsi var. Büdcədən kənar girişlər səbəblə saxlanır.
- HAR request ID-ləri ilə dəqiq URL korrelyasiyası. Kəşf edilən secret avtomatik replay edilmir.
- `js_observations` cədvəlində şifrəli müşahidələr, public count/status summary və provenance digest-ləri saxlanır. Vault yoxdursa blocked/retryable status verilir.
- Köhnə fallback-dəki səssiz 20-endpoint limiti çıxarılıb; URL-lər source-un origin/scheme/port-u ilə həll edilir.

## Yoxlama

- İlkin AST/engine/recovery/lifecycle suite: **147 passed in 2.32s**.
- Embedded map dəyişikliklərindən sonra JS/engine suite: **95 passed in 1.70s**.
- Bütöv loopback JS + map axını əlavə edildikdən sonra JS intelligence suite: **6 passed in 0.62s**.
- Compile, ruff və pip check: PASS.
- Benchmark: **36 evidence / 53 endpoint / 53 parametr kombinasiyası / 236 icra**, azalma yoxdur.
- Full suite: **1265 passed in 69.74s**, exit 0. Son əlavə loopback engine testi 6-testlik JS intelligence keçidində yoxlanıb; dəyişməyən full nəticələr reused.

## Məhdudiyyətlər

Dinamik runtime ifadələri icra edilmir; dynamic_endpoint kimi qeyd olunur. Frontend permission işarəsi backend zəifliyi təsdiqi deyil. Source content olmayan map girişi açıq unavailable səbəbi saxlayır. ECMAScript 2017-dən yeni sintaksisdə AST tamlığı iddia edilmir; fallback və məhdudiyyət auditdə görünür.

Release səviyyəli E2E/install/CI matrix, köhnə endpoint applicability və session leak yoxlamaları, CLI əlavələri və yekun sənədlər qalıb. v4.0.0 tag yaradılmayıb.


<!-- /coderabbit-ai-generated:v1 -->