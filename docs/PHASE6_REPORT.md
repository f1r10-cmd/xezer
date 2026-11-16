<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:9edf47ded924c29a781c1c4d5ca481a5f040e538de924370e539686a1ed70328 -->

# Faza 6 — Auth State Machine və sübutla IDOR yoxlaması

## İcra edilmiş hissələr

- `AuthContext` və `AuthStateMachine`: ENV və scan/host ilə məhdud vault reference-ləri, ayrıca cookie jar, expiry, origin/path ayrılığı və şifrəli sessiya tarixçəsi.
- `auth_contexts` YAML konfiqurasiyası. Inline credential qəbul edilmir. `verify_url` və anonim 401/403 nəzarəti olmadan kimlik təsdiqlənmiş sayılmır.
- Brain icrası auth provider-i initialize edir. Plan baxışı və HAR idxalı login trafiki yaratmır.
- Ownership məlum olmadıqda iki uyğun sessiya ilə bounded read-only applicability probe işləyir. Təsdiq üçün eyni obyektin owner-only siyasəti, iki fərqli təsdiqlənmiş subject, qorunan məlumat, anonim denial və təkrar açıqlanma tələb olunur.
- `auth_resource_policies` scope icazəsi vermir; yalnız təsdiq üçün istifadəçinin verdiyi siyasət sübutudur.
- Yeni `test_plan_results` cədvəli əvvəlki şifrəli nəticələri qoruyur. Rədd edilmiş planın gec alınan nəticəsi də tarixçədə qalır.

## Müqavilə dəyişiklikləri

İstifadəçinin 7-ci cavabına əsasən `state_changing` üçün əlavə CLI təsdiqi tələb olunmur. YAML `forbidden` qadağası qüvvədədir. `--allow-state-changing` uyğunluq üçün saxlanılıb. `authorize_request(..., destructive=True)` həmişə rədd edilir; mövcud dağıdıcı template qoruyucuları saxlanılıb.

İstifadəçinin 6-cı cavabına əsasən HTTP 429 identity rotation yaratmır. Köhnə `rotate` seçimi runtime-da `respect` kimi işləyir. `Retry-After` daxili cooldown tavanı ilə qısaldılmır; paralel uğurlu cavab aktiv rate limit-i silmir. Mövcud 403 recovery müqaviləsi saxlanılıb.

`request_restrictions` siyahısında hər qayda `hosts`, `paths`, `methods`, `forbidden` sahələrini verir. Qaydalar yalnız explicit deny əlavə edir. HTTP sərhədi hər təkrar sorğu və redirect üçün method/path qaydasını yoxlayır; Brain və auth sorğuları technique-ni də verir.

## Sübut

- Auth/strategy/planner/config/recovery/lifecycle: **123 passed**.
- Auth inteqrasiyasının ilkin full suite-i: **1244 passed in 75.31s**.
- Request restriction və 429 dəyişikliklərindən sonra məqsədli suite: **94 passed in 4.89s**.
- Son nəticə tarixçəsi/rejection testləri: **40 passed in 1.21s**.
- Compile, ruff (`E4,E7,E9,F,B,W`) və `git diff --check`: PASS.
- Benchmark: **36 evidence, 53 endpoint, 53 parametr kombinasiyası, 236 icra**; regression yoxdur, saxlanmış baseline dəyişməyib.
- Son full suite: **1248 passed in 73.94s**, exit 0. Ondan sonra gecikmiş nəticənin tarixçədə qorunması dəyişikliyi və yeni testi üçün 40-testlik auth/planner dəsti keçdi; dəyişməyən suite nəticələri yenidən istifadə edildi. GitHub CI push-dan sonra yoxlanacaq.

Əsas testlər `tests/test_auth_state.py`, `tests/test_authorization.py`, `tests/test_http_policy.py`, `tests/test_strategy_interface.py` və `tests/test_brain_planner.py` daxilindədir. Planted IDOR təsdiqlənir; secure/public endpoint, eyni subject, admin/user fərqi, overlapping policy və expired sessiya təsdiqlənmir.

## Qalan işlər və məhdudiyyətlər

- Release səviyyəsində bütün köhnə native/external engine-lərin technique/path restrictions sərhədlərinin auditi qalıb; subprocess-in daxili HTTP sorğularının bu qatdan keçdiyi iddia edilmir.
- JSON owner-only resurslar üçün təsdiq həyata keçirilib. Siyasəti naməlum və ya başqa response formatlı endpoint-lər görünən inconclusive nəticə saxlayır.
- Phase 7–8, yekun E2E/install, session leak audit, refreshed Azerbaijani sənədlər və v4.0.0 release qapıları tamamlanmayıb.


<!-- /coderabbit-ai-generated:v1 -->