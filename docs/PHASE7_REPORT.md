<!-- coderabbit-ai-generated:v1 -->

# Faza 7 — Sübut korrelyasiyası və feedback loop

## İcra

Mövcud AdaptiveController, EventLedger, TaskLedger, Scheduler və DurableStore genişləndirilib. Ayrı icra və ya avtorizasiya mexanizmi yaradılmayıb.

- Auth sessiyası yarananda və HAR idxalı bitəndə hadisə EventLedger-də davamlı saxlanır.
- HAR idxalı offline qalır: graph və planlar yenilənir, login və target sorğusu göndərilmir.
- RequestGraph əlaqələri, uyğun finding sübutları və auth sessiya reference-ləri prerequisite_hash-a daxildir.
- Dəyişməyən failed nəticə təkrarlanmır. Əlaqəsiz finding hash-i dəyişmir.
- `max_reconsideration_rounds` default **3**-dür; 0–100 tam ədəd qəbul edilir. Hər dəyişmiş versiyanın qərarı və səbəbi `plan_reconsiderations` cədvəlində saxlanır; limit restart-dan sonra da qüvvədədir.
- Hazır follow-up mövcud durable növbədə qeyd olunur; icra yenidən scope/RoE və istifadəçi rəddini yoxlayır.
- Nəticə AdaptiveController-ə ötürülür. Şifrəli sübutlar əvvəlki nəticələri əvəz etmədən saxlanır.
- Sxem **v11**: additive table/index; əvvəlki cədvəllər qorunur.

## Yoxlama

- Feedback/auth/planner/Chain/recovery/lifecycle/HAR məqsədli suite: **136 passed in 4.02s**.
- Full suite: **1259 passed in 74.35s**. Sonradan hadisə restore və durable follow-up bağlantıları üçün 76-testlik auth/planner/Chain dəsti ayrıca keçdi; dəyişməyən full nəticələri reused.
- EventLedger restart dedup testinin ilk keçidi restore-a DB row verildiyini aşkar etdi; mövcud `recovery.event_records()` adapteri ilə düzəldildi.
- Compile, ruff və diff whitespace yoxlamaları keçir.
- Benchmark: **36 evidence / 53 endpoint / 53 parametr kombinasiyası / 236 icra**, azalma yoxdur.

## Məhdudiyyətlər

HAR idxalı yalnız offline qiymətləndirmə aparır. Hazır testlərin şəbəkə icrası növbəti Brain/Chain icrası və ya `--test-plan --approve` axınında olur. Dəyişmiş sübutu olmayan failed testlər təkrar işə salınmır.

Yekun E2E, install və release yoxlamaları hələ tamamlanmayıb. Phase 8 və məhsulun yekun qapıları növbəti işdir.
