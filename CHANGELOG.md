<!-- coderabbit-ai-generated:v1 -->

# Dəyişikliklər

## v4.0.0 hazırlığı — buraxılmayıb

- Offline HAR idxalı və RequestGraph; 15 sinifli Brain, iki plugin, davamlı plan audit-i.
- DiffEngine, auth state machine, sübutla IDOR, bounded feedback, JS AST/maps/HAR əlaqələri.
- Schema 12 additive migrations; əvvəlki scan/task/event/followup məlumatları qorunur.
- `--findings` və `--compare-scans`; CLI-in mövcud rejimləri saxlanılıb.
- Kateqoriya əsaslı endpoint istisnaları səbəbli deferred qərar və bounded probe-a çevrilib.
- Native 429 identity rotation dayandırılıb; Retry-After/cooldown qorunur.
- State-changing icazəsi YAML-dan gəlir; əlavə CLI approval tələb olunmur.
- JWT tool mətni acceptance sübutu olmadan confirmed yaratmır. Bu, saxta
  təsdiqin təmiridir; candidate və maskalanmış müşahidə saxlanır.
- Test fixture-lərində context teardown ilə ClientSession sızmaları düzəldilib.
- Installer nonzero/timeout probe-nu verified saymır; x8 Cargo əmri ilə düzəldilib,
  help çıxışındakı IP ünvanı versiya kimi göstərilmir.
- CI Python 3.10–3.14 və iki sabit benchmark keçidi ilə genişləndirilib.
- External CLI daxili request policy enforcement açıq release maneəsidir;
  v4.0.0 tag-i və production-ready iddiası yoxdur.

Əvvəlki versiyaların qeydləri [docs/CHANGELOG.md](docs/CHANGELOG.md)-də qorunur.
