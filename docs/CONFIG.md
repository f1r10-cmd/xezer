<!-- coderabbit-ai-generated:v1 -->

# Konfiqurasiya

Əsas yol `config/targets.yaml`-dır; `--config` onu dəyişir. Lokal başlanğıc üçün
`config/examples/example_local.yaml` kopyalanır. `targets.yaml` Git-ignored qalır.
Boş scope qəbul edilmir. Aşağıdakı nümunə yalnız synthetic loopback tətbiqi üçündür.

## T&R: alət icazəsi path üzrə deyil, SCOPE üzrə verilir

`program_rules.forbidden` açıq qadağaları göstərir; tanınan qadağa yoxdursa
əməliyyat scope-un hər yolunda tətbiq edilə bilər. Engine, plugin, vulnerability
class və installer tool adları tanınır. Naməlum ad warning yaradır və tanınmış
icazəli testi bloklamır. Qadağaları təxminlə genişləndirmirik.
Profil/büdcə parametrləri əvvəlki kimi saxlanır; ilkin şərti olmayan test reason
ilə deferred qalır. `--approve` scope/RoE və destructive nəzarətini üstələmir.

```yaml
program: XEzer-local
aggressiveness: aggressive
scope:
  - domain: 127.0.0.1
    in_scope: [127.0.0.1]
    out_of_scope: []
program_rules:
  forbidden: []
  allow_wildcard_expansion: true
limits:
  requests_per_second: 5
  max_concurrency: 5
chain:
  enabled: true
  max_depth: 3
  max_tasks: 200
max_reconsideration_rounds: 3
block_strategy:
  http_429: respect
  http_403: backoff
vault:
  enabled: true
  key_file: ""
```

`max_reconsideration_rounds` 0–100 arası integer-dir. Eyni prerequisite hash
uğursuz testi təkrar işə salmır; dəyişmiş hash üçün round və reason DB-də qalır.
`chain.max_tasks` Brain və applicability probe üçün də bounded limitdir;
büdcə bitəndə qalan URL ID-ləri və reason nəticədə saxlanır.

## Açıq path/method qadağaları

```yaml
request_restrictions:
  - hosts: [127.0.0.1]
    paths: ["/billing/*"]
    methods: [POST, PUT, PATCH, DELETE]
    forbidden: ["*"]
  - hosts: [127.0.0.1]
    paths: ["/search"]
    methods: [GET]
    forbidden: [sqli]
```

Dörd sahə mütləqdir və boş olmayan string list qəbul edir. `paths` `/` ilə
başlamalıdır; host/path glob uyğunluğu və encoded/decoded path yoxlanır.
Bu nümunə ayrıca icazə siyahısı deyil, mövcud scope-a explicit deny əlavə edir.
Native HTTP sərhədi hər sorğuda yoxlayır. External CLI daxilindəki sorğular üçün
bu nəzarət təsdiqlənməyib: bu konfiqurasiyanı external tool-larla tam enforced
hesab etmək olmaz. Release maneəsi [yekun hesabatda](FINAL_REPORT.md) izah edilir.

## İki synthetic auth identity

Bu hissəni yalnız öz loopback tətbiqinizin faktiki portuna uyğunlaşdırın.
ENV dəyişənlərinə yalnız synthetic test dəyərləri qoyun; YAML-da parol yazmayın.
Vault üçün `QBH_VAULT_KEY` və ya `vault.key_file` lazımdır.

```yaml
auth_contexts:
  - name: user_a
    role: user
    login_url: http://127.0.0.1:8080/login
    login_method: POST
    login_format: json
    login_fields:
      username_env: TARGET_USER_A
      password_env: TARGET_USER_A_PASS
    verify_url: http://127.0.0.1:8080/me
    subject_field: user.id
    session_ttl_seconds: 900
  - name: user_b
    role: user
    login_url: http://127.0.0.1:8080/login
    login_method: POST
    login_format: json
    login_fields:
      username_env: TARGET_USER_B
      password_env: TARGET_USER_B_PASS
    verify_url: http://127.0.0.1:8080/me
    subject_field: user.id
    session_ttl_seconds: 900
auth_resource_policies:
  - id: synthetic-private-object
    origin: http://127.0.0.1:8080
    path_pattern: "/*/7"
    owner_field: owner_id
    object_id_field: id
    protected_fields: [private_data]
    roles: [user]
    access_policy: owner_only
```

`verify_url` login ilə eyni origin olmalıdır. Təsdiq edilmiş subject və anonim
401/403 nəzarəti olmadan sessiya IDOR confirmation üçün etibarlı deyil.
`login_format` json/form/basic; GET/POST login; TTL 1–86400 saniyədir.
`*_vault_ref` scan/host ilə məhdud mövcud secrets row ID-sinə istinad edə bilər.
`auth_resource_policies` test icazəsi vermir, yalnız ownership təsdiqinə sübutdur.

## Nuclei və kompatibil flag-lər

`vuln.allow_all_templates`, `vuln.allow_destructive`, `intrusive_templates`
siyasətləri saxlanılıb. `allow_destructive` adı tarixi olsa da genuinely destructive
tag-lar həmişə istisna edilir; flag qeyri-zərərli intrusive kateqoriyalar üçündür.
`--allow-state-changing` uyğunluq flag-idir; YAML qadağası yoxdursa əlavə CLI
approval tələb edilmir. 429 üçün köhnə `rotate`/`backoff_then_rotate` seçimləri
native runtime-da `respect` davranışına keçir.
