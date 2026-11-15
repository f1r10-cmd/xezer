```
# XEzer — Stateful Intelligence & Coverage-Preserving Optimization
## Master Architecture Evolution Directive (v2 — Consolidated)

You are working on XEzer, an existing Python-based security testing and bug bounty automation platform.

---

# 0. SYSTEM CONTEXT — READ FIRST

You know NOTHING about this system. This section gives you the essential context so you do NOT need to waste effort discovering what already exists. Trust this section. Verify only when a specific task requires it.

## 0.1 What XEzer is

XEzer (also called QBH internally — code lives in `qbh/` package) is an autonomous bug bounty hunter that discovers targets, enumerates subdomains/endpoints/parameters, tests for vulnerabilities, chains discoveries into follow-up tests, confirms findings with evidence, and produces bounty-ready reports (Markdown + JSON + HackerOne format).

**Core philosophy (NON-NEGOTIABLE):**
- Everything within authorized scope is PERMITTED. The system should test everything it is authorized to test.
- The system must NEVER skip a check because it is "unsure" or "doesn't know" — uncertainty means TEST IT, not skip it.
- The system must PRODUCE RESULTS. A scan that runs but reports nothing because it silently skipped tests is a FAILURE.
- The system must work SMART to avoid rate limits and blocks (through intelligence: pacing, deduplication, prioritization) — NOT through evasion (no IP rotation to evade limits, no bypassing WAF restrictions outside authorized scope).

## 0.2 Current repository state

- **Git commit:** `770dafd833eac4a8615aaedf9ebaea4355531f74` on `main` branch
- **Tests:** 1017 passing, 2 skipped
- **Coverage:** 83.60%
- **Lint:** ruff clean with `--select E4,E7,E9,F,B,W`
- **Compile:** `python -m compileall -q qbh main.py` clean

## 0.3 Architecture map (existing — do NOT rebuild these)

```

main.py                        # CLI entry point (argparse, modes: full/recon/vuln/hunt/report/install)
qbh/
├── conductor.py              # Central orchestrator — STAGE_MAP, _run_stage(), pipeline logic
├── scheduler.py              # Central scheduler — bounded queue, priority, host/endpoint fairness, backpressure
├── tasks.py                  # TaskLedger — SHA-256 task_identity(), lifecycle (QUEUED/RUNNING/COMPLETED/PARTIAL/FAILED/TIMED_OUT/CANCELLED/SKIPPED)
├── chain.py                   # ChainPipeline — trigger→follow-up chaining, EventLedger, local step execution
├── adaptive.py               # AdaptiveController — evaluate signals, plan follow-ups, record outcomes
├── urlintel.py               # URL Intelligence — normalization, classification, eligibility (eligible/ineligible/deferred), F-07 reconsideration
├── db.py                     # SQLite — SCHEMA_VERSION=6, scans/hosts/urls/findings/evidence/secrets/stages, migrations
├── metrics.py                # Metrics — ledger (intention) vs scheduler (actual execution) separation
├── authorization.py          # Unified scope/RoE decision center (fail-closed)
├── scope.py                  # ScopeEnforcer — exact/wildcard/CIDR/out-of-scope
├── http_policy.py            # HttpPolicy — rate limit, concurrency, timeout, Retry-After, redirect scope
├── egress.py                 # EgressController — subprocess targets, DNS pinning, process group SIGKILL
├── vault.py                  # Encrypted secret vault (Fernet)
├── redact.py                 # Secret masking for reports/logs
├── context.py                # Shared context passed to engines (config, state, scheduler, ledgers)
├── results.py                # EngineResult, StageResult contracts
├── installer.py              # Tool detection + installation
├── hunter.py                 # Hunter orchestrator (--mode hunt)
├── payloads.py               # WAF/filter bypass matrix (path/header/verb)
├── engines/                  # All engines (recon, vuln, jsanalysis, content, ferox, api_enum, api_fuzz, param_enum, sqli, xss, ssti, ssrf, jwt, sourcecode, race, cve_intel, validation, bypass, takeover, secret_replay, library_cve, confirm)
├── adapters/base.py         # subprocess execution (shell=False)
├── antiblock/               # Guardian, Identity, ProxyManager, UARotator
├── stealth/                 # StealthStack, WAF detection, humanizer, pacing, policy
└── report/                  # generator.py, exporters.py (MD + JSON + HackerOne)
tests/                        # 1017 tests, all loopback-only (no external network)

```

## 0.4 Current execution flow

```

main.py → Conductor.resolve_targets() → deep_enum → recon → fingerprint
→ [vuln | js | content | ferox] (parallel, via Scheduler — these 4 only)
→ api_enum → api_fuzz (via Chain) → param_enum → cve_intel → validation
→ chain/adaptive follow-ups → metrics → finish_scan → report

```

**What uses the Scheduler:** ONLY `vuln`, `js`, `content`, `ferox` (4 engines). All other stages run sequentially or via their own bounded mechanisms.

**Key recent developments (already implemented, tested, working):**
- TaskLedger with SHA-256 task identity (dedup by scan_id + engine + endpoint + method + param + test-type + profile)
- EventLedger (chain event dedup)
- Scheduler with bounded queue, priority, host fairness, endpoint-family fairness, backpressure with bounded retry
- URL Intelligence with three-state eligibility (eligible/ineligible/deferred) and F-07 deferred reconsideration
- AdaptiveController follow-ups connected to real stage status (F-01)
- Metrics separation: planning (ledger) vs actual execution (scheduler) (F-05)
- STAGE_MAP in Conductor (F-04)
- Scan status written to DB BEFORE report generation (Phase 4)
- Benchmark: 75% reduction in executed tasks on synthetic workload without losing findings (3000→753 tasks, 297 deduped, 1725 skipped, 225 deferred)

## 0.5 Known gaps (from most recent architecture audit)

| # | Gap | Impact |
|---|---|---|
| 1 | TaskLedger/EventLedger/AdaptiveController are RAM-only — no durable persistence, no crash recovery | Hours of work lost on interruption |
| 2 | URL Intelligence integrated with SQLi/XSS/SSTI/SSRF/JS/LibraryCVE/ParamEnum but NOT with api_enum/content/jwt/api_fuzz/bypass | Inconsistent test selection |
| 3 | Only 4 engines use central Scheduler — rest are sequential or self-managed | Suboptimal resource utilization |
| 4 | No real-world end-to-end validation (only loopback fixtures) | Operational readiness unproven |
| 5 | Documentation outdated relative to code (ARCHITECTURE.md references 562 tests, not current 1017) | Misleads future developers |
| 6 | No request relationship model, no authentication context model, no HAR ingestion | Limited testing intelligence |

## 0.6 Efficiency directives for YOU (the AI agent)

- **Do NOT** read entire files when you only need a specific function. Use targeted reads.
- **Do NOT** re-discover architecture — trust section 0 above.
- **DO** run existing tests to verify baseline before making changes: `.venv/bin/python -m pytest -q --tb=no 2>&1 | tail -5`
- **DO** run lint before committing: `.venv/bin/python -m ruff check --select E4,E7,E9,F,B,W .`
- **DO** write focused tests (not exhaustive tests) for each change you make.
- **DO NOT** refactor unrelated modules unless explicitly instructed.
- **DO NOT** modify existing test expectations unless a change you make requires it — and if so, DOCUMENT WHY.
- **ALWAYS** verify your change works: run the specific test file, run lint, confirm no regression.
- **NEVER** claim something works without running it.
- **The virtual environment is at `.venv/`** — use `.venv/bin/python` and `.venv/bin/pytest`.

---

# 1. NON-NEGOTIABLE RULES

1. This is NOT a greenfield rewrite. Preserve existing architecture, capabilities, security controls, database compatibility, CLI behavior, and working engines unless a verified technical reason requires a change.
2. **The system must test EVERYTHING within authorized scope.** Never skip a check because of uncertainty. If unsure → TEST IT. Skipping requires an EXPLICIT reason (out-of-scope, forbidden by RoE, truly duplicate, only-destructive option available).
3. **A scan that previously discovered a valid finding must not silently stop discovering it** because of optimization, deduplication, caching, concurrency, or orchestration changes.
4. Do not promise a particular speed improvement before measuring it.
5. Never silently discard endpoints, parameters, identities, findings, evidence, or failed tests.
6. Never automatically classify an unverified detection as a confirmed vulnerability.
7. Do not bypass target rate limits, WAF restrictions, program restrictions, or authorization boundaries. Work SMART (pacing, dedup, priority) — not through evasion.
8. Do not introduce rotating public proxies or distributed IP rotation to evade rate limits.
9. Never expose, log, or export authentication tokens, cookies, passwords, or secrets unnecessarily.
10. Do not perform destructive actions against targets.
11. All active tests must respect explicit authorization, scope, rate limits, and applicable Rules of Engagement.
12. Use local fixtures, mocks, and controlled test environments for verification.
13. Do not create parallel implementations of functionality that already exists (see section 0.3/0.4).
14. Preserve backward compatibility wherever reasonably possible.
15. Do not modify the repository until the initial audit (Phase 0) is complete and documented.
16. **Do not commit or push unless explicitly instructed.**

---

# 2. PHASE 0 — ARCHITECTURE AUDIT & VERIFICATION (CREDIT-EFFICIENT)

Do NOT re-read the entire repository. Section 0 above gives you 80% of what you need. Your job in Phase 0 is to VERIFY specific integration points, not re-discover them.

## 2.1 Verify current state (FAST)

Run these and record results:

```bash
git log --oneline -5
git status
.venv/bin/python -m compileall -q qbh main.py
.venv/bin/python -m ruff check --select E4,E7,E9,F,B,W .
.venv/bin/python -m pytest -q --tb=no 2>&1 | tail -5
```

Expected: clean compile, clean lint, 1017+ passing tests (allow small drift if minor changes were made since).

## 2.2 Targeted integration point checks (NOT full file reads)

For each item below, read ONLY the relevant function/class and confirm it matches section 0.4. If it does not, note the discrepancy.


| Check                             | File               | What to confirm                                                               |
| --------------------------------- | ------------------ | ----------------------------------------------------------------------------- |
| STAGE_MAP completeness            | `qbh/conductor.py` | Which stages are defined, which use Scheduler (expect: vuln/js/content/ferox) |
| TaskLedger persistence            | `qbh/tasks.py`     | Confirm RAM-only (no SQLite writes for ledger events)                         |
| EventLedger persistence           | `qbh/chain.py`     | Confirm RAM-only                                                              |
| AdaptiveController outcomes       | `qbh/adaptive.py`  | Confirm`record_outcome()` exists and is called from conductor                 |
| URL Intelligence engines using it | `qbh/urlintel.py`  | Confirm which engines call eligibility functions                              |
| Scheduler queue limits            | `qbh/scheduler.py` | Confirm bounded queue, priority, fairness, backpressure exist                 |
| DB schema current state           | `qbh/db.py`        | Confirm SCHEMA_VERSION, existing tables, migration mechanism                  |
| Metrics ledger vs scheduler split | `qbh/metrics.py`   | Confirm`executed` comes from scheduler, not ledger                            |
| Report generation order           | `qbh/conductor.py` | Confirm`finish_scan()` before `generate_report()`                             |

## 2.3 Verify known gaps (do NOT fix yet — just document)

Confirm or refute each gap from section 0.5. For each, state: "CONFIRMED" or "REFUTED — actually works like [X]" with file/line reference.

## 2.4 Phase 0 output

Produce a short document (save as `docs/PHASE0_AUDIT.md`) containing:

- Current test/lint/compile results (from 2.1)
- Confirmed/refuted gaps (from 2.3)
- A prioritized list of what Phase 1 should address
- A list of "low-hanging fruit" improvements that can be made quickly

**Phase 0 acceptance criteria:**

- [ ]  Compile passes
- [ ]  Lint passes
- [ ]  All existing tests pass
- [ ]  `docs/PHASE0_AUDIT.md` created with all sections above
- [ ]  No code changes made yet (audit only)

---

# 3. PHASE 1 — BASELINE, INTELLIGENT NORMALIZATION, AND COVERAGE-PRESERVING OPTIMIZATION

## 3.0 Establish reproducible baseline (before any optimization)

Create a deterministic local benchmark:

- File: `tests/benchmarks/` (new directory)
- Fixture: a loopback aiohttp app with multiple endpoints (static, dynamic, parameterized, JS, API patterns from section — reuse patterns from `tests/conftest.py` fixtures if they exist)
- Runner: `tests/benchmarks/run_baseline.py` — runs a synthetic scan against the loopback app

The benchmark must measure and output as JSON:

```json
{
  "total_duration": ...,
  "total_http_requests": ...,
  "requests_per_engine": {...},
  "unique_endpoints": ...,
  "unique_endpoint_param_combos": ...,
  "duplicate_tasks": ...,
  "skipped_tasks": ...,
  "skipped_reasons": {...},
  "deferred_tasks": ...,
  "failed_tasks": ...,
  "timed_out_tasks": ...,
  "scheduler_queue_time_avg": ...,
  "concurrency_avg": ...,
  "concurrency_peak": ...,
  "rate_limit_responses": ...,
  "findings_by_severity": {...},
  "findings_by_confidence": {...},
  "evidence_records": ...,
  "engine_execution_coverage": {...}
}
```

Save the result as `tests/benchmarks/baseline.json`. This is your REFERENCE — after every optimization, regenerate and compare. **If findings decrease or coverage drops, the optimization is WRONG and must be fixed.**

## 3.1 Improve URL normalization (multi-identity model)

**Current state:** `qbh/urlintel.py` normalizes URLs for deduplication. Risk: aggressive normalization can merge URLs that should be tested differently.

**Required change:** Implement multiple URL identity levels, each used for its specific purpose:

```python
class URLIdentity:
    def __init__(self, raw_url):
        self.infra_id = ...      # for infrastructure discovery (host+scheme+port)
        self.testing_id = ...   # for generic vuln testing (host+scheme+port+path+method)
        self.param_id = ...      # for parameter testing (+ params+values if relevant)
        self.idor_id = ...       # for IDOR/BOLA (+ user-context markers, object IDs)
        self.auth_id = ...      # for authentication-context testing (+ auth state)
```

**Rules:**

- NEVER merge different HTTP methods, parameters, parameter values, user identities, or content types when they matter to the test.
- Numeric identifiers (e.g., `/user/123` vs `/user/456`) are NOT necessarily interchangeable — preserve them for IDOR testing, merge only for infrastructure discovery.
- Every normalization decision must have a `reason` field (why this identity level is safe for this test type).
- Store original request data alongside normalized identity — normalization NEVER destroys original.

**Where to change:** `qbh/urlintel.py`. Add `URLIdentity` class, integrate with existing `task_identity` in `qbh/tasks.py` (extend the `task_identity()` input to accept identity level, default to current behavior for backward compat).

**Tests to add:** `tests/test_url_identity.py` — test that:

- Same URL, different methods → different testing_id
- Same URL, different numeric IDs → same infra_id, different idor_id
- Same URL, different params → different param_id
- Each identity type preserves original URL
- Backward compatibility: existing `task_identity` calls produce same results

## 3.2 Technology-aware test planning (4-state eligibility)

**Current state:** URL Intelligence has 3 states: eligible/ineligible/deferred. Missing: "unknown" (when fingerprint data is insufficient).

**Required change:** Add `unknown` state in `qbh/urlintel.py`:

- `eligible`: fingerprint + URL pattern both support this engine
- `ineligible`: fingerprint or URL pattern explicitly rules out this engine (with reason)
- `deferred`: not enough evidence yet — will be reconsidered when new evidence arrives
- `unknown`: fingerprint is missing/incomplete — engine MAY still apply

**Critical philosophy:** An incomplete fingerprint must NOT filter out a test. If we don't know the tech stack, we should still test with generic strategies (or mark as `unknown` and let a generic engine handle it).

**Where to change:** `qbh/urlintel.py` — extend eligibility enum, update `compute_eligibility()` to return the new state when fingerprint is absent. Update F-07 reconsideration to handle `unknown` → `eligible/ineligible` transitions when fingerprint data arrives.

**Tests to add:** `tests/test_eligibility_states.py` — test that:

- Missing fingerprint → `unknown`, not `ineligible`
- Fingerprint arrival → `unknown` becomes `eligible` or `ineligible` with recorded reason
- A test is never skipped SOLELY because fingerprint is incomplete

## 3.3 Safe response classification (do not discard 403/404/405/500)

**Current state:** Some code paths may treat 403 as "blocked" and skip further testing, or treat 404 as "endpoint doesn't exist."

**Required change:** Create a `ResponseClassifier` in `qbh/urlintel.py` (or new file `qbh/response_classifier.py` if urlintel.py is too large):

```python
class ResponseClassifier:
    def classify(self, status, method, auth_context, content_type, 
                 redirect_behavior, response_structure, endpoint_role, 
                 previous_observations) -> ResponseClass:
        ...
```

**Rules:**

- 403: may indicate auth-required → preserve for bypass/auth-context testing
- 404: may be soft-404 → preserve with lower priority
- 405: method mismatch → try other methods (this is a signal, not a dead end)
- 500: may indicate injectable parameter → preserve for further testing
- HEAD response ≠ GET response — never assume equivalence
- Every classification records `reason` and `evidence_refs`

**Where to change:** Create the classifier, integrate it with existing Guardian's 403/429 handling (do not replace Guardian — Guardian handles rate-limiting/blocks, ResponseClassifier handles testing-relevance). Make sure the existing `observe_block=False` mechanism in bypass engine is NOT broken.

**Tests to add:** `tests/test_response_classifier.py` — 403/404/405/500 each produce actionable classifications, HEAD≠GET, classification reasons recorded.

## 3.4 Adaptive scheduling improvements

**Current state:** Scheduler (`qbh/scheduler.py`) works with bounded concurrency, fairness, backpressure. Check if it uses observed rate-limit (429) responses to dynamically reduce concurrency for that host.

**Required change (if not already present):**

- Per-host dynamic concurrency: when a host returns 429, reduce that host's concurrent slots temporarily
- Bounded cooldown: re-increase concurrency after observed healthy responses
- Respect Retry-After: existing HttpPolicy does this — verify Scheduler does NOT override it
- Retry storms: verify max_attempts is enforced (should already be in TaskLedger)

**Where to change:** `qbh/scheduler.py` — add per-host concurrency scaling. Integrate with Guardian's existing cooldown data (Guardian already tracks block events — reuse it, do not duplicate).

**Tests to add:** `tests/test_adaptive_scheduling.py` — 429 triggers per-host concurrency reduction, concurrency recovers, Retry-After respected, no retry storm.

## 3.5 Intelligent caching (if not already present)

**Current state:** Check `qbh/http_policy.py` and `qbh/db.py` for existing caching. The `urlintel.py` may cache classification results.

**Required change (if absent or insufficient):**

- Add a response cache keyed by: `(target, endpoint, method, params, auth_context, test_strategy, strategy_version, relevant_fingerprint_state)`
- Invalidation rules: fingerprint change, strategy version change, auth context change, explicit TTL
- Cache stores response metadata (status, headers, size, first N bytes of body) — NOT full response bodies unless needed for diff testing
- **Historical findings and evidence are NEVER garbage-collected** — findings persist independently of cache expiry

**Where to change:** Prefer adding a `CacheManager` class in `qbh/cache.py` (new file). Integrate with HttpPolicy (check cache BEFORE making request, store response AFTER receiving).

**Tests to add:** `tests/test_cache.py` — cache hit/miss, invalidation on fingerprint change, invalidation on strategy version change, findings NOT deleted on cache expiry.

## 3.6 Phase 1 acceptance criteria

- [ ]  `tests/benchmarks/baseline.json` exists and is reproducible (run twice → same findings count, same endpoint coverage)
- [ ]  URL identity levels implemented, existing task dedup behavior unchanged (existing tests pass)
- [ ]  4-state eligibility (eligible/ineligible/deferred/unknown) implemented
- [ ]  ResponseClassifier handles 403/404/405/500 without discarding them from potential testing
- [ ]  Per-host adaptive concurrency in Scheduler (if not already present)
- [ ]  Response cache with correct invalidation (if not already present)
- [ ]  All existing tests still pass (any failure requires documentation of WHY the test expectation changed)
- [ ]  Benchmark comparison: findings count is SAME or HIGHER than baseline
- [ ]  Benchmark comparison: endpoint coverage is SAME or HIGHER than baseline
- [ ]  Lint passes, compile passes
- [ ]  New tests added for all new functionality
- [ ]  No optimization achieved by silently reducing coverage (prove by comparing baseline.json metrics before/after)

**Phase 1 output:** Document in `docs/PHASE1_REPORT.md` with baseline vs after metrics, all acceptance criteria PASS/PARTIAL/FAIL.

---

# 4. PHASE 2 — DURABLE EXECUTION AND RECOVERY

## 4.1 Audit existing persistence

Confirm: TaskLedger, EventLedger, AdaptiveController pending follow-ups, retry state, deferred candidates are all RAM-only.

## 4.2 Add durable persistence

**Approach:** Add SQLite tables for durable state. Use `qbh/db.py` — add new tables alongside existing schema (SCHEMA_VERSION bump):

```sql
-- New tables (additive, non-breaking)
CREATE TABLE task_state (
    task_id TEXT PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    identity_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    engine TEXT NOT NULL,
    endpoint TEXT,
    method TEXT,
    params TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    attempts INTEGER DEFAULT 0,
    last_error TEXT,
    result_data TEXT,  -- JSON
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE event_state (
    event_id TEXT PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT,  -- JSON
    processed_at TEXT,
    followup_task_ids TEXT,  -- JSON array
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE followup_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    trigger_finding_id INTEGER,
    proposed_action TEXT NOT NULL,
    prerequisite_hash TEXT,
    status TEXT DEFAULT 'pending',  -- pending/executed/skipped/failed
    created_at TEXT NOT NULL,
    executed_at TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```

**Integration points:**

- TaskLedger: add `persist_to_db()` called after every state transition. Do NOT replace in-memory operation — DB is for recovery only.
- EventLedger: same pattern.
- AdaptiveController: pending follow-ups persisted.
- On scan start: check for `running` scans in DB → if found and `--resume` flag given → load from durable state.

## 4.3 Recovery behavior

- Restarted process loads pending/running tasks from DB.
- Completed tasks (status=COMPLETED) are NOT re-executed (dedup via identity_hash).
- Interrupted tasks (status=RUNNING but process crashed) are re-queued.
- Retried tasks retain history (attempts counter, last_error).
- Recovery does NOT bypass scope/authorization checks (re-verify on resume).
- Scan ID isolation maintained.

## 4.4 Tests

`tests/test_durable_recovery.py`:

- Simulate crash (kill process mid-scan using subprocess)
- Restart with `--resume` → verify pending tasks recovered, completed not re-executed
- Verify scan_id isolation (scan A's recovery doesn't affect scan B)
- Verify task history (attempts) preserved across recovery

**Phase 2 acceptance:**

- [ ]  New tables created with migration (SCHEMA_VERSION bumped, existing data preserved)
- [ ]  TaskLedger/EventLedger/Adaptive persist to DB
- [ ]  `--resume` flag works for interrupted scans
- [ ]  Crash recovery tested with actual process kill
- [ ]  All existing tests pass
- [ ]  Migration is backward-compatible (old DB opens without data loss)

---

# 5. PHASE 3 — BURP TRAFFIC INGESTION (HAR IMPORT)

## 5.1 HAR importer

Create `qbh/ingest/har_importer.py`:

- Parse standard HAR format (JSON) — support Burp Suite exports
- Extract: request (method, URL, headers, body, cookies), response (status, headers, body, content-type), timings if available
- Content-type-aware parsing: JSON, form-encoded, multipart (parse fields), binary (store reference only)
- Request deduplication: use `task_identity` from `qbh/tasks.py` — same request = same identity
- Evidence preservation: raw request stored in evidence table with provenance (`source: "har_import"`)
- Import validation: required fields present, URL is valid, timestamps parseable
- Error reporting: collect all errors, do NOT fail entire import on one bad entry — skip and report

## 5.2 Database additions

```sql
CREATE TABLE imported_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    source TEXT NOT NULL DEFAULT 'har',
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    path TEXT,
    query_params TEXT,  -- JSON
    headers TEXT,       -- JSON (sensitive values redacted via existing redact.py)
    request_body BLOB,  -- encrypted if contains secrets
    response_status INTEGER,
    response_headers TEXT,  -- JSON
    response_body BLOB,
    started_at TEXT,
    time_ms REAL,
    sequence_order INTEGER,  -- order in HAR file
    dedup_identity TEXT NOT NULL,
    provenance TEXT,  -- original HAR file + entry index
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```

## 5.3 Request Graph

Create `qbh/ingest/request_graph.py`:

```python
class RequestGraph:
    def add_request(self, request_id: int) -> RequestNode
    def add_inferred_edge(self, from_id: int, to_id: int, 
                          relation: str, confidence: float, provenance: str)
    def get_related(self, request_id: int) -> List[RequestNode]
    def get_auth_context_chains(self) -> List[List[RequestNode]]
```

**Critical:** HAR files do NOT reliably indicate causal parent-child relationships. Two consecutive requests ≠ dependency.

Store edges with:

- `relation_type`: "session_continuation" | "auth_flow" | "same_endpoint_family" | "parameter_progression" | "unknown"
- `confidence`: 0.0–1.0
- `provenance`: WHY this edge was inferred (e.g., "both requests use same session cookie X, request 2 accesses /api/user/<id> extracted from response 1")

DB table:

```sql
CREATE TABLE request_graph_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_request_id INTEGER NOT NULL,
    to_request_id INTEGER NOT NULL,
    relation_type TEXT NOT NULL,
    confidence REAL NOT NULL,
    provenance TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (from_request_id) REFERENCES imported_requests(id),
    FOREIGN KEY (to_request_id) REFERENCES imported_requests(id)
);
```

The user must be able to inspect what was inferred and WHY.

## 5.4 Sensitive data protection

- Use existing `qbh/redact.py` for header/body masking in reports
- Use existing `qbh/vault.py` pattern for encrypting sensitive request bodies (e.g., if body contains password field)
- Never log raw secrets

## 5.5 CLI

```
python main.py --import-har <file.har> [--scan-id N]
python main.py --list-imported [--scan-id N]
python main.py --request-graph [--scan-id N]  # shows nodes + inferred edges + confidence
```

## 5.6 Tests

`tests/test_har_import.py`:

- Valid HAR file imports correctly
- Malformed entries are skipped with error report (not crash)
- Request dedup works correctly (same request = one entry)
- Sensitive data is redacted in views but preserved for testing
- Request graph edges have confidence and provenance
- Import does NOT trigger any network requests

**Phase 3 acceptance:**

- [ ]  HAR can be imported via CLI
- [ ]  Imported requests are inspectable
- [ ]  Request graph is viewable with confidence/provenance
- [ ]  No raw secrets in any output/log
- [ ]  All existing tests pass

---

# 6. PHASE 4 — XEzer BRAIN (Intelligence Layer)

## 6.1 Request Classifier

Create `qbh/brain/classifier.py`:

```python
class RequestClassifier:
    def classify(self, request: ImportedRequest) -> List[Classification]:
        # Returns: category, confidence, evidence_refs
```

**Categories:** authentication, account_management, user_resources,
administrative_resources, file_upload_download, search, payment_checkout,
api_operations, object_access, configuration, business_workflow, unknown.

**Evidence sources:** HTTP method, URL/route patterns, parameters, request/response structure, JavaScript references (from existing JS analysis), API schemas (from existing api_enum), authentication context, existing findings.

Every classification carries `confidence` and `evidence_refs` (list of what led to this decision).

## 6.2 Vulnerability Knowledge Base

Create `qbh/brain/knowledge/` — versioned, structured JSON files (not code — data-driven).

**File structure:** `qbh/brain/knowledge/<vuln_class>.json`

Example (`idor.json`):

```json
{
    "id": "idor",
    "name": "Insecure Direct Object Reference",
    "preconditions": [
        {"type": "endpoint_has_object_id", "required": true},
        {"type": "multiple_auth_contexts_available", "required": true}
    ],
    "relevant_endpoint_types": ["user_resources", "object_access", "api_operations"],
    "required_auth_states": ["authenticated_user_a", "authenticated_user_b"],
    "required_evidence": [
        {"type": "different_response_for_different_users", "description": "User A accesses User B's object — response differs from User A accessing own object"}
    ],
    "safe_test_strategy": "read_only_object_access",
    "expected_behavior": "authorized_user_gets_200_with_own_object",
    "potential_false_positives": [
        {"scenario": "object_is_public", "mitigation": "check_if_object_accessible_without_auth"}
    ],
    "confirmation_criteria": [
        "distinct_users_receive_distinct_responses_for_same_object_id",
        "object_id_not_accessible_to_guest_user_unless_intended_public"
    ],
    "impact": "unauthorized_access_to_other_users_data",
    "safe_poc_constraints": {"methods_allowed": ["GET"], "data_modification": false},
    "dependencies": [],
    "required_authorization": ["in_scope", "read_only_tests_permitted"]
}
```

**Initial vulnerability classes to implement (data only, not test logic yet):**
IDOR, BOLA, broken_access_control, privilege_escalation, auth_weakness, session_handling, business_logic_flaw, sqli, xss, ssrf, ssti, lfi_path_traversal, file_upload_weakness, api_authorization_weakness, jwt_implementation_weakness.

## 6.3 Test Strategy Plugin Interface

```python
# qbh/brain/strategy.py
class TestStrategy(Protocol):
    vuln_class: str  # e.g., "idor"
  
    def is_applicable(self, context: TestContext) -> tuple[bool, str]:
        """Returns (applicable, reason)."""
        ...
  
    def plan_test(self, context: TestContext) -> TestPlan:
        """Returns a plan with steps, prerequisites, expected outcomes."""
        ...
  
    def execute_test(self, context: TestContext, plan: TestPlan) -> TestResult:
        """Executes the planned test. Must respect scope/RoE."""
        ...
```

**Each strategy is a plugin** — new vulnerability classes are added by creating a new file in `qbh/brain/strategies/`, NOT by modifying a central orchestrator.

## 6.4 Context Builder

Create `qbh/brain/context.py`:

```python
class TestContextBuilder:
    def build(self, request_id: int) -> TestContext:
        # Pulls together:
        # - request + response from imported_requests
        # - related requests from request_graph
        # - authentication state (from Phase 5)
        # - related endpoints (from existing URL Intelligence)
        # - previous findings for this endpoint
        # - previous failed/deferred tests for this endpoint
        # - API schemas if available
        # - application fingerprint
        ...
```

The planner must be able to explain: "This test is relevant because [X,Y,Z]. Prerequisites missing: [A,B]."

## 6.5 Tests

`tests/test_request_classifier.py` — classification with confidence and evidence
`tests/test_knowledge_base.py` — all vuln class JSON files are valid and loadable
`tests/test_strategy_interface.py` — plugin interface works, new plugin can be registered

**Phase 4 acceptance:**

- [ ]  Request classifier works with multiple evidence sources
- [ ]  Knowledge base for initial vuln classes exists (data, valid JSON, loadable)
- [ ]  Plugin-based strategy interface implemented (add new strategy = new file, no central modification)
- [ ]  Context builder aggregates request + related + auth + findings + prior tests
- [ ]  All existing tests pass

---

# 7. PHASE 5 — DIFFERENTIAL ANALYSIS ENGINE

Create `qbh/brain/diff_engine.py`:

```python
class DiffResult:
    difference_summary: str
    relevant_evidence: List[Evidence]
    confidence: float
    possible_interpretations: List[str]
    false_positive_considerations: List[str]
    recommended_next_verification: Optional[str]

class DiffEngine:
    def compare(self, baseline_response, test_response) -> DiffResult:
        ...
```

**Compare:** HTTP status, headers (relevant ones), content-type, JSON structure, selected semantic fields, object ownership indicators, sensitive data exposure indicators, body similarity, error behavior, redirect behavior, timing (only when reliably measured).

**Normalization:** Timestamps, request IDs, CSRF tokens, randomized fields — normalize for comparison. Do NOT remove meaningful differences during normalization.

**A difference is NOT automatically a vulnerability.** The Diff Engine returns interpretations, not conclusions.

**Tests:** `tests/test_diff_engine.py` — baseline vs test comparison, normalization does not hide real differences, false positive considerations generated, sensitivity to JSON structure changes.

---

# 8. PHASE 6 — AUTHENTICATION STATE MACHINE

Create `qbh/brain/auth_state.py`:

```python
class AuthContext:
    name: str        # "guest", "user_a", "user_b", "admin"
    role: str        # "unauthenticated", "user", "admin"
    session_id: str  # reference to stored session (not raw token — vault)
    cookies: dict    # references to vault entries
    provenance: str  # "user_provided_via_config" | "captured_from_har" | "created_by_login_flow"
    valid_until: Optional[datetime]

class AuthStateMachine:
    def register_context(self, name, role, credentials_source) -> AuthContext
    def is_valid(self, context: AuthContext) -> bool
    def get_compatible_requests(self, context: AuthContext) -> List[RequestNode]
```

**User provides auth contexts in config** (NOT auto-created):

```yaml
auth_contexts:
  - name: "user_a"
    role: "user"
    login_url: "https://target.com/login"
    login_method: "POST"
    login_fields: {"username_env": "TARGET_USER_A", "password_env": "TARGET_USER_A_PASS"}
  - name: "user_b"  
    role: "user"
    # ...
  - name: "admin"
    role: "admin"
    # ...
```

Credentials come from environment variables or existing vault — NEVER hardcoded in config.

**For IDOR/BOLA testing:** Compare behavior across User A vs User B for same object IDs. Non-destructive, read-only verification by default.

**NEVER** infer IDOR from sequential identifiers or 200 responses alone — require evidence of unauthorized access to a distinct protected resource.

**NEVER** create unauthorized accounts.

**Tests:** `tests/test_auth_state.py` — context registration from config, session validity, role comparison, IDOR detection with proper evidence (not just 200).

---

# 9. PHASE 7 — EVIDENCE CORRELATION AND FEEDBACK LOOP

Integrate with existing ChainPipeline, AdaptiveController, TaskLedger, EventLedger.

**When new evidence arrives (a finding, a HAR import, a new auth context):**

1. Identify related endpoints, sessions, parameters, previous tests (via RequestGraph + URL Intelligence + database queries)
2. Find previously deferred/failed tests whose prerequisites may now be satisfied (via `prerequisite_hash` comparison)
3. Generate candidate follow-ups (create `FollowUp` objects, deduplicate via EventLedger)
4. Check scope and authorization again (ALWAYS re-verify — never trust cached authorization)
5. Check relevance (is the target still in scope, still interesting)
6. Apply deduplication and bounded scheduling (existing TaskLedger + Scheduler)
7. Execute only permitted and safe tests (existing RoE checks)
8. Store result with provenance (existing evidence mechanism)
9. Re-evaluate related hypotheses (existing AdaptiveController)

**A previous failed test must NOT automatically repeat on every new finding.** Use `prerequisite_hash` — only re-run if prerequisites actually changed.

**Feedback bounded by `max_reconsideration_rounds`** (configurable, default 3). Each round records WHY it was reconsidered.

**Where to change:** `qbh/adaptive.py` — extend `evaluate()` to accept new evidence types. `qbh/chain.py` — extend trigger types to include "auth_context_added", "har_import_completed". Do NOT replace the existing pipeline — extend it.

**Tests:** `tests/test_feedback_loop.py` — new evidence triggers appropriate follow-up, previous failed test re-runs only when prerequisites change, duplicate events don't create duplicate follow-ups, bounded rounds respected, full history of why a test was reconsidered is stored.

---

# 10. PHASE 8 — JAVASCRIPT INTELLIGENCE (post Phase 1-7)

If time permits after Phases 1–7 are stable:

Investigate JavaScript analysis enhancement:

- AST parsing (evaluate tree-sitter or esprima as dependency)
- Route extraction from frontend code
- API endpoint discovery
- Role/permission check discovery in frontend
- Feature-flag discovery
- Source map analysis
- Secret detection (reuse existing secret_replay engine patterns)
- Internal service references
- Cross-reference frontend code with observed HTTP traffic (from Phase 3 HAR imports)

**Never automatically use a discovered secret against an unrelated service or outside scope.** Correlate and produce a reviewable test proposal first.

**This is LAST priority — do not start until Phases 1–7 are verified.**

---

# 11. PHASE 9 — AI TRIAGE (optional layer)

**AI is an optional reasoning and prioritization layer — NOT a source of truth.**

Use AI to: summarize evidence, explain likely vulnerability classes, prioritize findings, identify missing verification evidence, recommend safe follow-ups, explain relationships.

**AI NEVER independently marks a finding as confirmed.** Final status requires reproducible evidence and explicit verification criteria.

Support local model integration as optional backend (Ollama, etc.).

**The core system MUST remain operational without an LLM** — AI is an enhancement, not a dependency.

Do NOT implement this phase until explicit instruction is given.

---

# 12. NUCLEI AND EXISTING ENGINE STRATEGY

**Do NOT remove Nuclei.** It stays as one engine among several.

The unified planner (Phase 4) decides when to use Nuclei based on:

- Technology fingerprint
- Template tags and metadata
- Target scope
- Test policy (existing `config/vuln` settings)
- Previous execution history
- Existing evidence

**Do NOT assume generic templates are irrelevant when fingerprint is incomplete.** Preserve all existing Nuclei template policies (intrusive_templates, allow_all_templates, allow_destructive).

Preserve template provenance, version, execution result, evidence.

Architecture allows XEzer-native test plugins (Phase 4 strategy interface) and external tools (Nuclei, ffuf, etc.) to coexist.

---

# 13. DATABASE AND ARCHITECTURE REQUIREMENTS

- Inspect existing schema (`qbh/db.py`) before proposing migrations
- **Prefer additive, backward-compatible migrations** — SCHEMA_VERSION bump, new tables/columns only
- Use explicit relationships (foreign keys), appropriate indexes, transactions, uniqueness constraints
- Do NOT store secrets in plaintext when avoidable (use vault pattern)
- Preserve scan isolation and provenance
- Do NOT create a second database architecture

---

# 14. CLI ADDITIONS

```
python main.py --import-har <file.har>
python main.py --list-imported [--scan-id N]
python main.py --request-graph [--scan-id N]
python main.py --test-plan [--scan-id N] [--approve | --reject <id>]
python main.py --pending-followups [--scan-id N]
python main.py --resume <scan_id>
python main.py --compare-scans <id1> <id2>
python main.py --findings [--scan-id N] [--severity high]
```

Every automated decision should be explainable through CLI output or generated audit record. Do NOT introduce unnecessary interactive complexity.

---

# 15. TESTING AND ACCEPTANCE — UNIVERSAL RULES

- Every phase requires automated tests
- Use deterministic fixtures (loopback, mock, controlled environments)
- **Regression tests proving valid findings from baseline are not lost after optimization**
- Existing test suite must continue to pass (exceptions require documented reason)
- Generate `docs/PHASE<N>_REPORT.md` for each phase with baseline vs new metrics

**NEVER report an optimization as successful if it reduces findings, endpoint coverage, or parameter coverage.**

---

# 16. EXECUTION ORDER & STOP POINTS

Execute phases in STRICT order:

```
Phase 0 (Audit) → Phase 1 (Baseline + Optimization) → Phase 2 (Durability)
  → Phase 3 (HAR) → Phase 4 (Brain) → Phase 5 (Diff) → Phase 6 (Auth SM)
  → Phase 7 (Feedback Loop) → Phase 8 (JS, if time) → Phase 9 (AI, on request)
```

**After each phase:**

1. Run all tests + lint + compile
2. Generate the phase report (`docs/PHASE<N>_REPORT.md`)
3. STOP and wait for user confirmation before proceeding to next phase

**Do NOT start the next phase until the current phase report is complete and the user has confirmed to proceed.**

---

# 17. FINAL GOAL

**XEzer must evolve from a collection of security scanners into a stateful, evidence-driven security testing and reasoning platform that:**

- Understands application context
- Selects relevant tests intelligently
- Never skips a test because it is unsure (tests instead)
- Learns from new evidence
- Re-evaluates previous hypotheses
- Optimizes execution WITHOUT sacrificing coverage or authorization boundaries
- Recovers from interruption without losing work
- Accepts external traffic (HAR) as intelligence source
- Makes every decision explainable and auditable

**The system must test everything within scope and PRODUCE RESULTS. It must work smart to avoid rate limits — through pacing, deduplication, and prioritization — not through evasion.**
