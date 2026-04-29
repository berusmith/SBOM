---
iteration: 1
phase: 3 — Architecture Audit
date: 2026-04-29
status: complete (read-only); findings feed Phase 7 plan
finding_id_prefix: ARCH-1.NNN
---

# Iteration 1 — Architecture Audit

> Findings are anchored to `calibration.md` rubric anchors. Each finding cites file:line and names the canonical reference (Cosmic Python / Litestar / etc.) that does it differently. **Confidence**: High = directly observed via file read; Medium = inferred from structure; Low = theoretical.

---

## 3.1 Layering & dependency direction

### [ARCH-1.001] God router `releases.py` — 2102 LOC, 37 endpoints, 9 cross-cutting helpers
- **Severity**: P0(阻斷)
- **Category**: Architecture / Module
- **Trigger**: Phase 1 LOC ranking + `releases.py` deep read
- **Location**: `backend/app/api/releases.py:1-2102`
- **Observation**: A single router file holds the entire release lifecycle:
  - 37 endpoints (upload SBOM, rescan, EPSS/NVD/GHSA/KEV enrich, list components, list vulns, CSV export, PDF report ×4 (general / IEC 62443-4-1/4-2/3-3 / NIS2), evidence package, CSAF, CycloneDX XML / SPDX JSON export, SBOM quality, integrity, signature upload/verify/delete, lock/unlock, version/notes patch, patch-stats, gate, dependency-graph, upload-source, scan-image, scan-iac, sbom-from-source, sbom-from-binary)
  - 9 module-private helpers carrying business logic: `_SLA_DAYS`, `_is_suppressed`, `_sla_info`, `_assert_release_org`, `_enrich_kev`, `_enrich_epss`, `_enrich_ghsa`, `_highest_severity`, `_import_syft_cdx`
  - 2 module-level concurrency primitives: `_active_enrichments: set[str]`, `_enrichment_lock: threading.Lock`
- **Why it matters**: violates SRP at the file scale. New SBOM-related work has no obvious home — every contributor adds another endpoint, growing the file linearly. Wave D's reachability extension would push this past 2500 LOC. The 9 helpers cannot be reused outside `releases.py`. The two concurrency primitives bind release enrichment to single-process semantics with no enforcement (multi-worker uvicorn silently breaks them).
- **Reference**: Litestar core (~150–300 LOC per router file); Cosmic Python ch.5 service-layer pattern; Polar.sh `app/<feature>/endpoints.py` shape
- **Refactor Type**: **Move Method** (Fowler) ×9 helpers; **Extract Class** (per use case); **Split Phase** between HTTP I/O and use-case execution
- **Behavior-Equivalence Risk**: **High**
  - Endpoint URLs, HTTP verbs, request/response shapes must remain byte-identical
  - The 9 helpers are private; renaming + moving = 0 external breakage iff their callers in `releases.py` import correctly post-split
  - Concurrency primitives must keep the same identity (one lock instance, one shared set) — moving without care could create per-module lock instances
- **Security Impact**: **High** — every endpoint enforces `_assert_release_org` (legacy 403) or `require_release_in_scope` (404 / CWE-204). The split MUST preserve which check each endpoint uses. Forgetting to wire ownership = SDLC-001 CI failure (defense-in-depth)
- **Recommendation**:
  - Phase 7 plans the split into use-case modules under `services/usecases/release/` (or analogous per `architecture.md` §4.1):
    - `upload_sbom.py` — 1 endpoint + sbom_parser + score_sbom + diff
    - `enrich.py` — 4 endpoints (rescan / enrich-epss / enrich-nvd / enrich-ghsa) + 3 helpers (`_enrich_*`)
    - `reports.py` — 5 endpoints (general PDF / IEC ×3 / NIS2 / evidence package / CSAF / CycloneDX XML / SPDX JSON / sbom-quality)
    - `signature.py` — 3 endpoints (upload / verify / delete) — **separate commit, security carve-out per code-principles J5**
    - `lock.py` — 2 endpoints (lock / unlock)
    - `lifecycle.py` — get / patch version / patch notes / delete / list components / list vulns / list vulns CSV / patch-stats / gate / dependency-graph / integrity
    - `scanners.py` — scan-image / scan-iac / upload-source / sbom-from-source / sbom-from-binary + `_import_syft_cdx`
  - Helpers (`_is_suppressed`, `_sla_info`, `_assert_release_org`, `_highest_severity`) extracted to `domain/` package per ARCH-1.002
  - Concurrency primitives moved to `services/usecases/release/_enrichment_state.py` (single shared module)
- **Test Strategy**: characterization tests at HTTP level for all 37 endpoints (drive each, snapshot response). Function-level tests for the 9 helpers per AC-T1 in `calibration.md` §3.3
- **Effort**: L (multi-day)
- **Risk of Fix**: ripples to `monitor.py` (one import: `_enrich_kev`/`_enrich_epss`-equivalent), `services/firmware_service.py` (currently uses none), Wave D's reachability dispatch
- **Confidence**: High

### [ARCH-1.002] Anemic models — domain logic lives in routers
- **Severity**: P1(嚴重)
- **Category**: Architecture / Domain Model
- **Trigger**: Phase 1 model layer scan + `releases.py:64-85` reading
- **Location**:
  - Logic on Vulnerability invariants: `backend/app/api/releases.py:64-85` (`_is_suppressed`, `_sla_info`)
  - Logic on Vulnerability collection: `backend/app/api/releases.py:2098-2101` (`_highest_severity`)
  - Pure data: `backend/app/models/vulnerability.py:1-62` (zero methods, just columns)
- **Observation**: `Vulnerability` ORM model is 62 lines of `Column(...)` declarations with **zero behavior**. Invariants like "`suppressed=True` AND (`suppressed_until` is null OR `suppressed_until > now`)" live on the router as `_is_suppressed`. SLA computation lives on the router as `_sla_info`. The "highest severity in a list" reduce lives on the router as `_highest_severity`.
- **Why it matters**:
  - **Single source of truth** is broken — frontend rebuilds the same logic in JS (`ReleaseDetail.jsx` filters `v.suppressed` based on backend's pre-computed `suppressed` field, but if logic ever needs to change, two systems must change in lockstep)
  - **Duplication risk** — `_is_suppressed` is called by 4 sites in `releases.py`; if a future router needs the same check, copy-paste is the path of least resistance
  - **Testability** — function under test requires a real Vulnerability row with the right columns; small unit test impossible
- **Reference**: Cosmic Python ch.1 — the `Allocate` aggregate enforces `BatchOverflow` invariant in `__post_init__`; the same pattern fits `Suppression` value object exactly
- **Refactor Type**: **Move Method** to a new `domain/` package; or **Introduce Parameter Object** (`SuppressionState`) extracted from Vulnerability
- **Behavior-Equivalence Risk**: **Low** if helpers are moved bit-identically; the move is `git mv backend/app/api/releases.py:_is_suppressed → backend/app/domain/suppression.py:is_suppressed` plus all 4 call sites get an import update
- **Security Impact**: **None** — pure logic move; no security control involved
- **Recommendation**:
  - Create `backend/app/domain/` package with at minimum:
    - `suppression.py` — `is_suppressed(vuln) -> bool` + `Suppression` dataclass with `__post_init__` invariants
    - `sla.py` — `sla_info(vuln) -> SLAStatus` + `SLAStatus` enum + `_SLA_DAYS` constant
    - `severity.py` — `highest_severity(vulns) -> Severity | None` + `SEVERITY_ORDER` (currently in `core/constants.py`)
    - `vex.py` — VEX state machine (status × justification × response invariants currently scattered across `vulnerabilities.py` PATCH handlers)
  - Re-export from `domain/__init__.py` for ergonomic imports
  - Per AR-2 (`architecture.md` §4.4): no Repository pattern. ORM stays in `models/`; domain reads from ORM rows but does not own DB access
- **Test Strategy**: function-level pytest unit tests on each domain function; this is exactly what `calibration.md` AC-T1 demands (≥ 1/3 function-level)
- **Effort**: M (1–2 days; small surface)
- **Risk of Fix**: 4 call sites in `releases.py` to update; 1 call site in `vulnerabilities.py`; potentially 1 in `monitor.py`. CI integration test catches missed call sites
- **Confidence**: High

### [ARCH-1.003] Two parallel ownership-check patterns — partial migration
- **Severity**: P1(嚴重)
- **Category**: Architecture / Consistency / Security
- **Trigger**: `core/deps.py:87-130` ADR comment + grep for `_assert_release_org` vs `require_release_in_scope`
- **Location**:
  - Legacy: `backend/app/api/releases.py:87-93` (`_assert_release_org` returns 403)
  - Modern: `backend/app/core/deps.py:103-130` (`assert_release_in_scope` / `require_release_in_scope` returns 404)
  - Per CLAUDE.md "30 callers migration is separate cleanup, not in Phase 5 scope"
- **Observation**: The codebase has **two parallel patterns** for the same security-critical check. The old returns 403, the new returns 404 to defeat the CWE-204 oracle. The author flagged migration of "30 callers" as deferred but did not start.
- **Why it matters**:
  - **Inconsistency** — a new contributor reading `releases.py` sees both styles and might pick the wrong one
  - **Oracle risk** — the 30+ legacy `_assert_release_org` call sites still leak 403 vs 404 distinction (the old CWE-204 behavior)
  - **CI gap** — SDLC-001 enforcement test only checks that *some* check is wired, not which one; legacy 403 sites pass the CI test but still leak the oracle
- **Reference**: CWE-204 (Observable Response Discrepancy); the new pattern is correct — the question is finishing the migration
- **Refactor Type**: **Substitute Algorithm** at every call site
- **Behavior-Equivalence Risk**: **Medium** — for security tooling using the 403 to differentiate "no permission" from "doesn't exist" the change is a deliberate contract evolution. Per D1 (lenient regime), no external consumers depend on this distinction; the React frontend treats 403 and 404 with similar UX (redirect or "not found" message). Verify per page.
- **Security Impact**: **Positive** — closes oracle leakage on 30+ sites
- **Recommendation**: as part of the `releases.py` split (ARCH-1.001), every endpoint adopts `Depends(require_release_in_scope)` and removes its inline call to `_assert_release_org`. The legacy helper is deleted at the close of the split PR.
- **Test Strategy**:
  - HTTP characterization tests assert `404` (not `403`) on cross-org access for every release-id endpoint (one test per endpoint × 2 cases: not-exist / exists-but-not-yours)
  - SDLC-001 CI test gains an assertion: "if route uses `_assert_release_org`, fail" — preventing regression
- **Effort**: M (~30 endpoints touched, but each is a one-line change once the dependency is added to the function signature)
- **Risk of Fix**: low; ownership semantics identical, only status code changes
- **Confidence**: High

### [ARCH-1.004] Inline `BaseModel` in 18 of 21 routers — schemas package half-finished
- **Severity**: P2(中等)
- **Category**: Architecture / API design / Module
- **Trigger**: `wc -l backend/app/schemas/*.py` (3 files: org/product/release) vs `grep -c "class.*BaseModel" backend/app/api/*.py` (auth 5, cra 4, vulnerabilities 3, organizations 2, settings 2, tisax 2, users 2, licenses 2, policies 2, share 1, products 1, firmware 1, tokens 1, ...)
- **Location**: every router under `backend/app/api/` except `organizations.py`, `products.py`, `releases.py` (and even those define inline schemas alongside the imported ones)
- **Observation**: The `schemas/` package was started for the first 3 resources and never finished. 18 of 21 routers carry their request/response shapes as inline `class X(BaseModel)` definitions inside the same file as the route handler. Many routers also use `body: dict` (untyped) — see `releases.py:537,1502` (PATCH `/version`, `/notes`).
- **Why it matters**:
  - OpenAPI introspection works (FastAPI hoists inline classes), but **importing a request shape from another module is impossible without copy-pasting the class** — couples upstream callers (or tests) to the exact line of the router
  - **Codegen** for clients/SDKs cannot share types across endpoints
  - **Untyped `body: dict` endpoints** lose Pydantic's validation for free, accept any shape, silently ignore extras (under D1 lenient OK; under strict regime = audit gap)
- **Reference**: Litestar core (every endpoint takes a typed DTO from a `schemas/` module); FastAPI Full Stack template (`app/schemas/{user,item,...}.py` per resource)
- **Refactor Type**: **Extract Class** (move inline classes to `schemas/<resource>.py`) + **Replace Type Code with Class** for `body: dict`
- **Behavior-Equivalence Risk**: **Low** when classes are moved bit-identically; **Medium** when introducing Pydantic for previously-untyped `body: dict` (strictness changes might reject inputs that previously slipped through)
- **Security Impact**: positive — converts untyped `body: dict` to validated schema; reduces silent acceptance of malformed input
- **Recommendation**:
  - Iter-1 scope: only the schemas of the **37 endpoints touched during the `releases.py` split** are extracted to `schemas/release_*.py` (per `calibration.md` §3 plan)
  - Out of iter-1 scope: the other 60+ inline schemas in 17 untouched routers (deferred to a future iter or done opportunistically)
  - For `body: dict` PATCH endpoints (`update_version`, `update_notes`): introduce `ReleaseVersionUpdate(BaseModel)` and `ReleaseNotesUpdate(BaseModel)` with explicit fields and length caps
- **Test Strategy**: characterization tests assert response shape on a few endpoints; if inline → schemas move is bit-identical, no behavior change
- **Effort**: M (37 endpoints in iter-1 scope; remaining 60+ in future iters)
- **Risk of Fix**: low for moves; medium for `body: dict` → typed (one-time hardening)
- **Confidence**: High

### [ARCH-1.005] `services/` flat namespace mixes 5 concerns
- **Severity**: P2(中等)
- **Category**: Architecture / Module / Naming
- **Trigger**: `ls backend/app/services/` (25 files, no sub-dirs)
- **Location**: `backend/app/services/`
- **Observation**: 25 modules live at the same level under `services/`:
  - **Domain logic**: `reachability.py`, `sbom_parser.py`, `license_classifier.py`
  - **External integrations** (anti-corruption layer territory): `nvd.py`, `epss.py`, `kev.py`, `ghsa.py`, `vuln_scanner.py` (OSV)
  - **Reports** (PDF generators): `pdf_report.py`, `iec62443_report.py`, `iec62443_42_report.py`, `iec62443_33_report.py`, `nis2_report.py`, `tisax_pdf.py`, `pdf_shim.py`, `cjk_pdf.py`, `font_manager.py`
  - **Scanners** (subprocess wrappers): `trivy_scanner.py`, `syft_scanner.py`, `signature_verifier.py`, `firmware_service.py`
  - **Notifications**: `alerts.py`
  - **Background jobs**: `monitor.py`
  - **Format conversion**: `converter.py`
  - **Seeding**: `tisax_seed.py`
- **Why it matters**:
  - Flat tree at this scale obscures what each module does — the names help but `services/` is a "miscellaneous" bucket
  - **No anti-corruption layer signal** — OSV / NVD / EPSS / KEV / GHSA shapes can change upstream and bleed straight through to our DB columns; if their schemas were behind an `integrations/` adapter folder, the boundary would be obvious
  - **Wave D namespace conflict** — adding `reachability_integration.py` next to existing `reachability.py` would compound the flatness problem; `architecture.md` §4.5 already addresses this
- **Reference**: Cosmic Python ch.5 (`adapters/` folder for external systems); FastAPI Full Stack template's `crud/` separation; Polar.sh `app/integrations/`
- **Refactor Type**: **Move Module** + **Repackage**
- **Behavior-Equivalence Risk**: **Low** — moves are import-path changes; the modules' behavior is unchanged
- **Security Impact**: none directly; positive indirect (anti-corruption layer makes future input-validation hardening easier)
- **Recommendation**: per `architecture.md` §4.1, target tree:
  ```
  services/
  ├── usecases/         # NEW — split of releases.py
  ├── reports/          # IEC + NIS2 + TISAX + general PDF
  │   ├── pdf_helpers/  # pdf_shim, cjk_pdf, font_manager
  │   ├── iec62443/
  │   ├── nis2/
  │   └── tisax/
  ├── scanners/         # Trivy, Syft, signature_verifier, reachability/
  │   └── reachability/ # python_analyzer + integration (per WD-1)
  ├── integrations/     # OSV (vuln_scanner), NVD, EPSS, KEV, GHSA
  ├── notifications/    # alerts (split into webhook + smtp + formatters)
  ├── monitor.py        # cross-cutting; stays at top level
  └── (sbom_parser, license_classifier, converter stay at top level — pure domain)
  ```
  - Iter-1 scope: only the moves required by the `releases.py` split (`scanners/reachability/`, `services/usecases/release/`, possibly `integrations/`)
  - Out of iter-1 scope: full `reports/` consolidation, full `notifications/` split — deferred
- **Test Strategy**: integration tests cover end-to-end, so import-path moves are caught instantly if any wire is wrong
- **Effort**: M for iter-1 slice (~3–5 modules moved)
- **Risk of Fix**: low; pattern is `git mv` + import update + test
- **Confidence**: High

---

## 3.2 Module boundaries

### [ARCH-1.006] No anti-corruption layer for upstream OSV/NVD/EPSS/KEV/GHSA shapes
- **Severity**: P2(中等)
- **Category**: Architecture / Module
- **Trigger**: reading `vuln_scanner.py`, `nvd.py` (referenced), `_enrich_ghsa` in `releases.py:119-175`
- **Location**: integration calls scattered across `releases.py`, `monitor.py`
- **Observation**: `_enrich_ghsa` (releases.py:119-175) builds component dict (`comp_list = [{"purl": c.purl ..., "name": c.name, "version": c.version} for c in components_raw]`) then unpacks GHSA's response (`adv.get("ghsa_id")`, `adv.get("cve_id")`, `adv.get("cvss_score")`, etc.) directly into `db.add(Vulnerability(...))`. If GHSA's API changes a field name, the bug surfaces 1 step from the DB write.
- **Why it matters**:
  - Upstream shape drift = silent DB corruption (or `KeyError` at scan time)
  - No place to cache, mock, or evolve the upstream contract independently of our schema
  - Phase 4 will add NVD / OSV testing pain (no seam for fakes)
- **Reference**: Cosmic Python ch.5 — `adapters/` folder where each external service has an interface + implementation; failure or shape change is contained
- **Refactor Type**: **Introduce Parameter Object** for upstream responses (e.g. `GhsaAdvisory` dataclass parsed in `services/integrations/ghsa.py`); router consumes the dataclass, not the raw dict
- **Behavior-Equivalence Risk**: **Low** — pure encapsulation
- **Security Impact**: positive — explicit parsing surfaces failure of upstream input validation
- **Recommendation**: alongside ARCH-1.001 split, the `_enrich_*` helpers move into `services/integrations/<source>.py` and return typed DTOs; routers consume DTOs, not dicts. **Out of iter-1 scope** unless the touched-slice happens to include this — track as a Phase-2 candidate
- **Test Strategy**: with typed DTOs, fake `GhsaAdvisory` instances drive tests; no need to mock `httpx`
- **Effort**: M (5 integration modules; iter-1 may only do 1–2)
- **Risk of Fix**: low
- **Confidence**: Medium (depends on how much of the integration layer is touched in iter-1)

### [ARCH-1.007] Module-level mutable globals limit deployability + testability
- **Severity**: P2(中等)
- **Category**: Architecture / Concurrency / Module
- **Trigger**: reading `releases.py:56-57` + `monitor.py:15-21`
- **Location**:
  - `releases.py:56` — `_active_enrichments: set[str] = set()`
  - `releases.py:57` — `_enrichment_lock = threading.Lock()`
  - `monitor.py:15-21` — `_stop_event`, `_scan_lock`, `_is_scanning`, `_last_run_dt`, `_last_run_count`, `_last_skip_dt`, `_scheduler_thread`
- **Observation**: Concurrency primitives are module-level singletons. Within a single uvicorn worker this works correctly. Across multiple uvicorn workers (`--workers N`), each worker has its own set + lock + monitor thread — they don't coordinate. A user could trigger N concurrent NVD enrichments by hitting the API N times in a row hoping for different workers; the monitor would fire scans N× per cycle.
- **Why it matters**:
  - **Implicit single-process assumption** — current deploy is single-process (`uvicorn ... --port 9100` without `--workers`), so no actual breakage today
  - **Testability** — module globals make unit testing hard (need to reset state between tests)
  - **Future scale** — when commercialised, multi-worker becomes the norm; the breakage is silent
- **Reference**: Litestar's `LifespanContext` for app-scoped state; Cosmic Python ch.7 for "use the unit of work, not module globals"
- **Refactor Type**: **Replace Magic Number with Symbolic Constant** doesn't apply; closer to **Replace Method with Method Object** — make a `MonitorService` class instantiated in `lifespan`
- **Behavior-Equivalence Risk**: **Medium** — single-instance semantics must be preserved; if a `MonitorService` class is instantiated in `lifespan` and held on `app.state.monitor`, the existing public `start() / stop() / trigger() / get_status()` functions become wrappers that call `app.state.monitor.<method>()`. The risk is forgetting to wire `app.state.monitor` in tests or in some other entry point
- **Security Impact**: none directly; positive indirect (multi-worker safety becomes possible later)
- **Recommendation**:
  - Iter-1: low-priority. Park as DEBT-012; document the single-process assumption explicitly in `monitor.py`'s docstring
  - Future iter: extract `MonitorService` class + `EnrichmentRegistry` class; instantiate in `lifespan`; expose via `app.state` or via FastAPI `Depends`
- **Test Strategy**: when refactored, unit tests can construct a fresh `MonitorService` per test
- **Effort**: M
- **Risk of Fix**: medium (subtle concurrency)
- **Confidence**: Medium

### [ARCH-1.008] `_oidc_meta` mutable global cache, never invalidated
- **Severity**: P3(優化)
- **Category**: Architecture / Module
- **Trigger**: `auth.py:107` reading
- **Location**: `backend/app/api/auth.py:107`
- **Observation**: `_oidc_meta: dict = {}` caches the OIDC discovery document forever. If the IdP rotates keys or changes its endpoint URLs, every login fails until backend restart.
- **Why it matters**: low likelihood × high impact when it fires (login outage)
- **Reference**: standard OIDC client behavior (auto-refresh discovery doc on jwks_uri rotation signal)
- **Refactor Type**: **Replace Magic Number with Symbolic Constant** — TTL the cache (e.g. 1 hour); or invalidate on signature-verification failure
- **Behavior-Equivalence Risk**: low — TTL only changes timing
- **Security Impact**: positive (key rotation works)
- **Recommendation**: park as DEBT-013; iter-1 not in scope
- **Effort**: S
- **Confidence**: High (the issue exists; impact is rare)

---

## 3.3 Data model

### [ARCH-1.009] Anemic `Vulnerability` model — every column, zero method
- **Severity**: P1(嚴重)
- **Category**: Architecture / Data Model
- **Trigger**: reading `models/vulnerability.py:1-62`
- **Location**: `backend/app/models/vulnerability.py`
- **Observation**: 62 lines, all `Column(...)` declarations, 1 relationship. Zero methods. Zero `__post_init__` invariants. Zero validators. Yet the entity carries:
  - 5-state VEX status (`open / in_triage / not_affected / affected / fixed`) with cross-field invariants (`justification` only valid for `not_affected`; `response` only for `affected`)
  - SLA computation based on `(severity, scanned_at, status, suppressed)` quadruple
  - Suppression rules: `suppressed=True` AND (`suppressed_until is None` OR `suppressed_until > now`)
  - Reachability label semantics
- **Why it matters**: covered by ARCH-1.002. Listed separately here because the *data model* itself signals anemia — the columns are designed to be set and read, not to enforce.
- **Reference**: same as ARCH-1.002 — Cosmic Python ch.1 `Allocate` pattern
- **Recommendation**: see ARCH-1.002. The `domain/` package owns invariant enforcement; ORM `Vulnerability` stays a row mapper

### [ARCH-1.010] Dead column `dtrack_project_uuid` on `Release`
- **Severity**: P3(優化)
- **Category**: Architecture / Data Model / Dead Code
- **Trigger**: reading `models/release.py:17`
- **Location**: `backend/app/models/release.py:17`
- **Observation**: `dtrack_project_uuid = Column(String, nullable=True)` — Dependency-Track integration was replaced by direct OSV.dev calls per `CLAUDE.md`. Column remains.
- **Why it matters**: dead column on a frequently-accessed table. SQLite cannot DROP COLUMN, so it cannot be removed cheaply. But the model and serializers can stop exposing it.
- **Recommendation**: remove from `models/release.py` declaration (SQLAlchemy will silently leave the column); add ledger note that the column is "dead but live in DB until next table-rewrite migration"
- **Effort**: S
- **Risk of Fix**: low (model field removal; verify no serializer reads it — there is none)
- **Confidence**: High

---

## 3.4 Concurrency & state

### [ARCH-1.011] `monitor.py` background thread retains DB session ownership across long loops
- **Severity**: P2(中等)
- **Category**: Architecture / Concurrency
- **Trigger**: reading `monitor.py:34-174`
- **Location**: `backend/app/services/monitor.py:46-170` (single `db = SessionLocal()` for the whole `_do_scan_all`)
- **Observation**: `_do_scan_all` opens one DB session at line 46, keeps it open through ALL release scans (line 51-127), then through expired-suppression cleanup (line 130-154), then through final stats commit (line 156-163), and only closes in `finally` (line 170). For an org with 50 releases × 200 components each, the session may be open for minutes. Errors mid-loop call `db.rollback()` but continue with the same session.
- **Why it matters**:
  - **Long-held connections** — a single connection blocked on OSV API for minutes; under load this exhausts pool quickly
  - **Stale snapshot** — long-running session may not see commits from request handlers
  - **Rollback contagion** — one rollback can poison subsequent operations on the same session if not careful
- **Reference**: SQLAlchemy session-per-request pattern (FastAPI's `Depends(get_db)`); for batch jobs, "session per release" or "session per chunk"
- **Refactor Type**: **Extract Method** + **Replace Magic Number with Symbolic Constant** (chunk size); or **Substitute Algorithm** (session per release)
- **Behavior-Equivalence Risk**: Medium — release scanning order and commit grouping change; a partial failure may leave different state than today
- **Security Impact**: none
- **Recommendation**: park as DEBT-014; not in iter-1 scope. Future iter: `with SessionLocal() as db:` per release, accept that one release's failure does not poison the next
- **Effort**: M
- **Confidence**: Medium

---

## 3.5 Side-effect management

### [ARCH-1.012] `audit.record(db, ...)` requires explicit `db.commit()` afterward — easy to forget
- **Severity**: P2(中等)
- **Category**: Architecture / Side Effects
- **Trigger**: every `audit.record` call site in `releases.py` is followed by `db.commit()`; missing it = audit row never persists
- **Location**: pattern repeats 15+ times in `releases.py` (e.g. lines 296-297, 411-412, 1410, 1470-1471, 1484-1485, 1496-1497)
- **Observation**: `audit.record()` only does `db.add(AuditEvent(...))`. It does NOT commit. Each caller commits manually afterward. If a caller forgets the commit, the audit row is silently lost.
- **Why it matters**: the audit log is a security-relevant append-only contract. Missing entries = blind spot. Forget-to-commit is a tiny bug, large consequence.
- **Refactor Type**: **Inline Function** the commit into `audit.record()` (ensure it's safe — what about a transaction in progress?), OR ensure caller transactions always commit
- **Behavior-Equivalence Risk**: **Medium** — if `audit.record` commits internally, the parent transaction's batching changes; e.g. `lock_release` (line 1483-1486) currently commits twice (once for `release.locked = True`, once for audit). Doing one commit instead of two changes timing
- **Security Impact**: positive (eliminates silent audit-loss class of bug)
- **Recommendation**:
  - Option A: Make `audit.record` commit internally; document the contract
  - Option B: Add a CI check / lint rule "every `audit.record(` line is followed by `db.commit()` within 3 lines"
  - Iter-1: pick option A as part of the `releases.py` split (one transaction = one user-visible action; audit is part of that action). Risk acknowledged.
- **Test Strategy**: characterization tests assert audit row exists after every audit-emitting endpoint
- **Effort**: M
- **Risk of Fix**: medium
- **Confidence**: High

---

## 3.6 Evolvability

### [ARCH-1.013] Inline `__import__` for deferred config access
- **Severity**: P3(優化)
- **Category**: Architecture / Code style
- **Trigger**: `releases.py:472` `has_token = bool(getattr(__import__("app.core.config", fromlist=["settings"]).settings, "GITHUB_TOKEN", ""))`
- **Location**: `backend/app/api/releases.py:472`
- **Observation**: One-line use of `__import__` for what should be `from app.core.config import settings` at the top of the file (or already imported as `_cfg`). The file already imports `settings as _cfg` at line 20.
- **Why it matters**: code-smell tier; harms readability and is unnecessary
- **Recommendation**: replace with `_cfg.GITHUB_TOKEN` (the import is already there)
- **Effort**: S (one-line tidy)
- **Risk of Fix**: nil
- **Confidence**: High

### [ARCH-1.014] No formal ADR for the OSV batch optimization
- **Severity**: P3(優化)
- **Category**: Architecture / Doc density
- **Trigger**: cross-checking `.knowledge/decisions/` (only `0001-fastapi-dependency-upgrade.md` and `0002-lifespan-migration.md`) vs the OSV optimization documented in `CHANGELOG.md:73-80`
- **Location**: `.knowledge/decisions/` is missing an ADR for OSV `querybatch` migration
- **Observation**: A non-trivial design decision (per-PURL → batched + parallel) is recorded in CHANGELOG but not as an ADR. The CHANGELOG describes WHAT, not WHY-this-approach-vs-alternatives.
- **Why it matters**: future contributors won't know whether async vs threadpool was considered, what the upper bound is, or why 20 workers was chosen
- **Recommendation**: write `.knowledge/decisions/0003-osv-batch-strategy.md` as part of Phase 8 (Tidy commit; see `code-principles.md` §H5 doesn't apply here)
- **Effort**: S
- **Confidence**: High

---

## Summary table

| ID | Severity | Cat | Title | Effort |
|---|:---:|---|---|:---:|
| ARCH-1.001 | P0 | Arch | God router `releases.py` 2102 LOC | L |
| ARCH-1.002 | P1 | Arch | Anemic models — domain logic in routers | M |
| ARCH-1.003 | P1 | Arch | Two parallel ownership-check patterns | M |
| ARCH-1.004 | P2 | Arch | Inline `BaseModel` in 18 routers | M |
| ARCH-1.005 | P2 | Arch | `services/` flat namespace | M |
| ARCH-1.006 | P2 | Arch | No anti-corruption layer for upstream APIs | M |
| ARCH-1.007 | P2 | Arch | Module-level globals limit multi-worker | M |
| ARCH-1.008 | P3 | Arch | `_oidc_meta` cache never invalidated | S |
| ARCH-1.009 | P1 | Arch | Anemic `Vulnerability` model | (covered by ARCH-1.002) |
| ARCH-1.010 | P3 | Arch | Dead column `dtrack_project_uuid` | S |
| ARCH-1.011 | P2 | Arch | `monitor.py` long-held DB session | M |
| ARCH-1.012 | P2 | Arch | `audit.record` requires manual commit | M |
| ARCH-1.013 | P3 | Arch | Inline `__import__` for config | S |
| ARCH-1.014 | P3 | Arch | No ADR for OSV batch | S |

**Severity distribution**: P0 ×1, P1 ×3, P2 ×7, P3 ×4 (∑14)

End of architecture-audit.md
