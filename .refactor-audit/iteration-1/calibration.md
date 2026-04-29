---
iteration: 1
phase: 2 — World-Class Reference Calibration
date: 2026-04-29
status: complete; rubric stable for iter-1; per-iter dimension scores updated in verification.md
---

# Iteration 1 — Calibration

> Goal: anchor the 1–10 scale to **named reference projects** (not vibes), then plan the maturity Δ +1.0 weighted target distribution.

---

## 1. Reference projects roster

The choice of reference is layered to this project's stack: FastAPI/SQLAlchemy backend + React/Vite frontend + Python ecosystem norms + cross-cutting engineering practice. Each project below is consulted for at least one dimension; some span several.

### 1.1 Backend (Python / FastAPI / SQLAlchemy ecosystem)

> Each project is followed by a per-dimension anchor justification. A reference without a concrete "this project anchors that dim BECAUSE" is not a reference.

**Cosmic Python** — *Architecture Patterns with Python* companion code, Percival & Gregory 2020. [github.com/cosmicpython/code](https://github.com/cosmicpython/code), Apache-2.0.
- **Architecture clarity** — ports/adapters made concrete in chapters 5–6; the `adapters/` folder = anti-corruption layer model for our OSV/NVD/GHSA case
- **Domain purity** — chapter 1's `Allocate` aggregate is the canonical "pure dataclass, invariants enforced in `__post_init__`" pattern; directly applicable to our Suppression / SLA / VEX state machine
- **Test quality** — chapter 4's Service Layer tests demonstrate driving use cases with fake repos; the safety-net pattern for the `releases.py` split

**Litestar** — [github.com/litestar-org/litestar](https://github.com/litestar-org/litestar), MIT.
- **API design** — explicit DTO discipline (separate request/response models per endpoint); demonstrates schema-first contract design without 3-layer Pydantic over-abstraction
- **Architecture clarity** — plugin architecture shows how to keep the framework boundary thin while exposing extensibility points; directly comparable to our `services/integrations/` split

**FastAPI core** — [github.com/fastapi/fastapi](https://github.com/fastapi/fastapi), MIT.
- **Readability density** — Sebastián Ramírez's own functions are routinely under 30 LOC with type hints + docstrings; benchmark for our service modules
- **API design** — `Depends` chain composability is a model for our `get_current_user → require_admin → require_admin_scope` chain (which we already do well)

**Full Stack FastAPI Template** — [github.com/fastapi/full-stack-fastapi-template](https://github.com/fastapi/full-stack-fastapi-template), MIT.
- **Architecture clarity** — official blueprint for `app/api/`, `app/crud/`, `app/models/`, `app/schemas/` separation; the `crud/` layer is one option we explicitly REJECT (per AR-2: SQLAlchemy session is the repository)
- **Build & tooling** — Vite + uvicorn + alembic; minus alembic (we have AD-001 inline migration), our shape is similar

**Polar.sh** — [github.com/polarsource/polar](https://github.com/polarsource/polar), Apache-2.0.
- **API design** — real-world FastAPI multi-tenant SaaS with idempotency tokens and consistent error shapes; reference for our future commercialisation work
- **Multi-tenant patterns** — `organization_id` filter discipline at the SQL layer; comparable to our `get_org_scope` + `require_release_in_scope`

**SQLAlchemy 2.0** — [github.com/sqlalchemy/sqlalchemy](https://github.com/sqlalchemy/sqlalchemy), MIT.
- **Abstraction discipline** — every abstraction in SQLAlchemy is justified per occurrence; the library itself is a 7/10 model for "no extra layer unless it pays for itself"
- **Doc density** — its own ChangeLog and SQLAlchemy 2.0 migration guide are exemplary for documenting non-obvious choices; benchmark for our `.knowledge/decisions/` ADR depth

**Sentry backend** (`getsentry/sentry`) — Business Source License.
- **Observability** — first-party metric + log + trace integration shipped end-to-end; the model for what observability "8/10" looks like in Python
- **Performance awareness** — explicit hot-path identification + database query budgets per endpoint; reference for the perf-CI integration we may add later

**HTTPX** ([github.com/encode/httpx](https://github.com/encode/httpx)) — BSD-3.
- **Test quality** — its own test suite uses pytest + `parametrize` + `pytest-asyncio` markers; exemplar of how to test an async library; pattern for our `vuln_scanner` retry/timeout tests
- **Error handling** — typed exception hierarchy (`HTTPError → RequestError → ConnectError`) with context preservation; reference for the typed exceptions we'll introduce in `domain/`

### 1.2 Frontend (React / Vite ecosystem)

> Refactoring UI (Wathan & Schoger) was previously listed here. **Removed 2026-04-29** — visual design book is `.ui-audit/` lane scope, not refactor-audit lane. Lane separation matters.

**Excalidraw** — [github.com/excalidraw/excalidraw](https://github.com/excalidraw/excalidraw), MIT.
- **Architecture clarity** — single-purpose component decomposition; canvas + tool + scene split into ~10 well-named directories; benchmark for breaking ReleaseDetail.jsx in a future iter
- **Test quality** — Jest + Playwright with realistic interaction tests; reference if we ever add frontend tests (out of scope this iter)

**Cal.com** — [github.com/calcom/cal.com](https://github.com/calcom/cal.com), AGPL-3.0.
- **Architecture clarity** — feature-module organisation (one folder per feature, internal sub-tree); analogous to the bounded-context split we're proposing for `releases.py` (mirrors well into a future `frontend/src/features/releases/` reorg if/when ReleaseDetail.jsx is split)

**TanStack Query / Router** — [github.com/TanStack](https://github.com/TanStack), MIT.
- **Readability density** — type-driven names (`useQuery`, `invalidateQueries`); short, intention-revealing identifiers; reference for naming hooks/util-functions
- **API design** — client-side library API consistency; the model for the `frontend/src/api/client.js` evolution if it ever needs more than axios + interceptors

**shadcn/ui** — [github.com/shadcn-ui/ui](https://github.com/shadcn-ui/ui), MIT.
- **Architecture clarity** — composition-over-inheritance for components (no `BaseModal extends BaseDialog`); canonical pattern for `components/Modal.jsx`, `components/ConfirmModal.jsx` etc. (which we already do)

**Sentry frontend** (`getsentry/sentry`) — BSL.
- **Architecture clarity** — at-scale React with strict component-size discipline (max LOC enforced via lint); model for how a 2087-LOC ReleaseDetail.jsx eventually decomposes
- **Performance awareness** — explicit re-render budgets; React Profiler integration in dev; reference for the Phase-5 hot-spot (4) measurement on ReleaseDetail.jsx

### 1.3 Cross-cutting engineering references

**Stripe API** (public docs + SDKs).
- **API design (10/10 anchor)** — 15 years of consistency; idempotency keys; structured errors (`type` / `code` / `message`); versioning discipline; the gold standard

**Linear** (closed source; public engineering talks).
- **Performance awareness** — public benchmarks of <100ms interaction latency; reference for B2B SaaS perf bar (not directly applicable to our backend Python, but anchors the "what good frontend perf looks like" intuition)

**TigerBeetle** — [github.com/tigerbeetle/tigerbeetle](https://github.com/tigerbeetle/tigerbeetle), Apache-2.0.
- **Architecture clarity (10/10 anchor)** — layer violations are build failures; the upper bound of architectural enforcement
- **Performance awareness (10/10 anchor)** — every hot path benchmarked; CI rejects regressions; explicit "no allocation in hot path" rules
- **Code review discipline** — TIGER style guide is the bar for review rigor; cited per finding when relevant

**SQLite** — [sqlite.org](https://sqlite.org).
- **Test quality (10/10 anchor)** — test:code ≈ 600:1 across 3 harnesses (TCL, ANSI C, fuzzers); deterministic across 7 OS × 4 arch
- **Doc density (10/10 anchor)** — documentation = 70% of repo; every quirk explained
- **Abstraction discipline (10/10 anchor)** — amalgamation has zero unnecessary layers

**PostgreSQL** — [postgresql.org](https://postgresql.org).
- **Test quality** — multi-decade regression test discipline; reference for "regression test as living spec" pattern
- **Performance awareness** — query planner discipline + EXPLAIN as primary debugging tool; cited for our DB-layer findings

**tokio** — [github.com/tokio-rs/tokio](https://github.com/tokio-rs/tokio), MIT.
- **Performance awareness** — async perf benchmarking discipline; reference if Phase-5 ever discusses our `monitor.py` background thread vs an asyncio task

**Honeycomb backend** (talks + open posts).
- **Observability (10/10 anchor)** — structured events with correlation IDs through every layer; in-product breadcrumbs; the upper bound for what observability looks like

### 1.3 Cross-cutting engineering references

| Source | What it anchors |
|---|---|
| **Stripe API** (public docs + SDKs) | Top-of-class API design discipline (consistency, idempotency, error structure, versioning) — sets the 10/10 for API design |
| **Linear** (closed source; public engineering talks) | UX consistency + perf engineering benchmark for B2B SaaS |
| **TigerBeetle** ([github.com/tigerbeetle/tigerbeetle](https://github.com/tigerbeetle/tigerbeetle)) | Code review discipline; explicit "no allocation in hot path" rules; sets the 10/10 for performance awareness |
| **SQLite** ([sqlite.org](https://sqlite.org)) | Long-lived single-codebase discipline; 600:1 test:code ratio; sets the 10/10 for test quality + doc density |
| **PostgreSQL** | Long-lived enterprise OSS with regression test rigor; Phase-3 boundary discussions |
| **tokio** ([github.com/tokio-rs/tokio](https://github.com/tokio-rs/tokio)) | Performance + observability under async; reference for Phase 5 if we discuss Python async patterns |
| **Honeycomb backend** (talks + open posts) | Sets 10/10 for Observability — structured events with correlation IDs through every layer |

### 1.4 Refactoring methodology references (cited per finding)

| Source | Used for |
|---|---|
| Martin Fowler — *Refactoring* (2nd ed., 2018) | Naming Phase-8 refactor moves (Extract Method, Move, Replace Type Code with Polymorphism, …) |
| Kent Beck — *Tidy First?* (2024) | The structural-vs-behavioural commit split discipline (encoded in `code-principles.md` §H4) |
| Michael Feathers — *Working Effectively with Legacy Code* (2004) | Characterization-test approach for the `releases.py` god-router split |
| Cosmic Python — *Architecture Patterns with Python* (2020) | Hexagonal target shape (encoded in `architecture.md` §4) |
| Robert Martin — *Clean Architecture* (2017) | Dependency-direction reasoning |
| Eric Evans — *Domain-Driven Design* (2003) | Domain layer scope; pulling invariants out of routers |
| Brendan Gregg — *Systems Performance* (2nd ed.) | USE / RED method; Phase-5 measurement discipline |
| Adam Wathan — *Refactoring UI* (2018) | UI quality bar |

---

## 2. Per-dimension rubrics (1–10)

For each dimension below: anchor scores are tied to the projects above. The current score and target after iter-1's Phase-8 execution are stated. **Anchors at 10 / 7 / 5 / 3 are mandatory; intermediate scores interpolate.**

---

### 2.1 Architecture clarity

> "Can a stranger find where to add feature X in under 5 minutes by reading the layout?"

| Score | Anchor |
|:---:|---|
| **10** | TigerBeetle — layer violations are build-failures; every directory has a one-line README of its scope |
| **8** | Cosmic Python ch.5–6 reference code: ports/adapters explicit; service layer thin; each aggregate boundary is its own module |
| **7** | Litestar core OR Full Stack FastAPI Template: routers→services→repos clean; no god-modules; some `shared/` exists but is small |
| **5** | Average mid-size FastAPI side-project: routers exist, services exist, but boundaries are observable not enforced; some helpers leak |
| **3** | God router (≥ 1500 LOC, ≥ 20 endpoints) with business logic inline; helpers private to that router |
| **1** | Single-file or random-pile; layering is aspirational only |

**Current**: **5** — `releases.py` 2101 LOC is a textbook 3/10 god-router, but the rest of the codebase (other 20 routers, services/, models/, core/) sits at ~6. Weighted: 5.

**Target after iter-1**: **7** — split `releases.py` into 5–7 named sub-modules under `services/usecases/`; introduce `services/{usecases,reports,scanners,integrations}/` subdirectories per `architecture.md` §4.1. Reaches Litestar / Full Stack template tier in the touched slice; some legacy routers still inline-schema (acceptable iter-1 progress).

**Δ = +2**

---

### 2.2 Domain purity

> "Where do business invariants live? Are they enforced where they are stated?"

| Score | Anchor |
|:---:|---|
| **10** | Cosmic Python ch.6: domain layer has zero framework imports; pure dataclasses with invariants enforced in `__init__` / `__post_init__`; SQLAlchemy mapping is via classical `mapper_registry` |
| **8** | Sentry's billing domain: dedicated `domain/` package; framework-agnostic value objects |
| **6** | Pydantic-coupled domain: validation moved into a model class but coupled to Pydantic / SQLAlchemy semantics |
| **4** | SQLAlchemy ORM doubles as domain (anemic); business rules live in route handlers |
| **1** | No domain concept; raw SQL + dict shuffling in handlers |

**Current**: **3** — anemic ORM models; `_is_suppressed` / `_sla_info` (E1/E2 invariants in `code-principles.md`) live in `releases.py` instead of on the entity / domain object. CRA state machine transitions are scattered across `cra.py` + `models/cra_incident.py`'s `audit_log` string.

**Target after iter-1**: **6** — extract Suppression / SLA / VEX state machine into a small `domain/` package; ORM stays anemic per AR-2 (no Repository pattern). Cross the line from "everything in router" to "invariants stated where they live, enforced once".

**Δ = +3** (largest single dim move; this is iter-1's centrepiece)

---

### 2.3 Abstraction discipline / cost awareness

> "How many indirections does a typical call traverse? Are they earning their keep?"

| Score | Anchor |
|:---:|---|
| **10** | SQLite amalgamation: every abstraction's cost is paid in measurable cycles; nothing exists "just in case" |
| **8** | TigerBeetle: explicit "no inheritance, no exceptions, no hidden allocation" rules; abstractions justified per occurrence |
| **7** | This project today: no Repository pattern around SQLAlchemy; no DTO trinity; `pdf_shim` is honest about being a shim and named that way |
| **5** | Average: a few unnecessary base classes; factory factories; "we might need this someday" |
| **3** | Spring-Boot-in-Python pattern: `AbstractBaseFactoryServiceImpl<T>` for one implementation |
| **1** | Indirection-for-its-own-sake; following 4 hops to find what writes a row |

**Current**: **7** — surprisingly disciplined. The `pdf_shim` is exemplary: a shim that calls itself a shim, exists for a stated license reason, and does not pretend to be a clean abstraction.

**Target after iter-1**: **7** — hold the line. Q10's red lines AR-1/2/3 (`architecture.md` §4.4) explicitly cap abstraction. Adding Suppression/SLA value objects passes AR-1 because they are used by ≥ 2 modules (router + monitor + notifier).

**Δ = 0** (deliberate hold)

---

### 2.4 Readability density

> "Can a stranger read a function and know what it does in 10 seconds without reaching for context?"

| Score | Anchor |
|:---:|---|
| **10** | Stripe Python SDK: every public function has docstring + example; no function over 30 lines without comment; consistent vocabulary across 200+ resources |
| **8** | TanStack Query: type-driven names; small functions; intention-revealing identifiers; consistent vocabulary |
| **7** | This project today: CLAUDE.md is unusually rich; naming generally good; function lengths reasonable EXCEPT in god files (releases.py has multiple 50+ LOC handlers) |
| **5** | Average: some 100-line functions; some opaque vars (`data`, `info`, `manager`) |
| **3** | Single-letter variables; undocumented public API; inconsistent vocabulary |
| **1** | Obfuscated; magic numbers; non-English identifiers in non-i18n contexts |

**Current**: **7** — strong on convention + documentation; weak on function length in god files. `releases.py:upload_sbom` and friends are likely 80–150 LOC each (verified in Phase 4).

**Target after iter-1**: **8** — splitting god files brings maximum function size down; named sub-modules give better-than-stripe-y vocabulary at the package level. Won't reach 9–10 without docstring discipline pass (separate iter).

**Δ = +1**

---

### 2.5 Error handling quality

> "Are errors typed, contextualised, and routed correctly? Are recoverable vs catastrophic kept apart?"

| Score | Anchor |
|:---:|---|
| **10** | Rust idiomatic: `Result<T, E>` pervasive; error context captured at every layer (`anyhow`/`thiserror`); recoverable vs not distinguished by type |
| **8** | Litestar / Sentry Python: typed error hierarchies per module; conversion via `__cause__`; user vs internal errors separated |
| **6** | This project's *goal* state: stratified — domain errors as named exception types, infra errors as broad `except` with logger.exception, user-facing zh-TW messages preserved |
| **4** | This project's *current* state: 46 broad `except Exception`; no typed hierarchy; some `except: pass` patterns; exception-as-control-flow in monitor |
| **1** | Empty catches; swallowed errors; stack traces leak to users |

**Current**: **5** — between "this project today (4)" and "goal state (6)". User-facing messages in zh-TW are consistently HTTPException; broad-excepts are mostly accompanied by logger.exception (mitigates the smell). 46 broad-excepts is the count to triage in Phase 4.

**Target after iter-1**: **6** — triage the 46 broad-excepts in Phase 4 → keep legitimate ones (top-level retry/cleanup), narrow the smelly ones (catch specific exception types). Introduce typed exceptions for domain errors that emerge during the split (e.g. `SuppressionExpired`, `LockedReleaseModificationAttempt`).

**Δ = +1**

---

### 2.6 Test quality (not just coverage)

> "Will a refactor break loudly? Are tests fast, independent, deterministic, behaviour-focused?"

| Score | Anchor |
|:---:|---|
| **10** | SQLite: test:code ≈ 600:1; deterministic across 7 OS × 4 arch matrices; multiple test harnesses (TCL + ANSI C + fuzzers) |
| **8** | pytest itself: extensive `parametrize`, fixtures, plugin ecosystem; characterization tests for its own behaviour |
| **6** | This project's *goal* state after iter-1: pytest unit + characterization on refactored slices, integration suite preserved, ~30%+ coverage on touched code |
| **4** | This project's *current* state: stdlib HTTP-only integration; one structural CI test; no unit tests; no coverage measurement |
| **2** | Sparse manual smoke; tests fail intermittently; nobody trusts them |
| **1** | No automated tests |

**Current**: **3** — strong CI gating + structural enforcement test push us above 2; absence of unit tests + zero frontend tests + no coverage keep us below 4. Generous reading is 4; conservative is 3.

**Target after iter-1**: **6** — pytest dev-only added (per D2 / `code-principles.md` §F7); characterization tests for the `releases.py` slices being moved; ~30% coverage on the split modules. Frontend stays at 0 (Q4: out of scope).

**Δ = +3** (second-largest dim move)

---

### 2.7 Observability

> "Can on-call see what's happening when a customer reports 'something is broken'?"

| Score | Anchor |
|:---:|---|
| **10** | Honeycomb backend: structured events with correlation IDs through every layer; in-product breadcrumbs |
| **8** | Sentry: structured logs + metrics + distributed tracing |
| **6** | OpenTelemetry-instrumented FastAPI app: trace per request, structured logs, basic metrics export |
| **4** | This project today: stdlib `logging.getLogger(__name__)`; AuditEvent for write actions; no correlation; no metrics; `/health` endpoint exposes monitor status |
| **2** | Print statements; no log levels; no audit trail |
| **1** | Silent system |

**Current**: **4** — AuditEvent (21 event types, append-only) lifts us above pure stdlib logging. `/health` endpoint exposes meaningful state (db + monitor). No correlation_id, no metrics.

**Target after iter-1**: **4** — explicit hold per Q7. Observability investment is its own audit lane; mixing it into refactor would hide behavior-equivalence regressions in log diffs.

**Δ = 0**

---

### 2.8 Performance awareness

> "Are hot paths identified? Are there benchmarks? Are regressions caught?"

| Score | Anchor |
|:---:|---|
| **10** | Brendan Gregg's discipline / TigerBeetle: USE/RED metrics, flamegraphs, latency histograms in CI with regression budgets |
| **8** | tokio: every hot path benchmarked; regression budgets in CI; perf reviews per PR |
| **6** | One-time profiling pass on hot paths; benchmarks committed but not in CI |
| **5** | This project today: OSV batch optimization shows awareness (200 → 51 HTTP, recorded once); no committed benchmark; no CI perf gate |
| **3** | "Feels fast enough"; no measurement |
| **1** | N+1 in hot paths in production; nobody noticed |

**Current**: **5** — single recorded optimization with documented number is meaningful. Lack of committed benchmark prevents future verification; lack of CI gate prevents regression catching.

**Target after iter-1**: **6** — D6 hot-spot benchmarks (4 hot spots) committed to repo as runnable scripts. Not in CI yet (separate decision).

**Δ = +1**

---

### 2.9 API design quality

> "Is the API surface predictable, evolvable, hard to misuse?"

| Score | Anchor |
|:---:|---|
| **10** | Stripe API: 15 years of consistency, predictable evolution, idempotency keys, versioning discipline, error structure (`type` / `code` / `message`) standardised |
| **8** | GitHub REST: conventions documented; auth predictable; errors structured; deprecation discipline |
| **7** | Litestar / Polar.sh: clear DTO discipline; consistent verbs/prefixes; OpenAPI is first-class output |
| **6** | This project today: consistent verbs/prefixes; status codes mostly right (404 vs 403 oracle handling correct); inline `BaseModel` in 18/21 routers fragments shape |
| **4** | Inconsistent verbs; mixed envelope/no-envelope; error shapes vary by endpoint |
| **1** | Ad-hoc; everything is POST; status codes random |

**Current**: **6** — strong status-code semantics (especially 404 oracle prevention); fragmented schemas drag us down. SDLC-001 enforcement test is unusual discipline that lifts the score above pure inline.

**Target after iter-1**: **7** — only the routes touched during the `releases.py` split move to centralised schemas. ~37 endpoints upgrade; remaining 60+ stay inline (acceptable iter-1 progress; full sweep is a separate iter).

**Δ = +1**

---

### 2.10 Dependency hygiene

> "Are deps minimal, justified, audited, version-controlled?"

| Score | Anchor |
|:---:|---|
| **10** | TigerBeetle: zero runtime deps |
| **9** | SQLite: zero runtime deps; build-time only |
| **8** | This project today: 17 backend + 6 frontend runtime deps, ALL permissive licences, version-pinned, CI-audited (`pip-audit --strict` + `npm audit --omit=dev`), license-rotated to drop LGPL deps |
| **6** | Average: pinned but unaudited; some LGPL leakage |
| **4** | No lockfile; drift between dev/prod |
| **1** | `npm install -g everything`; `pip install` without pinning |

**Current**: **8** — discipline is real and CI-enforced. License Path B (100% permissive runtime) is unusual rigour for a one-developer project.

**Target after iter-1**: **8** — adding pytest-dev + optional pytest-cov + optional hypothesis (per F7) keeps us at 8 because they go to a SEPARATE `requirements-dev.txt` and never enter the runtime path. The 8/10 anchor explicitly contemplates dev-only deps as separate.

**Δ = 0**

---

### 2.11 Build & tooling

> "How fast is the dev loop? How clear is the failure mode? How portable is the setup?"

| Score | Anchor |
|:---:|---|
| **10** | Cargo / Bazel: hermetic, reproducible, fast; one-command everything |
| **8** | Vite + uvicorn + multi-job CI in < 5min: fast feedback; no Docker required in dev |
| **7** | This project today: Vite + uvicorn + .bat launchers + 6-job CI; no Docker burden; .env discipline; structural enforcement test in CI |
| **5** | Works but slow / manual; some commands require copy-paste from README |
| **3** | Bespoke Makefile incantations; "ask Bob if this fails" |
| **1** | "works on my machine" |

**Current**: **7** — `start_backend.bat` + Vite + 6-job CI workflow is solid. Lacks pre-commit hooks (lint/format on commit) and lacks one-shot dev-up command.

**Target after iter-1**: **7** — no tooling refactor planned this iter. Adding pytest enables `pytest -k` runs but doesn't move tooling rating.

**Δ = 0**

---

### 2.12 Doc density

> "Is intent recorded? Are quirks explained? Can a stranger reconstruct decisions?"

| Score | Anchor |
|:---:|---|
| **10** | SQLite: documentation = 70% of repo; every quirk explained; ADRs for everything |
| **9** | This project today: CLAUDE.md (18.5KB) + NEXT_TASK.md + CHANGELOG.md + .knowledge/ (decisions/patterns/pitfalls/references) + .ui-audit/ + .refactor-audit/ — multi-track planning docs unusual for a one-developer project |
| **7** | Cosmic Python book code: README + ADRs + chapter mapping |
| **5** | Average: README + maybe API.md |
| **3** | README only |
| **1** | "the code is the documentation" |

**Current**: **9** — borderline 9–10; only the per-module docstring density (currently sparse) and per-module ADR coverage hold us back from 10.

**Target after iter-1**: **9** — refactor maintains existing docs + adds ADRs to `.knowledge/decisions/` for each major architecture change in the split (likely 2–3 new ADRs). Holds at 9.

**Δ = 0**

---

## 3. Maturity Δ +1.0 weighted target — distribution

Per `ledger.md` Iter-1 row, target weighted Δ = **+1.0** (current 5.75 → target 6.75 across 12 dimensions). Distribution:

| # | Dimension | Now | Target | Δ | What gets us there |
|---:|---|:---:|:---:|:---:|---|
| 1 | Architecture clarity | 5 | 7 | **+2** | Split `releases.py` into 5–7 sub-modules; introduce `services/{usecases,reports,scanners,integrations}/` |
| 2 | Domain purity | 3 | 6 | **+3** | Extract Suppression / SLA / VEX state into `domain/`; routers stop carrying invariant logic |
| 3 | Abstraction discipline | 7 | 7 | 0 | Hold (AR-1/2/3 red lines) |
| 4 | Readability density | 7 | 8 | **+1** | Smaller files; named sub-modules; max function size drops |
| 5 | Error handling | 5 | 6 | **+1** | Triage 46 broad-excepts; introduce typed domain exceptions for new domain layer |
| 6 | Test quality | 3 | 6 | **+3** | pytest dev-only + characterization tests on refactored slices; ~30%+ coverage on touched code |
| 7 | Observability | 4 | 4 | 0 | Hold (Q7 — separate audit) |
| 8 | Performance awareness | 5 | 6 | **+1** | 4 hot-spot benchmarks committed as runnable scripts |
| 9 | API design | 6 | 7 | **+1** | Centralize schemas for the 37 routes touched during the split |
| 10 | Dependency hygiene | 8 | 8 | 0 | pytest-dev added separately ⇒ no runtime change |
| 11 | Build & tooling | 7 | 7 | 0 | No tooling refactor this iter |
| 12 | Doc density | 9 | 9 | 0 | Refactor maintains; 2–3 new ADRs in `.knowledge/decisions/` |
| | **Sum** | **69** | **81** | **+12** | **avg 5.75 → 6.75** ✓ exactly +1.00 |

### 3.1 Sanity checks on the distribution

- **Six dims hold (Δ=0)**: abstraction (deliberate cap), observability (out of scope), build/tooling (no refactor), deps (no runtime change), docs (already 9), and the implicit hold means the +1.0 target is concentrated in **6 dims** that move
- **Movers' weighted contribution**: +12 ÷ 12 dims = +1.00 weighted average ✓
- **Highest movers (+3)** are the two areas the project is weakest: domain purity and test quality — exactly where iter-1's primary effort lands
- **No dim moves more than +3**: prevents over-claiming. A single iter realistically moves a weak dim 2–3 levels with focused work; 4+ would imply cross-iter leverage

### 3.2 Re-measurement

`verification.md` (Phase 9) re-scores each dim with explicit evidence:
- For each dim that moved: cite the specific commit(s) + before/after artefact
- For each dim that held (Δ=0): assert no regression with diff evidence
- If any dim regressed, audit fails per protocol §10.4 ("不退步")

### 3.3 Operational acceptance criteria — preventing self-grading inflation

> Per user feedback iter-1 (2026-04-29): a dimension target is only "achieved" if a measurable acceptance criterion holds. Otherwise the score is downgraded honestly in `verification.md` and the gap moves to iter-2.

**Test quality 6 — acceptance criteria (must ALL hold):**
- **AC-T1.** ≥ **1/3 of new characterization tests are function-level** — directly call `_is_suppressed`, `_sla_info`, `_assert_release_org`, the new `domain/` value-object methods, etc. Pure HTTP-shape tests (POST request → assert response shape) do not count toward this 1/3
- **AC-T2.** Coverage tool (pytest-cov) reports ≥ **30% coverage on the slices touched in Phase 8** (NOT 30% global — only the files moved/refactored)
- **AC-T3.** All new tests are deterministic (run 5× in a row → same result) and < 5s wall-clock total (otherwise pytest CI cost compounds)
- **AC-T4.** Fixtures and parametrize used at least once each — demonstrates the dev-only dep (`pytest`) earns its keep beyond what stdlib could do

**Failure mode**: if AC-T1 fails (function-level < 1/3), Test quality scores **5** (not 6). Verification.md records "test quality investment under-target, characterization tests over-rotated to HTTP shape; iter-2 backlog: extract function-level tests for the helpers that were moved". The Δ +1.0 weighted target is then re-stated in ledger as an over-claim from iter-1, and iter-2 inherits +1 of debt to make up.

**Domain purity 6 — acceptance criteria:**
- **AC-D1.** A `domain/` package exists and contains at least 3 modules (Suppression, SLA, VEX state)
- **AC-D2.** No file under `domain/` imports from `app.api.*`, `fastapi`, `sqlalchemy.*`, or any third-party HTTP/DB framework
- **AC-D3.** At least one invariant per domain class is enforced in `__post_init__` / `__init__` (e.g. `Suppression(suppressed=True, suppressed_until=…)` rejects past timestamps)
- **AC-D4.** Routers no longer carry `_is_suppressed` / `_sla_info` definitions — these are moved to and re-exported from `domain/`

**Failure mode**: if AC-D2 fails (framework imports leak into `domain/`), Domain purity scores **5** (not 6). The +3 collapses to +2.

**Architecture clarity 7 — acceptance criteria:**
- **AC-A1.** `releases.py` is < 600 LOC after the split (down from 2101)
- **AC-A2.** At least 5 sub-modules emerge under `services/usecases/` (or equivalent per `architecture.md` §4.1)
- **AC-A3.** Each sub-module has a one-line docstring at the top stating its single responsibility
- **AC-A4.** No new file is over 600 LOC

**Failure mode**: if `releases.py` is 600–1000 LOC after split, Architecture clarity scores **6** (not 7). If > 1000, it stays at **5** and the iter is declared a partial success in ledger.

**Other +1 dimensions** (Readability +1, Error +1, Perf +1, API +1) — accepted as judgement calls in `verification.md`. They do not have hard acceptance criteria because each affects a small slice; an honest scorer can tell whether 6→7 or 5→6 reflects reality.

### 3.4 Composite outcome rules

- **Iter-1 success**: weighted Δ ≥ +0.8 with no single dim regression
- **Iter-1 partial success**: weighted Δ in [+0.5, +0.8); ledger records what missed and why
- **Iter-1 fail (work re-evaluated)**: weighted Δ < +0.5 OR any dim regression. Triggers a Phase-10 retrospective before iter-2 plan

---

## 4. How this rubric is used in Phase 4

Each finding in `code-audit.md` will:
- Cite the dimension(s) it touches
- State the current dim score impact ("this finding is one of three reasons Architecture clarity is at 5")
- State the proposed dim score impact ("fixing this raises Architecture clarity ≈ 0.5 points toward target")

Each finding in `architecture-audit.md` will additionally:
- Cite the reference project that does this better
- Quote the specific pattern or Cosmic-Python chapter / page that describes the canonical fix

Each finding in `performance-audit.md` will:
- State the measurement method (Phase 5 hot-spot benchmark or theoretical estimate)
- Carry a Confidence label (High / Medium / Low) per protocol §8.1
- Quantify the hypothesised improvement (≥ X% reduction in Y metric)

---

## 5. Honesty notes

- **The 1–10 scale is anchor-based, not statistically validated.** A team using a different reference set might score this project differently by 1–2 points per dim. The internal *consistency* (relative rankings, deltas) is what matters for tracking iter-over-iter progress.
- **The Δ +1.0 target is a planning estimate.** Phase 9's re-measurement uses the same rubric and the same referee (this audit's agent) — drift is bounded by writing rubric anchors here, not in the scorer's head.
- **Doc density 9 is already high enough that further investment has diminishing returns** for this iter. Future iters may evaluate "doc density per public API" as a sub-metric.
- **Test quality 3 → 6 is ambitious.** It depends on pytest dev-only landing AND characterization tests being meaningful (not just shallow assertions). If the characterization tests turn out to be HTTP-shape duplicates of `test_all.py`, the realised score may be 4–5 instead of 6 — flagged here so verification.md can downgrade honestly.

---

End of calibration.md
