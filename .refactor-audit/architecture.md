---
created: 2026-04-29
purpose: Architecture as it is today + target shape; updated each iteration
status: living document
---

# Architecture — Current & Target

> **Convention**: this file is rewritten as the architecture evolves. Each section ends with `Last updated: <iter>-<date>`. Removed elements move to `known-debt.md` or are noted as "obsolete since iter N".

## 1. Current shape (as of iteration 1, 2026-04-29)

### 1.1 Backend layout

```
backend/
├── app/
│   ├── main.py                — FastAPI bootstrap, inline SQLite migrations, admin seeding, CORS, rate limit, lifespan, health
│   ├── api/                   — 21 router files (~100+ endpoints)
│   ├── models/                — 22 SQLAlchemy ORM declarations
│   ├── schemas/               — Pydantic v2 — ONLY Org, Product, Release; rest inline in routers
│   ├── services/              — 25 modules: business logic + external integrations + reports + scanners + notifications
│   └── core/                  — config, database, deps, security, audit, plan, rate_limit, constants
├── tests/                     — 1 pytest-style structural test + 39-fixture reachability corpus
└── requirements.txt
```

### 1.2 Layering — actual dependency flow

```
                ┌──────────────────────────┐
                │   api/* (HTTP routers)   │
                └────┬───────────────┬─────┘
                     │               │
                     ▼               ▼
                ┌────────┐      ┌──────────┐
                │services│◄────►│  models  │  ← bidirectional; smell
                └───┬────┘      └────┬─────┘
                    │                │
                    ▼                ▼
                ┌──────────────────────┐
                │  core/ (db, config,  │
                │   deps, security,    │
                │   audit, plan, rl)   │
                └──────────────────────┘
                          │
                          ▼
                ┌──────────────────────┐
                │ external: OSV / NVD  │
                │ EPSS / KEV / GHSA /  │
                │ Trivy / Syft / EMBA  │
                │ SMTP / Slack / Teams │
                │ OIDC / SQLAlchemy DB │
                └──────────────────────┘
```

### 1.3 Layer responsibilities

| Layer | Files | Responsibility | Smells observed |
|---|---|---|---|
| **api** | 21 routers | HTTP I/O, auth, validation (inline Pydantic), routing | God router `releases.py` (2101 LOC, 37 endpoints); business logic leaking down |
| **schemas** | 3 files | Request/response shapes | Only Org/Product/Release defined; 18 routers carry inline `BaseModel` instead |
| **services** | 25 files | Business logic, external integrations, reports | Flat namespace; mixes domain + infrastructure; no anti-corruption layer for OSV/NVD/GHSA |
| **models** | 22 files | SQLAlchemy ORM | ORM entities used as domain entities (anemic); no separation |
| **core** | 8 files | Cross-cutting (config, db, deps, security, audit, plan, rate_limit, constants) | Reasonable scope; `deps.py` carries authn + authz |

### 1.4 Frontend layout

```
frontend/src/
├── pages/        — 22 route components (largest: ReleaseDetail 2087, Help 1071)
├── components/   — 10 shared widgets (Button, Modal, Toast, Skeleton, Layout, etc.)
├── hooks/        — useFocusTrap, useToast, ...
├── api/          — axios client (single instance)
├── constants/    — colors, etc.
├── i18n/         — zh.js (582), en.js (580)
└── utils/
```

State: local `useState` only — no Redux/Zustand (deliberate constraint).

### 1.5 Cross-cutting mechanisms in place

- **Authn/authz**: `Depends(get_current_user)` mounted globally in `main.py`; sub-deps `require_admin`, `require_admin_scope`, `get_org_scope`, `require_release_in_scope`
- **Multi-tenant safety net**: SDLC-001 — `test_endpoint_decorator_enforcement.py` walks routes in CI
- **Schema migrations**: inline in `main.py` lines 33–175 (`_add_column` helper, idempotent); see `.knowledge/patterns/inline-sqlite-migration.md`
- **Rate limiting**: `core/rate_limit.py` middleware (300/min/IP global) + dedicated `/login` limit
- **Audit logging**: `core/audit.py` (21 event types, append-only)
- **Plan gating**: `core/plan.py` — `require_plan(feature)` returns 402; `check_starter_limit` enforces resource caps
- **Background jobs**: `services/monitor.py` — start/stop in `lifespan`
- **PDF compatibility shim**: `services/pdf_shim.py` — fpdf2-shaped API on top of reportlab (Path-B license replacement)

## 2. Architectural strengths (preserve these)

1. **Documented invariants** — `CLAUDE.md` is unusually rich; `.knowledge/patterns/` records intentional choices
2. **Cross-DB helper layer** — `core/database.days_between` + `_add_column` typedef translation = honest about SQLite ↔ Postgres shift
3. **Dependency injection at the right boundary** — FastAPI `Depends` is used to enforce ownership before handlers run
4. **CI structural enforcement** — SDLC-001 catches forgotten ownership checks at PR time, not at incident time
5. **License discipline** — Path B (100% permissive runtime) maintained even when it forced rewriting two libraries
6. **No hidden dependencies** — every external service has a single named module under `services/` (NVD → `nvd.py`, OSV → `vuln_scanner.py`)
7. **Stdlib-first test contract** — tests run anywhere with no extra dep install; trade-off accepted in `.knowledge/patterns/stdlib-test-suite.md`

## 3. Architectural pain points (to evaluate in Phase 3)

1. **`releases.py` 2101 LOC, 37 endpoints, 0 schemas** — single largest source of risk; encompasses upload, scan, enrichment, lock, signature, reports, conversion, dependency graph
2. **Inline Pydantic in 18/21 routers** — request/response shapes are not introspectable from one place; impedes API contract testing, OpenAPI clarity, codegen
3. **`services/` is flat with mixed concerns** — business logic / integrations / reports / scanners / notifications all siblings
4. **Anemic models** — `models/vulnerability.py` is data; behavior (`_is_suppressed`, `_sla_info`) lives in `releases.py`. Invariants ("suppressed_until null + suppressed=True ⇒ permanent") leak into route handler logic
5. **No anti-corruption layer for external APIs** — OSV / NVD / EPSS / KEV / GHSA shapes can change and bleed straight into our DB
6. **`ReleaseDetail.jsx` 2087 LOC, 76 hooks** — known carry-over (UX-034); only refactored if frontend pass is in scope
7. **No characterization tests** — refactoring `releases.py` safely requires us to first capture today's HTTP behavior

## 4. Target architecture (proposed; not yet adopted)

> This section is a sketch for discussion in Phase 7. Nothing is committed. Updated by ledger after each iteration's decisions.

### 4.1 Proposed shape (Hexagonal-leaning, pragmatic)

```
backend/app/
├── api/             — HTTP only: parse → call use case → render. Thin.
├── schemas/         — ALL Pydantic v2 lives here (one file per resource)
├── domain/          — NEW. Business invariants, value objects (e.g. SuppressionState, SLAStatus)
├── services/
│   ├── usecases/    — NEW. One module per workflow (upload_sbom, rescan, lock_release, …)
│   ├── reports/     — IEC, NIS2, TISAX, PDF helpers
│   ├── scanners/    — Trivy, Syft, signature_verifier, reachability
│   └── integrations/— OSV, NVD, EPSS, KEV, GHSA, alerts (Slack/Teams/Email)
├── models/          — SQLAlchemy ORM ONLY; no business logic
└── core/            — unchanged
```

### 4.2 Constraints on the move
- No public-API change (HTTP shape, status codes, response bodies stay byte-identical)
- No DB schema change beyond additive (per established `inline-sqlite-migration` pattern)
- No new runtime dependency
- Each step must be independently revertible

### 4.3 Why this shape (and not pure Clean Arch)
- **Pragmatic over purist**: a one-developer project does not need a domain layer that mirrors models 1:1; pull a domain layer up only where invariants actually live (`Suppression`, `VEX state machine`, `SLA`, `CRA incident state`)
- **Hexagonal-leaning**: integrations get their own folder so we can put adapter interfaces between them and the use cases when contracts wobble
- **Use-case modules > class hierarchies**: Python is not Java; each workflow is one function with explicit dependencies

### 4.4 No-over-abstraction red lines (per user confirmation 2026-04-29)
These rules cap how far the Hexagonal target may travel. A refactor that crosses any of them is rejected even if architecturally "purer":

- **AR-1.** **No port for a single implementation.** If we have one OSV client and only ever will, do not introduce an `IVulnScanner` ABC + `OsvVulnScanner` implementation. The abstraction has zero current value and a permanent indirection cost. Add the port only when a *second* implementation is committed.
- **AR-2.** **No Repository pattern around SQLAlchemy.** SQLAlchemy's `Session` and ORM model classes already are a repository: `db.query(Release).filter(...)` is the read API, `db.add(release)` is the write API. Wrapping it in `class ReleaseRepository` adds noise without gain. The `services/` layer talks to the ORM directly.
- **AR-3.** **No three-layer Pydantic schema split.** Do not separate "API DTO" / "domain object" / "persistence DTO" as distinct types for the same concept. This project's scale does not justify it. Reuse one Pydantic model per resource (with `model_dump(include=...)` for response shaping) until the day a single concept actually needs three different shapes — then split that one concept only, not all of them.

### 4.5 Wave-D alignment (forced ordering — per user confirmation 2026-04-29)

**Decision**: split `releases.py` BEFORE Wave D sprint #3 starts, so Wave D's JS/TS + Java reachability extension lands on a clean sub-module rather than further bloating a god router.

**Architectural commitments to Wave D** (revised 2026-04-29 to resolve naming conflict with existing `services/reachability.py`):

The `releases.py` split MUST produce a **package** (directory) at `services/scanners/reachability/` — NOT a single file `reachability_integration.py` (which would collide with the existing `services/reachability.py` and create namespace confusion). The package contains:

```
backend/app/services/scanners/reachability/
├── __init__.py          # re-exports the public API; THIS is the frozen interface
├── python_analyzer.py   # renamed from existing services/reachability.py
│                        # contents unchanged in the split commit (Tidy First)
└── integration.py       # NEW. Wave-D contact point: dispatches by language to
                         # python_analyzer (today) and js_analyzer / java_analyzer (Wave D)
```

- **WD-1.** The split PR creates the `reachability/` package above. `python_analyzer.py` is bit-identical to today's `services/reachability.py` (rename + move only — `git mv`). `integration.py` exposes the dispatcher interface. `__init__.py` re-exports `scan_zip` and `classify_vulns` so existing callers (`releases.py:upload_source` × 4 sites, `releases.py:rescan` × 1 site) need only a one-line import change
- **WD-2.** The public Python interface = exactly what `__init__.py` re-exports. **Frozen** at the close of the iter-1 refactor PR. Wave D may add new functions inside `integration.py` (or add new analyzer modules) but may not change the re-exported signatures
- **WD-3.** The split PR includes a `# Wave-D contract` block at the top of `__init__.py` listing the frozen public signatures and their pre/post-conditions (`scan_zip(zip_bytes: bytes) -> ScanResult`, `classify_vulns(vulns, scan_result) -> list[ClassifiedVuln]`)
- **WD-4.** If Wave D needs a new capability that the frozen interface does not expose, it goes through a separate "interface evolution" commit BEFORE the analyzer change — never bundled
- **WD-5.** `services/reachability.py` (the old path) is **deleted** in the split commit, not left as a re-export shim. Existing imports in `releases.py` are updated to `from app.services.scanners.reachability import scan_zip, classify_vulns`. (No external consumer per D1 lenient regime ⇒ no compat shim needed.)

**Ordering rationale**: doing Wave D first on top of the 2101-LOC god router would push it past 3000 LOC and entangle the corpus acceptance gate with the refactor diff. The "split → freeze interface → Wave D → small follow-up audit" sequence is the lowest-total-cost path.

## 5. Architectural decisions to track (initial)

| ID | Decision | Status | Recorded |
|---|---|---|---|
| AD-001 | Inline SQLite ALTER vs Alembic | Adopted | `.knowledge/patterns/inline-sqlite-migration.md` |
| AD-002 | Stdlib-only tests vs pytest | Adopted | `.knowledge/patterns/stdlib-test-suite.md` |
| AD-003 | No new npm packages (charts as SVG) | Adopted | `CLAUDE.md` |
| AD-004 | SDLC-001 release-ownership middleware + CI enforcement | Adopted | `core/deps.py:87-130` + `tests/test_endpoint_decorator_enforcement.py` |
| AD-005 | 404 (not 403) on cross-org access | Adopted | per CWE-204 |
| AD-006 | Path-B license discipline (100% permissive runtime) | Adopted | `NOTICE.md` |
| AD-007 | Cascade-all delete on all FK | Adopted | `CLAUDE.md` data model |
| AD-008 | UUID PKs throughout | Adopted | `CLAUDE.md` data model |
| AD-009 | Hexagonal-leaning target | Adopted iter-1 | §4 above |
| AD-010 | No-over-abstraction red lines (AR-1/2/3) | Adopted iter-1 | §4.4 above |
| AD-011 | Wave-D alignment (split before sprint #3) | Adopted iter-1 | §4.5 above |

---

Last updated: iter-1, 2026-04-29 (§4.4 + §4.5 added: no-over-abstraction red lines + Wave-D alignment)
