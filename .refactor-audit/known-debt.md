---
created: 2026-04-29
purpose: Technical debt the team has consciously accepted, with reasoning + reassessment trigger
status: living document; entries get retired by the ledger when the debt is paid
---

# Known Debt — accepted with reasons

> Each entry has an **owner reasoning** (why we chose to live with it) and a **reassessment trigger** (the condition under which we revisit). If the trigger fires, the entry moves from "accepted" to "active refactor candidate".

## Format

```
### DEBT-{seq}: title
- Status: accepted | reassessing | retired (iter N)
- Surface area: file(s) / module(s)
- The trade-off: what we get vs what we pay
- Why accepted: link to ADR / pattern note / discussion
- Reassessment trigger: condition that makes this worth revisiting
- Compensating control: what we do today to make the debt safer
```

---

### DEBT-001: Inline SQLite ALTER instead of Alembic
- Status: **accepted**
- Surface area: `backend/app/main.py` lines 33–175
- The trade-off: simple deploy (no migration tool), no schema versioning, no rollback step, no DROP/RENAME COLUMN ability under SQLite
- Why accepted: documented in `.knowledge/patterns/inline-sqlite-migration.md`. Single-binary single-file deploy pattern. Under Postgres mode, the helper still works (typedef translation in `_add_column`)
- Reassessment trigger: any of (a) need to DROP/RENAME a column, (b) multiple-tenant DBs needing differential migration, (c) production team grows past one person
- Compensating control: `_add_column` is idempotent; `_table_exists` and `_list_columns` guard against assumptions; `_ALLOWED_TABLES` whitelist prevents SQL injection in the helper

### DEBT-002: Stdlib-only test suite (no pytest)
- Status: **accepted**
- Surface area: `test_all.py`, `test_full_verification.py`, `backend/tests/test_endpoint_decorator_enforcement.py`
- The trade-off: zero new deps to install for testing, runs in CI with just `python`; we lose pytest fixtures, parametrisation, plugin ecosystem (coverage, snapshot, hypothesis)
- Why accepted: documented in `.knowledge/patterns/stdlib-test-suite.md`. The integration test contract is tight enough that fixtures haven't been needed
- Reassessment trigger: this audit's Phase 7 plan — characterization tests for `releases.py` refactor may need pytest's parametrize. If so, propose adding pytest as a **dev-only** dep (NOT runtime) with explicit ledger note
- Compensating control: structural CI test (`test_endpoint_decorator_enforcement.py`) catches the most common refactor regression class (forgotten ownership check)

### DEBT-003: Inline `BaseModel` Pydantic in 18/21 routers
- Status: **accepted (refactor candidate)**
- Surface area: every router under `backend/app/api/` except `organizations.py`, `products.py`, `releases.py` (and even those have inline schemas alongside)
- The trade-off: schemas are inlined where used (good for locality), but cannot be referenced from another module without copy-paste (bad for DRY, bad for OpenAPI codegen, bad for client SDK generation)
- Why accepted: organic growth — routers were added one at a time; the `schemas/` package was started for the first 3 resources and never finished
- Reassessment trigger: this audit's Phase 7 will propose extracting shared shapes; ANY external SDK/client codegen need would force this immediately
- Compensating control: each schema is local to its single use site, so drift risk is bounded

### DEBT-004: `releases.py` is a god router (2101 LOC, 37 endpoints)
- Status: **active refactor candidate (iter 1 finding)**
- Surface area: `backend/app/api/releases.py`
- The trade-off: every release operation lives in one file (easy to grep), but the file mixes upload / scan / enrichment / signature / report / conversion / dependency-graph / lock concerns
- Why accepted: organic growth; not previously called out as a refactor target
- Reassessment trigger: **fired now**. The audit treats this as iter 1's primary architecture finding. Prerequisite for any safe split is characterization tests
- Compensating control: helpers are private (`_SLA_DAYS`, `_is_suppressed`, `_sla_info`, `_assert_release_org`); 0 of them are called from outside `releases.py`

### DEBT-005: `ReleaseDetail.jsx` is a god component (2087 LOC, 76 hooks)
- Status: **accepted; deferred via UX-034 carry-over**
- Surface area: `frontend/src/pages/ReleaseDetail.jsx`
- The trade-off: every release-detail interaction in one file (easy to find), but state management is gnarly and re-render performance is a quiet risk
- Why accepted: explicit deferral to a "dedicated session" per `.ui-audit/ledger.md` — not in any UI iteration scope
- Reassessment trigger: any of (a) re-render performance complaint from a user, (b) need to add another tab or major modal, (c) Wave D ships and forces touching reachability UI
- Compensating control: page is the only view; no shared state with siblings; ESLint catches obvious React rule violations

### DEBT-006: `Help.jsx` is a 1071-LOC content blob
- Status: **accepted; deferred via UX-033 carry-over**
- Surface area: `frontend/src/pages/Help.jsx`
- The trade-off: 24 articles inline in one component (easy to ship, easy to translate); not searchable as content database, not editable by non-developers, full bundle on first load
- Why accepted: explicit deferral
- Reassessment trigger: any of (a) need to expose article URLs as deep links to /api or as standalone routes, (b) translation team forms and needs CMS-shape input, (c) bundle size complaint
- Compensating control: lazy-loaded route, not on critical path

### DEBT-007: Anemic models — business logic lives in routers
- Status: **active refactor candidate (iter 1 finding)**
- Surface area: `backend/app/models/*.py` (data only) + `backend/app/api/releases.py` (logic that should live on the model)
- The trade-off: the SQLAlchemy ORM stays close to the DB, but invariants like "suppressed AND not expired" leak into routers (`_is_suppressed`, `_sla_info`)
- Why accepted: not previously called out
- Reassessment trigger: **fired now**. Phase 3 architecture audit will weigh this as a **separate domain layer** vs **methods on ORM models** trade-off
- Compensating control: helpers are private to `releases.py`; no duplication observed yet

### DEBT-008: `services/` is flat with mixed concerns
- Status: **active refactor candidate (iter 1 finding)**
- Surface area: `backend/app/services/` (25 modules)
- The trade-off: shallow tree (easy to find by name); no separation between domain logic, external integrations, reports, scanners, notifications
- Why accepted: not previously called out
- Reassessment trigger: **fired now**. Phase 3 will propose a sub-package layout (see `architecture.md` §4)
- Compensating control: every service module is named after either the upstream system or the report/scanner type, so intent is discoverable from the filename

### DEBT-009: 46 broad `except Exception` clauses
- Status: **accepted-pending-audit**
- Surface area: counted across `backend/app/`; concentrated in `releases.py`, `auth.py`, `firmware.py`
- The trade-off: top-level retry/cleanup blocks legitimately need broad catches; non-top-level catches are a smell
- Why accepted: not all are wrong, but a case-by-case pass has not happened
- Reassessment trigger: **fires in Phase 4 of iter 1** — every site classified as legitimate or smell
- Compensating control: most sites also `logger.exception(…)` so failure is observable

### DEBT-010: SEC-027 (admin password .env-to-DB drift)
- Status: **active candidate; mitigation deferred**
- Surface area: `backend/app/main.py:215-226` (single-shot seed) + `backend/app/api/auth.py:54-61` (no env-var fallback on hash mismatch)
- The trade-off: rotating `ADMIN_PASSWORD` in `.env` after first boot has no effect, but the seed-once pattern keeps boot fast
- Why accepted: not yet — committed as **candidate** with 4 mitigation options, awaiting selection
- Reassessment trigger: **fires in this audit's Phase 7** — selecting one of the 4 options
- Compensating control: documented in `.knowledge/audit/SEC-027-candidate-admin-rotation.md`; no active exploitation, just an operational footgun

### DEBT-011: 14 deferred Phase-3 security findings
- Status: **accepted under `lan_only: Low`**
- Surface area: tracked in `.knowledge/audit/security-audit-batch-tlt-2-21.md`
- The trade-off: items rated low risk under LAN-only deployment; would re-enter scope on commercialisation
- Why accepted: cost/benefit per `.knowledge/audit/EXECUTIVE-SUMMARY.md` §4
- Reassessment trigger: any of (a) commercialisation roadmap activates, (b) hosting model changes from Mac mini to multi-tenant SaaS, (c) any LAN-only assumption fails
- Compensating control: each finding has a documented `lan_only` rating and a re-evaluation condition

---

## How to retire an entry
1. Refactor the underlying issue
2. Verify with `verification.md` in the iteration that closes it
3. Move the entry's "Status:" to "retired (iter N, commit <hash>)"
4. Add a one-line entry under "Retired debt" below

## Retired debt

(none yet)

## Investigated, not debt

### Q9 / `sbom.db` at repo root — RESOLVED 2026-04-29
- Initial concern (recon.md): the 348 KB `sbom.db` at repo root looked like committed demo data
- Investigation: `git log --all -- sbom.db` returns empty (file is not tracked); `.gitignore:22` `/sbom.db` filters it; contents = 1 admin user row + all other tables empty
- Conclusion: stale local artifact from running the backend with `cwd=repo root` once. Not in git history. No DEBT entry warranted. Cleanup is local-only and may be done at any time without consultation.

Last updated: iter-1, 2026-04-29
