---
created: 2026-04-29
purpose: Encoded conventions and principles for THIS project — accumulates each iteration
status: living document; append-only unless a principle is explicitly retired in ledger
---

# Code & Architecture Principles

These principles are **observed in the codebase** or **written in CLAUDE.md / .knowledge/**, not aspirational. New principles are added here when they emerge from review; retired principles get an "obsolete since iter N" note rather than deletion.

## How this list is used

- During Phase 4 audits, every finding cites which principle it violates (or, for new principles, declares one)
- During Phase 8 refactoring, principles act as the rules for "what 'good' looks like" — a refactor that violates a principle is rejected even if it compiles
- During Phase 10 ledger update, new principles surfaced this iteration are appended

---

## A. Codebase invariants (mechanical)

- **A1.** All FK relationships use `cascade="all, delete-orphan"`
- **A2.** UUID primary keys throughout — no auto-increment ints
- **A3.** Schema changes go in `backend/app/main.py` migration block as `_add_column` calls — never Alembic
- **A4.** SQLite uses WAL mode (`PRAGMA journal_mode=WAL` in `core/database.py`)
- **A5.** Cross-DB SQL goes through `core/database.days_between` (and any future `_helper`) — never inline a dialect-specific function
- **A6.** Backend listens on **port 9100 only** (8080/8005/8009/8443 conflict with Tomcat on dev machine)
- **A7.** Frontend is built on the dev machine; production Mac mini does NOT run Node.js

## B. Public-contract preservation (behavior-equivalence)

- **B1.** HTTP status code semantics: 401 (no/invalid token) vs 403 (token valid, action forbidden) vs 404 (not found OR cross-org per CWE-204) vs 402 (plan insufficient) vs 409 (state conflict, message in zh-TW) vs 429 (rate limited) — these are stable contract
- **B2.** User-facing 4xx error `detail` strings are zh-TW (Traditional Chinese) — refactors that touch error handling must keep messages byte-identical unless explicitly changing UX
- **B3.** API token prefix `sbom_` is stable — clients pattern-match on it
- **B4.** SBOM file formats accepted: CycloneDX JSON, CycloneDX XML, SPDX JSON. SBOM file formats produced: same three plus CSAF JSON. No format may be silently changed (versions, field ordering, attribute names)
- **B5.** Webhook payload formats (Slack Block Kit, Teams MessageCard, generic JSON) and SMTP HTML/text formats are downstream contracts
- **B6.** Public router prefix paths (`/api/auth`, `/api/organizations`, …) and method+path combinations are not renamed without a deprecation window
- **B7.** OpenAPI `/docs` schema is implicitly public — adding fields is OK; removing or renaming requires migration plan

## C. Authn/authz invariants (security-equivalence)

- **C1.** Every router except `auth.login`, `notice`, `share/{token}`, `health` requires `Bearer` (mounted globally in `main.py`)
- **C2.** Every release-id endpoint MUST use `Depends(require_release_in_scope)` or call `assert_release_in_scope`. Forgetting this is caught by `tests/test_endpoint_decorator_enforcement.py` in CI (SDLC-001)
- **C3.** Cross-org access returns **404, not 403** — no oracle (CWE-204)
- **C4.** API token scope (`read|write|admin`) is enforced by HTTP verb in `core/deps.py:get_current_user` — DELETE blocked for `write`, all writes blocked for `read`
- **C5.** `require_admin_scope` (admin-only — write tokens denied) is required for token-management and user-management endpoints
- **C6.** Passwords are hashed with bcrypt via `passlib`; never logged, never returned in any response, never round-tripped via the client
- **C7.** SECRET_KEY guard fires on default OR < 32 bytes when `DEBUG=false` — process exits 1
- **C8.** ADMIN_PASSWORD guard fires on known defaults (`sbom@2024`, `please-change-this-password`, `admin`, `""`) when `DEBUG=false` — process exits 1
- **C9.** JWT JTI revocation: every issued JWT has a `jti`; `RevokedToken` blacklist consulted in `get_current_user`
- **C10.** OIDC `state` parameter is validated to prevent CSRF on the SSO callback

## D. Input safety invariants

- **D1.** XML conversion rejects `DOCTYPE` and `ENTITY` pre-parse, body capped at 5 MB (billion-laughs guard)
- **D2.** Source upload zips are zip-bomb-checked; 500 MB extraction cap
- **D3.** Filenames returned to clients pass through `safe_attachment_filename` (path-traversal guard)
- **D4.** CSV exports pass every cell through `csv_safe` (formula injection guard)
- **D5.** SBOM uploads are SHA-256 hashed (`sbom_hash` on Release) — integrity verifiable
- **D6.** SBOM signature verification supports ECDSA (cosign default), RSA-PSS, RSA-PKCS1; algorithm is auto-detected from key type (do not let attacker control the algorithm field)
- **D7.** Rate limit key is **`X-Real-IP` only** — `X-Forwarded-For` is intentionally ignored to defeat spoofing (handled at three layers: nginx clears, backend reads X-Real-IP, uvicorn `--no-proxy-headers`)

## E. Data invariants (domain rules)

- **E1.** A Vulnerability is "suppressed" iff `suppressed=True` AND (`suppressed_until` is null OR `suppressed_until > now`). The `_is_suppressed` helper in `releases.py:64` is canonical — do not reinvent
- **E2.** SLA tracking excludes suppressed vulns AND status in `("fixed", "not_affected")` AND severity not in `_SLA_DAYS` — see `_sla_info` in `releases.py:75`
- **E3.** VEX state machine: `status` ∈ {open, in_triage, not_affected, affected, fixed}; setting to anything other than `not_affected` clears `justification`; setting to anything other than `affected` clears `response`. Currently enforced ad-hoc in routers — candidate for domain extraction (see `architecture.md`)
- **E4.** CRA Incident state machine has named transitions (`detected → pending_triage → clock_running → t24/72 → final → closed`) per `CLAUDE.md` — must remain observable in `audit_log`
- **E5.** Release `locked=True` blocks mutation endpoints; the lock is enforced per-handler today (centralisation candidate)
- **E6.** AuditEvent rows are append-only (no UPDATE, no DELETE)
- **E7.** Vulnerability uniqueness is `(component_id, cve_id)` — enforced by `uq_comp_cve` unique index

## F. Module conventions

- **F1.** One router per resource; router prefix is `/api/<resource>` (plural); tag matches resource name
- **F2.** Schemas package contains Pydantic v2 models for shared resources; new schemas should land here, not inline in routers (this is an aspirational principle — most routers violate it today, see `known-debt.md`)
- **F3.** Service modules: one per concern; integration modules name the upstream service (`nvd.py`, `epss.py`, `ghsa.py`, `kev.py`, `trivy_scanner.py`, `syft_scanner.py`)
- **F4.** Background tasks use `BackgroundTasks` (FastAPI) for short jobs and `monitor.py` for periodic work — no Celery/RQ
- **F5.** Long I/O in async handlers is wrapped with `asyncio.to_thread` (e.g. `upload_source`, `scan_iac`)
- **F6.** No new npm packages; charts and graphs are hand-rolled SVG components
- **F7.** **Backend dev-only dependencies allowlist** (per user confirmation iter-1, 2026-04-29). The following packages may be added to a `backend/requirements-dev.txt` (separate from the runtime `requirements.txt`) without per-package justification: `pytest`, `pytest-cov` (optional, for coverage), `hypothesis` (optional, only when property-based testing is the right tool). All other new dependencies — runtime or dev — still require explicit justification + alternative analysis. Dev-only deps must NOT be imported by anything under `backend/app/`; they exist solely for the test suite and tooling.

## G. Error-handling conventions

- **G1.** User-facing errors raise `HTTPException(status_code=…, detail="…zh-TW…")` from the router; do not return raw exception strings
- **G2.** Internal errors should be logged with `logger.exception` (not `print`) using the module-level `logger = logging.getLogger(__name__)`
- **G3.** `except Exception` is acceptable at top-level retry/cleanup blocks but is a smell elsewhere (audit candidate, see `known-debt.md`)
- **G4.** Never include a stack trace in a 5xx response body returned to a user

## H. Testing & change-safety conventions

- **H1.** `test_all.py` is the regression baseline — must stay green at every commit (CI-enforced)
- **H2.** Schema changes (new column) require a corresponding migration in `main.py` AND an entry to the model class
- **H3.** New release-id endpoints require `Depends(require_release_in_scope)` — CI structural test will fail otherwise
- **H4.** Behavior-changing commits and structural-only commits are separate (Tidy First) — recorded in `CHANGELOG.md` and commit prefix
- **H5.** Wave-D-related code changes must run `validate_meta.py` + `run_corpus.py` before merge

## J. Phase-8 commit discipline (refactor execution)

- **J1.** **Default rule (small refactors)**: one commit, one finding ID, one Fowler-named refactor. Tidy / refactor / perf prefixes (`tidy:` / `refactor:` / `perf:`) stay separate.
- **J2.** **Exception (structural large refactors — per user confirmation iter-1, 2026-04-29)**: god-router / god-component decomposition (≥ 500 LOC moved, ≥ 5 sub-files emerging) MAY land as a single PR with multiple internal commits, provided ALL of the following hold:
  - Each internal commit is independently revertible (no commit references types/symbols a later commit creates without those existing in an ancestor commit)
  - The PR's combined diff passes the full safety net: original `test_all.py` + every characterization test added in the PR + any benchmark before/after deltas
  - The PR description maps each commit to its finding ID (or sub-finding) and labels it `tidy:` / `refactor:` / `perf:`
  - The PR's first commit adds the characterization tests; the structural commits follow; the PR's last commit confirms behavior equivalence
- **J3.** **Reason for J2**: local Windows dev with no per-commit CI loop; running the full safety net per commit would tank sprint velocity. Linux kernel patch-series practice has decades of evidence that "atomic PR / mid-PR commits" is a tractable safety boundary. The risk it adds is "a partial PR may not run cleanly mid-merge" — mitigated by the independently-revertible requirement.
- **J4.** **Tidy First still applies**: even within a multi-commit PR, structural moves (rename, extract, move) come in `tidy:` commits separate from any logic change. Mixing tidy + refactor in one commit is rejected even under J2.
- **J5.** **No bypass for security commits**: any commit touching `core/security.py`, `core/deps.py`, authn/authz logic, or input validation reverts to J1 (one-commit-one-finding) regardless of size, so the security review is per-commit.
- **J5-footnote** (added 2026-04-29 per iter-1 Q-P7-2 confirmation): a J5-tagged commit MUST carry the prefix `[J5-security-carveout]` in the first line of its commit message, AND the commit body MUST explicitly list the surface diff for each of the 4 J5-tracked surfaces (`core/security.py`, `core/deps.py`, authn/authz logic, input validation). For each surface, the body either says "no changes to <surface>" (with one-line rationale) OR lists the diff hunks. **This is the per-commit security review made auditable**; without this body, J5 is only nominal discipline. The auditor reading `git log` should be able to confirm the security surface diff without opening the actual code diff.
- **J6.** **Phase-8 incidental-fix policy** (added 2026-04-30 per iter-1 retrospective on commit `510ec8d` Stage A.3). During Phase-8 execution, a small fix discovered mid-commit MAY be bundled into the current commit if AND ONLY IF **all three** conditions hold:
  1. **Size cap**: `< 20 LOC` of diff total
  2. **Surface cap**: pure test infra OR build infra (e.g. `conftest.py`, `pytest.ini`, `requirements-dev.txt`); **zero production-code surface** (`backend/app/`, `frontend/src/`, `tools/` are forbidden — those require their own commit)
  3. **Disclosure**: the bundling is explicitly listed in (a) the commit message body AND (b) the iteration's `ledger.md` as a numbered decision (`D{N}`) with rationale
  
  If any condition fails — e.g. the fix is 25 LOC, OR touches production code, OR cannot be disclosed without obscuring the parent commit — STOP, open a fresh commit (or new finding ID), do not bundle.
  
  **Why this exists**: discovered through iter-1 A.3, where the in-memory SQLite StaticPool fix surfaced naturally during cross-org test write. Splitting it into its own commit would have produced a 5-line `fix(test):` commit that obscures A.3's narrative without adding audit value. Bundling + ledger entry preserves both narrative AND audit trail. Without this principle, future audits reading `git log` would flag every multi-concern commit as a J1 violation; with this principle, the disclosed bundling is on-record and clean.
  
  **Trigger for promotion to a separate commit**: if the same incidental-fix class repeats (e.g. another `< 20 LOC` test-infra fix in Stage B/C/D), promote it to a separate commit at that point — bundling is forgivable once per "discovery moment", not as a habit.

## I. Ops & deployment conventions

- **I1.** Production deployment is `bash deploy/deploy.sh`; first-time uses `bash deploy/first-deploy.sh`
- **I2.** Backend runs under launchd on Mac mini (`com.sbom.backend.plist`)
- **I3.** Backups: nightly gpg-AES-256, key file off-host (`deploy/backup.sh`)
- **I4.** `.env` files are not in git; `.env.server` is gitignored separately
- **I5.** Frontend assets are uploaded as `dist/`; the prod host does not have Node.js

---

## Principles surfaced in iteration N — appended below

### Iter-1 additions (2026-04-29, post user Q1–Q10 answers)
- **F7** — backend dev-only deps allowlist (`pytest`, `pytest-cov`, `hypothesis`)
- **J1–J5** — Phase-8 commit discipline (default + structural exception + security carve-out)
- See `architecture.md` §4.4 (no-over-abstraction red lines AR-1/2/3) and §4.5 (Wave-D alignment WD-1/2/3/4) — encoded as architecture decisions, listed here as cross-reference
