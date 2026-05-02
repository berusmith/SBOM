---
iteration: 1
phase: 1 — Reconnaissance
date: 2026-04-29
status: complete; awaiting user answers to question list before Phase 2
---

# Iteration 1 — Reconnaissance

## 1. Tech stack

### Languages & runtime
- **Backend**: Python 3.11+ (CI pins 3.11). Forward-compat habit: `from __future__ import annotations` in several files
- **Frontend**: JavaScript (ES modules, JSX). React 18.3.1
- **Build**: Vite 5.4.8 (frontend), no build for backend
- **Tests**: Python stdlib + `urllib`/`json` (no pytest)
- **Tooling languages in repo**: shell (deploy/), batch (start_*.bat), launchd plist

### Frameworks & libraries (key)
- Backend: FastAPI 0.120.4, Starlette 0.49.2, Uvicorn 0.30.6, SQLAlchemy 2.0.49, Pydantic 2.9.2 + pydantic-settings 2.5.2
- Auth: `python-jose[cryptography]` 3.5.0, `passlib[bcrypt]` 1.7.4 + `bcrypt` 4.3.0
- HTTP clients: `httpx` 0.27.2, `requests` 2.33.1
- Files: `python-multipart` 0.0.26, `aiofiles` 23.2.1, `pillow` 12.2.0
- Reports: `reportlab` 4.4.4 (LGPL replacement for fpdf2 — see `services/pdf_shim.py`)
- DB driver: `pg8000` 1.31.5 (LGPL replacement for psycopg2-binary; pinned per SEC-024)
- Frontend: react 18.3, react-router-dom 6, axios 1.7, i18next 26, lucide-react 1.8 (icons), tailwindcss 3.4

### Execution environment
- Dev: Windows 11 with bash + PowerShell available; ports 9100 (backend) + 3000 (frontend dev)
- Prod target: Mac mini (macOS) under launchd, behind nginx; PostgreSQL 16 via pg8000
- No Docker in dev or prod (deliberate — see `CLAUDE.md` constraints)

### Data stores & integrations
- DB: SQLite (dev, WAL mode) / PostgreSQL 16 (prod). Single-DB deploy
- Background jobs: in-process thread (`services/monitor.py`), no Celery/RQ
- External APIs (read-only consumers): OSV.dev (vuln search + batch), NVD API 2.0 (CVE detail), FIRST.org EPSS (exploit probability), CISA KEV (known-exploited list), GitHub Advisory DB (GHSA), optional OIDC IdP
- External binaries (subprocess): Trivy (Apache-2.0), Syft (Apache-2.0), EMBA (GPL-3.0, never bundled)
- Outbound notifications: SMTP, Slack incoming webhook, Teams incoming webhook, generic webhook

### Frontend
- React SPA served by Vite dev server (port 3000) in dev; `dist/` mounted under `/` by FastAPI in prod (`STATIC_DIR` env var)
- State: local React hooks only; no Redux / Zustand / Recoil / etc.
- i18n: react-i18next, two locale files (`zh.js`, `en.js`)
- No charting library — all viz is hand-rolled SVG

### Mobile / CLI / Other
- CLI: `tools/sbom-cli/sbom.py` — pure stdlib (`urllib`+`json`), 3 subcommands (`upload`, `gate`, `diff`)
- GitHub Action: `tools/sbom-action/action.yml` — composite action wrapping the CLI
- GitLab CI: `tools/sbom-gitlab-ci/` (per CLAUDE.md, not investigated this iteration)

## 2. Project scale

| Surface | LOC | Files | Largest single file |
|---|---:|---:|---|
| Backend `app/` | 12,737 | 83 .py | `api/releases.py` 2101 |
| Frontend `src/` | 12,712 | 47 .js+.jsx | `pages/ReleaseDetail.jsx` 2087 |
| Tests | 869 | 3 (+ 39 corpus fixtures) | `test_full_verification.py` 439 |
| CLI | ~250 | 1 | `tools/sbom-cli/sbom.py` |
| Docs | ~5K LOC MD | 11 | `CLAUDE.md` 18.5KB |

### Direct dependencies
- Backend: 17 runtime deps (all permissive)
- Frontend: 6 runtime + 5 dev (all permissive)
- Transitive: not counted this iteration; CI's `pip-audit --strict` and `npm audit --omit=dev` enforce known-vuln-free

## 3. Architectural layering (current)

See `architecture.md` §1 for the diagram and per-layer table. Headlines:

- **api/ (21 routers)** is the entry point; thin in some routers (`notice.py`, `search.py`), god-router-thick in `releases.py`
- **schemas/ (3 files)** is partially populated; 18 routers carry inline `BaseModel`
- **services/ (25 files)** is flat with mixed concerns (domain / integration / reports / scanners / notifications)
- **models/ (22 files)** is anemic — pure SQLAlchemy data, business logic lives in routers
- **core/ (8 files)** is well-scoped: `config`, `database`, `deps`, `security`, `audit`, `plan`, `rate_limit`, `constants`

## 4. Public-API surface (behavior-equivalence boundary)

### HTTP — what the world sees
- **21 routers**, mounted in `main.py:301-323`, each gated by `Depends(get_current_user)` except the explicit public allowlist
- **Public endpoints** (no auth):
  - `POST /api/auth/login`
  - `GET  /api/auth/oidc/login` `/oidc/callback` `/oidc/config`
  - `GET  /api/notice` (OSS attribution)
  - `GET  /api/share/{token}` (time-limited share links)
  - `GET  /health`
- **Endpoint-counts top 5**: `releases.py` 37, `settings.py` 11, `auth.py` 10, `tisax.py` 8, `cra.py` / `organizations.py` / `stats.py` / `products.py` / `policies.py` / `licenses.py` 6–7 each
- **Status semantics**: see `invariants.md` §I.1 (full table)
- **Error message language**: zh-TW for user-facing 4xx (per `CLAUDE.md`)

### Other public surfaces
- **DB schema**: documented in `docs/db-schema.md`. UUID PKs, `cascade=all, delete-orphan`, additive-only migrations
- **CLI**: `sbom upload | gate | diff`; env vars `SBOM_API_TOKEN`, `SBOM_API_URL`
- **GitHub Action**: 6 inputs (`sbom-file`, `release-id`, `api-token`, `api-url`, `fail-on-gate`, `product-id`)
- **File formats**: CycloneDX JSON/XML, SPDX JSON, CSAF JSON
- **Webhook formats**: Slack Block Kit, Teams MessageCard, generic JSON
- **OpenAPI**: `/docs` is implicitly contract — preserved by FastAPI route declarations

## 5. Existing tests

| Suite | Style | LOC | What it covers | Trustworthiness | Speed |
|---|---|---:|---|---|---|
| `test_all.py` | stdlib HTTP integration vs running backend | 255 | 54 regression tests for end-to-end behavior | High (CI gate; auto-loads backend/.env via dotenv) | ~30s estimated (not measured) |
| `test_full_verification.py` | stdlib HTTP integration | 439 | older / broader regression set | Unverified — needs Phase 4 audit | unknown |
| `tests/test_endpoint_decorator_enforcement.py` | structural — walks FastAPI routes via introspection | 175 | every release-id endpoint must use `Depends(require_release_in_scope)` | High (CI gate; SDLC-001 mandatory) | < 1s |
| 39-fixture reachability corpus | YAML metadata + sample source trees | 39 fixtures | acceptance gate for Wave D sprint #3 | High but project-specific | ~20s estimated |

### Critical gaps
- **No unit tests**. Zero. The smallest covered behavior is "make HTTP request → check JSON". A function-level refactor has no automated safety net.
- **No coverage measurement** — we cannot tell what % of `releases.py:1-2101` is exercised
- **No characterization tests** — the only way to know "did refactor X change behavior" is integration-suite regression
- **No frontend tests** at all (no Jest, no Vitest, no Playwright)
- **No load tests / no perf benchmarks**

## 6. Existing performance baseline

- **None formally established.**
- Documented optimization (in `CHANGELOG.md` `[Unreleased]`): OSV scan rewritten from N per-PURL queries to 1 batch + parallel detail fetches. Stated improvement: 200-component / 50-unique-vuln SBOM goes from ~200 HTTP to 1+50 HTTP. Not part of an automated benchmark — measured by hand once.
- **No APM**, no production telemetry, no Web Vitals collection in frontend
- **No load tests**

⇒ Phase 5 of this audit must establish first quantitative measurements. Findings raised without measurement get **Confidence: Low** per protocol §8.1.

## 7. Existing security controls (must preserve in Phase 8)

A separate **security audit** ran 2026-04-26 → 2026-04-28 over six phases (recon, threat model, dynamic PoC, synthesis, remediation, verification). 26 findings, 12 fix-commits, all Top-10 closed. See `.knowledge/audit/EXECUTIVE-SUMMARY.md`.

Active controls inventoried (full enforcement checklist in `invariants.md` §II):
- **Authn**: JWT bcrypt + `RevokedToken` blacklist; API token `sbom_` prefix + scope; OIDC SSO with `state` validation; SECRET_KEY + ADMIN_PASSWORD startup guards
- **Authz**: `require_admin` / `require_admin_scope` / `get_org_scope` / `require_release_in_scope` (the last is CI-enforced via SDLC-001)
- **Input safety**: XML billion-laughs guard (DOCTYPE/ENTITY reject + 5 MB cap), zip-bomb cap (500 MB), path traversal (`safe_attachment_filename`), CSV formula injection (`csv_safe`), SBOM signature algorithm derived from key (not attacker-controlled)
- **Boundary**: CORS whitelist (origin + method + header), rate limit 300/min/IP global + 10/5min on `/login`, `X-Real-IP` only (XFF spoof neutralised at three layers)
- **Supply chain CI**: pip-audit --strict, bandit, npm audit, gitleaks, syft+grype self-SBOM, regression suite, structural enforcement
- **Ops**: nightly gpg AES-256 backup with off-host key file
- **Multi-tenant**: 404 (not 403) on cross-org access (CWE-204)

### Open at audit start
- **SEC-027 candidate**: admin password `.env`-to-DB drift (mitigation deferred — see `known-debt.md` DEBT-010)
- 14 deferred Phase-3 findings rated `lan_only: Low`

## 8. Change scope since last audit

**N/A — this is the first iteration of `refactor-audit/`.**

Cross-track audits (security, UI) ran independently:
- UI: `.ui-audit/` iteration 3 closed 2026-04-28 (taste 4.7 → 6.8); 30 findings, 27 shipped, 2 deferred, 1 skipped
- Security: `.knowledge/audit/` six-phase cycle closed 2026-04-28 (26 findings, all Top-10 closed)

This refactor audit picks up architecture / code quality / performance — concerns the other two tracks did not cover.

## 9. Things I cannot see — questions for the user

These shape Phase 2–7 decisions. **Answers preferred before Phase 2**, but I can proceed with stated assumptions if you'd rather skip ahead.

### Q1. API contract scope — do external consumers exist?
- Has anyone integrated against the HTTP API beyond local development?
- Is the GitHub Action `tools/sbom-action/` used by any downstream repo?
- Is the CLI `tools/sbom-cli/sbom` installed by any user beyond you?
- **Why it matters**: this sets the strictness of "behavior equivalence". If no external consumers, response field ordering / extra optional fields can be tightened without ceremony. If consumers exist, even adding a required validation rule is a breaking change.

### Q2. Performance pain points
- Anything that "feels slow" today?
- Any production complaints about latency (SBOM upload, dashboard load, vulnerability scan, PDF report generation)?
- Any timeouts you've worked around?
- **Why it matters**: Phase 5 must prioritise. Without user-named pain, I'll pick from theory (N+1 risk, hot paths, large queries) — fine, but not as high-leverage as fixing what actually hurts.

### Q3. Test infrastructure boundary
- Is "no pytest" a hard constraint, or just a starting point?
- Are you open to **`backend/tests/unit/` with pytest as a dev-only dependency** (not in `requirements.txt`, only in a `requirements-dev.txt`) IF it's the prerequisite for safely refactoring the god router?
- **Why it matters**: refactoring 2101-LOC `releases.py` without unit-level safety nets means every step is gated by the integration suite — which is slow and HTTP-coupled. The protocol calls for characterization tests under Feathers' approach, and pytest+parametrize is the most pragmatic vehicle.

### Q4. Iteration cadence
- Are you OK with a multi-week refactor that lands ~1 commit per day, OR do you prefer a single intense session?
- Should this audit aim to **complete all of iter-1's plan within this session**, or **plan now, execute later**?
- **Why it matters**: refactor-audit iter-1 will likely produce 30–50 findings; executing all in one session is risky, but the protocol tolerates either pace.

### Q5. Wave-D coupling
- Should refactor priorities favour anything that **unblocks Wave D** (JS/TS + Java reachability)? Or treat Wave D as parallel work that we don't slow down?
- **Why it matters**: `releases.py` already has a `reachability` integration point that Wave D will extend. If we refactor `releases.py` first, Wave D lands cleaner; if we do them in parallel, merge conflicts.

### Q6. Acceptance of breaking-but-honest changes
- Today many endpoints accept request bodies with extra fields silently ignored (Pydantic default). If a refactor of inline `BaseModel` → centralised schemas tightens this with `model_config = {"extra": "forbid"}`, is that acceptable as a one-time hardening?
- Today error response bodies use `{"detail": "..."}` (FastAPI default). If we move to RFC 7807 problem+json, is that acceptable?
- **Why it matters**: these are NOT behavior-equivalent. Either we forbid them and stay strict, or we list them as deliberate Phase 8 contract evolutions in `invariants.md`.

### Q7. Observability investment
- Is there appetite for adding structured logging (e.g. `structlog`) and basic Prometheus metrics during refactor? Or stay with stdlib `logging`?
- Any APM tool likely to be adopted (OpenTelemetry, Sentry)?
- **Why it matters**: a refactor that splits `releases.py` is the right time to add a `correlation_id` and structured fields. Doing it later costs more.

### Q8. SEC-027 mitigation choice
- The audit document at `.knowledge/audit/SEC-027-candidate-admin-rotation.md` proposes 4 mitigation candidates. Should this refactor audit pick one, or is that a separate decision?
- **Why it matters**: option (a) docs-only is no code change; option (d) auto-rotate is meaningful refactor work. Either is fine but I need to know whether to scope it in.

### Q9. The `sbom.db` file at repo root — RESOLVED 2026-04-29
- **Initial concern**: the 348 KB `sbom.db` at repo root looked like committed demo data
- **Investigation result** (post-Phase-1 confirmation): `git log --all -- sbom.db` returns empty ⇒ file is NOT tracked. `.gitignore:22` `/sbom.db` filters it. Contents: 1 admin user row, all other tables empty
- **Conclusion**: stale local artifact from running the backend with `cwd=repo root` once. Not in git history. No DEBT entry warranted. Logged in `known-debt.md` under "Investigated, not debt" for traceability.

### Q10. Architecture target buy-in
- The architecture target sketched in `architecture.md` §4 (Hexagonal-leaning, `domain/` + `services/usecases|reports|scanners|integrations`) is one of several valid shapes. Does it align with your intuition?
- Alternatives: (a) keep flat `services/`, just split `releases.py`; (b) full Clean Arch; (c) modular monolith by bounded context (`releases/`, `vulnerabilities/`, `cra/` as top-level modules)
- **Why it matters**: this shapes every Phase 7 plan item; getting alignment now saves rework

---

## My working assumptions (to be confirmed by your answers)

In the absence of explicit answers, I will proceed in Phase 2 with these defaults:

- **A1**: No external API consumers beyond CLI/Action; cosmetic body changes (field ordering, extra optional fields) are OK; status codes / paths / required-field semantics are stable contract
- **A2**: No specific performance pain; Phase 5 prioritises theoretical risk areas (N+1, list endpoint pagination, PDF generation) and **establishes** baseline measurements
- **A3**: Pytest may be added as a **dev-only** dependency in `requirements-dev.txt` IF used as a characterization safety net; explicit ledger entry written
- **A4**: This audit produces a plan in this session and executes incrementally over multiple sessions
- **A5**: Wave D coupling is a soft preference — Phase 7 ranks `releases.py` refactor early
- **A6**: No silent contract evolution — extra-field tolerance and FastAPI default error shape stay as-is unless we add an explicit "deliberate evolution" entry to `invariants.md`
- **A7**: Stay with stdlib `logging` for now; observability investment is a separate audit
- **A8**: SEC-027 stays in `.knowledge/audit/`; this refactor audit notes it as DEBT-010 but does not pick a mitigation
- **A9**: `sbom.db` in repo treated as intentional demo data; refactor does not touch it
- **A10**: Adopt Hexagonal-leaning target (option proposed); revise on your feedback

## What I plan to deep-dive in Phase 3–5 of this iteration

Given this is iter-1 and the protocol expects deep coverage, I will:

- **Phase 3 (Architecture)** — quantify the god-router pain (`releases.py`), the schemas/ gap (18 inline-BaseModel routers), the services/ flat-namespace mix, the anemic-models story, and dependency-direction violations. Sketch the bounded-context split for `releases.py` (likely 5–7 sub-modules)
- **Phase 4 (Code Quality)** — exhaustive read of `releases.py`, `auth.py`, `main.py`, the top 5 services, and 3–5 frontend pages other than ReleaseDetail (which is deferred). Catalogue smells with file:line citations
- **Phase 5 (Performance)** — **scope narrowed per D5/D6 (user confirmation)**: 4 hot-spot benchmarks with scripts committed to repo for re-run:
  1. List endpoints with N+1 risk (top suspects: vulnerabilities listing, releases listing, dashboard aggregations)
  2. PDF report generation (reportlab cold start cost)
  3. OSV batch scan end-to-end (validate the documented "200 → 51 HTTP" claim)
  4. `ReleaseDetail.jsx` render cost with 76 useState/useEffect (frontend re-render profiling)
  Out of scope: full per-route latency sweep, frontend bundle size deep-dive (defer to dedicated perf audit)

## Honesty notes (Confidence flags)

- I have **not yet read** `releases.py` lines 100–2101, all of `auth.py`, all of `iec62443_*.py`, or any frontend code beyond the head of `ReleaseDetail.jsx`. Iter-1 deliverables call this out. Phase 3–5 will close it.
- I have **no measurements**. All performance claims in Phase 5 will start as theoretical, marked Confidence: Low until measured.
- I am **assuming** the security audit's controls are intact; I have not independently verified each one is still wired correctly. If you want a re-verification step, name it Q11 above.

---

End of recon.md
