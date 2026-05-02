# PR-2 Refactor Plan — performance wins + CODE-1.013 CSAF fix + K.7 codify + tidy

Generated 2026-05-02 post-PR-1 closure (master `28be089`, after D26 maintenance commit M002).
Branch: `refactor/iter-1-pr2-perf-tidy` (created from master `28be089`).

## §1 Scope (post-D26 correction)

PR-2 covers four targets, derived from PR-1 closing observations + iter-1 follow-up backlog:

1. **Performance wins (PERF-1.008)** — `backend/app/services/vuln_scanner.py` currently opens a fresh `httpx.Client` per OSV detail-fetch call (`_fetch_vuln` at line 135-143).  Each of up to 20 ThreadPool workers (`_MAX_WORKERS=20`) creates its own TCP connection + TLS handshake to `api.osv.dev`.  Refactor to share a single `httpx.Client` across all detail-fetch workers (HTTP/1.1 connection pool reuse, no TLS handshake per request).  Per `performance-audit.md` PERF-1.008: estimated 30-50% gain on the detail-fetch phase.
2. **CSAF namespace fix (CODE-1.013, spec-compliance bug; D26 corrected)** — `backend/app/services/usecases/release/reports.py:147` hardcodes CSAF VEX `publisher.namespace` as `https://example.com{namespace_suffix}`.  Per CSAF 2.0 §3.1.6, this MUST be a real authority IRI controlled by the publisher.  Refactor to env-var-driven (`CSAF_NAMESPACE` via `core/config.py` `Settings` BaseSettings field) with a sensible default.  Bundle the inline `# CODE-1.013 — fix in PR-2 F.5` stale comment cleanup (per §J6.5 broken-window pattern; "PR-2 F.5" was a never-executed PR-1 plan artifact).  Per `code-audit.md` CODE-1.013: P2 / Bug / Effort S / Risk low.  **Originally drafted as "perf-related" in PR-2 entry spec; reclassified to Bug+Tidy via §K invocation #9 / D26 (2026-05-02).**
3. **K.7 codification (D24+D25+D26 jointly motivated)** — `code-principles.md` §K currently has K.6 ("§K applies to all observable facts") added 2026-05-02 in F.4-audit.  K.7 codifies the misdiagnosis-pattern family with **3 sub-patterns** (existence / purpose / category) discovered during iter-1 PR-1 closing + PR-2 entry.  Standalone audit-doc work; no production-code surface.  Closes the K.7 deferral debt that D24 / D25 / D26 each individually noted.
4. **FU-1.012 — `stats.py:169` dead local cleanup** — `backend/app/api/stats.py:169` carries `inc_counts = {}  # per-org breakdown not needed (shown in totals)`, a never-read dead local that pre-dates PR-1 (blame `a72590e2` 2026-04-22).  PR-1 F-stage flagged it via pyflakes but did not bundle it (per §J6.5 same-file boundary — `stats.py` was not a F-stage touched file).  PR-2 takes it as a 1-line tidy commit.  Per ledger D18 / D20 / FU-1.012 entry in `refactor-plan.md` §10.

**PR-2 differs from PR-1 character**:
- PR-1 was 1 large architectural change (god-router decomposition, 23 production commits across Stages A-G).
- PR-2 is 4 small targeted changes (perf + spec-bug + tidy + audit-doc; estimated 11-15 commits across Stages I-M).
- Plan precision target: **≤ 3 §K invocations during PR-2 commit execution** (vs PR-1's 9 across full iter-1).  Achieved via stricter Phase 0 grep validation (this plan's Phase 0 already discharged the D24/D25/D26 misdiagnosis-pattern via M001/M002 maintenance commits; D26 specifically caught CSAF-as-perf misclassification before PR-2 branch was created).

## §2 Goals

- **Maturity weighted Δ**: from +0.75 (PR-1 close) to **≥ +0.83** (PR-2 close).  Cumulative iter-1 weighted Δ from baseline → +0.917 = crosses calibration §3.4 success threshold (+0.8).
  - **dim 8 Performance**: +1 (target hit; was miss in PR-1, root cause = no benchmark in iter-1)
  - **dim 6 Test quality**: +1 (bench scaffolding adds bench category; further validation of pytest infra investment)
  - **dim 5 Error handling**: hold (CODE-1.011 broad-except triage deferred to PR-3 to keep PR-2 character clean)
  - **dim 12 Doc density**: hold (K.7 codification is principle update, not new audit-doc body)
- **Hard blockers**: 13 (listed in §6)
- **Followup closure**: FU-1.012 closed, CODE-1.013 closed, K.7 codification deferral closed (D24+D25+D26 jointly motivated)

## §3 Stages (I-M)

Stage labels start at I (PR-1 used A-G; H reserved-but-unused to avoid letter collision with G.1/G.2 numbering).

### Stage I — Test infra & bench scaffolding

**Scope**: create `backend/tests/bench/` directory + `__init__.py` + `bench_osv.py` reproducer per `performance-audit.md` PERF-1.007 spec.  Bench is a stand-alone `python backend/tests/bench/bench_osv.py` script (NOT a pytest target) — per PERF-1.007, the requirement is "committable reproducer that prints `purl, vuln_count, elapsed_seconds`", deterministic, < 30s wall-clock against real OSV.dev API.

**Touched files**:
- NEW `backend/tests/bench/__init__.py` (0-line marker file, makes `bench/` a package for future expansion)
- NEW `backend/tests/bench/bench_osv.py` (~80 LOC stdlib + httpx; reproduces 3-PURL smoke test from `CHANGELOG.md:73`: `lodash@4.17.20`, `django@3.0.0`, `log4j-core@2.14.0` = 42 vulns; prints per-PURL timing + total)

**Estimated**: 1-2 commits / ~80 LOC test scaffolding.

**Maturity impact**: pre-Stage J prep (allows measurable J before/after); dim 6 (Test quality) +0.5 incremental (combined with Stage J completes the +1 for dim 6).

**Acceptance**: AC-PERF-T1 (bench file exists + executable) + AC-PERF-T2 (deterministic + < 30s wall-clock).

### Stage J — Performance fix PERF-1.008 (httpx.Client shared)

**Scope**: refactor `vuln_scanner.py:_fetch_vuln(vuln_id)` (line 135) to accept a shared `httpx.Client` parameter.  Hoist the client creation out of the per-call `with` block into the outer `scan_components` Phase 2 scope (currently lines 173-181).  All 20 ThreadPool workers reuse one client → one HTTP/1.1 connection pool → no per-call TLS handshake.

**Touched files**:
- `backend/app/services/vuln_scanner.py` — refactor `_fetch_vuln` signature (+1 param) and `scan_components` Phase 2 (open client outside ThreadPool, pass into futures)
- Re-run `bench_osv.py` from Stage I to capture before/after numbers in commit body

**Estimated**: 2-3 commits / ~30-50 LOC production refactor (signature change + caller update + bench result commit body containing measured before/after).

**Maturity impact**: dim 8 Performance +1 (target hit; PR-1 missed this).

**Acceptance**: AC-PERF-1 (grep verification: no `with httpx.Client(` inside `_fetch_vuln` body) + bench shows measurable gain on detail phase.

### Stage K — CSAF namespace fix (CODE-1.013, spec-compliance bug; D26 corrected)

**Scope** (post-D26 correction; was originally drafted as perf, now correctly classified as Bug+Tidy):
- Add `CSAF_NAMESPACE: str` field to `backend/app/core/config.py` `Settings(BaseSettings)` class (line 29 area; verified `pydantic_settings.BaseSettings` is the existing pattern, NO `os.getenv` raw usage in `core/`).  Default value: a non-`https://example.com` string consistent with iter-1 D1 lenient regime (open question — see §11 Open questions).
- `backend/app/services/usecases/release/reports.py:147` substitute `https://example.com{namespace_suffix}` → `f"{settings.CSAF_NAMESPACE}{namespace_suffix}"` (or equivalent injection pattern; reuse existing `from app.core.config import settings as _cfg` import already present in the file's imports).
- **Bundled per §J6.5 broken-window**: delete the inline comment at `reports.py:147` `# CODE-1.013 — fix in PR-2 F.5`.  This is a stale planning artifact (PR-1 Stage F was review-fix not CSAF; "F.5" tag was never used as planned).  Tool-flagged style stale-reference cleanup, in same commit as the fix it references.
- Add `.env.example` entry for `CSAF_NAMESPACE` (if `.env.example` exists; if not, document in commit body that `core/config.py` field default is the fallback).
- Add unit test: 1 test that mocks `_cfg.CSAF_NAMESPACE`, calls `_build_csaf_doc`, verifies `publisher.namespace` reflects the env var.

**Touched files**:
- `backend/app/core/config.py` — add `CSAF_NAMESPACE` field (~3 LOC)
- `backend/app/services/usecases/release/reports.py:147` — substitute string + delete stale comment (~5 LOC: -2 +3)
- `backend/.env.example` — add documented entry (~2 LOC; if file exists, else skip)
- `backend/tests/unit/test_csaf_namespace.py` (NEW) — 1-2 unit tests (~30 LOC)

**Estimated**: 2-3 commits / ~30-50 LOC production + ~30 LOC test.

**Maturity impact**: dim 12 +0 (audit-doc no impact); CODE-1.013 closed (open code-audit findings: N → N-1); §J6.5 second invocation in iter-1 (after F.2; bundled stale comment cleanup with the production fix).

**Acceptance**: AC-CSAF-1 (`grep "https://example.com" backend/app/services/usecases/release/reports.py` returns 0) + AC-CSAF-2 (`CSAF_NAMESPACE` documented in `.env.example` if file exists, else in `config.py` field default docstring) + AC-CSAF-3 (`reports.py:147` stale `# CODE-1.013 — fix in PR-2 F.5` comment removed).

### Stage L — Tidy (FU-1.012)

**Scope**: delete `backend/app/api/stats.py:169` `inc_counts = {}  # per-org breakdown not needed (shown in totals)`.  Verified by grep: zero references to `inc_counts` anywhere in `backend/` (single match at the assignment line itself; no later read site).  Per FU-1.012 spec in `refactor-plan.md` §10.

**Touched files**:
- `backend/app/api/stats.py` — delete 1 line

**Estimated**: 1 commit / -1 LOC (single-line delete; no test, no comment).

**Maturity impact**: dim 4 Readability +0 (1-line dead-local delete is below score-threshold).  FU-1.012 closed.

**Acceptance**: AC-TIDY-1 (`grep "inc_counts" backend/app/api/stats.py` returns 0).

### Stage M — K.7 codification (D24+D25+D26 jointly motivated, 3 sub-patterns)

**Scope**: add §K K.7 footnote to `code-principles.md` covering 3 misdiagnosis sub-patterns discovered during iter-1.  Insertion point: after K.6 (currently ends near line 250), before the `---` divider preceding "Iter-1 additions" section.

K.7 outline:

> **K.7 — Misdiagnosis-pattern family in §K verification probing**
> (added 2026-05-02 per iter-1 D24+D25+D26 jointly motivated).
> When a verification probe returns a result that contradicts the agent's
> mental model of the target, distinguish three failure axes — do NOT assume
> the first plausible explanation suffices:
>
> **K.7.1 — Existence misdiagnosis** (motivated by D24): probe returns "not
> found" → could be (a) target genuinely does not exist OR (b) target exists
> but probing identity has no access (private repo, restricted ACL, etc.).
> GitHub deliberately conflates (a) and (b) for private repos to prevent
> enumeration.  Resolution discipline: re-probe with a DIFFERENT identity
> before accepting "does not exist".
>
> **K.7.2 — Purpose misdiagnosis** (motivated by D25): probe-target exists
> but the *function* it serves differs from the agent's assumption.  D25
> example: `audit-mirror/master` exists but is a subtree-only audit-only
> branch, not a linear mirror of `origin/master`.  Resolution discipline:
> verify the design intent (config aliases, README, prior audit-doc) BEFORE
> assuming the target operates as the agent's mental model expects.
>
> **K.7.3 — Category misdiagnosis** (motivated by D26): probe-target exists
> AND its purpose is correctly understood, but its *classification within a
> taxonomy* is wrong.  D26 example: CSAF namespace fix exists, its purpose
> (CSAF 2.0 §3.1.6 compliance) was understood, but it was classified as
> "performance" when it actually belongs to "Bug" category in `code-audit.md`.
> Resolution discipline: when citing a finding, grep the canonical source
> (e.g. `code-audit.md` for code findings, `performance-audit.md` for perf
> findings) to verify category alignment BEFORE planning around it.
>
> **Closing meta-rule**: probe each axis (existence / purpose / category)
> separately rather than assuming the first explanation suffices.  When 3+
> probes return the same negative result with the same identity (D24
> example), the redundancy is along the wrong axis — diversify identities
> AND interpretations before concluding.
>
> **Standing**: permanent.  **First invocation**: PR-2 Stage M (this commit).

Plus update the "Iter-1 additions" tail section to add K.7 entry.

**Touched files**:
- `.refactor-audit/code-principles.md` — add K.7 section after K.6 (~50 LOC)

**Estimated**: 1 commit / ~50 LOC audit-doc.

**Maturity impact**: dim 12 +0 (principles are signal not source).  K.7 codification deferral closed (D24/D25/D26 each had "K.7 deferred" notes; closed jointly here).

**Acceptance**: AC-K7-1 (K.7 section exists) + AC-K7-2 (covers 3 sub-patterns each with D-entry cross-ref).

## §4 LOC delta forecast (per FU-1.013 template, first use)

| Stage | Production LOC | Test LOC | Audit-doc LOC | Total |
|-------|---------------:|---------:|--------------:|------:|
| I (test infra) | 0 | +80 | 0 | +80 |
| J (PERF-1.008) | +10 / -10 (refactor; net ~0) | 0 | 0 | 0 |
| K (CSAF fix + comment cleanup) | +5 / -3 (env var + reports.py + .env.example) | +30 | 0 | +32 |
| L (FU-1.012) | -1 (delete) | 0 | 0 | -1 |
| M (K.7 codify) | 0 | 0 | +50 | +50 |
| **Total** | **+1** | **+110** | **+50** | **+161** |

**PR-2 forecast**: ~+161 LOC across `backend/`(test/) + `.refactor-audit/`.  Production net ~+1 (CSAF env var + comment cleanup + FU-1.012 delete + Stage J refactor net-zero).  Test infra +110 dominates; expected and acceptable (this is the dim 6 +1 path).

**FU-1.013 first use note**: this plan validates the LOC delta forecast template introduced in iter-1 D20 / FU-1.013.  PR-2 actuals will be measured at close (Phase 9 verification.md analog) to validate template usefulness:
- Forecast accuracy ≤ ±20%: template considered useful, promote to standard.
- Forecast accuracy > ±50%: template needs categorization refinement.

## §5 Acceptance criteria

(verbatim 13 hard blockers from §6)

## §6 PR-2 acceptance gate

- [ ] AC-PERF-T1 — `backend/tests/bench/bench_osv.py` exists + executable
- [ ] AC-PERF-T2 — `bench_osv.py` runs deterministically < 30s wall-clock against real OSV.dev API
- [ ] AC-PERF-1 — `vuln_scanner.py` `_fetch_vuln` reuses outer client (grep verification: no `with httpx.Client(` inside `_fetch_vuln` body; outer scope opens 1 client shared across ThreadPool)
- [ ] AC-CSAF-1 — `grep "https://example.com" backend/app/services/usecases/release/reports.py` returns 0
- [ ] AC-CSAF-2 — `CSAF_NAMESPACE` env var documented (in `.env.example` if file exists, else in `config.py` field docstring)
- [ ] AC-CSAF-3 — `reports.py:147` stale `# CODE-1.013 — fix in PR-2 F.5` comment removed
- [ ] AC-TIDY-1 — `grep "inc_counts" backend/app/api/stats.py` returns 0
- [ ] AC-K7-1 — `code-principles.md` contains §K K.7 section
- [ ] AC-K7-2 — K.7 covers 3 sub-patterns (existence / purpose / category), each with D-entry cross-ref
- [ ] AC-T2-stable — `pytest --cov=app/services/usecases --cov=app/domain` reports ≥ 30% (PR-1 baseline 36%; PR-2 must not regress)
- [ ] AC-test_all-stable — `test_all.py` 54/54 PASS (no regression)
- [ ] AC-pytest-stable — `pytest tests/unit` cold green ≥ 154 passed (+ Stage K's new test, so ≥ 155)
- [ ] AC-no-behavior-regression — `git diff master..HEAD -- backend/app/api/` shows no contract-shape change to existing endpoints (CSAF env var is new mechanism, not contract change)

13 hard blockers.  Less than PR-1's 15 because PR-2 scope is smaller and doesn't touch architecture/domain layers.

## §7 Maturity dim impact estimate

| Dim | PR-1 close | PR-2 close estimate | Δ from PR-2 |
|-----|-----------:|--------------------:|------------:|
| 1 Architecture | 6 | 6 | 0 (hold) |
| 2 Domain purity | 6 | 6 | 0 (hold) |
| 3 Abstraction | 7 | 7 | 0 (hold) |
| 4 Readability | 8 | 8 | 0 (hold; FU-1.012 -1 line not score-affecting) |
| 5 Error handling | 5 | 5 | 0 (hold; CODE-1.011 deferred to PR-3) |
| 6 Test quality | 6 | 7 | +1 (bench scaffolding adds bench category to test infra) |
| 7 Observability | 4 | 4 | 0 (hold) |
| 8 Performance | 5 | 6 | +1 (PERF-1.008 + bench reproducer hits target) |
| 9 API design | 7 | 7 | 0 (hold) |
| 10 Dep hygiene | 8 | 8 | 0 (hold) |
| 11 Build | 7 | 7 | 0 (hold) |
| 12 Doc density | 9 | 9 | 0 (hold; K.7 codify is signal not source) |

**Sum (post PR-2)**: 6+6+7+8+5+7+4+6+7+8+7+9 = **80**
**Sum (PR-1 close)**: 78
**Δ from PR-2**: +2
**Weighted Δ**: 2/12 = **+0.167**

**Cumulative iter-1 weighted Δ from baseline**: PR-1 +0.75 + PR-2 +0.167 = **+0.917**.

Per `calibration.md` §3.4: ≥ +0.8 = **SUCCESS**.  PR-2 close pushes cumulative iter-1 weighted Δ across the success threshold for the first time.

## §8 Commit budget

- **T1 (informational)**: commit count target ~10-12
- **T2 (planning warning)**: > 12
- **T3-soft (warning, scope re-evaluation required)**: > 13 → §K STOP scope re-evaluation
- **T3-hard (block)**: > 16 → §K STOP rescope

**Stage commit estimates**:
- Stage I: 2 commits (bench infra commit + bench data smoke result commit)
- Stage J: 3 commits (refactor commit + bench-comparison commit + audit-doc D-entry recording PERF-1.008 closure)
- Stage K: 2-3 commits (config.py env var + reports.py + .env.example commit, then test commit, then audit-doc CODE-1.013-closed commit)
- Stage L: 1 commit (single-line tidy)
- Stage M: 1 commit (K.7 codification)
- Phase 9 verification: 1-2 commits (pr2-verification.md analog)
- Phase 10 closure: 2-3 commits (ledger consolidation + maybe ADR-0005 for K.7 if K.7 reaches ADR-worthy detail)

**Total estimate**: 11-15 commits.  Comfortably under T3-soft 13 in best case; touches T3-soft if Phase 10 needs 3 commits.  Audit-doc commits not counted per D16; production commit subset estimated 7-10.

## §9 Stage execution order

**I → J → K → L → M** (sequential, no parallelism within PR-2)

**Reasoning**:
- **I before J**: bench needs to exist before measuring J's gain (without baseline numbers, J's commit body can't claim "30-50% gain").
- **J before K**: J is the only Stage with potential cross-file ripple (`_fetch_vuln` signature change touches ThreadPool caller in `scan_components`); easier to land J cleanly first then verify K's CSAF flow doesn't break.
- **K before L**: K touches `reports.py` (Layer 2) and `core/config.py` (Layer 0); L touches `stats.py` (Layer 1).  Orthogonal but K's test infra (config.py env var + new test file) is more involved than L (1-line delete) — do K first to keep L as a small "palate cleanser" before Stage M.
- **M last**: K.7 codification benefits from having all 3 sub-patterns' D-entries (D24/D25/D26) available as cross-refs; D26 already on master pre-PR-2, so technically M can run anywhere, but landing M last makes the iter-1 codification debt closure a clean final beat before Phase 9 verification.

## §10 Followups (PR-2 will resolve / inherit)

**Resolved by PR-2 close**:
- FU-1.012 (dead `inc_counts`) — Stage L
- CODE-1.013 (CSAF placeholder namespace) — Stage K
- K.7 codification deferral (D24+D25+D26 jointly) — Stage M
- `reports.py:147` stale "PR-2 F.5" comment cleanup — Stage K (bundled per §J6.5)

**Inherited unchanged from PR-1 followups**:
- FU-1.001 (Pydantic min/max validation tightening) — deferred per Q-P7-3
- FU-1.002 (vulnerabilities.py last legacy `_assert_vuln_org`) — separate iter
- FU-1.003 (anti-corruption DTOs) — when 2nd consumer surfaces
- FU-1.004 (CycloneDX/SPDX exporters package) — iter-2 if `reports.py` re-split
- FU-1.005 - FU-1.009 (Suppression invariants) — iter-2 with suppress-endpoint
- FU-1.010 / FU-1.011 (download_shared_sbom + share-token SDLC-001 audit) — separate
- FU-1.013 (LOC delta forecast template) — PR-2 §4 first use (this plan validates template usefulness)

**PR-3 candidate inheritance**:
- CODE-1.011 broad-except triage (dim 5 +1 target)
- ARCH-1.003 partial closure (vulnerabilities.py legacy caller; can pair with FU-1.002)
- `lifecycle.py` 13-endpoint density re-split if dim 1 +2 wanted

## §11 §K invocation precision target + Open questions

PR-1 closed at 9 §K invocations (upper edge of healthy band).
**PR-2 target**: ≤ 3 §K invocations during commit execution.

**Levers reducing PR-2 §K count**:
1. Phase 0 grep validation already discharged D24/D25/D26 misdiagnosis-patterns at PR-1→PR-2 transition (D26 = the discharge for category misdiagnosis surfaced via this Phase 0 itself).
2. Stage M's K.7 codification introduces 3-axis probing discipline for future iter Phase 0 work.
3. PR-2 scope is multi-target small-effort; less surface for "design assumption" misdiagnosis (D25-style) than PR-1's god-router decomposition.

If PR-2 hits 4+ §K invocations during commit execution: plan precision regressed; trigger plan-precision review for iter-2 entry.

**Open questions — RATIFIED 2026-05-02 by user**:

- **Q-PR2-1**: (b) — `CSAF_NAMESPACE` empty → fallback `f"https://sbom-platform.local/{org_slug}"`; set → use env value
- **Q-PR2-2**: (a) — `bench_osv.py` offline → skip-and-warn (exit 0)
- **Q-PR2-3**: (a) — promote `seeded_release_with_sbom_and_component` from `test_releases_http_chars.py` to `tests/unit/conftest.py` shared scope
- **Q-PR2-4**: (b) — K.7 stays in `code-principles.md` (no ADR-0005)

Original question texts retained below for audit trail:


**Q-PR2-1 (Stage K env var default)**: when `CSAF_NAMESPACE` is not set in env, what should the `Settings` default be?
- (a) Keep `https://example.com` as fallback (preserves current observable behavior for users who don't configure; CODE-1.013 only "fixed" when user opts in).
- (b) Default to a sensible per-org-derived value like `f"https://sbom-platform.local/{org_slug}"` (CODE-1.013 closed unconditionally; minor risk of users surprised by output change).
- (c) Default to `None` and raise `HTTPException(status_code=500, "CSAF_NAMESPACE env var required")` — strictest but most noisy.
- **Agent recommendation**: (b) — D1 lenient regime means zero external consumers, so the output-change risk is low; (a) leaves the bug technically open; (c) is overly strict for an output-string fix.

**Q-PR2-2 (Stage I bench mode — real OSV vs mock)**: `bench_osv.py` reproducer per PERF-1.007 should hit real `api.osv.dev` (3-PURL smoke test runs 5.9s per `CHANGELOG.md:73` evidence).  Two questions:
- (a) Real OSV.dev requires internet — should bench skip/warn-and-exit if offline, or hard-fail?
- (b) Bench should NOT run as part of normal `pytest tests/unit/` (would slow CI + require internet).  Run is `python backend/tests/bench/bench_osv.py` standalone.
- **Agent recommendation**: skip-and-warn if offline (sets exit code 0 with "skipped: no internet"; matches `bench_osv.py` design as "reproducer when needed", not "regression guard CI must run").

**Q-PR2-3 (Stage K test fixtures — reuse or new)**: Stage K unit test for `_build_csaf_doc` needs a Release + 1+ Component fixture.  PR-1 has `seeded_release_with_sbom_and_component` in `test_releases_http_chars.py` that fits.
- (a) Reuse the existing fixture (move it to `conftest.py` so it's shareable, OR import from sibling test file).
- (b) Create a new fixture in `test_csaf_namespace.py` (duplicates seeding code, simpler isolation).
- **Agent recommendation**: (a) — promote `seeded_release_with_sbom_and_component` to `conftest.py` shared fixture, pulled in by both existing http-chars tests and new CSAF test.  Small net cleanup; no fixture duplication.

**Q-PR2-4 (Stage M K.7 ADR-worthy?)**: should K.7 codification be paired with **ADR-0005**, given that 9 §K invocations + 3 misdiagnosis patterns is a substantial principle-level finding?
- (a) Yes — ADR-0005 "Misdiagnosis-pattern family in verification probing" alongside `code-principles.md` K.7.  Standalone audit-trail anchor.
- (b) No — K.7 in `code-principles.md` is sufficient; ADR is reserved for architectural decisions, not principle codifications.
- **Agent recommendation**: (b) — K.7 is a refinement of an existing principle (§K), not a new architectural decision.  ADR-0005 would duplicate K.7 content without adding architectural rationale.  Save ADR-0005 slot for an actual architecture decision (e.g. PR-3's lifecycle.py re-split or PR-2's PERF-1.008 if bench shows surprising results).

## §12 Plan precision retrospective (post-PR-2 close target)

At PR-2 Phase 9 verification, measure:
- Forecast LOC accuracy: `actual_PR2_LOC` vs `+161 forecast` (per FU-1.013 validation).
- §K invocation count: actual PR-2 §K count vs ≤ 3 target.
- Commit budget: actual production commit count vs 7-10 estimate.
- Maturity actual vs estimate (dim 6 +1 / dim 8 +1 vs predicted).

Use these measurements to calibrate iter-2 plan precision.  Specifically: if FU-1.013 forecast accuracy is ≥ ±20%, promote LOC delta forecast to standard Phase 7 template; if §K count > 3, root-cause the gap (was it Phase 0 grep too narrow? plan assumption too coarse?) and tighten iter-2's Phase 0 protocol accordingly.

---

**Plan generated 2026-05-02.  HEAD at plan-write time: `28be089` (master, post-D26 maintenance commit M002).  PR-2 branch `refactor/iter-1-pr2-perf-tidy` created from this commit; not yet pushed to remote.  Awaiting user review + Phase 8 commit execution authorization.**
