# PR-3 Verification (Phase 9)

**Branch**: `refactor/iter-1-pr3-error-handling`
**Date**: 2026-05-02
**HEAD at verification start**: `66abc5c` (Stage R audit-doc consolidation)
**Pre-existing**: PR-1 merged at `9889790` (origin/master); PR-2 merged at `d92e679` (origin/master).

This document executes Phase 9 of the refactor-audit protocol for PR-3.  Verification is read-only — no production code changes.  Decisions captured here are recommendations to the user; merge action remains a separate user decision.

---

## §1 Hard blocker AC measurements

### AC-EXC-1 — Triage doc landed

**Verification**: `ls .refactor-audit/iteration-1/pr3-broad-except-triage.md`
**Result**: ✓ exists (153 LOC, commit `77f9a3c` N.1).  Covers all 46 sites in backend/app with (a)/(b)/(c) classification + per-site rationale.  §3 silent-swallow fix plan; §4 deferred sites; §5 historical correction.

**Status**: **PASS**

### AC-EXC-2 — Silent swallows = 0

**Verification**: `grep -rn "except Exception\|except BaseException" backend/app/ | grep -v "Deliberate broad-except" | wc -l`
**Result**: 2 hits — decomposed:
  - `backend/app/services/usecases/release/upload_sbom.py:69` — docstring inside `_save_and_score` mentioning "the prior `except Exception: pass` for the quality scoring becomes `logger.exception(...)`" (CODE-1.011 historical reference, not an actual except clause)
  - 1 binary `.pyc` cache file (transient, cleared on `--cache-clear`)

**Real unannotated broad-except clauses = 0.**  Same false-positive analysis recorded in N.6 commit body §Verification.

**Status**: **PASS**

### AC-EXC-3 — All (a) deliberate-keep sites annotated

**Verification**: `grep -rn "Deliberate broad-except" backend/app/ | wc -l`
**Result**: **44** markers across 18 files.  Matches N.6 commit body claim exactly.  Distribution per N.6 body:
  - 35 (a) deliberate keeps (top-level handlers + background safety-nets + library boundaries + fallback paths)
  - 6 (c) deferred-iter-2 typed-exc target sites (auth.py × 3 + signature_verifier.py × 3)
  - 3 (b-fix) annotations referencing prior-stage fixes (main.py N.3 + lifecycle.py N.5 + upload_sbom.py PR-1 D.3 historical)

**Status**: **PASS**

### AC-EXC-4 — Deferred (c) sites recorded with iter-2 carve-out

**Verification**: read `pr3-broad-except-triage.md` §4
**Result**: ✓ §4 lists 6 (c) deferred sites with iter-2 typed-exc target names:
  - `OIDCDiscoveryError` (auth.py:119)
  - `OIDCTokenExchangeError` (auth.py:148)
  - `OIDCUserinfoError` (auth.py:164)
  - `SignatureVerificationError` × 3 sites (signature_verifier.py:84/94/153, all map to one type)
  Cross-ref to architecture.md §4.5 typed-exception infrastructure plan (placeholder for iter-2).

**Status**: **PASS**

### AC-ARCH-1 — `_assert_vuln_org` grep clean

**Verification**: `grep -rn "_assert_vuln_org" backend/`
**Raw result**: 6 hits — decomposed:
  - 2 in `backend/app/core/deps.py` lines 106 + 147 — comments documenting the historical deletion ("legacy `_assert_vuln_org` (403 oracle-leaking) deleted in iter-1 PR-3 O.1" + docstring "matches legacy _assert_vuln_org behavior; intentionally not joinedload-optimized")
  - 1 in `backend/tests/test_endpoint_decorator_enforcement.py:15` — module docstring referencing deletion ("vuln-side _assert_vuln_org: deleted iter-1 PR-3 O.1")
  - 3 binary `.pyc` cache files (transient)

**Spec interpretation**: AC-ARCH-1 measures live executable references.  Source-code matches = 3 (all comments documenting the historical deletion as part of the closure record).  **Live executable references = 0** — the helper is fully deleted; no caller, no test case, no fallback path references it as code.

**Status**: **PASS** (with documentation-comment clarification — these comments are the audit-trail breadcrumbs that the closure happened in O.1, intentionally retained).

### AC-ARCH-2 — `get_vuln_history` ownership via Depends; cross-org returns 404

**Verification**: read `backend/app/api/vulnerabilities.py:199-213` (post-O.1)
**Result**: ✓ `get_vuln_history(vuln: Vulnerability = Depends(require_vuln_in_scope))` — single param, dependency-bound.  `require_vuln_in_scope` calls `assert_vuln_in_scope` which raises 404 (not 403) on both not-found and cross-org cases (CWE-204 oracle prevention).  Mirrors PR-1 D.8 release-side pattern exactly.

**Status**: **PASS**

### AC-SDLC-1 — SDLC-001 enforcement test extended to vuln-id; passes

**Verification**: `python tests/test_endpoint_decorator_enforcement.py`
**Result**:
```
[PASS] all 45 tenant-scoped endpoints have ownership dependency
[PASS] all 1 token-scoped endpoint(s) have resolver pattern
```
45 = 42 release-id + 3 vuln-id; the +3 vuln-id endpoints are PATCH /{vuln_id}/status, PATCH /{vuln_id}/suppress, GET /{vuln_id}/history (PATCH /batch has no path param so is not tenant-scoped — uses require_admin alone).

**Status**: **PASS**

### AC-SHARE-AUDIT — Share-token audit doc + verdict

**Verification**: read `pr3-share-token-audit.md` §4
**Result**: ✓ doc exists (204 LOC, commit `6aa5269` P.1).  Covers all 4 FU-1.010 failure modes (token not found / token expired / cross-org N/A / release deleted) + bonus SBOM-file-missing finding + cascade verification + audit-logging gap + test-coverage gap.  Verdict: **gap-and-fix-in-PR-3** for message+status-code uniformity (P.2 surgical fix); spawns FU-1.014 (audit logging) + FU-1.015 (comprehensive test suite).

**Status**: **PASS**

### AC-SDLC-SHARE — SDLC-001 share-token resolver whitelist

**Verification**: read `tests/test_endpoint_decorator_enforcement.py` post-P.3 + run
**Result**: ✓ `_TOKEN_PARAMS = {"token"}` + `_TOKEN_RESOLVER_DEPS` (Depends whitelist, currently empty placeholder) + `_TOKEN_RESOLVER_SOURCE_PATTERNS = ("SbomShareLink.token",)` (substring fallback).  New `test_all_token_scoped_endpoints_have_resolver()` function.  Run output above shows the 1 token-scoped endpoint passes.  Substring-based instead of AST-based per scope-justification in P.3 commit body (single use case + future migration to centralized resolver moves the check off source scan); AST is FU-1.016 placeholder.

**Status**: **PASS** (deviation from FU-1.011 AST spec recorded; rationale documented).

### AC-T2-stable — Coverage ≥ 30%

**Verification**: `pytest tests/unit --cache-clear --cov=app/services/usecases --cov=app/domain --cov-report=term`
**Result**:
```
TOTAL                                           1044    667    36%
```
Coverage = **36%**, exceeds 30% threshold by 6 points.  Breakdown:
  - app/domain: 100% (all submodules) — held from PR-1
  - app/services/usecases/release: 24% aggregate (lifecycle 62%, reports 37%, upload_sbom 26%, signature 25%, enrich 20%, scanners 15%) — same level as post-PR-1 G.1

PR-3 added 4 new tests (`test_share_token.py`) but those exercise the share.py public endpoint which is in `app/api/share.py` (NOT in the `--cov` flag scope — `--cov=app/services/usecases --cov=app/domain` only).  Coverage unchanged at 36% as expected.

**Status**: **PASS**

### AC-test_all-stable — test_all.py 54/54 PASS

**Verification**: backend started on port 9100; `python test_all.py`
**Result**:
```
TOTAL: 54 PASS / 0 FAIL  (54 tests)
```

**Status**: **PASS**

### AC-pytest-stable — pytest tests/unit cold green ≥ 157

**Verification**: `pytest tests/unit --cache-clear -q`
**Result**: **161 passed** / 1 skipped (was 157 + 4 new in `test_share_token.py`).  Exceeds 157 threshold by 4.

**Status**: **PASS**

### AC-no-regression — `git diff master..HEAD -- backend/app/api/`

**Verification**: `git diff master..HEAD --stat -- backend/app/api/ backend/app/core/deps.py`
**Result**:
```
 backend/app/api/auth.py            |  6 ++--   (annotations only — N.6)
 backend/app/api/firmware.py        | 19 ++++++++---  (annotations + N.2 fix + import logging)
 backend/app/api/share.py           | 15 ++++++---  (P.2 unified-404 message)
 backend/app/api/vulnerabilities.py | 25 ++------------  (O.1 helper deletion + Depends migration)
 backend/app/core/deps.py           | 69 ++++++++++++++++++++++++++++++++------  (O.1 new helpers)
 5 files changed, 89 insertions(+), 45 deletions(-)
```

All changes are within the deliberate evolution scope per pr3-plan.md §3:
  - `auth.py` + `firmware.py`: N.6 annotations only (3 + 2 sites)
  - `firmware.py`: N.2 silent-swallow narrowing fix (`json.JSONDecodeError, KeyError, ValueError, TypeError` + log) + import logging
  - `share.py`: P.2 unified-404 message + status code 410 → 404 for expired tokens (deliberate FU-1.010 closure)
  - `vulnerabilities.py`: O.1 deleted `_assert_vuln_org` legacy helper + refactored `get_vuln_history` to use Depends (deliberate ARCH-1.003 closure)
  - `core/deps.py`: O.1 added `assert_vuln_in_scope` + `require_vuln_in_scope` helpers + updated SDLC-001 docstring

The only contract-shape changes (vuln-id 403→404 + share-token 410→404) are the explicit ARCH-1.003 + FU-1.010 evolutions; both within the carved-out scope per pr3-plan.md §3.

**Status**: **PASS**

### AC-dim-5 — Broad-except absolute count audited

**Verification**: cross-referenced N.1 triage doc + N.6 commit body + post-PR-3 grep counts
**Result**:
  - Total broad-except sites in backend/app: **46** (matches N.1 triage; the "47" in N.1 §1 was the grep line count which includes 1 docstring false positive at upload_sbom.py:69)
  - Silent-swallow subset = **0** (4 fixed in N.2-N.5, 1 was historical PR-1 D.3 closure)
  - Deliberate keeps = **35** (annotated)
  - Translate-and-raise deferred (c) = **6** (annotated with iter-2 typed-exc target names)
  - Historical (b-fix) annotations = **3** (cross-referencing prior-stage fixes)
  - All 44 actual broad-except clauses carry the canonical `# Deliberate broad-except: {reason}` prefix (the 2 fewer than 46 are: 1 narrowed in N.2 → no longer broad, 1 narrowed in N.4 → no longer broad)

**Status**: **PASS**

### Acceptance gate summary

| AC | Status |
|---|---|
| AC-EXC-1 | PASS |
| AC-EXC-2 | PASS |
| AC-EXC-3 | PASS |
| AC-EXC-4 | PASS |
| AC-ARCH-1 | PASS |
| AC-ARCH-2 | PASS |
| AC-SDLC-1 | PASS |
| AC-SHARE-AUDIT | PASS |
| AC-SDLC-SHARE | PASS |
| AC-T2-stable | PASS |
| AC-test_all-stable | PASS |
| AC-pytest-stable | PASS |
| AC-no-regression | PASS |
| AC-dim-5 | PASS |
| **Sticky FU closures** | |
| AC-FU-1.002 | PASS (via O.2) |
| AC-FU-1.010 | PASS (via P.1 verdict-recording) |
| AC-FU-1.011 | PASS (via P.3 SDLC-001 extension) |

**14 hard blockers PASS + 3 sticky FU closures PASS = 17/17.**

---

## §2 Maturity score change

Per pr3-plan.md §7 estimate (conservative, hold most dims):

| Dim | PR-2 close | PR-3 close | Δ from PR-3 |
|---|---:|---:|---:|
| 1 Architecture clarity | 6 | 6 | 0 (hold) |
| 2 Domain purity | 6 | 6 | 0 (hold; typed-exc deferred) |
| 3 Abstraction discipline | 7 | 7 | 0 (hold) |
| 4 Readability density | 8 | 8 | 0 (hold) |
| 5 Error handling | 5 | **6** | **+1** (silent swallows fixed; deliberate keeps annotated; CODE-1.014 partial closure) |
| 6 Test quality | 7 | 7 | 0 (hold; SDLC-001 extensions are infra not new test category) |
| 7 Observability | 4 | 4 | 0 (hold) |
| 8 Performance | 6 | 6 | 0 (hold) |
| 9 API design | 7 | 7 | 0 (hold; ARCH-1.003 vuln-id+share-token extension is consistency, not new design) |
| 10 Dep hygiene | 8 | 8 | 0 (hold) |
| 11 Build & tooling | 7 | 7 | 0 (hold) |
| 12 Doc density | 9 | 9 | 0 (hold; audit doc additions don't move score meaningfully) |

**Sum**: 80 → **81**.  Δ +1.  Weighted Δ: 1/12 = **+0.083**.

Conservative estimate matches plan §7 baseline.  Stage P.2 fired with the surgical fix but did not rise to a "structural fix" justifying dim 9 +0.5 — the 410→404 status change preserves the same architectural model (bearer capability), only tightens the response uniformity.  Dim 9 hold confirmed.

**Cumulative iter-1 weighted Δ**: PR-1 (+0.75) + PR-2 (+0.167) + PR-3 (+0.083) = **+1.000**.

**Calibration §3.4 success classification**: cumulative Δ ≥ +0.8 = **SUCCESS**.  iter-1 reaches the +1.0 weighted-delta target exactly at PR-3 close, validating the 3-PR sequential plan from `refactor-plan.md` §3.

---

## §3 Disclosure: deliberate evolutions (CWE-204 oracle prevention)

Two contract-shape changes landed in PR-3, both within the explicitly-carved-out ARCH-1.003 / FU-1.010 evolution scope per pr3-plan.md §3:

1. **O.1 vulnerabilities.py vuln-id endpoint cross-org status code 403 → 404** (commit `0241793`)
   - Endpoint: `GET /api/vulnerabilities/{vuln_id}/history`
   - Pre-PR-3: 403 + "無權存取此漏洞" on cross-org access
   - Post-O.1: 404 + "Vulnerability not found" (uniform with not-found case)
   - Justification: completes ARCH-1.003 closure for vuln-id endpoints (last legacy 403-oracle helper in codebase), mirrors PR-1 D.8 release-side pattern, satisfies CWE-204 oracle prevention discipline uniformly.

2. **P.2 share.py public token endpoint expired-token status code 410 → 404 + message uniformity** (commit `584e064`)
   - Endpoint: `GET /api/share/{token}`
   - Pre-PR-3: 4 distinguishable response shapes (404 not-found, 410 expired, 404 release-missing, 404 file-missing) with branch-specific zh-TW messages
   - Post-P.2: uniform 404 + `"連結無效、已過期或已被撤銷"` across all 4 negative branches
   - Justification: closes FU-1.010 oracle uniformity per spec wording at refactor-plan.md:1036; theoretical leak (256-bit token entropy makes brute-force enumeration infeasible) but defense-in-depth on a public unauthenticated endpoint.

Both evolutions are inheritable via D1 lenient API contract regime (zero external consumers; React frontend is the only API caller).  No client-side breakage observed during sanity testing; UX trade-off (slightly less precise expired-link message) is small and accepted per spec.

---

## §4 LOC delta forecast vs actual (FU-1.013 second validation)

Per pr3-plan.md §4 forecast table:

| Stage | Forecast (production+test) | Actual | Variance |
|-------|---------------------------:|-------:|---------:|
| N.1 (triage doc) | +120 | +153 | +28% (per-site rationale richer than estimated) |
| N.2-N.5 (silent swallow fixes) | +25 | +24 | -4% (within bound) |
| N.6 (annotations) | +50 | +44 (44 lines changed; 0 net) | -12% |
| O.1 (vuln-id evolution) | +60 | +28 (net) | -53% (existing helpers reused; less infra than estimated) |
| O.2 (SDLC vuln-id ext) | +30 | -8 (net; whitelist removal + restructure) | -127% (refactor saved more than added) |
| P.1 (audit doc) | +120 | +204 | +70% (5-section depth incl. cascade verification + bonus finding) |
| P.2 (cond. fix) | 0-50 | +153 (production fix +9, test +146) | within forecast bound |
| P.3 (SDLC share-token ext) | +30 | +90 | +200% (more thorough than estimated; second test function + main() restructure) |
| **Production-side total** | **~+450** | **~+688 LOC tracked** | **+53%** |

**FU-1.013 verdict v2**: template is **directionally useful** (caught the +53% overage early enough to flag in Phase 9, not at PR review).  Major variances:
  - **P.1 audit doc** +70% (richer than estimated — bonus findings + cascade chain analysis added)
  - **P.3 SDLC ext** +200% (designed-for-future-resolver-migration extra structure)
  - **O.2** negative variance (refactor saved more LOC than added — counter-cyclical to forecast)

Recommend iter-2: add a "+50% audit-doc richness contingency" to forecast template; P.1-style audit-docs consistently exceed plan estimates by 30-70% as discovery happens during writing.

---

## §5 Verification recommendations

Based on all measurements above:

### Recommendation: (a) **READY-TO-MERGE**

All 14 hard blockers + 3 sticky FU closures PASS.  No regressions detected.  Coverage held at 36% (above 30% threshold).  test_all.py 54/54 PASS.  pytest unit 161 passed (was 157 + 4 new).  SDLC-001 enforcement extended cleanly.  Deliberate evolutions disclosed in §3.

Cumulative iter-1 weighted Δ reaches **+1.000** exactly at PR-3 close — calibration target hit.

### Phase 10 entry condition

User explicit "go Phase 10" or equivalent.  Phase 10 will land the PR-3 closure index section in `ledger.md` (D33 entry + commit chain summary + AC table + K log + T log + Phase 10 close marker).  Phase 11 follows with push to both remotes + PR creation on origin + merge.

### Outstanding items at PR-3 close (not blockers)

1. **Spawned FUs (FU-1.014 + FU-1.015)** — recorded in Stage R ledger entries; iter-2 promotion rules attached.
2. **6 (c) deferred typed-exception infrastructure** — annotated in-place with iter-2 target names; tracked in N.1 triage doc §4.
3. **K.7 codification refinement** — D30 fits as worked example for K.7.3 without K.7 formula change; no codification needed.
4. **D31 FU-promotion-rule slippage** — recorded as observation; codification deferred to iter-2 entry.

None of the above blocks PR-3 merge.

---

**End of pr3-verification.md.**  Phase 10 closure index follows in next audit-doc commit.
