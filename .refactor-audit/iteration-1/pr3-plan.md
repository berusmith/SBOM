# PR-3 Refactor Plan — error handling + ARCH-1.003 完整收尾 + share-token audit + tidy

Generated 2026-05-02 post-PR-2 closure (master `d92e679`).
Branch: `refactor/iter-1-pr3-error-handling` (created from master `d92e679`).

## §1 Scope (post-Phase-0 grep validation + §K #10 (α) reframe)

PR-3 covers four targets, derived from PR-2 closing observations + iter-1 follow-up backlog:

1. **Broad-except triage — CODE-1.014 partial scope** (per §K #10 (α) resolution; user spec originally said "CODE-1.011 broad-except triage" which conflated the two findings — see D30 to be recorded in Stage R).  Scope:
   - Fix the silent-swallow sites (broad-except + bare `pass`): **4 sites confirmed by Phase 0 grep** — `firmware.py:192`, `main.py:173`, `signature_verifier.py:192`, `lifecycle.py:313`.  (CODE-1.014 forecast was "~5 sites including CODE-1.011"; the CODE-1.011 site at `upload_sbom.py:80-85` is **already fixed** — uses `logger.exception(...)` not bare `pass`, presumably during PR-1 D.3 commit `e811bb2` "CODE-1.009/1.016/ARCH-1.013 bundled fixes".)
   - Annotate the deliberate-keep sites (top-level handler / background safety-net / library boundary): **~25 sites** per CODE-1.014 forecast; will refine in Stage N.1 triage.
   - **DEFER to iter-2**: the ~6 translate-and-raise sites (auth.py:119/148/164 + others — needs typed exception infrastructure first); the introduction of `domain/exceptions.py` NEW module with typed exceptions (separate architectural decision, deserves its own plan stage + ADR-0005 in iter-2).

2. **ARCH-1.003 完整收尾 (FU-1.002)** — `vulnerabilities.py` last legacy `_assert_vuln_org` caller.  Phase 0 grep confirms: definition at `vulnerabilities.py:26`, single caller at `vulnerabilities.py:208` inside `get_vuln_history`.  Other `vulnerabilities.py` endpoints (`batch_update_vex` / `update_vex` / `suppress_vuln`) use `Depends(require_admin)` only (admin-scope, no org check needed — same pattern as PR-1's `lock_release` / `unlock_release`).  Apply D.8-equivalent pattern to the 1 caller; extend SDLC-001 enforcement test to cover vuln-id endpoints.

3. **Share-token endpoint audit (FU-1.010 + FU-1.011)** — `download_shared_sbom` at `backend/app/api/share.py:185` (public, share-token-resolved).  Read-only audit per FU-1.010 promotion rule; production fix conditional on audit findings (Q-PR3-3).  **Process note**: FU-1.010's iter-2 promotion rule was "promote BEFORE PR-2 (perf wins)" — slipped in PR-2 because PR-2 character was perf+tidy, not share-token audit.  Picked up here.  D31 will record the slippage as a process observation.

4. **FU-1.001 (Pydantic min/max validation tightening)** — **Stage Q conditional pending Q-PR3-2 ratification**.  Character mismatch (schema-tightening ≠ error-handling) means default = defer to iter-2.

**PR-3 differs from PR-2 character**:
- PR-1 was 1 large architectural change (god-router decomposition).
- PR-2 was 4 small targeted changes (perf + spec-bug + audit-doc principle + tidy).
- PR-3 is **1 large theme (error handling) + 1 small ARCH closure + 1 audit + (optional) tidy**.
- Plan precision target: **≤ 3 §K invocations during PR-3 commit execution** (relaxed from earlier ≤ 2; PR-2 hit 0-execution but was "easy mode" — Q-PR2 ratification + K.7 codify resolved entry-stage ambiguity before Stage I started; PR-3 still touches new surface area, allow margin).

## §2 Goals

- **Maturity weighted Δ**: from +0.917 (PR-2 close) to **≥ +0.95** (PR-3 close).
  - **dim 5 Error handling**: target +1 (closes the only outstanding miss after PR-1/PR-2; broad-except absolute count drops, deliberate-keep sites annotated)
  - dim 1 / 9 may shift +0.5 if Stage P audit triggers structural fixes (audit-dependent)
- **Hard blockers**: 14 (listed in §6)
- **Followup closures**: FU-1.002 + FU-1.010 + FU-1.011 + (optional FU-1.001) + CODE-1.014 partial (silent swallows fixed)

If PR-3 hits all targets:
- **Cumulative iter-1 weighted Δ projection**: PR-2 +0.917 + PR-3 +0.083 (12-dim normalized) = **+1.000** — calibration target hit.
- iter-1 PR-1 + PR-2 + PR-3 fully closed; iter-2 entry can begin (frontend ReleaseDetail.jsx god-component, typed domain exceptions, etc.)

## §3 Stages (N-R, with Stage Q conditional)

Stage labels start at N (PR-1 used A-G; PR-2 used I-M; H/N intentionally skipped/started to avoid letter collision with PR-1/PR-2 numbering).

### Stage N — Broad-except triage (CODE-1.014 partial)

**Sub-stages**:

**N.1 (audit-doc, read-only)** — Write `.refactor-audit/iteration-1/pr3-broad-except-triage.md`.  Lists all 47 sites with per-site classification:
- **(a) deliberate keep** — top-level handler / background safety-net / library boundary catch-all.  For each site: 1-line rationale why broad-except is correct here.
- **(b) silent swallow** — needs `logger.exception(...)` + (optionally) re-raise specific type.  For each site: target replacement pattern.
- **(c) translate-and-raise** — needs typed exception (deferred to iter-2).  For each site: target typed exception name (placeholder).

Pre-Phase-0 known counts: ~4 (b) silent swallows confirmed by grep; ~25 (a) deliberate keeps + ~6 (c) translate-and-raise per CODE-1.014 forecast.  N.1 will refine.

Estimated: 1 commit / ~150 LOC audit-doc.

**N.2 — Fix `main.py:173` silent swallow (index creation)**.  Add `logger.exception(...)`; do NOT re-raise (index creation is best-effort during startup).  Estimated: 1 commit / ~3 LOC production.

**N.3 — Fix `signature_verifier.py:192` silent swallow**.  Same pattern: log + optionally re-raise specific type.  Need to verify what callers expect (does the catch site swallow because the caller treats no-result as "verification failed"?).  Triage in N.1 informs.  Estimated: 1 commit / ~5 LOC production.

**N.4 — Fix `firmware.py:192` silent swallow**.  Background scan job context.  Triage in N.1 informs.  Estimated: 1 commit / ~5 LOC production.

**N.5 — Fix `lifecycle.py:313` silent swallow (sbom_quality_grade computation)**.  Same pattern as already-fixed CODE-1.011 (use `logger.exception` to preserve gate behavior).  Estimated: 1 commit / ~3 LOC production.

**N.6 — Annotate deliberate-keep sites**.  Add inline comment `# Deliberate broad-except: {reason}` (per Q-PR3-1 (i) recommendation) to each (a) site.  Single commit covers all ~25 sites.  Estimated: 1 commit / ~25-50 LOC production (mostly comment additions).

**Stage N totals**: 6 commits estimated (1 audit-doc + 5 production).

**Maturity impact**: dim 5 +1 (broad-except absolute count drops 47 → 47 with 4 silent fixed + ~25 deliberate annotated + ~6 deferred = "47 broad-except, all classified" — dim 5 closes target).

**Hard blockers**: AC-EXC-1 / AC-EXC-2 / AC-EXC-3 / AC-EXC-4.

### Stage O — ARCH-1.003 完整收尾 (FU-1.002)

**O.1 — Production fix on `vulnerabilities.py`**.  Approach options:
- (a) Introduce `Depends(require_vuln_in_scope)` helper analogous to `require_release_in_scope`.  Cleaner pattern, more LOC.
- (b) Inline the ownership check inside `get_vuln_history` using existing `Depends(require_admin)` chain (single call site, no helper needed).  Simpler, less infra.

Phase 0 grep showed `_assert_vuln_org` is called in only 1 endpoint (`get_vuln_history`).  Plan default: (b) inline — single call site doesn't justify a new Depends helper.  If Stage P.1 audit reveals additional vuln-id endpoints needing the same check, switch to (a) at that point.

Estimated: 1 commit / ~10-15 LOC production (replace `_assert_vuln_org` call + delete the helper function).

**O.2 — SDLC-001 enforcement extension (FU-1.002 close)**.  Extend `tests/test_endpoint_decorator_enforcement.py` to cover vuln-id endpoints (current rule covers release-id endpoints only).  Pattern parallel to FU-1.011's planned share-token coverage.

Estimated: 1 commit / ~30-50 LOC test.

**Stage O totals**: 2 commits estimated.

**Maturity impact**: dim 9 hold (ARCH-1.003 closure is consistency, not new design); FU-1.002 closed.

**Hard blockers**: AC-ARCH-1 / AC-ARCH-2 / AC-SDLC-1.

### Stage P — Share-token endpoint audit (FU-1.010 + FU-1.011)

**P.1 — Audit (read-only, audit-doc)**.  Read `download_shared_sbom` end-to-end + share-token resolver helpers.  For each failure mode (token not found / token expired / token's release in another org / release deleted while link still active), confirm:
- HTTP status code uniform (do not differentiate "exists but expired" from "never existed" — both should 404 with same message).
- No information leakage about underlying release in error responses.
- Audit log records access attempts uniformly regardless of failure mode.

Produce `.refactor-audit/iteration-1/pr3-share-token-audit.md` with findings + verdict (no gap / gap-and-fix-in-PR-3 / gap-and-FU-1.014).

Estimated: 1 commit / ~80-150 LOC audit-doc.

**P.2 (CONDITIONAL)** — If P.1 audit verdict = "gap-and-fix-in-PR-3":
- Conditional on Q-PR3-3 ratification (agent recommendation: surgical fix in PR-3 if 1-2 sites + ~30 LOC; FU-1.014 split if architectural).
- Estimated: 0-3 commits / 0-50 LOC production (range depends on P.1 finding).

**P.3 — SDLC-001 enforcement extension (FU-1.011 close)**.  Extend `test_endpoint_decorator_enforcement.py` AST scan to whitelist share-token resolver call names per FU-1.011 spec (additive to Stage O.2's vuln-id extension).

Estimated: 1 commit / ~30 LOC test.

**Stage P totals**: 2-5 commits estimated (P.1 + P.3 always; P.2 conditional 0-3).

**Maturity impact**: dim 9 +0.5 if P.1 reveals tighten-able oracle paths and P.2 fixes them; otherwise hold.  FU-1.010 + FU-1.011 closed.

**Hard blockers**: AC-SHARE-AUDIT.

### Stage Q — FU-1.001 Pydantic min/max validation (CONDITIONAL — pending Q-PR3-2 ratification)

**Default**: skipped per agent recommendation (b) — character mismatch, defer to iter-2.

**If included (Q-PR3-2 = (a))**:
- Q.1 — `release_lifecycle.py` schema tighten: add `min_length=1, max_length=255` to `version`, `max_length=5000` to `notes` (replace silent truncation with 422 rejection).  Update handler to drop 400-with-zh-msg in favor of Pydantic 422 (or keep 400 with zh-msg and add 422 fallback — to be decided).
- Q.2 — Update `test_releases_http_chars.py` E.2 boundary tests to expect new behavior (4999 chars → 200, 5001 chars → 422, empty → 422 not 400).
- Estimated: 2 commits / ~30 LOC schema + ~20 LOC test changes.
- Adds 1 deliberate evolution on top of Stage O's ARCH-1.003 completion = PR-3 has 2 deliberate evolutions.  D1 §V.2 ledger entry needed for Q.1.

### Stage R — Audit-doc consolidation

**R.1 — Ledger D-entries**:
- D30 — §K invocation #10 (CODE-1.011 vs CODE-1.014 finding-ID category misdiagnosis); resolution (α) reframe Stage N as CODE-1.014 partial; cumulative §K count: 10.
- D31 — Process observation: FU-1.010 promotion-rule slippage (rule was "promote BEFORE PR-2", PR-2 closed without picking it up due to character mismatch).  Codification candidate (Q-PR3-N decision): K.8 or §F8 — "FU promotion rules MUST be re-checked at every PR-entry checklist".  Default: record as observation; defer codification to iter-2 entry.
- D32 — Stage P audit findings (whatever P.1 verdict was; if P.2 fired, also record fix).
- D33 — PR-3 closure index (Phase 10).

**R.2 — Code-audit.md status updates**:
- CODE-1.011 status: CLOSED (already done in PR-1 D.3 — Stage R adds Status block noting historical PR-1 closure + Stage N triage doc reference).
- CODE-1.014 status: partial CLOSED (silent swallows fixed + deliberate keeps annotated; translate-and-raise + typed-exc deferred to iter-2).

**R.3 — code-principles.md K.7 commentary refine** (CONDITIONAL — pending Q-PR3-N ratification or default-defer).  Default: defer.  If included: update K.7 closing meta-rule with signal-vs-noise commentary now that iter-1 has crossed 10 §K invocations (the K.6 "10+ = plan too imprecise" upper-edge needs nuance: iter-1's 10 are all SIGNAL §K, each caught a real issue).

**R.4 — verification.md analog (Phase 9, but folded into R for budget)**.  Or split as separate Phase 9 commit (decision in §9).

**Stage R totals**: 2-4 commits estimated.

## §4 LOC delta forecast (per FU-1.013 template, second use)

| Stage | Production LOC | Test LOC | Audit-doc LOC | Total |
|-------|---------------:|---------:|--------------:|------:|
| N.1 (triage doc) | 0 | 0 | +150 | +150 |
| N.2-N.5 (4 silent swallow fixes) | +20 / -10 = +10 net | 0 | 0 | +10 |
| N.6 (annotate ~25 deliberate keeps) | +25-50 (comments) | 0 | 0 | +37 |
| O.1 (ARCH vuln) | +10 / -10 = net 0 | 0 | 0 | 0 |
| O.2 (SDLC-001 vuln-id ext) | 0 | +40 | 0 | +40 |
| P.1 (audit doc) | 0 | 0 | +120 | +120 |
| P.2 (cond. fix) | 0-50 (audit-dependent) | 0-30 | 0 | 0-80 |
| P.3 (SDLC share-token ext) | 0 | +30 | 0 | +30 |
| Q.1-Q.2 (cond. FU-1.001) | 0-30 | 0-20 | 0 | 0-50 |
| R.1-R.3 (ledger + code-audit + maybe K.7) | 0 | 0 | +80-120 | +80-120 |
| **Total (no-cond P.2/Q)** | **~+50** | **~+70** | **~+370** | **~+490** |
| **Total (cond P.2 + Q included)** | **~+130** | **~+120** | **~+370** | **~+620** |

PR-3 forecast: **~+490 to +620 LOC** depending on conditional stages.  Production net is small (~+50 baseline, +130 if all conditional work done) — most of PR-3 is audit-doc + comments + tests, not new production code.

FU-1.013 second use: forecast accuracy will be measured at PR-3 close.

## §5 Acceptance criteria

(verbatim 14 hard blockers from §6)

## §6 PR-3 acceptance gate

- [ ] **AC-EXC-1** — `.refactor-audit/iteration-1/pr3-broad-except-triage.md` exists; covers all 47 sites with (a)/(b)/(c) classification + per-site rationale.
- [ ] **AC-EXC-2** — All silent swallow sites fixed (the 4 confirmed by Phase 0 + any others surfaced by N.1 triage).  Verified: `grep -B 1 -A 1 "except Exception:" backend/app/ | grep -A 1 "except Exception:" | grep "pass$"` returns 0 unannotated lines.
- [ ] **AC-EXC-3** — All (a) deliberate-keep sites have inline comment `# Deliberate broad-except: {reason}` (per Q-PR3-1 (i)).  Verified: `grep -B 1 "except Exception:" backend/app/` shows preceding comment for each non-fixed site, OR site is a (b) fix or (c) deferred-with-comment.
- [ ] **AC-EXC-4** — Triage doc explicitly lists (c) deferred sites with iter-2 carve-out note + cross-ref to where typed-exception plan will live (architecture.md §4.5 WD or new section).
- [ ] **AC-ARCH-1** — `grep -rn "_assert_vuln_org" backend/` = 0.
- [ ] **AC-ARCH-2** — `vulnerabilities.py` `get_vuln_history` endpoint enforces ownership check via inline pattern (or `Depends(require_vuln_in_scope)` if helper introduced).  Cross-org access returns 404 not 403 (uniform with D.8 / ARCH-1.003 evolution).
- [ ] **AC-SDLC-1** — `tests/test_endpoint_decorator_enforcement.py` extended to cover vuln-id endpoints; passes.
- [ ] **AC-SHARE-AUDIT** — `.refactor-audit/iteration-1/pr3-share-token-audit.md` exists with explicit verdict (no gap / gap-and-fixed / gap-and-FU-1.014); audit covers all 4 failure modes from FU-1.010 spec.
- [ ] **AC-SDLC-SHARE** — If FU-1.011 fix applied (Stage P.3), `test_endpoint_decorator_enforcement.py` AST scan whitelists share-token resolver calls.
- [ ] **AC-T2-stable** — `pytest --cov=app/services/usecases --cov=app/domain` reports ≥ 30%.
- [ ] **AC-test_all-stable** — `test_all.py` 54/54 PASS.
- [ ] **AC-pytest-stable** — `pytest tests/unit` cold green ≥ 157.
- [ ] **AC-no-regression** — `git diff master..HEAD -- backend/app/api/` shows no contract-shape change to existing endpoints (except ARCH-1.003 evolution scope = the deliberate carve-out).
- [ ] **AC-dim-5** — broad-except absolute count audited (47 sites all classified); silent-swallow subset = 0; deliberate keeps annotated.

**Conditional ACs** (apply only if Q-PR3-2 = include FU-1.001):
- [ ] **AC-FU-1.001** — `release_lifecycle.py` schemas tightened with min_length/max_length; E.2 boundary tests updated to match new behavior.

**Sticky FU closure ACs** (verified via ledger entries in Stage R):
- AC-FU-1.002 ✓ via Stage O.2 SDLC-001 vuln-id extension
- AC-FU-1.010 ✓ via Stage P.1 audit (verdict-recording closes the audit FU)
- AC-FU-1.011 ✓ via Stage P.3 SDLC-001 share-token extension

## §7 Maturity dim impact estimate

| # | Dim | PR-2 close | PR-3 close estimate | Δ from PR-3 |
|---|-----|-----------:|--------------------:|------------:|
| 1 | Architecture clarity | 6 | 6 | 0 (hold) |
| 2 | Domain purity | 6 | 6 | 0 (hold; typed exc deferred) |
| 3 | Abstraction discipline | 7 | 7 | 0 (hold) |
| 4 | Readability density | 8 | 8 | 0 (hold; comment additions don't move score meaningfully) |
| 5 | Error handling | 5 | **6** | **+1** (silent swallows fixed; deliberate keeps annotated; CODE-1.014 partial closure) |
| 6 | Test quality | 7 | 7 | 0 (hold; SDLC-001 extensions are infra not new test category) |
| 7 | Observability | 4 | 4 | 0 (hold) |
| 8 | Performance | 6 | 6 | 0 (hold) |
| 9 | API design | 7 | 7 | 0 (hold; ARCH-1.003 vuln-id extension is consistency, not new design) — could shift to **+0.5** if Stage P.2 fires with structural fix; conservative estimate hold |
| 10 | Dep hygiene | 8 | 8 | 0 (hold) |
| 11 | Build | 7 | 7 | 0 (hold) |
| 12 | Doc density | 9 | 9 | 0 (hold) |

**Sum (post PR-3, conservative)**: 6+6+7+8+6+7+4+6+7+8+7+9 = **81**
**Sum (PR-2 close)**: 80
**Δ from PR-3**: **+1**
**Weighted Δ**: 1/12 = **+0.083**

**Cumulative iter-1 weighted Δ**: PR-1 (+0.75) + PR-2 (+0.167) + PR-3 (+0.083) = **+1.000** → calibration target hit.

If Stage P.2 fires + dim 9 +0.5 happens: cumulative could push to **+1.04** (slight over-target).

## §8 Commit budget

- **T1 (informational)**: ~12-14 commits target
- **T2 (planning warning)**: > 14
- **T3-soft**: > 16 → §K STOP scope re-evaluation
- **T3-hard**: > 19 → §K STOP rescope

**Stage commit estimates (no conditional Q, conservative P)**:
- N: 6 commits (1 audit-doc + 5 production)
- O: 2 commits
- P: 2 commits (P.1 + P.3; no P.2)
- R: 3-4 commits (D30 + D31 + D33 closure + maybe D32 / K.7-refine)
- Phase 9: 1 commit (verification.md analog)

**Total estimate**: 14-15 commits.  Within T3-soft (16) by 1-2.

**With conditional Q + P.2**: + 2-5 commits → 16-20.  **Risks T3-soft / T3-hard** — if Q-PR3-2 = include AND P.1 surfaces a non-trivial gap, scope rebudget may be needed.

## §9 Stage execution order

**N.1 (triage doc) → N.2-N.5 (silent swallow fixes) → N.6 (annotate keeps) → O (ARCH-1.003) → P (share-token audit) → (Q if Q-PR3-2 = include) → R (audit-doc consolidation)**

Reasoning:
- **N.1 first**: triage doc informs N.2-N.6 scope; without it, fixes are guess-driven.
- **N.2-N.5 before N.6**: fix the silent swallows first; their try/except blocks become "(b) fixed" and are then naturally excluded from the (a)-annotation set in N.6.
- **N.6 before O**: closes Stage N as a coherent unit before moving to ARCH closure.
- **O before P**: O is small surgical fix (1 endpoint + 1 test extension); land it cleanly before Stage P's larger audit.
- **P after O**: Stage P uses `tests/test_endpoint_decorator_enforcement.py` (already extended in O.2 for vuln-id); P.3 builds on top with share-token extension — natural sequential build.
- **Q if included**: independent of N/O/P; can run anywhere after them.
- **R last**: ledger + code-audit updates need all preceding Stages' SHAs.

Phase 9 (`pr3-verification.md`) and Phase 10 (`PR-3 closure index` in ledger) follow R, then Phase 11 (push + PR + merge).

## §10 Followups (PR-3 will resolve / inherit)

**Resolved by PR-3 close**:
- FU-1.002 (vulnerabilities.py legacy `_assert_vuln_org` SDLC-001 extension) — Stage O.2
- FU-1.010 (`download_shared_sbom` ARCH-1.003 audit) — Stage P.1
- FU-1.011 (SDLC-001 share-token endpoint coverage) — Stage P.3
- CODE-1.011 (already partially closed in PR-1 D.3; Stage R notes historical closure)
- CODE-1.014 partial (silent swallows fixed + deliberate keeps annotated; translate-and-raise + typed-exc DEFERRED)

**Inherited unchanged from PR-2 followups**:
- FU-1.001 (Pydantic min/max validation tightening) — Q-PR3-2 default = defer to iter-2
- FU-1.003 (anti-corruption DTOs) — when 2nd consumer surfaces
- FU-1.004 (CycloneDX/SPDX exporters package) — iter-2
- FU-1.005 - FU-1.009 (Suppression invariants + ORM audit) — iter-2 with suppress-endpoint
- FU-1.013 (LOC delta forecast template) — second validation in PR-3 §4

**iter-2 candidate inheritance from PR-3**:
- Typed domain exceptions (`domain/exceptions.py` NEW module + ADR-0005) — explicitly deferred per (α)
- ~6 translate-and-raise sites (auth.py + others) — depends on typed exceptions infra
- (Possibly) FU-1.014 — share-token gap fix if Stage P.1 finds non-trivial issue and Q-PR3-3 = (b) split-into-FU
- ReleaseDetail.jsx frontend god-component (2087 LOC) — iter-2 entry candidate

## §11 §K invocation precision target + Open questions

**Pre-Phase-8 §K count for iter-1**: 10 (PR-1: 8, PR-2: 1 entry, PR-3 entry: 1 = D30 to be recorded in Stage R).

**PR-3 target**: ≤ 3 §K invocations during commit execution (relaxed from earlier ≤ 2; PR-2 hit 0-execution but was "easy mode" — Q-PR2 + K.7 codify resolved entry-stage ambiguity).  PR-3 still touches new surface area (broad-except triage + share-token audit) — allow margin.

If PR-3 hits 4+ §K during execution: K.7 effectiveness needs review.

**Open questions — RATIFIED 2026-05-02 by user**:

- **Q-PR3-1**: (i) — `# Deliberate broad-except: {reason}` canonical prefix (grep-able, no linter dep)
- **Q-PR3-2**: (b) — FU-1.001 deferred to iter-2 (Stage Q SKIPPED entirely)
- **Q-PR3-3**: conditional encoded in §3 Stage P.2 — surgical fix in PR-3 (≤30 LOC); architectural → spawn FU-1.014

Original question texts retained below for audit trail:


**Q-PR3-1 (Stage N triage methodology — inline comment pattern for deliberate keeps)**:
- (i) `# Deliberate broad-except: {reason}` (single canonical prefix, grep-able)
- (ii) `# noqa: BLE001` (relies on ruff/flake8 BLE rule even if linter not configured)
- (iii) freeform comment, no canonical prefix
- **Agent recommendation: (i)** — grep-able for future audits, doesn't depend on linter config, self-documenting.  AC-EXC-3 verification grep depends on this choice.

**Q-PR3-2 (FU-1.001 inclusion in PR-3)**:
- (a) include — minor character-merge ("defensive validation tightening" overlaps with error-handling mindset); cheap to do alongside Stage N
- (b) defer to iter-2 — character mismatch (schema-tightening ≠ error-handling); FU-1.001 promotion rule was "promote if iter-2 plan includes other deliberate evolutions"; PR-3 has 1 deliberate evolution (ARCH-1.003 vulnerabilities.py extension)
- **Agent recommendation: (b)** — character cleanliness over budget headroom; iter-2 plan can pick it up alongside frontend Pydantic-equivalent work.  Default = Stage Q SKIPPED.

**Q-PR3-3 (Share-token audit P.2 conditional)**:
- (a) fix in PR-3 if Stage P.1 audit finds gap — character aligned (ARCH closure is part of PR-3 Stage O); audit + fix in same PR cleaner
- (b) spawn FU-1.014 for PR-4 — keeps PR-3 budget tight; if gap is non-trivial, dedicated PR cleaner
- **Agent recommendation: depends on P.1 finding** — surgical (1-2 sites, ~30 LOC) → fix in PR-3; architectural (multiple endpoints, helper introduction) → spawn FU-1.014.  Plan §3 Stage P.2 encodes this conditional logic.

**Bonus codification candidates (NOT new Q questions; default = defer to Stage R or iter-2 entry)**:

- **K.7 commentary refine** — K.6's "10+ = plan too imprecise" threshold has been crossed by iter-1 (now 10 §K).  Refine: distinguish signal-§K (iter-1's all-10 caught real issues) vs noise-§K.  Default: defer codification to iter-2 entry.  Mention as observation in D31 commentary.
- **§F8 / K.8 — FU promotion-rule re-check at every PR-entry**.  Codification candidate from D31 (FU-1.010 slippage).  Default: defer codification to iter-2 entry.  Mention as observation in D31.

## §12 Plan precision retrospective (post-PR-3 close target)

At PR-3 Phase 9 verification, measure:
- Forecast LOC accuracy: actual PR-3 LOC vs forecast (per FU-1.013 second validation).
- §K invocation count: actual PR-3 execution §K count vs ≤ 3 target.
- Commit budget: actual production commit count vs 14-15 estimate.
- Maturity actual vs estimate (dim 5 +1 hit; cumulative weighted Δ +1.000 ± actual).

If all hit: iter-1 closes "true success" (calibration target +1.0 met exactly; iter-2 entry has clean slate).
If short: gap recorded, iter-2 inherits the shortfall as known debt.

---

**Plan generated 2026-05-02.  HEAD at plan-write time: `d92e679` (master, post-PR-2 merge).  PR-3 branch `refactor/iter-1-pr3-error-handling` created from this commit; not yet pushed to remote.  Awaiting user review + Q-PR3-1/2/3 ratification + Phase 8 commit execution authorization.**
