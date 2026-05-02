# ADR-0004: releases.py god-router decomposition strategy

## Status

Accepted 2026-04-30 (per Phase 7 plan §3); executed Stage D 2026-05-01;
validated Phase 9 2026-05-02; closed Phase 10 2026-05-02.

Iter-1 PR-1 closure record.  HEAD at decision-acceptance time: `17e0641`
(F.5-audit through G.2 inclusive).  This ADR lands in Phase 10 commit
`Phase-10.2`.

## Context

**Pre-PR-1 baseline**:
- `backend/app/api/releases.py` = **2,101 LOC**, **37 endpoints**, 4 inline
  helpers (`_SLA_DAYS`, `_is_suppressed`, `_sla_info`, `_assert_release_org`,
  `highest_severity`).  Single largest file in the backend.
- No domain layer — invariants (suppression, SLA, severity ordering) lived
  in router code, mixed with HTTP concerns + DB queries.
- 27 release-id endpoints used the legacy `_assert_release_org` ownership
  pattern returning 403 + zh-TW message `"無權存取此版本"` cross-org —
  a CWE-204 oracle leak (the 403 vs 404 distinction reveals to an attacker
  whether a release ID exists).

**Findings driving this decomposition**:
- ARCH-1.001 (`architecture-audit.md`): god-router pattern, no domain layer
  — the principal architectural finding of iter-1.
- ARCH-1.003 (`architecture-audit.md`): legacy 403 ownership pattern in 27
  release sites + 3 share.py admin endpoints — the principal security
  finding (and the *only* deliberate behavior change carried through PR-1).

**Calibration acceptance criteria** (from `calibration.md` §3.3):
- AC-A1: `releases.py` < 600 LOC after split
- AC-A2: ≥ 5 sub-modules emerge under `services/usecases/` (target 7)
- AC-A3: each sub-module has 1-line docstring
- AC-A4: no new file > 600 LOC
- AC-D1/D2/D3/D4: `domain/` package criteria (count ≥ 3, no framework
  imports, ≥ 1 invariant per class in `__post_init__`, routers no longer
  carry helpers)

**Constraints**:
- Behavior-equivalent decomposition for **all stages except D.8** (per
  ledger D11 — D.8 is the *one* deliberate contract evolution under D1
  lenient regime).
- No change to the public HTTP contract for the 36 non-evolved endpoints
  (verified by `test_releases_http_chars.py` characterization tests
  written in Stage A.3 *before* any move).
- `frontend/src/pages/ReleaseDetail.jsx` (2,087 LOC) untouched in PR-1
  — that's PR-2 / iter-2 territory.

## Decision

Adopt a **4-layer architecture** across `backend/app/`:

**Layer 1 — `backend/app/api/releases.py`** (45 LOC post-PR-1, 97.9% reduction)
- Becomes a UPLOAD_DIR-holder shell; the parent `router = APIRouter(prefix="/api/releases")`
  declaration remains for backwards-compatibility with imports but is no
  longer registered in `main.py` (per F.1 cleanup, commit `aa14009`).
- All 37 endpoints have moved out to layer 2.

**Layer 2 — `backend/app/services/usecases/release/`** (6 endpoint modules)
- `upload_sbom.py` (231 LOC) — POST `/sbom`
- `enrich.py` (318 LOC) — POST `/rescan`, `/enrich-epss`, `/enrich-ghsa`,
  `/enrich-nvd` (4 endpoints)
- `reports.py` (469 LOC) — GET `/report` and 10 other report/export endpoints
  (largest module; 78% of the 600-LOC cap)
- `signature.py` (142 LOC) — POST `/signature`, GET `/signature/verify`,
  DELETE `/signature` (3 endpoints; J5-security-carveout commit body)
- `scanners.py` (372 LOC) — POST `/upload-source`, `/scan-image`, `/scan-iac`,
  `/sbom-from-source`, `/sbom-from-binary` (5 endpoints)
- `lifecycle.py` (396 LOC) — GET `/`, PATCH `/version`, DELETE `/`, PATCH
  `/notes`, GET `/components`, `/vulnerabilities`, `/vulnerabilities/export`,
  `/compliance`, POST `/lock`, `/unlock`, GET `/patch-stats`, `/gate`,
  `/dependency-graph` (13 endpoints)

Each module is registered as its own `APIRouter` with the same `/api/releases`
prefix; FastAPI merges paths transparently.

**Layer 3 — `backend/app/domain/`** (4 modules, 203 LOC total)
- `severity.py` (43 LOC) — `SEVERITY_ORDER` canonical mapping +
  `highest_severity(vulns)` helper.  INV-D1 invariant enforced via call-site
  warning (`SEVERITY_ORDER.get(sev, -1)` not `0` — see ledger D14).
- `sla.py` (42 LOC) — `SLA_DAYS` mapping + `sla_info(vuln)` predicate.
- `suppression.py` (96 LOC) — `Suppression` value object + `is_suppressed(vuln)`
  predicate.  3 invariants enforced in `__post_init__` (past-naive-until
  rejected; inconsistent state rejected; naive datetime coerced to UTC).
- `vex.py` (9 LOC) — namespace placeholder for full VEX state-machine
  extraction in iter-2 (current location: `backend/app/api/vulnerabilities.py`
  PATCH handlers).

Per AC-D2: zero framework imports across all 4 modules (verified by
`grep -rn "from fastapi\|from sqlalchemy\|from app.api" backend/app/domain/`
returning 0 matches).

**Layer 4 — `backend/app/schemas/`** (2 new + pre-existing)
- `schemas/release_lifecycle.py` (50 LOC) — `ReleaseVersionUpdate` +
  `ReleaseNotesUpdate` typed bodies for PATCH `/version` + `/notes` (added
  in E.2 per Q-P7-3 behavior-equivalence rule).
- `schemas/share_link.py` (19 LOC) — `ShareLinkCreate` extracted from
  inline `BaseModel` in `share.py` (E.1).

**Decomposition strategy** — Stage D, 8 commits:

| Commit | SHA | Description |
|--------|-----|-------------|
| D.1 | `7386b7f` | Skeleton: create `usecases/release/` package + register 6 sub-routers (initially empty) |
| D.2 | `0bcbc47` | Move `upload_sbom` + extract 6 helpers |
| D.3 | `e811bb2` | Move enrich endpoints + helpers; bundled CODE-1.009 / CODE-1.016 / ARCH-1.013 fixes |
| D.4 | `20e42cf` | Move 11 report endpoints to `reports.py` |
| D.5 | `4cedc08` | Move signature endpoints (J5-security-carveout commit body) |
| D.6 | `9e56829` | Move 5 scanner endpoints + `_import_syft_cdx` helper |
| D.7 | `f8e190f` | Move 13 lifecycle endpoints; `releases.py` 522 → 95 LOC |
| D.8 | `c3ac0a1` | ARCH-1.003 contract evolution: 27 endpoint sites flipped 403→404 atomically; legacy `_assert_release_org` helper deleted (J5-security-carveout commit body) |

Plus F-stage cleanup commits:

| Commit | SHA | Description |
|--------|-----|-------------|
| F.1 | `aa14009` | Drop 65 dead imports + dead `releases.router` registration |
| F.2 | `61e4265` | Drop 6 dead imports in `share.py` (3 PR-1-caused + 3 pre-existing) |

And the AC-T2 remediation:

| Commit | SHA | Description |
|--------|-----|-------------|
| G.1 | `b9dbf19` | 10 characterization tests (Set 5 of `test_releases_http_chars.py`); pushed coverage 26% → 36% |

## Consequences

**Positive (tied to maturity dim hits per `verification.md` §2)**:
- **Dim 1 Architecture +1** (target +2 missed conservatively per Phase 9 review:
  `lifecycle.py` 13 endpoints in one file + `reports.py` 469 LOC are not
  grokkable in 30s; module sizes within cap but module-internal density mid).
- **Dim 2 Domain purity +3** (target hit fully — `domain/` has 0 framework
  imports per AC-D2; Suppression value object enforces 3 invariants per AC-D3).
- **Dim 4 Readability density +1** (smaller files; each usecase module has
  named single-responsibility docstring per AC-A3).
- **Dim 9 API design +1** (schema centralization in `schemas/`; ARCH-1.003
  contract evolution unifies 27 endpoints to canonical 404).
- **ARCH-1.003 closure**: 27 release sites + 3 share.py admin endpoints
  unified to `Depends(require_release_in_scope)` 404 oracle prevention pattern.
  Verified by HARD LOCK 2.A grep (`_assert_release_org` = 0 matches across
  `backend/`) and HARD LOCK 2.B grep (`無權存取此版本` = 0 matches).
- **Test coverage gain**: 0% → 36% on usecases + domain post-G.1 (AC-T2 PASS
  with 6-percentage-point margin).
- **D17 strict improvement**: `_active_enrichments` race window in `enrich_ghsa`
  eliminated as side-effect of `Depends(require_release_in_scope)` migration.

**Negative (tied to maturity dim misses)**:
- **Module-internal density**: `lifecycle.py` 13 endpoints in one module —
  the largest functional bundle.  An honest reviewer would want this further
  split (e.g. into `lifecycle.py` + `lifecycle_admin.py` + `lifecycle_query.py`),
  but no such split was in plan §3 scope.  Dim 1 +1 vs target +2 reflects this.
- **`reports.py` 469 LOC** = 78% of the 600-LOC cap.  Within bounds but the
  closest-to-cap file in PR-1.  An iter-2 candidate for further splitting
  (e.g. `reports_compliance.py` + `reports_export.py` + `reports_quality.py`).
- **6 modules vs target 7** (acceptable per AC-A2 ≥ 5 minimum but visible
  miss vs the stretch target in plan §3).
- **§K STOP triggered 6 times during iter-1** — signals plan precision room
  for improvement, though all 6 invocations correctly blocked an instruction
  that would have fixed an error in production-commit form (see ledger D11
  context, D17, D19, D20, D21, D23).
- **D16 budget T3-soft tripped 1 time** (D22, AC-T2 remediation).  First
  T-trigger trip in iter-1.
- **LOC growth +13.1%** on `backend/*.py` (decomposition + test additions
  decomposed in D20: ~1,097 LOC tests + ~452 LOC module skeleton overhead +
  schemas + balance).

**Neutral (carried forward)**:
- **13 followups** (FU-1.001..013) recorded in `refactor-plan.md` §10 for
  iter-2 / PR-2 promotion.
- **ARCH-1.003 partial**: `vulnerabilities.py` still has 1 legacy
  `_assert_vuln_org` caller (FU-1.002).  D11 standing accepts this as
  iter-2 cleanup scope.
- **VEX state placeholder** in `domain/vex.py` (9 LOC, "Iter-1 placeholder
  only" docstring) — full extraction is iter-2 candidate.
- **Maturity weighted Δ +0.75** (target +1.0) — partial success per
  calibration §3.4.  Honest record, not a merge blocker.

## Alternatives considered

**(A) Single big atomic commit for D.1-D.8**
- *Rejected* per ledger D7 (J2 multi-commit-per-PR exception for god-router
  splits).  An 8-stage atomic commit would be impossible to review and
  impossible to bisect for regressions.  Linux kernel patch-series practice
  is the reference precedent.

**(B) Split `releases.py` purely by HTTP method (GET / POST / DELETE buckets)**
- *Rejected*.  Semantic grouping by use-case (upload / enrich / reports /
  signature / scanners / lifecycle) is more grokkable for future contributors
  reading `services/usecases/release/`.  Method-based split would scatter
  related operations (e.g. `POST /lock` + `POST /unlock` + `GET /` would be
  in different files despite operating on the same lifecycle concept).

**(C) Use-case grouping with 6 modules — ADOPTED**
- The chosen path.  Each module name matches a clear responsibility ("what
  does this endpoint do *for the user*").  Module count (6) hits AC-A2 ≥ 5
  with one-short of the stretch target 7 — reasonable balance between
  granularity and not-over-fragmenting.

**(D) Maximum granularity — one file per endpoint (37 modules)**
- *Rejected* per AR-1 (no over-abstraction red line in `code-principles.md`).
  37 files for 37 endpoints would optimize for the wrong axis (endpoint
  isolation vs use-case cohesion); the 80-line average wouldn't add clarity
  beyond what 6 well-named modules already give.  Also would violate the
  spirit of AR-2 (depth limit on layering — 37 modules would force a
  navigation index of its own).

**(E) Split into more granular modules (7 or 8 instead of 6)**
- *Considered for `lifecycle.py`* — could become `lifecycle_state.py` (lock
  / unlock / version / notes) + `lifecycle_query.py` (get / components /
  vulns / compliance / patch-stats / gate / dep-graph) for an 7th module.
  *Deferred to iter-2*.  Plan §3 budget locked at 6 modules; further split
  is a refactor of a refactor and was rejected per J4 (Tidy First — don't
  start the next refactor before closing this one).

## Implementation references

- ledger D7 — Phase-8 commit discipline relaxed to multi-commit-per-PR for
  god-router splits (the rule that authorized D.1-D.8)
- ledger D11 — ARCH-1.003 evolution recorded as the sole deliberate contract
  evolution under D1 lenient regime
- ledger D14 — INV-D1 SEVERITY_ORDER -1 default invariant codified across
  3 places (the `domain/severity.py` warning is an artifact of this decision)
- ledger D17 — D.8 incidental side-effect change (race window improvement)
- ledger D18 — F-stage review-fix sweep (F.1 + F.2 dead-code cleanup)
- ledger D20 — Phase 8 closure sanity-sweep findings (commit partition +
  LOC growth) + D16 revision
- ledger D21 — §K invocation #5 (Phase 9 AC-T2 fail discovery)
- ledger D22 — T3-soft trigger acceptance for AC-T2 remediation
- ledger D23 — §K invocation #6 (Phase 10 ADR 0003 file-name correction)
- Stage D commits: `7386b7f` (D.1) / `0bcbc47` (D.2) / `e811bb2` (D.3) /
  `20e42cf` (D.4) / `4cedc08` (D.5) / `9e56829` (D.6) / `f8e190f` (D.7) /
  `c3ac0a1` (D.8)
- F-stage commits: `aa14009` (F.1) / `61e4265` (F.2) / `6f03f9f` (F.3
  audit-doc) / `55e53d8` (F.4-audit) / `e0c3008` (F.5-audit)
- G-stage commits: `b9dbf19` (G.1 AC-T2 remediation) / `17e0641` (G.2
  audit-doc)
- Phase 9 commit: `15ad717`
- `verification.md` §1-§5 — acceptance criteria + maturity + recommendation
  for the entire decomposition
- `code-principles.md` §J1-J6.5 / §K + K.6 — commit + STOP discipline that
  governed the execution
- `architecture.md` §4.4 (AR-1/2/3 no-over-abstraction red lines) +
  §4.5 (Wave-D contract alignment WD-1/2/3/4 — applies to the
  scanners/reachability sister-package, not directly to releases.py split,
  but the same plan landed both)

## References

- ARCH-1.001 (`architecture-audit.md`) — god-router finding, P0 severity
- ARCH-1.003 (`architecture-audit.md`) — legacy 403 ownership pattern, P0
  security severity
- code-audit findings CODE-1.009, CODE-1.011, CODE-1.016, CODE-1.020 —
  bundled cleanups during Stage D commits
- `code-principles.md` §J5 (security carve-out) + J5-footnote (4-surface
  diff body) — the discipline that wrapped D.5 + D.8 commit bodies
- `code-principles.md` §AR-1/2/3 — no-over-abstraction red lines that
  bounded module count to 6 (rejected alternative D)
