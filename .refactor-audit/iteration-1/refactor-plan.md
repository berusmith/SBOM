---
iteration: 1
phase: 7 — Refactor Plan
date: 2026-04-29
status: awaiting user "go" before Phase 8 execution
applies_to_findings: ARCH-1.001/002/003/005/009/010/013, CODE-1.001/002/003/004/006/008/011/012/013/014/016/017/020/021/027/028, PERF-1.001/005/007/008
---

# Iteration 1 — Refactor Plan

> Encodes the 5 review corrections from user 2026-04-29:
> - **R1**: 3 PRs not 1 (J2 narrowed to god-router split only)
> - **R2**: three-point time estimate + pessimistic trigger
> - **R3**: ARCH-1.003 carved out as deliberate **contract evolution** sub-section, not refactor
> - **R4**: explicit commit-level dependency DAG + per-stage revertibility + PR-level fallback
> - **R5**: §0 Pre-flight checklist before any commit

---

## §0 Pre-flight checklist

> All boxes must be checked before the first Phase-8 commit. If any box fails, **STOP and consult**, do not proceed.

```
[ ] 0.1 backend/requirements-dev.txt created with:
        pytest==8.3.3
        pytest-cov==5.0.0   # optional but already approved by F7
        # hypothesis omitted — only add if a finding actually needs property-based tests

[ ] 0.2 `cd backend && python -m pip install -r requirements-dev.txt` exits 0

[ ] 0.3 `pytest --version` reports 8.3.x (sanity)

[ ] 0.4 `git status` shows working tree clean
[ ] 0.5 `git fetch origin && git status` shows master at the same SHA as origin/master
        (if behind/ahead, sync first — do not start refactor on diverged branch)

[ ] 0.6 Backend baseline green:
        - Start backend: `cd backend && python -m uvicorn app.main:app --port 9100`
          (in a separate terminal; needs DEBUG=true OR a strong .env)
        - In another terminal: `python test_all.py`
        - Expected: 54/54 pass
        - If any test red: fix BEFORE starting (out of refactor-audit scope but blocks Phase 8 — write a "tidy:" or "fix:" commit on master first)

[ ] 0.7 `git checkout -b refactor/iter-1-god-router-split` from up-to-date master
        (confirm: `git rev-parse --abbrev-ref HEAD` reports the new branch name)

[ ] 0.8 Wave D GitHub issue status confirmed:
        - If NOT yet opened: refactor-audit's PR-1 lands first, then file Wave D issue per
          NEXT_TASK.md guidance.  Required by architecture.md §4.5 WD-1 (interface freeze
          must precede Wave D sprint #3).
        - If ALREADY opened with sprint #3 in flight: STOP — coordinate with Wave D before
          starting; the freeze contract changes meaning.

[ ] 0.9 sbom.db at repo root:
        - Status confirmed (per known-debt.md "Investigated, not debt"): stale local
          artifact, gitignored, contains 1 admin row.  Either clean
          (`rm sbom.db sbom.db-shm sbom.db-wal` if present) or leave — does not block.

[ ] 0.10 Open editor / IDE preference recorded — refactor will produce ~28 commits over
         multiple sessions; long-running branch life expected.  Confirm you have time
         for 6–10 working days (per §2 estimate).
```

---

## §1 Plan structure overview

3 sequential PRs, ~28 commits total. Each PR opens only after the prior is merged.

| PR | Scope | Commit discipline | ~Commits | Stages |
|----|---|---|---:|---|
| **PR-1** | God-router split + safety net + domain extraction + Wave-D-aligned reachability package + schema centralisation for touched routes + ARCH-1.003 contract evolution | **J2** (multi-commit per PR — qualifies as god-router decomposition; per code-principles.md §J2) | ~18–20 | A → B → C → D → E |
| **PR-2** | 4 perf wins (PERF-1.001/005/007/008) + 1 bug fix (CODE-1.013 CSAF namespace) | **J1** (one-finding-per-commit) | 5 | F |
| **PR-3** | Tidy + 2 ADRs | **J1** | 3–5 | G |

**Sequencing rationale**: PR-1's safety net (Stage A) is the only blocker for the rest. PR-2's perf wins do not depend on the god-router being split (PERF-1.001 touches stats.py, PERF-1.005 touches main.py lifespan, PERF-1.008 touches vuln_scanner.py — none collide with PR-1). But by sequencing PR-2 after PR-1, we avoid merge-conflict pain on shared imports and keep review focus narrow.

**Why not parallel PRs?**: per user R1 — independent review, no review-context contamination. Sequential keeps each PR's diff minimal and reviewable.

---

## §2 Time estimate (three-point + pessimistic trigger)

| Path | Days | Conditions |
|---|---:|---|
| **Optimistic** | 3 | Characterization tests for all 9 helpers + 37 endpoints land in ~1 day; releases.py split + domain extraction land in ~1 day with no surprises; stages F + G land same day; all PRs reviewed and merged within 24h each |
| **Realistic** | 6 | Stage A takes ~1.5 days (test infra + 50–80 tests); Stage B + C ~1 day; Stage D ~2 days (the actual god-router split); Stage E ~0.5 day; Stage F ~0.5 day; Stage G ~0.5 day. Includes 0.5–1 day of debug for surprises (test fixture data shape mismatches, import cycles surfaced by domain extraction) |
| **Pessimistic** | 10 | Characterization tests reveal hidden behavior coupling (e.g. an endpoint depended on a side effect we didn't capture); domain extraction surfaces a cross-cutting invariant we hadn't seen; multi-day debugging on one of D.2–D.7 |

### Pessimistic triggers — when to cut scope and recover

| Trigger | When fires | Action |
|---|---|---|
| **T1** | Characterization tests still red on Day 3 (Stage A not done) | **Cut PR-1 scope to A–D**. Stage E (schema centralisation) deferred; opens as PR-2 prerequisite. PR-1 closes at D.8. |
| **T2** | Stage D mid-split breaks a `test_all.py` test we cannot fix in 2h | **Revert latest D.N commit**, resume from previous green. If 2nd D.N fails the same way, **stop and re-plan** Stage D. |
| **T3-soft** | Day 7 reached, PR-1 not on track to finish by Day 9 | **Soft checkpoint** (per user iter-1 review): evaluate remaining stages; if estimated remaining work > 5 working days, trigger T1 immediately (cut scope to A–D, Stage E deferred to PR-2 prerequisite). Otherwise continue toward Day 9. Day-7 is NOT a hard stop — that would compress pessimistic 10d into realistic 6d and violate the three-point estimate. |
| **T3-hard** | Day 9 reached, PR-1 still unfinished | **Hard stop on PR-1**. Land what's done; defer rest to iter-2. Update ledger with partial-success outcome (per `calibration.md` §3.4 composite outcome rules). See "Partial-success minimum scope" below. |
| **T4** | A discovered bug requires changing a public API contract not in §3.9 evolution | **STOP**. Open a separate decision: continue with strict equivalence (paper over the bug) OR add to §3.9 evolution list. Do NOT silently change behavior. |

### Partial-success minimum scope (T3-hard)

Per user iter-1 review: if T3-hard fires, PR-1 only counts as "partial success" (per `calibration.md` §3.4 — weighted Δ in [+0.5, +0.8)) if **all of the following are landed**:
- **Stage A complete** — pytest infra + characterization tests for all 9 helpers + ≥ 50% of HTTP characterization for the 37 endpoints
- **Stage B complete** — `domain/` package with Suppression/SLA/Severity moved
- **Stage C complete** — `services/scanners/reachability/` package + Wave-D contract block in `__init__.py`
- **Stage D minimum** — D.1 (skeleton) + D.2 (upload_sbom moved) + D.3 (enrich endpoints moved). The remaining D.4–D.8 + Stage E are deferred to iter-2 PR.

If any of A / B / C / D.1-D.3 is incomplete at T3-hard, PR-1 is **fail** (per §3.4: weighted Δ < +0.5), triggers retrospective per `calibration.md` §3.4 before iter-2 plan.

The Wave-D contract block (Stage C.1) is mandatory under partial-success because it's the interface freeze for `architecture.md` §4.5 WD-2; iter-2 (or Wave D itself) should not have to invent it later.

---

## §3 PR-1 — God-router split (J2 multi-commit)

### §3.1 Stage overview

| Stage | Commits | Effort | Reverts cleanly | J5 carve-out |
|---|---:|---|:-:|:-:|
| A — Safety net | 3 | M | Yes (additive) | No |
| B — Domain extraction | 4 | M | Per-commit, but B.2 is atomic across releases.py + stats.py | No |
| C — Reachability package | 2 | S | C.1+C.2 atomic if both land; C.1 alone leaves shim | No |
| D — releases.py split | 7 (D.1–D.7) + 1 (D.8 = §3.9 evolution) | L | Per-commit revertable | D.5 + D.8 (each = single commit, per-commit security review) |
| E — Schema centralisation (touched routes only) | 2 | S | Per-commit revertable | No |
| **Total PR-1** | **~19** | | | |

### §3.2 Commit-level dependency DAG

```
A.1 (pytest infra)
  ├── A.2 (function-level char tests)
  └── A.3 (HTTP char tests for 37 endpoints)
        │
B.1 (domain/ skeleton)  ◄──── A.1
  └── B.2 (move helpers — releases.py + stats.py)  ◄──── A.2 + B.1
        ├── B.3 (collapse _SLA_DAYS + SEVERITY_ORDER)  ◄──── B.2
        └── B.4 (Suppression __post_init__ invariants)  ◄──── B.1 + A.2
              │
C.1 (git mv reachability.py → package + shim)  ◄──── A.3 (covers integration smoke)
  └── C.2 (integration.py dispatcher + import update in releases.py)  ◄──── C.1
        │
D.1 (services/usecases/release/ package skeleton)  ◄──── A.3
  ├── D.2 (move upload_sbom)  ◄──── D.1 + B.2 (uses domain helpers)
  │     └── D.3 (move enrich endpoints)  ◄──── D.1 + D.2 (shares helper imports)
  ├── D.4 (move PDF / CSAF / evidence + extracted template)  ◄──── D.1
  ├── D.5 (move signature endpoints — J5 single commit)  ◄──── D.1
  ├── D.6 (move scanner endpoints)  ◄──── D.1 + C.2 (uses reachability package)
  ├── D.7 (move lifecycle / lock / list)  ◄──── D.1 + B.2
  └── D.8 (§3.9 ARCH-1.003 contract evolution — J5 single commit)  ◄──── D.2..D.7 ALL done
        │
E.1 (extract inline BaseModel → schemas/release_*.py for moved routes)  ◄──── D.2..D.7 done
  └── E.2 (typed bodies for update_version + update_notes)  ◄──── E.1
```

**Critical path** (longest dependency chain):
A.1 → A.2 → B.1 → B.2 → D.2 → D.3 → D.8 → E.1 → E.2  =  **9 sequential commits**

Stages B / C / D-mid can interleave on parallel workdays if multiple sessions per day, but the critical path imposes a floor on calendar time.

### §3.3 Per-commit revertibility table

| Commit | Revert mechanism | Affects others if reverted |
|---|---|---|
| A.1 | `git revert` — pure additive (new files) | Nothing breaks; A.2/A.3 fail to run after revert (acceptable mid-PR) |
| A.2 | `git revert` — pure additive | Nothing |
| A.3 | `git revert` — pure additive | Nothing |
| B.1 | `git revert` — pure additive | B.2/B.3/B.4 import errors after revert |
| B.2 | `git revert` — atomic across `releases.py` + `stats.py` (helper move + caller updates in same commit) | B.3 unaffected; D.2/D.3/D.7 import errors after revert |
| B.3 | `git revert` — atomic | None |
| B.4 | `git revert` — pure additive | None |
| C.1 | `git revert` — restores `services/reachability.py`, removes new package | C.2 import error after revert |
| C.2 | `git revert` — restores old import path in releases.py, removes integration.py | None unless D.6 already shipped (D.6 imports through new path) |
| D.1 | `git revert` — pure additive (empty package + main.py include line) | D.2..D.8 fail to register routes |
| D.2 | `git revert` — atomic (delete from releases.py + add to upload_sbom.py in same commit) | E.1 import error after revert |
| D.3..D.7 | Same pattern as D.2, each independently revertable | E.1 import error per affected route |
| D.5 | **J5 carve-out** — single commit, full security re-review on revert | Same as D.2 |
| **D.8** | **J5 carve-out + EVOLUTION** — see §3.9 | Reverting reverts the contract evolution; status codes flip back to 403 on those 30 sites |
| E.1 | `git revert` — restores inline BaseModel in moved modules | None |
| E.2 | `git revert` — restores `body: dict` on update_version/update_notes | Frontend would break IF E.2 also updated frontend caller (it doesn't — body shape was already JSON) |

### §3.4 PR-level fallback strategy

> **Fallback is `git revert`, not `git reset --hard`** — for these reasons:
> 1. Force-push to master is forbidden by team safety policy (already implicit per the harness's "never force push to main/master")
> 2. Preserves history of the attempt; future iter-2 can read why iter-1 was reverted
> 3. The negation commit is itself a record of what failed
> 4. Audit/compliance lanes can trace the rollback through git log

**Pre-merge fallback** (PR open, mid-construction):
- Bad commit not yet pushed: `git reset --hard HEAD~1` then re-attempt
- Bad commit pushed to PR branch: `git revert HEAD && git push` (preserves PR commit history)
- Whole stage going wrong: `git revert <stage-start-sha>..<HEAD>` — series revert, preserves history
- Whole PR off-track: close PR without merge; discard branch; restart from §0

**Post-merge fallback** (PR-1 merged, regression discovered):
- Single commit suspected: `git revert <bad-sha> && git push origin master` — per-commit revert
- Whole PR regression: `git revert -m 1 <merge-commit-sha> && git push origin master` — reverts the full merge as one commit
- This is **the standard Linux-kernel pattern**: never rewrite shared history; negate via revert

**Trigger for post-merge fallback**:
- `test_all.py` red on master after PR-1 merge → revert the merge within 2 hours
- Production behavior diff observed (any 5xx spike, any audit-row missing) → revert immediately
- Wave D PR opened against the new interface and discovered the contract is wrong → coordinate before reverting (Wave D may need the change)

**Single-reviewer mode acknowledged** (per user Q-P7-5 iter-1, 2026-04-29): no second reviewer is available for this iter. J2 multi-commit risk is **accepted** via the per-commit revertibility table (§3.3) + the post-merge revert SLA above as the sole safety net. This acknowledgement is the explicit risk acceptance — should a second reviewer become available in a future iter, J2 commits may add a "second-reviewer signed off" field to commit bodies as additional defense.

---

### §3.5 Stage A — Safety net (~3 commits)

#### A.1 — `tidy:` introduce pytest dev-only infrastructure
```
files added:
  backend/requirements-dev.txt        # pytest==8.3.3, pytest-cov==5.0.0
  backend/pytest.ini                  # testpaths = tests/unit; -ra; --strict-markers
  backend/tests/unit/__init__.py
  backend/tests/unit/conftest.py      # FastAPI TestClient fixture, in-memory DB fixture

commit message:
  tidy(test): add pytest dev-only infrastructure

  - backend/requirements-dev.txt — pytest + pytest-cov, separate from runtime
    requirements.txt; License Path B unaffected (not bundled at deploy)
  - backend/pytest.ini — strict markers, testpaths under tests/unit
  - backend/tests/unit/conftest.py — in-process FastAPI TestClient + sqlite
    :memory: session fixture for per-test isolation

  Per .refactor-audit/iteration-1/calibration.md §3.3 AC-T1: function-level
  characterization tests for the helpers about to be moved in PR-1 stages B–D.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

#### A.2 — `test:` function-level characterization tests for movable helpers
```
files added:
  backend/tests/unit/test_suppression.py     # _is_suppressed boundary cases
  backend/tests/unit/test_sla.py             # _sla_info × 4 severities × 4 statuses
  backend/tests/unit/test_severity.py        # _highest_severity edge cases
  backend/tests/unit/test_webhook_validation.py  # _validate_webhook_url SSRF guard
  backend/tests/unit/test_osv_parser.py      # _parse_vuln + _numeric_to_severity

target test count: 30–40 tests, all parametrized
target runtime: < 2 seconds
target coverage on moved-helper code: ≥ 80%

commit message:
  test(unit): function-level characterization tests for refactor safety

  Tests for the helpers that will move during PR-1 stages B–D:
  - _is_suppressed (releases.py:64) — null suppressed_until, future, past, naive vs aware
  - _sla_info (releases.py:75) — every (severity, status) cell + suppressed branch
  - _highest_severity (releases.py:2098) — empty, single, multi, info-only
  - _validate_webhook_url (alerts.py:19) — SSRF cases per audit baseline §II.6
  - _parse_vuln (vuln_scanner.py:59) — CVSS text fallback + v4 vector extraction

  Per AC-T1 (calibration.md §3.3): function-level tests must be ≥ 1/3 of new
  tests for Test quality dim to score 6 (vs HTTP-shape dominant = 5).

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

#### A.3 — `test:` HTTP characterization tests for releases.py 37 endpoints
```
files added:
  backend/tests/unit/test_releases_http_chars.py  # parametrize per endpoint

each endpoint covered with:
  - happy path (typical input → 2xx + response shape snapshot)
  - cross-org (404 expected — captures pre-evolution 403 for D.8 baseline)
  - locked release (409)
  - missing release (404)
  - missing required field (422)

target test count: ~75 (37 endpoints × ~2 cases each)
target runtime: < 5 seconds (TestClient is in-process)

commit message:
  test(http): characterization snapshots for releases.py 37 endpoints

  Captures the current HTTP contract before PR-1 Stages D–E refactor.
  Each endpoint:
  - Asserts exact response status code
  - Asserts response JSON shape (top-level keys; types of values; not byte-equal,
    to allow timestamps to vary between runs)
  - Records cross-org behavior (403 today; will flip to 404 in D.8 evolution)

  D.8 commit will UPDATE the cross-org assertions from 403 to 404 in the same
  commit that flips the production behavior — this is the labeled evolution
  (§3.9 of refactor-plan.md).

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

### §3.6 Stage B — Domain extraction (~4 commits)

#### B.1 — `tidy:` create `domain/` package
```
files added:
  backend/app/domain/__init__.py
  backend/app/domain/suppression.py    # placeholder; imports nothing yet
  backend/app/domain/sla.py
  backend/app/domain/severity.py
  backend/app/domain/vex.py
```

#### B.2 — `refactor:` move helpers (atomic across releases.py + stats.py)
```
moves:
  releases.py:_is_suppressed     → domain/suppression.py:is_suppressed
  releases.py:_sla_info          → domain/sla.py:sla_info  + SLAStatus enum
  releases.py:_highest_severity  → domain/severity.py:highest_severity
  releases.py:_SLA_DAYS          → domain/sla.py:SLA_DAYS
  stats.py:_SLA_DAYS             → REMOVED, import from domain/sla
update call sites:
  releases.py × ~6 sites (gate, list_vulnerabilities, _sla_info usages)
  stats.py × 1 site
no behavior change (helpers are bit-identical)
```

#### B.3 — `tidy:` collapse SEVERITY_ORDER
```
moves:
  core/constants.py:SEVERITY_ORDER  → domain/severity.py:SEVERITY_ORDER
  alerts.py:_SEV_ORDER              → REMOVED, import from domain/severity
canonical scale chosen: critical=4, high=3, medium=2, low=1, info=0
                       (matches existing core/constants.py — alerts.py adapter pattern preserved)
```

#### B.4 — `refactor:` add Suppression value object with __post_init__ invariants
```
new in domain/suppression.py:

  @dataclass(frozen=True)
  class Suppression:
      suppressed: bool
      suppressed_until: datetime | None = None
      reason: str | None = None
      def __post_init__(self):
          if self.suppressed_until is not None and self.suppressed_until.tzinfo is None:
              raise ValueError("suppressed_until must be timezone-aware")

  def is_suppressed(suppression: Suppression, now: datetime | None = None) -> bool:
      ...

is_suppressed adapter for ORM Vulnerability stays alongside (drop-in for callers).
This is the AC-D3 invariant requirement.
```

### §3.7 Stage C — Reachability package (~2 commits)

#### C.1 — `tidy:` rename + relocate `reachability.py` to package
```
git mv:
  backend/app/services/reachability.py
  → backend/app/services/scanners/reachability/python_analyzer.py

new files:
  backend/app/services/scanners/__init__.py        # empty
  backend/app/services/scanners/reachability/__init__.py  # re-exports scan_zip + classify_vulns

# Wave-D contract block at top of __init__.py per architecture.md §4.5 WD-3
__init__.py contents:

  """
  # Wave-D contract (frozen at iter-1 PR-1 merge, do not modify in Wave D sprint #3)
  #
  #   scan_zip(zip_bytes: bytes) -> ScanResult
  #     pre: zip_bytes is a valid ZIP archive ≤ 50MB
  #     post: returns ScanResult(presence: PackagePresence, ast_reachable: set[str])
  #
  #   classify_vulns(vulns, scan_result, comp_map) -> dict[str, str]
  #     pre: vulns is iterable of Vulnerability rows; comp_map is {id: Component}
  #     post: returns {vuln_id: label} where label ∈
  #       {function_reachable, reachable, test_only, not_found, unknown}
  #
  # Wave D may add new analyzer modules (js_analyzer.py, java_analyzer.py) and
  # extend integration.py to dispatch by language; it must NOT change the
  # signatures above.
  """
  from .python_analyzer import scan_zip, classify_vulns, ScanResult, PackagePresence
  __all__ = ["scan_zip", "classify_vulns", "ScanResult", "PackagePresence"]
```

#### C.2 — `refactor:` add integration.py dispatcher + update releases.py import
```
new file:
  backend/app/services/scanners/reachability/integration.py
    # Today: just delegates to python_analyzer
    # Wave D will replace this body with language-aware dispatch

releases.py update:
  - from app.services.reachability import scan_zip as _scan_zip, classify_vulns as _classify_vulns
  + from app.services.scanners.reachability import scan_zip as _scan_zip, classify_vulns as _classify_vulns
```

### §3.8 Stage D — releases.py split (~7 commits + D.8 in §3.9)

For each D.N (N = 2..7):
- Create `backend/app/services/usecases/release/<concern>.py` containing the moved router endpoints + helpers
- Delete those endpoints' definitions from `backend/app/api/releases.py`
- Update `backend/app/main.py` to also `app.include_router(usecases.<concern>.router)` — same auth middleware applied
- Run characterization tests (Stage A.3) — must stay green

#### D.1 — `tidy:` create usecases/ package skeleton
```
files added:
  backend/app/services/usecases/__init__.py
  backend/app/services/usecases/release/__init__.py
  backend/app/services/usecases/release/upload_sbom.py    # empty router
  backend/app/services/usecases/release/enrich.py
  backend/app/services/usecases/release/reports.py
  backend/app/services/usecases/release/signature.py
  backend/app/services/usecases/release/scanners.py
  backend/app/services/usecases/release/lifecycle.py

main.py:
  + app.include_router(usecases.release.upload_sbom.router, dependencies=_auth)
  + ... (one per sub-module)
```

#### D.2 — `refactor:` move upload_sbom + helpers
```
moves to usecases/release/upload_sbom.py:
  - upload_sbom endpoint (releases.py:178-319)
  - extracted helpers: _validate_and_parse, _save_to_disk, _score_quality_safe,
    _snapshot_previous, _replace_components, _scan_and_persist, _enrich_all,
    _compute_diff (per CODE-1.001 plan)
  - _enrichment_lock + _active_enrichments stay in releases.py for now
    (used by enrich endpoints — moves in D.3)

scope cleanup:
  - upload_sbom now < 30 LOC, calling 8 helpers (per CODE-1.001 recommendation)
  - quality grade silent-swallow becomes logger.exception (CODE-1.011 fix bundled)
  - _is_suppressed call site updated to use domain.suppression.is_suppressed
```

#### D.3 — `refactor:` move enrich endpoints + _enrich_kev/_enrich_epss/_enrich_ghsa
```
moves to usecases/release/enrich.py:
  - enrich_epss, enrich_nvd, enrich_ghsa endpoints
  - _enrich_kev, _enrich_epss, _enrich_ghsa helpers
  - rescan_vulnerabilities (with CODE-1.009 simplification — fix the "tricky"
    new-vuln detection by tracking newly_added list directly)
  - _enrichment_lock + _active_enrichments registry move here
  - _enrich_ghsa drops the unused `new_count` return (CODE-1.016)

audit:
  - audit.record(...) calls preserved verbatim
  - alerts payload identity preserved (per invariants.md §I.4)
```

#### D.4 — `refactor:` move PDF/CSAF/evidence endpoints + extracted template
```
moves to usecases/release/reports.py:
  - download_report, download_iec62443_report, download_iec62443_42_report,
    download_iec62443_33_report, download_nis2_report (5 endpoints)
  - download_evidence_package
  - export_csaf
  - export_cyclonedx_xml
  - export_spdx_json
  - sbom_quality
  - integrity

extractions (CODE-1.003 + CODE-1.002 + CODE-1.004):
  - _render_compliance_pdf(release_id, generator_fn, *, include_brand=False,
    include_cra_incidents=False, filename_prefix="...") template
  - build_csaf_doc(release, components, vulns) → reused by export_csaf AND
    download_evidence_package
  - build_evidence_zip(parts) → wraps zipfile assembly
  - move CycloneDX XML / SPDX JSON construction to services/exporters/ if time;
    otherwise keep in this module (acceptable scope cap)
```

#### D.5 — `refactor:` move signature endpoints (J5 carve-out — single commit, per-commit security review)
```
moves to usecases/release/signature.py:
  - upload_signature, verify_release_signature, delete_signature

J5 reason: signature flow is input validation + cryptographic verification.
Per code-principles.md §J5 + the J5-footnote (added 2026-04-29 per Q-P7-2):
  - First-line prefix MUST be [J5-security-carveout]
  - Body MUST list explicit surface diff for each of 4 surfaces (no verbal review)

commit message template:
  refactor(release): [J5-security-carveout] move signature endpoints to usecases/

  Moves upload_signature / verify_release_signature / delete_signature endpoints
  from backend/app/api/releases.py:1363-1472 to
  backend/app/services/usecases/release/signature.py.  Behavior-equivalent move.

  Per code-principles.md §J5 + J5-footnote, this commit is the per-commit
  security review carve-out within PR-1's multi-commit J2 envelope.  Surface
  diff for the 4 J5-tracked surfaces (the per-commit security review made
  auditable):

    [1/4] backend/app/core/security.py
          → no changes (no diff hunks in this commit)

    [2/4] backend/app/core/deps.py
          → no changes (existing require_admin / get_current_user / require_plan
            dependencies are imported into the new module; no new dependency
            defined; no signature changed)

    [3/4] authn/authz logic
          → no changes (every moved endpoint carries the SAME Depends() chain
            it had in releases.py; verified by diff:
              upload_signature:    Depends(require_plan("signature")) +
                                   Depends(require_admin)             — preserved
              verify_release_*:    Depends(get_org_scope)              — preserved
              delete_signature:    Depends(require_admin)              — preserved)

    [4/4] input validation
          → no changes:
            - algorithm still derived from key via detect_algorithm(public_key_pem)
              when body.algorithm is empty (per invariants.md §II.2 D6)
            - signature_b64 still validated by _verify_sig(...) BEFORE storage
              (per invariants.md §II.2 D7)
            - safe_attachment_filename still applied to any returned filename
            - SUPPORTED_ALGORITHMS allowlist preserved verbatim

  Review checklist (each box verified with diff inspection):
    [x] detect_algorithm still derives from key, not body field (D6)
    [x] _verify_sig still called BEFORE storing the signature (D7)
    [x] safe_attachment_filename still applied to download path
    [x] No new endpoint added to public allowlist (signature endpoints
        already required Bearer; no change)

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

#### D.6 — `refactor:` move scanner endpoints + _import_syft_cdx
```
moves to usecases/release/scanners.py:
  - scan_container_image, scan_iac_archive (Trivy)
  - upload_source (reachability via Stage C package)
  - sbom_from_source, sbom_from_binary (Syft)
  - _import_syft_cdx helper

Reachability call site uses Stage C package:
  from app.services.scanners.reachability import scan_zip, classify_vulns
```

#### D.7 — `refactor:` move lifecycle/lock/list/get endpoints
```
moves to usecases/release/lifecycle.py:
  - get_release, update_version, update_notes, delete_release
  - list_components, list_vulnerabilities, export_vulnerabilities_csv
  - lock_release, unlock_release
  - get_patch_stats, get_gate, get_dependency_graph

uses domain helpers via:
  from app.domain.suppression import is_suppressed
  from app.domain.severity import highest_severity
  from app.domain.sla import sla_info, SLA_DAYS
```

After D.7, `releases.py` should be < 200 LOC (just `_assert_release_org` legacy
helper + a few stragglers). All routes moved.

### §3.9 ARCH-1.003 contract evolution (D.8 — labeled EVOLUTION, not refactor)

> **This is NOT a behavior-equivalent refactor.** It changes HTTP status code on ~30 endpoints from 403 to 404 (CWE-204 oracle prevention). Per `invariants.md` §V.2, the change is recorded in this iteration's `ledger.md` as the **first deliberate contract evolution under D1 lenient regime**. J5 carve-out applies (single commit, full security review).

#### Pre-D.8 prerequisites (all must hold)
- [ ] D.2..D.7 fully shipped — no `_assert_release_org` callers remain in moved modules (they all use `Depends(require_release_in_scope)` already from D.2 onward — see D.N implementation)
- [ ] Frontend grep performed (HARD LOCK 1 added 2026-04-30 per user feedback):
  ```bash
  grep -rn "status === 403\|err\.status === 403\|response\.status === 403\|response\.status_code === 403\|err\.response\?\.status === 403\|: 403" frontend/src
  ```
  **Result of the grep MUST be reported back to user verbatim before D.8 starts**, regardless of whether it's 0 matches or N matches. The agent does NOT auto-proceed on 0 matches:
  - **0 matches** → wait for user "go D.8" confirmation; then user runs a second-pass cross-validation grep `grep -rn "403" frontend/src` (broader; un-pattern-filtered) to catch matches that fell outside the regex above (e.g. axios interceptor numeric checks, TypeScript `as const` numeric literals, i18n string fragments containing "403")
  - **N > 0 matches** → list each match with file:line + 3-line context + planned fix; user reviews the per-site fix plan; user reviews the D.8 commit message preview; only then "go D.8"
  Reason: 0 matches in the regex above does NOT prove no frontend code differentiates 403 from 404; only that the regex didn't catch any. Auto-proceeding on 0 matches would be unjustified confidence.
- [ ] Stage A.3 characterization tests' cross-org assertions are ready to flip from 403 → 404 in the same commit (one diff: `assert response.status_code == 403` → `== 404`)
- [ ] D.8 commit message preview must be sent to user for review BEFORE the commit is created (per agent's prior commitment in Stage C end-of-stage report)

#### D.8 J5 surface diff — contract-evolution extension (added 2026-04-30 per user feedback)

D.8 is the only J5 carve-out commit in PR-1 that is ALSO a contract evolution.
The standard J5-footnote requires diff disclosure for 4 surfaces (`core/security.py`,
`core/deps.py`, authn/authz logic, input validation).  When D.8's frontend grep
finds matches that require frontend code changes, those frontend changes land in
the SAME commit (per HARD LOCK 1: "if any match is about cross-org-403-handling,
STOP and update frontend in same commit").

**Special extension for D.8 only**: if frontend changes are bundled, the commit
body MUST add a `[5/5] cross-layer surface` section listing the frontend
file:line + diff hunks.  This is NOT a standing J5 policy (J5 normally bans
production-code surface bundling per J6's spirit) — it is a contract-evolution
specific extension because:

  - D.8 is a back-end contract change (status code map evolution)
  - The React frontend is the first-party consumer of that contract (per D1)
  - Splitting "back-end flips status code" + "frontend updates handler" into
    two commits would leave master in an inconsistent state between commits
    (frontend expecting 403, backend returning 404 → user sees confusing UX)
  - Atomic landing is the lowest-risk approach for first-party-consumer changes

**[5/5] cross-layer surface format** (when present):
```
  [5/5] frontend/src cross-layer (D.8-evolution-extension only)
        → list of file:line entries with the cross-org 403/404 differentiation
        → for each: 3-line context + the diff hunk applied
        → rationale: "back-end status flip 403→404 requires frontend handler
          update to keep first-party consumer behavior consistent"
```

If the frontend grep finds 0 matches (no frontend code differentiates 403),
**the [5/5] section is omitted** and the standard 4-surface diff body applies.
The grep result itself (with exit code) is recorded in the commit body to
prove the verification ran.

#### Post-D.8 verification (HARD LOCK 2 added 2026-04-30 per user feedback)
- [ ] **Zero `_assert_release_org` residue across the entire repo (HARD LOCK 2.A)**:
  ```bash
  grep -rn "_assert_release_org" backend/
  ```
  Expected: **0 matches** (production code AND tests AND comments — all zero). The helper is DELETED in D.8, not deprecated, not aliased, not wrapper-shimmed. Per ARCH-1.003 root-cause analysis: the reason "30 sites still on legacy" was that the legacy path remained reachable. D.8 removes the path entirely so reachability is impossible. If grep returns ANY match (even in a comment or docstring), STOP, fix, re-verify; do not allow the residue to live past D.8.

- [ ] **Zero `無權存取此版本` zh-TW message residue (HARD LOCK 2.B, added 2026-05-01 per user feedback)**:
  ```bash
  grep -rn "無權存取此版本" backend/
  ```
  Expected: **0 matches**. This is the zh-TW detail string that the legacy 403 raised. Catching it via a SEPARATE grep (orthogonal to the helper-name grep) detects a class of refactor anti-pattern: someone renamed the helper to escape HARD LOCK 2.A but kept the legacy message string verbatim. If 2.A returns 0 but 2.B returns matches, that is exactly the pattern to STOP on — the helper-name grep was satisfied via cosmetic rename, not real elimination of the legacy path. Both 2.A AND 2.B must be 0 for HARD LOCK 2 to pass.
- [ ] Cross-org HTTP characterization tests assert 404 (not 403) on every release-id endpoint that previously legacy-403'd; pytest run on the test_releases_http_chars.py shows the assertion flip succeeded
- [ ] `test_all.py` still 54/54 PASS post-D.8 — D.8 changes no test_all.py expectation (test_all.py uses admin tokens which are not affected by the cross-org check)

#### D.8 commit content
```
backend changes:
  - Delete _assert_release_org helper from backend/app/api/releases.py and from
    every usecases/release/*.py file that pasted it
  - Replace every call site:
      product, org = _assert_release_org(release, org_scope, db)
    with:
      release: Release = Depends(require_release_in_scope)
      product, org = _release_context(release, db)   # new helper for the (product, org) tuple per CODE-1.008
  - Verify SDLC-001 enforcement test (test_endpoint_decorator_enforcement.py) still
    passes; ideally extend it to flag any remaining _assert_release_org reference

frontend changes (same commit):
  - per grep result above; usually 0 changes if all 403s are about admin-only

test changes (same commit):
  - flip every cross-org assertion in test_releases_http_chars.py from 403 → 404
  - run full pytest unit + test_all.py to verify

commit message:
  refactor(deps)+evolution: ARCH-1.003 — cross-org returns 404, not 403

  This is a DELIBERATE CONTRACT EVOLUTION, not a behavior-equivalent refactor.
  Status code on ~30 release-id endpoints changes when a viewer accesses a
  release outside their organization scope:
    Before: 403 with detail "無權存取此版本"
    After:  404 with detail "Release not found" (CWE-204 oracle prevention)

  Compatibility regime: D1 lenient (per invariants.md §V) — only the React
  frontend consumes the API today.  Frontend grep shows N matches updated
  in this commit (0 if no cross-org-403-specific handling existed).

  The new behavior matches the documented invariant in invariants.md §I.1
  ("Cross-org access to release | 404 | never 403"); the legacy 403 sites
  were violating that invariant and are now in compliance.

  Per code-principles.md §J5, this is a single-commit security-review carve-out
  even within PR-1's multi-commit J2 envelope.

  Per invariants.md §V.2, this is the FIRST deliberate contract evolution under
  D1 lenient regime; ledger.md iter-1 row records this fact for traceability
  if/when D1 is later revoked.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

#### Post-D.8 ledger update (in PR-1's last commit, see Stage E or as separate Tidy)
```
ledger.md addition under iter-1 row:
  | D11 (post-PR-1) | Contract evolution shipped: ARCH-1.003 (D.8) — 30 release-id
    endpoints flipped 403 → 404 on cross-org access.  First exercise of D1 §V.2
    obligation; if D1 is later revoked, this evolution is grandfathered (it
    matches the documented invariant) but recorded here for audit completeness. |
```

### §3.10 Stage E — Schema centralisation (~2 commits)

#### E.1 — `tidy:` extract inline BaseModel from moved modules to schemas/release_*.py
```
extract from usecases/release/upload_sbom.py / enrich.py / reports.py / signature.py /
            scanners.py / lifecycle.py:
  - any inline `class FooPayload(BaseModel)` → schemas/release_<concern>.py:FooPayload

scope: ONLY the schemas in moved modules (~12 schemas total).
out of scope: 60+ inline schemas in 17 untouched routers (deferred to a future iter).
```

### Stage E scope lock (added 2026-05-01 per iter-1 user feedback)

PR-1 production-code count is at 18 (post-D.8) against plan estimate of ~19.
Stage E adds 2 commits → 20 production commits.  D16 budget rule:
`> 22 invoke T3-soft, > 25 invoke T3-hard`.  Margin is tight.

To preserve the budget, Stage E scope is HARD-LOCKED:

**E.1 — limited to D-touched modules ONLY**
Inline `BaseModel` extraction applies to schemas declared in the 7 D-touched
modules (upload_sbom.py / enrich.py / reports.py / signature.py / scanners.py /
lifecycle.py / share.py — the latter only its admin endpoints touched in D.8).
Inline schemas in the OTHER 17 router files (auth, organizations, products,
vulnerabilities, cra, search, settings, policies, users, admin, tisax,
licenses, firmware, tokens, convert, notice, plus share.py's public download
endpoint) are EXPLICITLY OUT OF E.1 scope — they remain as-is.  Future
follow-up `FU-1.012` slot reserved for the broader sweep.

**E.2 — limited to two endpoints ONLY**
`update_version` + `update_notes` only.  Other untyped `body: dict` endpoints
in the codebase (anywhere — including non-D-touched routers) are OUT OF E.2
scope.  Per Q-P7-3 the typed-body conversion is BEHAVIOR-EQUIVALENT
(silent truncation preserved); 4-boundary-input verification per §6 acceptance
gate.

**STOP-on-scope-creep enforcement**: if E.1 or E.2 surfaces additional
related items that look "obvious to clean up", §K discipline applies — STOP,
disclose, do NOT silently expand scope.  Recovery via FU- entries in §10,
not commit bloat.

#### E.2 — `refactor:` typed bodies for update_version + update_notes (CODE-1.012, BEHAVIOR-EQUIVALENT)
```
REVERSED per user Q-P7-3 iter-1 (2026-04-29):
  Earlier draft proposed "body: dict → typed Pydantic with strict validation"
  which would convert silent-truncation into 422.  That is an evolution, not a
  refactor — adds a new rejection path on existing-valid input (5001-char notes
  that today succeeds becomes 422 tomorrow).  The user requires PR-1 to carry
  AT MOST ONE deliberate contract evolution (D.8 / ARCH-1.003); evolution-by-
  refactor-side-effect blurs review boundary.

  E.2's revised scope: type the body for documentation + Pydantic schema
  introspection, but PRESERVE THE EXACT BEHAVIOR via explicit field validators.

new in schemas/release_lifecycle.py:

  from pydantic import BaseModel, field_validator

  class ReleaseVersionUpdate(BaseModel):
      version: str
      # No min_length / max_length here — empty-string check stays in handler
      # (preserves zh-TW 400 message; Pydantic min_length would emit 422 instead).

      @field_validator("version", mode="before")
      @classmethod
      def _coerce_strip(cls, v) -> str:
          # Mirrors handler today: (body.get("version") or "").strip()
          return str(v if v is not None else "").strip()

  class ReleaseNotesUpdate(BaseModel):
      notes: str = ""

      @field_validator("notes", mode="before")
      @classmethod
      def _coerce_truncate(cls, v) -> str:
          # Mirrors handler today: str(body.get("notes", "") or "")[:5000]
          # Silent truncation preserved — no 422 emitted on > 5000 input.
          return str(v if v is not None else "")[:5000]

usecases/release/lifecycle.py:
  - replace `body: dict` with the typed Pydantic models
  - HANDLER STILL DOES the empty-string check + raises 400 with zh-TW message
    (preserves invariants §I.1 status code map for `update_version`)
  - HANDLER STILL DOES the `notes or None` step (preserves NULL semantics)
  - No 422 path introduced; no 400 path introduced; no body shape rejected
    that was previously accepted

behavior equivalence — verified against 4 boundary inputs in characterization
tests (added in this commit):
  | Input                           | Today's behavior              | After E.2     |
  |---------------------------------|-------------------------------|---------------|
  | version=""                      | 400 "版本號不可為空"           | 400 (same)    |
  | version="   " (whitespace only) | 400 "版本號不可為空" (post-strip) | 400 (same)    |
  | notes="" (empty)                | release.notes = None          | None (same)   |
  | notes=4999 chars                | stored as-is                  | stored as-is  |
  | notes=5001 chars                | silently truncated to 5000    | silently truncated to 5000 |
  | notes=null (JSON)               | "" → None                     | "" → None (same) |

Per invariants.md §V — this is BEHAVIOR-EQUIVALENT, NOT contract evolution.
Tightening to reject 5001-char input (or empty version with 422 instead of 400)
is a SEPARATE deliberate decision, filed as followup FU-1.001 in §10 below.
PR-1 maintains exactly ONE contract evolution (D.8 / ARCH-1.003).
```

---

## §4 PR-2 — Performance + bug fixes (J1 one-commit-one-finding)

> Opens only after PR-1 merged to master. Sequential. Each commit has one finding ID. Each commit can be reverted independently.

| Commit | Finding | What | Effort |
|---|---|---|---|
| F.1 | PERF-1.001 | Push `overdue_count` to SQL with `days_between` | S |
| F.2 | PERF-1.005 | reportlab warmup at lifespan | S |
| F.3 | PERF-1.008 | Share `httpx.Client(http2=True)` across OSV detail ThreadPool + measure smoke test before/after | S |
| F.4 | PERF-1.007 | Commit `backend/tests/bench/bench_osv.py` reproducer (~30 LOC stdlib) | S |
| F.5 | CODE-1.013 | CSAF namespace from env var (`CSAF_NAMESPACE` default) instead of `https://example.com` | S |

Each F.N includes a `# Performance Data:` block in the commit message with before/after numbers (where applicable):
```
F.1: stats.overdue_count
  Before: 5K-row Python loop (~50–150ms theoretical; not measured pre)
  After:  1 SQL query (~5–10ms theoretical; measured post)
  Improvement: ~10–30× on this single computation
```

If the measured improvement is < 50% of the theoretical estimate, the commit message records the actual number and notes the discrepancy. Per protocol §8.5, performance claims must have evidence.

---

## §5 PR-3 — Tidy + ADRs (J1)

| Commit | Finding(s) | What |
|---|---|---|
| G.1 | CODE-1.011 (already in D.2 if landed there; skip if duplicate) | `logger.exception` for any remaining silent swallow |
| G.2 | CODE-1.016 + CODE-1.017 + ARCH-1.013 | Drop dead `new_count` return; concurrency-globals docstring; replace `__import__("app.core.config")` with normal import (this last one already in D.3 if scoped there; skip if duplicate) |
| G.3 | ARCH-1.014 | Add `.knowledge/decisions/0003-osv-batch-strategy.md` ADR + `0004-releases-split-decision.md` ADR |
| G.4 | CODE-1.028 | Resolve `test_full_verification.py` status — **hard rule below**, no verbal judgment |
| G.5 | ARCH-1.010 + dead model fields | Remove `dtrack_project_uuid` from `models/release.py` (column stays in DB unused; documented in known-debt) |

### G.4 hard decision rule (per Q-P7-4 iter-1, 2026-04-29)

> No verbal judgment. The decision branch is mechanical and the evidence is committed.

**Step 1** — At PR-3 start (before writing any G.4 code), with backend running on port 9100:
```bash
python test_full_verification.py 2>&1 | tee .refactor-audit/iteration-1/test_full_verification_run.log
```

**Step 2** — Inspect the log. Enumerate every test case and what it verifies. Build the cross-ref table:
```bash
grep -E "^def test_|^def verify_" test_full_verification.py > /tmp/tfv_cases.txt
grep -E "^def test_" test_all.py > /tmp/tall_cases.txt
diff -u /tmp/tall_cases.txt /tmp/tfv_cases.txt
```
Or, if function names diverge, do a manual case-by-case mapping in a comment block.

**Step 3** — Decide based on the comparison:

| Result | G.4 commit content | Decision rationale committed where |
|---|---|---|
| **All subset** (every `test_full_verification.py` case is also covered by `test_all.py`) | `git rm test_full_verification.py` + new `known-debt.md` entry **DEBT-017**: "historical ad-hoc verification absorbed into test_all.py — file deleted PR-3 G.4 commit \<SHA\>; superseded-by mapping in `iteration-1/test_full_verification_run.log`" | commit body cites the run log path + lists per-case "test_X (in tfv) ⇒ test_Y (in tall)" |
| **Has additional cases** (test_full_verification covers cases not in test_all) | Rewrite the additional cases as pytest under `backend/tests/unit/test_release_full_verification.py` (or appropriate name); delete the original file; CI gains the new pytest file via existing pytest infra (Stage A.1) | commit body cites the run log path + lists which cases were absorbed vs which were rewritten as pytest |

**Step 4** — Both the run log AND the case-comparison table go into the G.4 commit. The commit body cites the log file path (relative to repo root). No verbal-only judgment; the decision is auditable from git history alone.

---

## §6 Acceptance gates per PR

### Commit budget calculation (added 2026-04-30 per ledger.md D16)

The estimates in §1 / §2 / §3.4 ("~19 commits", "6–10 days") count ONLY
**production-code commits** — any commit that touches `backend/app/`,
`backend/tests/`, `frontend/src/`, `tools/`, or any other source path.

**Audit-doc commits do NOT count toward the budget.**  An audit-doc commit
touches only `.refactor-audit/` (this directory).  Such commits are
J1-disciplined per-finding records with zero production-behavior surface
and zero review burden on the god-router decomposition.  Counting them
would inflate the apparent PR review cost without inflating the actual
review cost.

Reviewer guidance: when validating PR-1's commit list against the budget,
filter out audit-doc commits first, then count what remains.  If the
filter produces a number > 22 (15% over the 19 estimate), invoke
T3-soft (re-evaluate scope); if > 25, invoke T3-hard (cut scope).

**PR-1 actual landing (post-F.3, 2026-05-02)**: 22 production commits —
**exactly at the T3-soft warning line** per §3.4 trigger thresholds
(`> 22` invokes T3-soft; strict greater-than).  Margin to T3-soft = 0;
not exceeded.  Stage breakdown: A.1-A.3 (3) + B.1-B.4 (4) + C.0-C.2 (3)
+ D.1-D.8 (8) + E.1-E.2 (2) + F.1-F.2 (2) = 22.  Audit-doc commits at
PR-1 close: 12 (Phase 1-7 baseline + 11 mid-iter audit-doc commits
through F.4-audit), NOT counted.  **Implication for future J2 PRs**:
this PR-1 review-fix sweep (F-stage, 2 production commits) consumed all
remaining margin to T3-soft.  Future PRs of comparable scope should
reserve **≥ 2 production commits of headroom in the plan estimate**
specifically for review-fix sweeps; otherwise a review fix can trip
T3-soft on the first invocation.  Cross-ref: ledger D16 (budget rule) +
D18 (F-stage triggered review-fix) + D19 (§K STOP that prevented an
F.4-production fix-forward from crossing the line).

### PR-1 acceptance gate (before merge)
- [ ] All Stage A unit tests pass (≥ 30 function-level + ≥ 75 HTTP characterization)
- [ ] `test_all.py` 54/54 green (existing CI gate)
- [ ] `test_endpoint_decorator_enforcement.py` green
- [ ] `pytest --cov=backend/app/services/usecases backend/app/domain` reports ≥ 30% on the new packages (AC-T2)
- [ ] AC-A1: `releases.py` < 600 LOC (target: < 200 LOC after Stage D)
- [ ] AC-A2: `services/usecases/release/` has ≥ 5 sub-modules (target: 7)
- [ ] AC-A3: each sub-module has a 1-line docstring at top
- [ ] AC-A4: no new file > 600 LOC
- [ ] AC-D1/2/3/4: domain/ package satisfies all 4 acceptance criteria
- [ ] AC-T1: ≥ 1/3 of new tests are function-level (count: function-level / total)
- [ ] Frontend grep for `403` returned 0 cross-org references (or all updated in D.8)
- [ ] **E.2 byte-equality verified**: all 4 boundary inputs (`version=""`, `version="   "`, `notes=4999 chars`, `notes=5001 chars`) produce identical responses (status code + JSON body) before vs after the typed-model conversion. Per Q-P7-3 iter-1: E.2 must be behavior-equivalent, NOT contract evolution.
- [ ] **D.8 is the sole contract evolution in PR-1**: ledger.md iter-1 row records exactly one D11 entry (D.8 / ARCH-1.003); no D11.x evolution from E.2 or any other commit
- [ ] PR description maps each commit to its finding ID

### PR-2 acceptance gate
- [ ] All commits pass `test_all.py`
- [ ] Each `perf:` commit message includes Performance Data block with measured numbers
- [ ] PERF-1.007 (`bench_osv.py`) runnable: `python backend/tests/bench/bench_osv.py` succeeds and prints elapsed time

### PR-3 acceptance gate
- [ ] All commits pass `test_all.py`
- [ ] 2 new ADRs in `.knowledge/decisions/` (0003 + 0004)
- [ ] `.knowledge/index.md` updated to reference new ADRs
- [ ] If `test_full_verification.py` is deleted, commit message names the superseding test
- [ ] If `dtrack_project_uuid` removed from model, ledger notes "column dropped from model; lives in DB unused"

### Final iter-1 close-out (after PR-3 merge)
- [ ] `verification.md` written per Phase 9 spec — includes:
  - Maturity score per dimension (re-measured)
  - AC-T1/D1-4/A1-4 status (PASS / FAIL with downgrade rationale)
  - Composite outcome classification (success / partial / fail per `calibration.md` §3.4)
  - Performance before/after table with actual numbers
- [ ] `ledger.md` updated per Phase 10 spec
- [ ] `architecture.md` updated to reflect new shape (move §1 "Current shape" descriptions to match new tree)
- [ ] `code-principles.md` appended with any new principles surfaced
- [ ] `known-debt.md` updated: DEBT-001..016 status + retired entries

---

## §7 Open questions (❓)

> Items that need user input before or during Phase 8.

❓ **Q-P7-1**: For C.1 — should I keep a 1-line shim at `services/reachability.py` re-exporting from the new package? Pro: backward-compat for any forgotten import; Con: dead code per AR-1 ("no port for a single implementation"). My recommendation: **no shim** — D1 lenient regime means we don't owe back-compat to anyone, and Stage A.3 catches missed imports.

❓ **Q-P7-2**: For D.5 (signature endpoints) — should this be its own MICRO-PR (PR-1.5) given J5 carve-out? My recommendation: **no, single commit inside PR-1 with explicit `[J5]` tag in commit message** — full PR overhead is excessive for one commit.

❓ **Q-P7-3**: For E.2 — `body: dict` → typed model rejects malformed input with 422 (was: silent truncation/acceptance). This is a strictness-only contract evolution. My recommendation: **proceed under D1 §V.2** — record in ledger as minor evolution alongside D.8.

❓ **Q-P7-4**: For G.4 (`test_full_verification.py`) — without running it, I don't know if it covers anything `test_all.py` doesn't. My recommendation: **investigate during PR-3** — if it's a strict subset, delete; if it has extra coverage, wire into CI.

❓ **Q-P7-5**: When PR-1 is open and ready to review, who reviews? If it's only you, the J2 multi-commit-per-PR has lower review-throughput risk. If a second reviewer is needed (e.g. for the security commit D.5), say so now — affects PR-1 cadence.

---

## §8 What this plan does NOT cover

Explicit out-of-scope items, parked in `known-debt.md` for future iters:

| Item | Why deferred | Track in |
|---|---|---|
| ARCH-1.007 (multi-worker concurrency rework) | Single-process today; future-iter when commercialisation requires multi-worker | DEBT-012 |
| ARCH-1.008 (`_oidc_meta` cache TTL) | Low impact; iter-2 candidate | DEBT-013 |
| ARCH-1.011 (monitor long-held DB session) | Subtle concurrency; needs design conversation | DEBT-014 |
| ARCH-1.012 (audit.record manual commit) | Wide blast radius; iter-2 candidate | (new DEBT entry) |
| PERF-1.002 (get_stats 9 queries) | Measure first after PERF-1.001; only attack if dashboard still slow | DEBT-015 |
| PERF-1.009 (ReleaseDetail.jsx 76 hooks) | Couples to UX-034 carry-over; needs frontend iter | DEBT-016 |
| Inline schemas in 17 untouched routers (≥ 60 schemas) | E.1 covers only routes touched in PR-1; full sweep deferred | DEBT-003 enlarged |
| Anti-corruption layer for OSV/NVD/EPSS/KEV/GHSA full split | ARCH-1.006; deferred unless `releases.py` split touches these contracts | (new DEBT entry) |
| Frontend audit | Out of refactor-audit lane this iter | `.ui-audit/` track |
| Observability investment (structured logging, OTel, metrics) | Q7 — separate audit lane | future audit |
| SEC-027 mitigation choice | Q8 — security audit lane | `.knowledge/audit/` track |
| SEC-028 candidate (OIDC `id_token` not validated) | Cross-lane — security audit lane | `.knowledge/audit/` track (CODE-1.015 reference) |

---

## §9 Summary

- **3 PRs**, sequential, ~28 commits total
- **6–10 working days** (realistic), pessimistic trigger T3 hard-stops at day 7
- **PR-1** is the substantive work (god-router split + safety net + domain extraction + Wave-D-aligned reachability package + schema centralisation for touched routes + ARCH-1.003 contract evolution carved out as §3.9)
- **PR-2** is 5 small perf + bug commits, behavior-equivalent or measured evolution
- **PR-3** is tidy + 2 ADRs
- **Each PR has explicit acceptance gate**, including AC-T1/D1-4/A1-4 from `calibration.md` §3.3 — Δ +1.0 maturity is contingent on these
- **Fallback strategy**: `git revert` (never `git reset --hard` on master)
- **First deliberate contract evolution under D1**: D.8 (ARCH-1.003), recorded in ledger
- **5 open questions** (`❓`) await your input

After your review, if you approve, **say "go"** and I will start with §0 Pre-flight checklist execution, then commit A.1.

---

## §10 Followups — surfaced during planning, deferred to iter-2 candidacy

> Items noticed during Phase 7 planning that are **not** in iter-1 scope but should not be lost. Each gets a `FU-{Iter}.{Seq}` ID; iter-2's Phase 1 reads this section to decide which to promote.

### FU-1.001 — Tighten `update_notes` / `update_version` validation
- Reason this is NOT in iter-1: per Q-P7-3, evolutions in PR-1 are limited to D.8 (ARCH-1.003) only; tightening validation = a second deliberate evolution that blurs review boundary
- Proposed change (deferred): replace silent truncation at 5000 chars with explicit 422 rejection; replace empty-version 400-with-zh-msg with 422 (or keep 400 if zh-TW message is part of contract). Requires explicit ledger entry under D1 §V.2 if adopted
- Iter-2 promotion rule: promote if iter-2 plan includes other deliberate evolutions (so the review boundary cost is amortised); otherwise defer further
- Cross-ref: CODE-1.012 (the original finding); Q-P7-3 (the user's directive)

### FU-1.002 — Extend SDLC-001 enforcement test to flag legacy `_assert_release_org`
- Reason this is NOT in iter-1: D.8 already deletes `_assert_release_org`; the enforcement test extension is a defense-in-depth that makes accidental re-introduction impossible
- Proposed change: `tests/test_endpoint_decorator_enforcement.py` adds an assertion: any release-id endpoint that imports / calls `_assert_release_org` fails the test (the helper itself is gone, but a re-introduction attempt would re-create it)
- Iter-2 candidate: low effort, high value
- Cross-ref: ARCH-1.003 (the original migration); D.8 (the iter-1 commit that deletes the helper)

### FU-1.003 — Anti-corruption layer for OSV/NVD/EPSS/KEV/GHSA shapes (typed DTOs)
- Reason this is NOT in iter-1: ARCH-1.006 deferred per `architecture-audit.md` "out of iter-1 scope unless touched-slice covers"; iter-1 touches the call sites but leaves the dict-shaped boundary
- Proposed change: introduce `OsvVulnDTO` / `NvdCveDTO` / `EpssScoreDTO` / `KevEntryDTO` / `GhsaAdvisoryDTO` dataclasses; integrations parse upstream JSON into typed DTOs; routers consume DTOs not raw dicts
- Cross-ref: ARCH-1.006

### FU-1.004 — Move CycloneDX XML / SPDX JSON construction to `services/exporters/`
- Reason this is NOT in iter-1: D.4 leaves these in `usecases/release/reports.py` per scope cap; full extraction is one more sub-module
- Cross-ref: CODE-1.004

### FU-1.005 — Suppression timezone enforcement (reject naive datetime in __post_init__)
- Reason this is NOT in iter-1: per Constraint B (user iter-1 review 2026-04-30), B.4 explicitly forbids "時區強制" — naive datetimes are coerced to UTC for the past-future comparison, not rejected at construction
- Proposed change: tighten `Suppression.__post_init__` to raise ValueError on naive `suppressed_until`; consistent with the project-wide "all timestamps are timezone-aware" convention (every other DB-write path already passes tz-aware datetimes)
- Iter-2 promotion rule: promote when (a) a real call site is found that constructs Suppression from naive datetime (today: zero such sites; existing read paths use the predicate `is_suppressed(vuln)` which silently coerces), OR (b) audit log shows a row with suppressed_until missing tzinfo (data corruption signal)
- Cross-ref: code-principles.md §E1; B.4 commit `e690bb6` body (out-of-scope items list); domain/suppression.py docstring

### FU-1.006 — Suppression reason length / charset constraints
- Reason this is NOT in iter-1: per Constraint B "do NOT add" list — adding constraints later is hard to remove without breaking existing rows that violate the new constraint; defer until a concrete complaint
- Proposed change: add `max_length` (e.g. 5000 chars matching release.notes cap) + printable-ASCII-only check (or relaxed equivalent); rejection on violation
- Iter-2 promotion rule: promote ONLY if (a) DB has 99-percentile reason-length data showing > 5000 chars regularly happens (signal of unintended large input), OR (b) a CSV-injection / log-formatting bug is observed from unbounded reason text in audit log / alerts
- Cross-ref: B.4 commit `e690bb6` body (out-of-scope items list)

### FU-1.007 — Suppression suppressed_by user_id existence check (cross-table FK)
- Reason this is NOT in iter-1: `Suppression` is a value object, not an ORM row; FK validation requires a DB session, which `Suppression` MUST NOT carry — that would violate AC-D2 (domain importing `sqlalchemy`)
- Proposed change: introduce a separate validator function (e.g. `services/usecases/release/suppress.py:validate_suppressor(suppression, db_session, user_id)`) that verifies the user exists, is_active, and has suppress permission. Suppression itself stays DB-agnostic
- Iter-2 promotion rule: promote when audit log entries for suppress operations show non-existent user_ids (data corruption signal)
- Cross-ref: B.4 commit `e690bb6` body; calibration.md §3.3 AC-D2

### FU-1.008 — Suppression cross-row uniqueness (no two active suppressions on same vuln_id)
- Reason this is NOT in iter-1: requires DB query at construction time — same AC-D2 violation risk as FU-1.007
- Proposed change: at write time, query `SELECT COUNT(*) FROM vulnerabilities WHERE id=:vid AND suppressed=true` and reject if > 0 BEFORE persisting the new suppression. Alternative for Postgres: partial unique index `CREATE UNIQUE INDEX ... ON vulnerabilities(id) WHERE suppressed=true`. SQLite supports partial indexes since 3.8 (sufficient for our deployment)
- Iter-2 promotion rule: promote when monitoring observes duplicate active-suppression rows for the same vulnerability (data integrity signal). May not be a real risk if the data model already enforces 1 vulnerability row per (component_id, cve_id) tuple via uq_comp_cve
- Cross-ref: B.4 commit `e690bb6` body; uq_comp_cve unique index in main.py:168

### FU-1.010 — Audit `download_shared_sbom` (public share-token endpoint) for ARCH-1.003 root-cause completeness
- Reason this is NOT in iter-1: D.8 closed ARCH-1.003 for the **JWT-protected** sites (releases.py + 6 usecases modules + share.py 3 admin endpoints).  share.py ALSO contains a separate **public share-token endpoint** `download_shared_sbom` (the bottom of share.py, post-line ~199) that does its own share-token resolution and ownership check — that path's oracle-prevention guarantees are NOT verified by D.8 because (a) it does not call `_assert_release_org`, (b) it has different auth (share_token, not JWT), and (c) the SDLC-001 enforcement test (`tests/test_endpoint_decorator_enforcement.py`) detects `Depends(require_release_in_scope)`-style dependencies, which the share-token resolver does not use — so SDLC-001 is silently ineffective on this code path
- Proposed change: read `download_shared_sbom` end-to-end and any `_load_sbom` / share-token resolver helpers; for each failure mode (token not found / token expired / token's release in another org / release deleted while link still active), confirm:
  - HTTP status code is consistent (do not differentiate "exists but expired" from "never existed" — both should 404 with same message, e.g. "Share link invalid or expired")
  - No information about the underlying release (release_id, version, product name) leaks in error responses
  - Audit log records access attempts uniformly regardless of failure mode
- Iter-2 promotion rule: promote BEFORE PR-2 (perf wins).  Reason: ARCH-1.003 oracle-prevention completeness across all auth boundaries is more important than perf wins; any oracle leak on the public path is an exploitation surface.  PR-2's perf changes do not depend on this; it can be a separate small PR slotted in iter-2 ahead of PR-2
- Cross-ref: ARCH-1.003; D.8 commit; SDLC-001 enforcement test design assumption (see FU-1.011)

### FU-1.011 — Extend SDLC-001 enforcement test to cover share-token endpoints
- Reason this is NOT in iter-1: `tests/test_endpoint_decorator_enforcement.py` (the SDLC-001 CI gate) walks FastAPI routes and detects `Depends(require_release_in_scope)` / `Depends(require_admin)` etc.  share.py's public `download_shared_sbom` endpoint does not use these dependencies (its auth is share_token resolution inline in the function body), so SDLC-001 silently does not enforce ownership on it.  This was not visible until D.8 forced an end-to-end audit of share.py
- Proposed change: extend `test_endpoint_decorator_enforcement.py` so that any FastAPI route containing a `release_id` path parameter — REGARDLESS of auth shape — must satisfy at least one of:
  - Has `Depends(require_release_in_scope)` or `Depends(require_admin)` or `Depends(require_admin_scope)` in its signature (current rule), OR
  - The function body's first ~10 lines contain a known ownership-check call (whitelist: `_share_release_check(token, release_id, db)` or similar named helper)
  Detection method: AST scan of the function body for the whitelisted call names.  The whitelist is maintained alongside the test
- Iter-2 promotion rule: same iter as FU-1.010 (the AST-based check is the enforcement that catches future regressions on the manual share-token path)
- Cross-ref: FU-1.010; SDLC-001 design (deps-based detection); ARCH-1.003; FU-1.002 (which tightens the legacy-detection side)

### FU-1.009 — Audit existing ORM data for Suppression invariant-1 violations
- Reason this is NOT in iter-1: B.4 commit `e690bb6` body explicitly notes "ORM 既有資料不會觸發 ValueError 因為走預測式而非構造式" — Suppression's invariants are forward-looking only. Existing rows in `vulnerabilities` may currently be in an invariant-1-violating state (`suppressed=True` AND `suppressed_until < now()`), which the predicate `is_suppressed(vuln)` correctly interprets as "expired = not effectively suppressed" but which the value object would reject if constructed from those columns
- Proposed change: write a one-shot script `backend/tools/audit_suppression_state.py` that queries `SELECT COUNT(*) FROM vulnerabilities WHERE suppressed=1 AND suppressed_until IS NOT NULL AND suppressed_until < CURRENT_TIMESTAMP` and reports the count. Decide remediation:
  - **Option A**: bulk-UPDATE those rows to `suppressed=False, suppressed_until=NULL` (matches `monitor.py` expired-suppression cleanup intent — see `services/monitor.py:130-154`)
  - **Option B**: leave the rows as-is and document "the `is_suppressed` predicate already handles this correctly via the expired-treated-as-not-suppressed semantic; the value object's invariant-1 only applies to NEW writes"
- **Wider observation (already a debt signal)**: the Suppression value object exists in iter-1 but NO production write path constructs it. The suppress endpoint in `vulnerabilities.py` still mutates ORM columns directly. A natural follow-on refactor: rewrite the suppress endpoint to (a) construct `Suppression(...)` first (triggering invariant validation at the boundary), then (b) persist to ORM. That makes the value object load-bearing instead of decorative
- Iter-2 promotion rule: promote at the same time as the suppress-endpoint rewrite (whoever wires Suppression onto the write path) — both naturally land in the same iter
- Cross-ref: B.4 commit `e690bb6` body; `services/monitor.py:130-154` expired-cleanup loop; `backend/app/api/vulnerabilities.py` (the future write-path call site)

### FU-1.012 — `stats.py:169` pre-existing dead local `inc_counts = {}` cleanup
- Reason this is NOT in iter-1: `stats.py` is not a F-stage touched file (F.1 only touched `releases.py` + `main.py`; F.2 only touched `share.py`).  Per `code-principles.md` §J6.5 condition (a) "same-file boundary", a J6.5 review-time bundling requires the dead code to live in the same file the parent commit is already modifying — cross-file pickup is explicitly forbidden by J6.5 to prevent uncontrolled scope creep.  Pyflakes flagged this finding during the F-stage final sweep (`stats.py:169:5: local variable 'inc_counts' is assigned to but never used`); blame `a72590e2` 2026-04-22 confirms it predates PR-1.  An adjacent finding `stats.py:16:1: 'app.models.vex_history.VexHistory' imported but unused` is a `# noqa: F401` annotated model side-effect import (false positive — pyflakes does not honor noqa) and does NOT belong in this followup
- Proposed change: a single-line tidy commit deleting line 169 (`inc_counts = {}  # per-org breakdown not needed (shown in totals)`) plus a verification step (Grep `inc_counts` across `stats.py` to confirm no later read site — comment already says "not needed", but the grep is the contract).  Expected diff: 1 line deleted, 0 added
- Iter-2 promotion rule: opportunistic — promote when next iter's first audit lint-pass runs.  If `code-principles.md` §J6.5's promotion threshold (`> 3 invocations per PR signals lint baseline drift`) trips at any point in iter-2 PR-1, this FU is bundled into the resulting planned audit-time lint sweep stage; otherwise it is a stand-alone tidy commit
- Cross-ref: F-stage final pyflakes sweep output (D18 verification line); `code-principles.md` §J6.5 condition (a); ledger D18 (F-stage scope) + D19 (§K STOP that prevented F-stage cross-file expansion)

### FU-1.013 — 為 future iter PR 估算加入 expected LOC delta 分項表
- Reason this is NOT in iter-1: Plan §3 沒設 LOC budget, iter-1 sanity sweep 用的 ±5% heuristic 是 reviewer 口頭值不是契約; 在 iter-1 中追加會是「事後加 KPI」反 pattern
- Proposed change: Phase 7 plan template 加入 "LOC delta forecast" 子段, 要求列出 (a) test additions / (b) module split overhead / (c) schema centralization or other intentional growth / (d) expected shrink from refactor — 加總給出 expected net delta, 並說明 ±X% 容忍度
- Iter-2 promotion rule: plan 階段必做 (template change), 非 followup-as-task
- Cross-ref: ledger D20 (原始 trigger event) + plan §3 / Phase 7 future template change

End of refactor-plan.md
