# ADR-0003: OSV batch query strategy — cite-only, not actionable

## Status

Accepted (2026-04-30 per ledger D6 + D6.3 correction).  Iter-1 PR-1 closure
record (Phase 10, 2026-05-02).

## Context

Phase 5 of iter-1 narrowed performance-audit scope to four hot-spots per
ledger D5/D6:

  1. List endpoints with N+1 risk
  2. PDF report cold start (reportlab init)
  3. **OSV batch query (this ADR)**
  4. `frontend/src/pages/ReleaseDetail.jsx` render with 76 useState/useEffect

The OSV scan was *already optimized* before iter-1 began.  `CHANGELOG.md:73`
records it under the heading `效能(OSV 掃描重寫:per-PURL → 批次 + 唯一漏洞詳情並行)`,
with a smoke test showing 200 components → 51 HTTP calls (1 batch + 50 unique
detail fetches), 3-PURL fixture (lodash@4.17.20 + django@3.0.0 + log4j-core@2.14.0
= 42 vulns) finishing in 5.9 seconds.  `CHANGELOG.md:338` is the corresponding
entry in the README-style summary at the end (`CVE 掃描（OSV.dev API，依 PURL 批次查詢）`).

D6.3 (user feedback during Phase 5) ruled that re-measuring an already-optimized
service violates the "不重工" (no double-work) principle.  The instruction was:
*cite the existing evidence in `performance-audit.md`, do not re-run, do
commit a small reproducer benchmark for future regression detection*.

**File-name clarification (the §K invocation #6 finding, 2026-05-02 — see
ledger D23)**: the implementation lives in `backend/app/services/vuln_scanner.py`
(NOT `services/osv.py`).  The filename is a historical artifact — when the
file was first written it handled multiple vulnerability sources, and as OSV
became the dominant code path the filename was retained for `git blame`
continuity rather than renamed.  The grep evidence `ls backend/app/services/ |
grep osv` returns 0 matches; `vuln_scanner.py` is the canonical location and
is also documented as such in `CLAUDE.md`'s service registry table.  This
ADR cites `vuln_scanner.py:2-15` (the OSV docstring), `vuln_scanner.py:30`
(`OSV_BATCH_URL` constant), `vuln_scanner.py:107-149` (`_query_batch`
implementation), and `vuln_scanner.py:146-end` (`scan_components` orchestrator)
as the authoritative implementation references.

## Decision

For iter-1:

- **Do not re-do the OSV batch optimization** — code at `vuln_scanner.py:107`
  (`_query_batch`) and `vuln_scanner.py:146` (`scan_components`) already
  implements the two-phase batch + parallel-detail strategy.  No defect
  detected; refactoring would be churn.
- **Do not commit a reproducer benchmark in iter-1** — this is the root
  cause of dim 8 (Performance awareness) maturity miss recorded in
  `verification.md` §4.2.  The benchmark would have triggered dim 8 +1
  (target hit) but the plan §3 budget did not include a dedicated
  Phase-8 commit slot for it; introducing one mid-iter would constitute
  scope expansion and would not survive §J6 incidental-fix conditions.
- **Do cite the existing optimization** in `performance-audit.md` as the
  evidence for hot-spot 3 — this ADR is the durable architectural record
  of that citation choice.
- **Defer the reproducer benchmark to iter-2 / PR-2**, as
  `backend/tests/bench/bench_osv.py`, per `performance-audit.md` §5.4
  PERF-1.007 description.

## Consequences

**Positive**

- Avoids re-doing already-correct code (compliant with iter-1 J4 Tidy First
  + the broader "no churn" red line in `code-principles.md`).
- Existing optimization remains under `git blame` of the original commit
  rather than an iter-1 noise commit — preserves the historical narrative
  for future audits.
- Dim 8 maturity miss is **explicit and recorded**, not hidden — the gap
  is visible to iter-2 planning rather than carried as latent debt.
- PR-2 inherits a concrete actionable item (`bench_osv.py`) with a clear
  spec from `performance-audit.md` PERF-1.007 — not a vague "measure perf"
  bullet.

**Negative**

- Maturity dim 8 (Performance awareness) misses target by +1 (actual 0 vs
  target +1).  Recorded in `verification.md` §2 + §4.2.
- No automated regression guard for the OSV batch strategy until PR-2
  ships `bench_osv.py`.  A future contributor who "improves" `vuln_scanner.py`
  could regress the 200→51 HTTP optimization without any failing test.
  Mitigation: the optimization is documented in the module docstring
  (`vuln_scanner.py:2-22`) and CHANGELOG entry, so a careful reviewer
  catches it; an automated guard is the iter-2 promise.
- The ADR-vs-implementation filename mismatch (`osv` in user's mental model,
  `vuln_scanner` in reality) is now permanently in the audit trail via
  this Context section + ledger D23.  This is a feature not a bug — the
  naming inertia is now visible to future readers.

**Neutral**

- D6.3 correction (user feedback during Phase 5) is the recorded basis
  for the cite-only path — this ADR codifies the rationale beyond the
  ledger entry.
- ADR 0003 is the first iter-1 ADR; ADR 0004 (releases.py split decision)
  is the second.  Calibration §3 dim 12 target action ("2-3 new ADRs in
  `.knowledge/decisions/`") is partially addressed (2 of 2-3 minimum).

## Alternatives considered

**(A) Redo OSV optimization in iter-1**
- *Rejected*.  The existing implementation has no detected defect.  Redo
  would be pure churn; CHANGELOG `73:` entry already documents the result
  (200→51 HTTP, 5.9s smoke test).  Violates iter-1 J4 Tidy First spirit.

**(B) Write `bench_osv.py` reproducer in iter-1 without redoing the optimization**
- *Rejected*.  Plan §3 did not allocate a commit slot for this work; adding
  one mid-iter would either: (i) push production count above 22 (D16 T3-soft)
  for a non-mandatory item, or (ii) require §J6 incidental-fix conditions
  which the work does NOT satisfy (it is production-code surface, not
  test/build-infra surface).  Violates §J6 Surface cap condition.  PR-2
  is the right home.

**(C) Cite-only with reproducer deferred to PR-2 — ADOPTED**
- The chosen path.  Honest record of "we evaluated, code is fine, we did
  not benchmark, here is the future test plan".  Maturity dim 8 miss is
  the price; preserves iter-1 scope discipline.

**(D) Cite-only AND write the dim-8 benchmark spec into the iter-2
  refactor plan immediately**
- *Partially adopted via FU mechanism* — `performance-audit.md` PERF-1.007
  + S-class effort + High confidence is the spec; iter-2 plan promotion is
  automatic when iter-2 begins.  No additional ADR action needed.

## Implementation references

- `backend/app/services/vuln_scanner.py:2-22` — module docstring with
  Phase 1 batch + Phase 2 parallel-detail strategy explained, including the
  200→51 HTTP claim
- `backend/app/services/vuln_scanner.py:30` — `OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"`
- `backend/app/services/vuln_scanner.py:33-34` — comment on the 1000-query
  upper bound from OSV docs (`# OSV documents 1000 queries / batch as the upper bound`)
- `backend/app/services/vuln_scanner.py:107-149` — `_query_batch(client, purls)`
  function — POST to `/v1/querybatch` for one chunk, returns list-of-lists
  aligned with input
- `backend/app/services/vuln_scanner.py:146-end` — `scan_components(components)`
  orchestrator: chunks PURLs into ≤_BATCH_SIZE batches, runs Phase 1, then
  parallel detail fetches for unique vuln ids
- `backend/app/services/vuln_scanner.py:164` — call site of `_query_batch`
  inside the orchestrator's chunk loop
- `CLAUDE.md` service registry — `vuln_scanner.py | OSV.dev /v1/query per PURL;
  deduplicates on (component_id, cve_id)` (the canonical-source confirmation
  that this is the OSV file)

**Future bench_osv.py reproducer location convention**:
`backend/tests/bench/bench_osv.py`, naming pattern `bench_<service>.py`
NOT `bench_<file>.py` — the bench targets the OSV behavior (the
two-phase batch+parallel strategy), not the file name.  This decouples
the future benchmark from any potential `vuln_scanner.py` rename
(should iter-2 or later decide to align the filename with its current
single-purpose role).

## References

- ledger D5 — Phase 5 perf scope narrowing to 4 hot-spots
- ledger D6 — D5 hot-spot list (this ADR is hot-spot #3)
- ledger D6.3-correction — cite-only ruling (basis for this ADR's Decision)
- ledger D20 — LOC growth decomposition (mentions Stage A test additions
  + module split overhead; OSV optimization is unrelated to that growth)
- ledger D23 — §K invocation #6 (the file-name correction this ADR's
  Context paragraph 3 records)
- `.refactor-audit/iteration-1/performance-audit.md` (Phase 5 record):
  - line 7: hot-spot scope statement
  - line 14: D6.3 cite ruling
  - lines 144-159: §5.4 Hot-spot 3 — OSV batch scan + PERF-1.007 finding
- `CHANGELOG.md`:
  - line 73: `### 效能(OSV 掃描重寫:per-PURL → 批次 + 唯一漏洞詳情並行)`
    section header
  - line 338: `CVE 掃描（OSV.dev API，依 PURL 批次查詢）` summary entry
- `verification.md` §2 dim 8 — performance awareness target miss recorded
- `verification.md` §4.2 — dim 8 in dimension target misses list
- FU candidate via PERF-1.007 (already in performance-audit.md backlog;
  promotes to iter-2 / PR-2 plan when that PR opens)
