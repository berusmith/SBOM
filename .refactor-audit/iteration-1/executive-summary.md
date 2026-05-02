---
iteration: 1
phase: 6 — Findings Report (Executive Summary)
date: 2026-04-29
audience: technical lead — single-page synthesis of architecture-audit + code-audit + performance-audit
---

# Iteration 1 — Executive Summary

## TL;DR

Iter-1 audit covered **12,737 LOC backend / 12,712 LOC frontend** read-only. Produced **35 distinct findings** (14 architecture + 18 code quality + 9 performance — minus rollups) across 4 severity levels. The finding pool is dominated by **one structural issue** (god router `releases.py` 2102 LOC) and **one safety-net gap** (zero unit tests). All other findings are reachable as a side effect of fixing those two.

**Recommended Phase 7 plan**: a single-PR-multi-commit refactor of `releases.py` into 6–7 use-case modules + `domain/` package, gated by pytest characterization tests, with 4 small perf wins bundled. Realistic maturity Δ: **+1.0 weighted** (5.75 → 6.75) if all acceptance criteria from `calibration.md` §3.3 hold.

---

## 1. Severity × Category statistics

| Category | P0 | P1 | P2 | P3 | Total |
|---|:---:|:---:|:---:|:---:|:---:|
| Architecture | 1 | 3 | 7 | 4 | 14 (5 P-headlines) |
| Code Quality | 1 | 2 | 9 | 6 | 18 |
| Performance | 0 | 0 | 3 | 4 | 9 (incl. 2 positive obs) |
| **Sum** | **2** | **5** | **19** | **14** | **40 raw / ~35 distinct after rollup** |

P0 issues:
1. **ARCH-1.001** — God router `releases.py` 2102 LOC (33% of backend; entire release lifecycle)
2. **CODE-1.027** — Zero unit tests; HTTP-integration-only safety net cannot validate function-level invariants

The two P0s are **complementary**: ARCH-1.001 is the work to do; CODE-1.027 is the safety net required to do it.

P1 issues (5):
- ARCH-1.002 / ARCH-1.009 — anemic models (Vulnerability has zero behavior; logic in routers)
- ARCH-1.003 — two parallel ownership-check patterns (legacy 403 vs modern 404 / CWE-204); ~30 sites still on legacy
- CODE-1.001 — `upload_sbom` 142 LOC, 12 responsibilities
- CODE-1.002 — `download_evidence_package` 154 LOC, 5 outputs assembled inline

All 5 P1s are **resolved as a side effect** of the ARCH-1.001 split (with CODE-1.027 unit tests as the safety net).

---

## 2. New / resolved / regressed (vs prior iters)

This is **iter-1**; there are no prior `.refactor-audit/` iters. Cross-track audits ran earlier:
- **Security audit** (`.knowledge/audit/`) closed 2026-04-28 — 26 findings, all Top-10 closed. SEC-027 candidate open. **No regression to security baseline expected from this audit's Phase 8** per `invariants.md` §II.
- **UI audit** (`.ui-audit/` iter-3) closed 2026-04-28 — 30 findings, taste 4.7 → 6.8. Frontend explicitly out of iter-1 scope per Q4.

---

## 3. Engineering maturity score — current vs target

Per `calibration.md` §3 the +1.0 weighted target distributes as:

| Dim | Now | Target | Δ | Driver finding |
|---|:---:|:---:|:---:|---|
| Architecture clarity | 5 | 7 | +2 | ARCH-1.001 split + ARCH-1.005 services/ subdirs |
| **Domain purity** | 3 | 6 | **+3** | ARCH-1.002 / ARCH-1.009 — domain/ package |
| Abstraction discipline | 7 | 7 | 0 | hold (AR-1/2/3 red lines) |
| Readability density | 7 | 8 | +1 | CODE-1.001 / 1.002 / 1.003 — long methods extracted |
| Error handling | 5 | 6 | +1 | CODE-1.011 / 1.014 — silent swallows fixed; broad except triaged |
| **Test quality** | 3 | 6 | **+3** | CODE-1.027 — pytest dev-only + characterization tests (AC-T1 must hold) |
| Observability | 4 | 4 | 0 | hold (Q7 — separate audit) |
| Performance awareness | 5 | 6 | +1 | PERF-1.007 reproducer + PERF-1.001/008 small wins |
| API design | 6 | 7 | +1 | CODE-1.012 typed bodies; ARCH-1.004 schemas in scope routes |
| Dependency hygiene | 8 | 8 | 0 | pytest-dev (separate file) |
| Build & tooling | 7 | 7 | 0 | no tooling refactor |
| Doc density | 9 | 9 | 0 | maintained; new ADRs in `.knowledge/decisions/` |
| **Sum** | **69** | **81** | **+12** | **avg 5.75 → 6.75 ✓ exactly +1.00** |

Acceptance criteria for the +1.0 (per `calibration.md` §3.3):
- **AC-T1** — ≥ 1/3 of new characterization tests are function-level (else Test quality scores 5, not 6)
- **AC-D1/2/3/4** — `domain/` package exists, framework-imports-free, invariants in `__post_init__`, routers no longer carry helpers (else Domain purity scores 5)
- **AC-A1/2/3/4** — `releases.py` < 600 LOC (down from 2101), ≥ 5 sub-modules, 1-line docstrings each, no new file > 600 LOC

Composite outcome rules (per `calibration.md` §3.4):
- Iter-1 **success** if weighted Δ ≥ +0.8 with no regression
- Iter-1 **partial** if Δ in [+0.5, +0.8); ledger records what missed
- Iter-1 **fail** if Δ < +0.5 OR any regression — triggers retrospective before iter-2 plan

---

## 4. High Behavior-Equivalence Risk findings (need extra safety net)

These are the findings where Phase 8 must **add characterization tests BEFORE the structural change**:

| ID | Risk | Required safety net |
|---|:---:|---|
| ARCH-1.001 | High | Full HTTP characterization for all 37 endpoints (request/response shape snapshots) + function-level tests for the 9 helpers |
| ARCH-1.003 | Medium | HTTP test for every release-id endpoint asserting 404 (not 403) on cross-org access |
| ARCH-1.012 | Medium | Audit-row count assertions wrapping every audit-emitting endpoint |
| CODE-1.001 | Medium | Test orchestrator + each `_helper` independently |
| CODE-1.002 | Medium | ZIP manifest byte-equality test; CSAF schema assertion |
| CODE-1.009 | Medium | `rescan` notification CVE-list correctness test (will probably surface the existing bug) |
| CODE-1.011 | Low | Quality grade test that fails when score_sbom raises (verifies the new logger.exception fires) |
| CODE-1.013 | Low | CSAF namespace test assertion against env-derived value |
| ARCH-1.011 | Medium | Monitor-thread session lifecycle test (deferred — not iter-1) |

---

## 5. Expected performance improvements

**Iter-1 in-scope perf actions** (4 small commits, all behavior-equivalent):

| Finding | Hot-spot | Expected improvement | Confidence |
|---|---|---|:---:|
| PERF-1.001 | Dashboard `overdue_count` | 5K-row Python loop → 1 SQL query → ~10–30× on this single computation | Medium |
| PERF-1.005 | First PDF after restart | reportlab warmup at lifespan → ~200–700ms on first request | Low |
| PERF-1.007 | OSV batch | (cite existing 200→51 HTTP, 5.9s benchmark) + commit reproducer script | High |
| PERF-1.008 | OSV detail phase | shared `httpx.Client(http2=True)` across pool → ~30–50% on detail phase | Medium |

**Out of iter-1 scope** (deferred):
- PERF-1.009 (ReleaseDetail.jsx 76 hooks) — couples to UX-034 carry-over; needs frontend iter
- PERF-1.002 (get_stats 9 queries) — measure first; only attack if dashboard still slow after PERF-1.001
- PERF-1.006 (PDF endpoint repeated component fetch) — opportunistic only

---

## 6. Side-effect on other audit lanes

- **Security audit lane**: No security finding produced (this is a refactor audit). One adjacent observation surfaced — **CODE-1.015** (OIDC `id_token` not validated) — filed for future security-lane attention as `SEC-028 candidate`. Not iter-1 scope.
- **UI audit lane**: PERF-1.009 (ReleaseDetail.jsx 76 hooks) couples to UX-034 carry-over. Logged in `known-debt.md` DEBT-016 as a perf-track flag.
- **Wave D**: ARCH-1.001 split's Wave-D alignment is encoded in `architecture.md` §4.5 (WD-1/2/3/4 — `services/scanners/reachability/` package + `__init__.py` re-exports as the frozen interface).

---

## 7. New `known-debt.md` entries to add

After this audit, the following entries should be appended to `known-debt.md`:

- **DEBT-012** — module-level concurrency globals (`_active_enrichments`, `_enrichment_lock`, monitor's 7 globals); single-process today, breaks under multi-worker uvicorn (ARCH-1.007). Reassessment trigger: commercialisation switch to multi-worker
- **DEBT-013** — `_oidc_meta` global cache never invalidated (ARCH-1.008); reassessment trigger: IdP key rotation incident
- **DEBT-014** — `monitor._do_scan_all` long-held DB session (ARCH-1.011); reassessment trigger: connection-pool exhaustion observed
- **DEBT-015** — `get_stats` issues 9 sequential queries (PERF-1.002); reassessment trigger: dashboard latency complaint
- **DEBT-016** — `ReleaseDetail.jsx` 76 hooks render cost (PERF-1.009); reassessment trigger: user complaint OR Wave D forces frontend touch
- **SEC-028 candidate** — OIDC `id_token` not validated (CODE-1.015); cross-lane reference to `.knowledge/audit/` for security-lane handling

---

## 8. Honesty notes

- **All performance numbers are theoretical** until Phase 8 measurements land. PERF-1.001 (10–30×), PERF-1.005 (200–700ms), PERF-1.008 (~30–50%) are marked Confidence: Medium or Low accordingly. Phase 9 verification.md will replace estimates with actuals.
- **Test quality 3 → 6 is contingent** on AC-T1 holding. Honest fallback to 5 is documented if HTTP-shape tests dominate.
- **ARCH-1.011 / ARCH-1.012** (long-held DB session, audit commit coupling) are P2 architecture concerns I'm flagging but **not pushing into iter-1 scope** — they require their own design conversation. Iter-1's centerpiece is the `releases.py` split; loading it with concurrency rework risks blowing the budget.
- **`test_full_verification.py` (439 LOC) status is unverified** — CI runs `test_all.py` but not this file; CODE-1.028 flags this for Phase 7 to investigate (delete vs wire to CI).
- **Frontend findings are minimal** — only `ReleaseDetail.jsx` perf signal (PERF-1.009) — because Q4 deferred frontend. A future UI-perf iter would surface 5–15 more findings.

---

## 9. Phase 7 plan preview (not yet a refactor plan — that's the next deliverable)

The recommended shape:

**Stage A — Safety net** (~3 commits, ~half a day)
- A.1: `tidy:` introduce `backend/requirements-dev.txt` with `pytest`, `pytest-cov` + `backend/tests/unit/` directory + `pytest.ini`
- A.2: `test:` characterization tests for `_is_suppressed`, `_sla_info`, `_highest_severity`, `_validate_webhook_url`, `_parse_vuln`, `_query_batch` (function-level — satisfies AC-T1)
- A.3: `test:` HTTP characterization for the 37 `releases.py` endpoints (response-shape snapshots; one parametrize per endpoint)

**Stage B — Domain extraction** (~4 commits, ~half a day)
- B.1: `tidy:` create `backend/app/domain/` package with `suppression.py`, `sla.py`, `severity.py`
- B.2: `refactor:` move `_is_suppressed`, `_sla_info`, `_highest_severity` to `domain/`; update 4+1 call sites in releases.py and stats.py
- B.3: `tidy:` collapse `_SLA_DAYS` (from releases.py + stats.py) and `SEVERITY_ORDER` (from constants.py + alerts.py) to single sources in `domain/`
- B.4: `refactor:` add domain `__post_init__` invariants for `Suppression` value object

**Stage C — Reachability package** (~2 commits, ~quarter day)
- C.1: `tidy:` `git mv backend/app/services/reachability.py backend/app/services/scanners/reachability/python_analyzer.py` + `__init__.py` re-export shim
- C.2: `refactor:` introduce `services/scanners/reachability/integration.py` dispatcher; update `releases.py` import to the package (5 sites)

**Stage D — releases.py split** (~6–8 commits, ~1 day)
- D.1: `tidy:` create `services/usecases/release/` package
- D.2: `refactor:` move `upload_sbom` + helpers to `usecases/release/upload_sbom.py`
- D.3: `refactor:` move enrichment endpoints to `usecases/release/enrich.py`
- D.4: `refactor:` move PDF/CSAF/evidence endpoints to `usecases/release/reports.py` (with extracted template)
- D.5: `refactor:` move signature endpoints to `usecases/release/signature.py` (J5 carve-out — single-commit)
- D.6: `refactor:` move scanner endpoints to `usecases/release/scanners.py`
- D.7: `refactor:` move lifecycle / lock / list endpoints to `usecases/release/lifecycle.py`
- D.8: `refactor:` migrate all `_assert_release_org` call sites in the new modules to `Depends(require_release_in_scope)` (returns 404 not 403); delete `_assert_release_org` (ARCH-1.003 close)

**Stage E — Schema centralisation (touched routes only)** (~2 commits)
- E.1: `tidy:` extract inline `BaseModel` from new modules to `schemas/release_*.py`
- E.2: `refactor:` `update_version` + `update_notes` from `body: dict` to typed Pydantic models (CODE-1.012)

**Stage F — Perf + bug fixes** (~5 commits)
- F.1: `perf:` PERF-1.001 — push overdue_count to SQL with `days_between` (with measurement)
- F.2: `perf:` PERF-1.005 — reportlab warmup at lifespan
- F.3: `perf:` PERF-1.008 — share `httpx.Client` across OSV detail ThreadPool (with smoke-test before/after)
- F.4: `tidy:` PERF-1.007 — commit `backend/tests/bench/bench_osv.py` reproducer
- F.5: `fix:` CODE-1.013 — CSAF namespace from env var instead of `https://example.com`

**Stage G — Tidy** (~3 commits)
- G.1: `tidy:` CODE-1.011 — `logger.exception` for quality grade computation
- G.2: `tidy:` CODE-1.016 / CODE-1.017 / ARCH-1.013 — drop dead `new_count` return; add concurrency-globals docstring; replace `__import__` with normal import
- G.3: `chore:` write 2 ADRs in `.knowledge/decisions/` (0003-osv-batch-strategy, 0004-releases-split-decision)

**Total**: ~22–25 commits across 1 PR (per J2 — multi-commit PR for god-router split). Estimated 2–3 working days end-to-end with characterization tests. Deferred: ARCH-1.011, ARCH-1.012, ARCH-1.007 (long-held session, audit coupling, multi-worker concurrency) — flagged for iter-2.

The actual Phase 7 plan (`refactor-plan.md`) — including dependency graph, rollback strategy, per-commit safety-net checks, and ❓ markers for any decisions — is the next deliverable, awaiting your "go".

End of executive-summary.md
