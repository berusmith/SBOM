# Refactor-Audit Ledger

> Cross-iteration accumulator. Every iteration appends one entry; nothing is rewritten. Companion to `.ui-audit/ledger.md` (UI track) and `.knowledge/audit/` (security track) — these three audit lanes evolve in parallel and do not overlap.

## Cross-iteration index

| # | Date | Scope | New findings | Resolved | Carried | Maturity Δ | Commits | Notes |
|---|------|-------|---:|---:|---:|---:|---:|-------|
| **1** | **2026-04-29** | **First iteration — establish baseline + recon** | TBD (Phase 3–6) | 0 | 0 | TBD (target +1.0 weighted) | 0 (Phase 1–7 read-only) | Baseline set in `baseline.md` (frozen) |

## Iteration 1 entry — 2026-04-29

| Field | Value |
|-------|-------|
| Date | 2026-04-29 |
| Scope | Phase 0–1 of first refactor-audit iteration |
| Phase 0 outcome | Confirmed first iteration; no prior `.refactor-audit/` artefacts; baseline files created |
| Phase 1 outcome | `iteration-1/recon.md` produced; question list to user |
| Phase 2 outcome | `iteration-1/calibration.md` — 22 references tagged per dimension; 12-dim 1–10 rubric; +1.0 weighted Δ distribution + AC-T/D/A acceptance criteria (§3.3) + composite outcome rules (§3.4) |
| Phase 3 outcome | `iteration-1/architecture-audit.md` — 14 findings (ARCH-1.001…014). P0=1 (god router 2102 LOC), P1=3 (anemic models, dual ownership patterns, anemic Vulnerability), P2=7, P3=4 |
| Phase 4 outcome | `iteration-1/code-audit.md` — 18 distinct findings (CODE-1.001…028 with rollups). P0=1 (zero unit tests), P1=2 (upload_sbom 142 LOC, evidence_package 154 LOC), P2=9, P3=6 |
| Phase 5 outcome | `iteration-1/performance-audit.md` — 9 findings (PERF-1.001…009 incl. 2 positive obs). 4 hot-spot scope per D6. D6.3-correction: OSV not re-measured, cite + commit reproducer script |
| Phase 6 outcome | `iteration-1/executive-summary.md` — 35 distinct findings, 2 P0 (complementary: god router + zero tests), Δ +1.0 plan |
| Phase 7 outcome | `iteration-1/refactor-plan.md` — 3 PRs sequential (J2 only on PR-1 god-router split; F + G on J1); 6–10 day realistic estimate with pessimistic triggers T1–T4; ARCH-1.003 carved out as §3.9 deliberate contract evolution (first under D1 lenient); commit-level dependency DAG + per-commit revertibility table + PR-level fallback strategy (`git revert`, never `--hard`); §0 pre-flight checklist (10 boxes); 5 open questions awaiting input |
| Phase 8 status | Pending user "go" |
| Surface inventoried | Backend 12,737 LOC / 83 files; Frontend 12,712 LOC / 47 files; 21 routers / 25 services / 22 models |
| God-file flags | `backend/app/api/releases.py` 2101 LOC (37 endpoints); `frontend/src/pages/ReleaseDetail.jsx` 2087 LOC (76 hooks) |
| Test posture | 1 integration suite (54 stdlib HTTP), 1 structural test, 39-fixture corpus; no unit tests, no coverage |
| Perf baseline | None formal — only OSV batch optimization documented |
| Security baseline | Phase 5/6 of separate security audit closed Top-10; SEC-027 candidate open |

### Iter-1 decisions adopted after user Q1–Q10 answers (2026-04-29)

| ID | Decision | Reason | Encoded in |
|---|---|---|---|
| **D1** | API contract regime: **lenient** (no external consumers today) | Q1: only React frontend consumes the API; no tokens issued externally | `invariants.md` §V (with explicit revocation triggers) |
| **D2** | Add **pytest** (+ optional pytest-cov, hypothesis) to a new `backend/requirements-dev.txt` | Q3: 2101-LOC `releases.py` god router has 0 unit tests; HTTP-integration granularity cannot validate `_is_suppressed` / `_sla_info` boundary cases needed for behavior-equivalence safety net during Phase-8 split. Dev-only ⇒ runtime License Path B unaffected, NDA / customer-data compliance unaffected (local execution, no network egress). | `code-principles.md` §F7 |
| **D3** | **Split `releases.py` BEFORE Wave D sprint #3 starts** | Q5: Wave D's reachability extension will land in `releases.py`; doing it before split pushes file past 3000 LOC and entangles corpus acceptance gate with refactor diff. Sequence: split → freeze interface → Wave D → mini-audit = lowest total cost. | `architecture.md` §4.5 (WD-1/2/3/4) |
| **D4** | Adopt **Hexagonal-leaning** target with three "no over-abstraction" red lines | Q10: caps abstraction at the level this project's scale justifies | `architecture.md` §4.4 (AR-1/2/3) |
| **D5** | Phase 5 perf scope **narrowed** from "full first benchmark" to **4 hot-spot benchmarks + scripts in repo** | Q2: 12,737 LOC full sweep eats a day with most data unused; concentrate on N+1 list endpoints, PDF cold start, OSV batch end-to-end, ReleaseDetail.jsx render | recon.md §6 + this ledger |
| **D6** | Hot-spot list (Phase 5 scope): (1) list endpoints with N+1 risk, (2) PDF report generation (reportlab cold start), (3) OSV batch scan end-to-end, (4) `ReleaseDetail.jsx` render with 76 useState/useEffect | Q2 user-named scope | recon.md §6 |
| **D6.3-correction** | Phase-5 hot-spot (3) **does not re-measure**. Existing evidence found in `CHANGELOG.md:73-80` (200 → 51 HTTP, 3-PURL smoke test = lodash@4.17.20 / django@3.0.0 / log4j-core@2.14.0 totalling 42 vulns in 5.9s). Phase 5 cites the existing measurement and adds a small reproducer script (`backend/tests/bench/bench_osv.py`, ~30 LOC) so the claim becomes re-runnable. Re-measuring without new code change would violate the "不重工" rule | User feedback iter-1, 2026-04-29 | `performance-audit.md` (Phase 5) |
| **D7** | Phase-8 commit discipline **relaxed**: god-router/god-component splits MAY use multi-commit-per-PR | Q4 + practical: local Windows dev, no per-commit CI loop; Linux kernel patch-series practice supports atomic-PR / mid-PR-commit safety boundary. Security commits exempt. | `code-principles.md` §J |
| **D8** | Iteration cadence: **plan now, execute over multiple sessions** along Wave D's edges | Q4 confirmation | implicit; affects Phase 7 sizing |
| **D9** | **Out of scope this iter**: extra=forbid / RFC 7807 (Q6), structured logging / Prometheus / OTel (Q7), SEC-027 mitigation (Q8) | Q6/Q7/Q8 | followups |
| **D10** | `sbom.db` at repo root: **investigated and resolved as non-issue** — gitignored, untracked, stale local artifact | Q9 + git log + content inspection | `known-debt.md` "Investigated, not debt" |

## Conventions

- Iteration findings IDs use prefix `REF-{Iteration}.{Seq}` (matches the protocol's `REF-{Iteration}.{Seq}`)
- Severities: P0 / P1 / P2 / P3 / P4
- Each iteration's working files (`recon.md`, `calibration.md`, `architecture-audit.md`, `code-audit.md`, `performance-audit.md`, `refactor-plan.md`, `verification.md`) live under `iteration-{N}/`
- Foundation files (`baseline.md`, `architecture.md`, `code-principles.md`, `invariants.md`, `known-debt.md`, this `ledger.md`) live at audit root and accumulate
- `baseline.md` is **frozen** after iter-1 creation — it is the historical snapshot
- `architecture.md` and `code-principles.md` are **living** — each iteration appends a section
- `known-debt.md` entries are appended on creation, mutated on re-evaluation, retired by ledger

## Iteration plan template

When starting iteration N+1, the agent must:
1. Read this ledger
2. Read the most recent `iteration-{N}/` outputs
3. Read `architecture.md`, `invariants.md`, `known-debt.md`, `code-principles.md`
4. Confirm whether iter-N findings are resolved / regressed / outstanding
5. Re-baseline maturity scores (without re-doing iter-N work)
6. Pick a focus area NOT covered in iter-N

## Maturity score history

Updated each iteration in `.refactor-audit/iteration-{N}/verification.md`. Initial estimates in `baseline.md` §8.

| Iter | Date | Avg | Architecture | Domain | Abstraction | Readability | Errors | Tests | Observability | Performance | API | Deps | Tooling | Docs |
|------|------|----:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 (baseline) | 2026-04-29 | 5.75 | 5 | 3 | 7 | 7 | 5 | 3 | 4 | 5 | 6 | 8 | 7 | 9 |

(Subsequent rows added by each iteration's verification.md)
