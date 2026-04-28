# .ui-audit Ledger

> 跨迭代追蹤。每次迭代結束附加一行;不刪不改 prior rows。

## Cross-iteration index

| # | Date | Scope | New | Resolved | Carried | Taste score | Notes |
|---|------|-------|----:|--------:|--------:|:-----------:|-------|
| 1 | 2026-04-26 | Full audit (`.knowledge/ui-audit/`) | 36 | 22 | 14 | n/a (not graded) | Wave A/B/C: tokens + a11y mechanics + RWD basics |
| 2 | 2026-04-28 | Lite (`.knowledge/ui-audit-lite/`) | 16 | 13 | 3 | n/a | Priority-5 pages × RWD/Interaction/A11y; 8 P1 mostly mechanical |
| **3** | **2026-04-28** | **Calibration + stress-test (`.ui-audit/`)** | **TBD** | **0** | **TBD** | **TBD** | First taste-graded iteration; first under `.ui-audit/` protocol |

## Iteration 3 entry — 2026-04-28

| Field | Value |
|-------|-------|
| Date | 2026-04-28 |
| Scope | Calibration + stress-test (taste-first) — first iteration under `.ui-audit/` |
| Findings | 30 (planned) — see `audit-report.md` for full 35 incl. P4 polish |
| Resolved | 27 ✅ shipped, 2 📋 deferred to iter 4 (UX-3.012, UX-3.028), 1 🚫 skipped per default (UX-3.035) |
| Carried over | iter-1+2 carry-overs unchanged (UX-031/032/033/034/035/036, UX-012-lite) plus 4 new `b` follow-ups (UX-3.002b, 3.008b, 3.012b, 3.028a/b, 3.029b) |
| Taste score | **4.7 → 6.8** (+2.1 weighted; target was +2.5) |
| Notes | Token system grew significantly (easing / spacing / elevation / font-family); motion layer fully shipped (Button / Modal / Toast / Skeleton); i18n holes filled on ReleaseDetail + FirmwareUpload + Dashboard riskOverview thead; 2 P1 a11y/perf bugs fixed (Skeleton purge / TrendChart kbd-inaccessible). Frontend build passes 0 error. |

Commits in iter 3 range: `6f0f018..HEAD` — ~30 commits.

## Carry-over master list (still open at iter 3 start)

| ID | Severity | Source iter | Reason |
|----|----------|-------------|--------|
| UX-031 | P3 | 1 | Dark mode — large effort, brand decision dep |
| UX-032 | P3 | 1 | `prefers-contrast` / Forced colors — defer |
| UX-033 | P3 | 1 | `Help.jsx` 1071 LOC content extraction — defer |
| UX-034 | P3 | 1 | `ReleaseDetail.jsx` 2081 LOC split — dedicated session |
| UX-035 | P3 | 1 | Bundle subset analysis — defer (no perf complaint) |
| UX-036 | P3 | 1 | Automated a11y/perf tooling — blocked by no-new-deps |
| UX-012-lite | P2 | 2 | Dashboard `<section aria-labelledby>` × 5 — low ROI |
| Token migration | (foundational) | 1 | Additive-only by design |

## Conventions

- Finding IDs in iteration 3 use prefix `UX-3.{seq}` (per protocol's `UX-{Iteration}.{Seq}`).
- Severities: P0 / P1 / P2 / P3 / **P4** (P4 = "taste / polish only" — new in iter 3).
- Iteration 3 introduces **taste score** dimension (1–10 per Phase 2 calibration axis).
- Files at `.ui-audit/{recon,calibration,audit-report,plan,verification}.md` are overwritten each iteration.
- Files at `.ui-audit/{baseline,design-principles,ledger,iteration-{N}}.md` accumulate.
