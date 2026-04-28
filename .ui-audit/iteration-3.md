---
iteration: 3
started: 2026-04-28
status: in-progress (Phase 1 delivered, awaiting Phase 2 entry)
---

# Iteration 3 — record

> 持續更新;Phase 0 → Phase 10 全部紀錄收進這檔。Phase deliverables 另存 `.ui-audit/{recon,calibration,audit-report,plan,verification}.md`。

## Phase 0 — Iteration context (2026-04-28)

**Round number**: 3rd UI/UX iteration overall (1st under `.ui-audit/` protocol).

**Why iter 3 is different from iter 1+2**: Iterations 1 + 2 were a11y / RWD compliance work (mechanics). This iteration introduces (a) taste calibration vs world-class refs and (b) systematic real-world stress testing.

**Top 3 unfinished items from prior iterations** (selected for impact):
1. **UX-031 dark mode** — single highest "make-it-look-pro" lever; deferred since iter 1.
2. **`text-xs` density audit** — 358 instances; iter 1+2 only added the token, never policed usage.
3. **Tabular numerals** — 0 instances; trivial token addition with high payoff for tables.

(Other unfinished: UX-033 Help split, UX-034 ReleaseDetail split, UX-035 bundle, UX-036 tooling, UX-012-lite section grouping — all explicitly carried over per `ledger.md`.)

**Iteration 3 plan** (subject to user confirmation in Phase 7):
- Phase 2 (calibration): grade against Linear / Stripe / Vercel / Plane / Raycast on 8 dimensions.
- Phase 4 (stress test): real-content extremes + device extremes + network/state extremes.
- Phase 5 (page audit): focus on visual rhythm + microinteractions + state quality + tabular numerals.
- Phase 6 (findings): expect ~15-25 new issues; many will be P3/P4 polish.
- Phase 7 (plan): batch by "shipping confidence × visual impact"; recommend bite-size.
- **NOT this iteration**: dark mode shipping, ReleaseDetail split, Help split, automated tooling adoption.

## Phase 1 — Discovery (2026-04-28)

See `.ui-audit/recon.md` for full discovery output.

**Key takeaways**:
- A11y mechanics are nearly complete (100% th[scope], 90%+ htmlFor pairing, focus-visible global, prefers-reduced-motion global).
- Visual taste / motion / density / dark-mode are largely untouched.
- 8 questions to user parked at recon §8; assumptions documented at recon §9 for proceed-without-answer mode.

**Quantitative drift since iter 1**:
- `text-gray-500` 138 → 3 (good)
- `<th>` without scope 93 → 0 (good)
- `htmlFor` 4 → 38 (good)
- `text-xs` 368 → 358 (-3%, still high)
- `tabular-nums` 0 → 0 (untouched)
- `dark:` variants 0 → 0 (deferred)

## Phase 2 — Calibration (2026-04-28)

See `.ui-audit/calibration.md`. 8 dimensions × 5 reference products (Linear /
Stripe Dashboard / Vercel / Plane / GitHub Security). Entry score **4.7/10**
weighted; target 8.7. Biggest gaps: D2 typography (4) and D4 microinteraction
(3). Full per-dim breakdown in calibration.md §2-3.

## Phase 3-6 — Findings (2026-04-28)

See `.ui-audit/audit-report.md`. 35 findings total (5 P1, 10 P2, 12 P3, 7 P4,
0 P0). 0 regressions from iter 1+2. Visual / Motion / Microinteraction
dominate the count — confirms calibration's verdict.

## Phase 7 — Plan (2026-04-28)

See `.ui-audit/plan.md`. 6 Wave structure (A foundations / B P1 fix / C
microinteractions / D visual / E state / F mop-up). Tier 2 recommended;
user chose **Tier 3 (go all)** with my default ❓ answers.

## Phase 8 — Implementation (2026-04-28)

30 commits across the 6 Waves. Two findings deferred (UX-3.012 focus-ring
sweep — risk underestimated; UX-3.028 sticky-col — blocked by RiskOverview
column count bug). One skipped per default (UX-3.035 Modal lg).

Notable scope discipline:
- followups.md grew with 7 well-reasoned deferral entries — bigger work
  than iter 3's budget but right framing for iter 4
- Dashboard's i18n sweep stayed scope-tight (9 listed strings + 4 same-flow
  partners); ~15 sister strings parked for UX-3.002b
- ReleaseDetail.jsx scope deliberately small — only the audit-listed sites
  touched, the broader 2081-LOC refactor (UX-034) stays unchanged

## Phase 9 — Verification (2026-04-28)

See `.ui-audit/verification.md`. Frontend build 0 error in 1.64s. 27/30
findings ✅ landed; 13 of those flagged 🔬 (need real-device confirmation
of visual / motion fidelity). 2 deferred / 1 skipped tracked.

Taste score moved from **4.7 → 6.8** (+2.1 weighted; target was +2.5).
Shortfall mostly from D1 spacing rhythm (Dashboard only) and D7 focus-ring
deferral. D4 microinteraction hit target (3 → 7).

## Phase 10 — Iteration ledger (2026-04-28)

`ledger.md` updated with iter 3 row.
`design-principles.md` updated with new principles learned (motion layer,
EmptyState pattern, row-flash convention, partial-fail banner).

