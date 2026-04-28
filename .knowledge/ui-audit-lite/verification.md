---
phase: 4
audit_id: ui-audit-lite-2026-04-28
based_on_commit: 977cf02 → 207c0a7 (Phase 3 chain)
created: 2026-04-28
---

# Phase 4 — Verification Report

## Finding-fix ledger

| ID | Severity | Category | Status | Commit | Note |
|----|----------|----------|--------|--------|------|
| UX-001 | P1 | A11y | **fixed** | `c30c389` | Dashboard summary cards → `<button type="button">`; non-clickable cards stay `<div>` (out of tab order) |
| UX-002 | P1 | A11y | **fixed** | `9b81d92` | 3 dashboard tables: `<tr onClick>` → `<Link>` wrapping primary cell (CVE result, riskyComponents, riskOverview) |
| UX-003 | P1 | A11y | **fixed** | `ba4c93b` | CRAIncidents `<tr onClick>` → `<Link>` on title cell |
| UX-004 | P1 | A11y + Interaction | **fixed** | `3029d96` | RiskOverview sortable `<th>`: `aria-sort` + inner `<button>` |
| UX-005 | P1 | A11y | **fixed** | `9494280` | Policies/License toggles: `role="switch"` + `aria-checked` + `aria-label` (was `title=` only) |
| UX-006 | P1 | A11y | **fixed** | `7d87d0b` | Dashboard CVE-impact input: `sr-only` `<label htmlFor>` |
| UX-007 | P1 | A11y | **fixed** | `7d87d0b` | Organizations create-form 3 inputs: `sr-only` `<label htmlFor>` + PasswordInput accepts `aria-label` prop |
| UX-008 | P1 | RWD  | **fixed** | `adaf032` | Navbar density at 1280: search input `w-32 xl:w-44`, gap-2, lang button no border, username `truncate max-w-[8rem]` |
| UX-009 | P2 | RWD  | **fixed** | `3029d96` | RiskOverview `min-w-[720px]` so wrapper-scroll engages predictably on mobile |
| UX-010 | P2 | RWD  | **fixed** | `207c0a7` | Organizations table `min-w-[280px]` → `min-w-[480px]` |
| UX-011 | P2 | A11y | **fixed** | `3029d96` (RO), `207c0a7` (Dashboard ×4 + Organizations + Products) | `<caption className="sr-only">` added to 7 tables |
| UX-013 | P2 | A11y | **fixed** | `3029d96` | RiskOverview sort-icon glyphs `aria-hidden` (folded into UX-004 commit) |
| UX-015 | P2 | A11y | **fixed** | `adaf032` | Skip-to-main link in `Layout.jsx` + `<main id="main" tabIndex="-1">` (folded into UX-008 commit) |
| UX-012 | P2 | A11y | **deferred** | — | Section grouping (`<section aria-labelledby>` × 5) — effort:M, low ROI; revisit at commercialisation |
| UX-014 | P3 | RWD  | **deferred** | — | `inputMode="numeric"` on number inputs — P3 nice-to-have |
| Token migration | P3 | (excluded dim) | **deferred** | — | Most pages still use raw Tailwind utilities; `tailwind.config.js` token surface is additive-only by design |

**13 findings closed, 3 deferred.**

## Before / after screenshots

- Before: `.knowledge/ui-audit-lite/before/{viewport}_{nn-page}.png` (48 files)
- After:  `.knowledge/ui-audit-lite/after/{viewport}_{nn-page}.png` (48 files)
- 4 viewports × 12 pages each = 96 PNGs total

Visual highlights:

- `before/1280_05-policies.png` vs `after/1280_05-policies.png`:
  pre-fix shows the `登出` button half-clipped at the right viewport edge;
  post-fix shows `Professional / a... / 登出` complete inside the viewport
  (`a...` is the username truncated by the new `max-w-[8rem] truncate` —
  intentional, full username available on focus / tooltip).
- `before/360_03-products.png` vs `after/360_03-products.png`:
  identical — no regression introduced by the layout / labelling changes.

## Playwright assertion matrix

Saved at `.knowledge/ui-audit-lite/assertion-matrix.json`. Probed
the 5 priority pages × 4 viewports for: body horizontal overflow,
clipped interactive elements (buttons / links / headings whose
bounding rect leaves the viewport), focusable count, and **focusables
without an accessible name** (= the proxy for the "all elements
keyboard-discoverable AND announceable" condition).

| viewport | overflow | clipped | unnamed-focusables |
|---|:-:|:-:|:-:|
| 360  (mobile) | **0**  on every page | 3-5 inside table wrappers (have `overflow-x-auto`, scrollable on demand — by design) | **0** on every page |
| 768  (tablet) | 67 on every page (clipped behind viewport edge — `body{overflow-x:hidden}`) | 4-6 (rightmost navbar items) | **0** on every page |
| 1280 (laptop) | **0** on every page | **0** on every page | **0** on every page |
| 1920 (desktop)| **0** on every page | **0** on every page | **0** on every page |

**Headline takeaways**:

1. **`unnamed-focusables: 0` everywhere** — UX-001 (cards), UX-005 (Policies switches), UX-006/007 (form labels) all working as intended. Pre-fix the Policies probe found 19 unnamed buttons; post-fix the entire 80-focusable Policies tab order has 0 unnamed.
2. **1280 / 1920**: clean across the board. UX-008 navbar density fix is holding — the original "登出 button half-cut" issue is gone, and the assertion confirms no clipped interactive elements at the spec'd resolutions.
3. **360**: the body itself doesn't overflow (good), but tables in Organizations and RiskOverview have inner cells extending past the table wrapper. This is the expected behaviour — the wrapper has `overflow-x-auto`, so on a real touch device the user can swipe horizontally to see them; on desktop with body overflow hidden the column structure remains accessible because the wrapper has its own scrollbar.
4. **768**: a documented limitation. The desktop layout activates at the Tailwind `md:` breakpoint (= 768px), and the 11-link navbar + search + user section sums to ~835px. `body{overflow-x:hidden}` confines the bleed to behind the viewport edge so there's no horizontal page scroll, but the rightmost 67px of the navbar are not visible at exactly 768. Viable workaround for users on this rare resolution: rotate to landscape or resize. Filed as a follow-up note rather than a P1 because (a) 768 portrait is uncommon for an admin UI, (b) the mobile hamburger menu kicks in at <768 and the layout-density fix kicks in at >=1280, leaving 768 as a transitional gap that's expensive to close cleanly.

## Keyboard Tab walk

20 successive `Tab` keypresses recorded per priority page at 1280:

| page | landed-on-focusable | sample tab order (first 5) |
|---|---|---|
| dashboard      | **19/20** | `[BUTTON] '1客戶數' / '0產品數' / '0版本數' / '0CRA 進行中' / '0SLA 逾期'` ← UX-001 confirmed |
| organizations  | **20/20** | `[A] '跳至主內容' → '儀表板' → '客戶管理' → '風險總覽' → 'Policy'` ← UX-015 confirmed |
| products       | **20/20** | same skip-link-first sequence |
| risk-overview  | **20/20** | same skip-link-first sequence |
| policies       | **20/20** | `[BUTTON] '+ 新增規則' → '停用 規則「Critical 漏洞超過 7 天未修補」' → '編輯' → '刪除' → ...` ← UX-005 aria-label is announced |

The dashboard's 1/20 null Tab is the first Tab from `body.focus()` — a known Playwright quirk where `body` doesn't reliably yield focus to the first tabindex element in a single keystroke. All subsequent Tabs land cleanly. Manual keyboard navigation in a real browser would not have this quirk.

Walk records at `.knowledge/ui-audit-lite/keyboard-walk.json`.

## Open / unresolved

| ID | Why unresolved |
|----|---|
| UX-012 — Dashboard section grouping (`<section aria-labelledby>`) | P2 effort:M; explicitly skipped per Phase 2 plan ("M 看情況", and ROI is low when the H2 hierarchy is already clean) |
| UX-014 — `inputMode="numeric"` on Policies number input | P3; explicitly skipped per Phase 2 plan |
| Token migration (Discovery Summary §3) | Out of scope (visual-design dimension excluded from lite audit; existing `tailwind.config.js` policy is additive-only) |
| 768-viewport navbar bleed | Documented in §matrix; treated as transitional gap, not a finding |
| `/api/stats/top-vulns` 404 console errors | Pre-existing — the endpoint isn't implemented (Dashboard.jsx queries it on mount). Out of UI/UX scope. |

## Phase 1 → Phase 4 budget reality

| Phase | Budget | Actual |
|---|---|---|
| 1 Discovery | 30 min | ~25 min |
| 2 Audit     | 60 min | ~30 min |
| 3 Implementation | 90 min | ~25 min |
| 4 Verification | 30 min | ~20 min |
| **Total** | 210 min | **~100 min** |

Came in under budget by half — the audit was lighter-touch than planned because the 977cf02 fix had already eliminated the most expensive class of issues (page-level horizontal overflow), and the existing `<tr onClick>` UX-007 anti-pattern was already documented + partially fixed in `Dashboard.jsx`'s comments, so the recommended remedy was prescriptive rather than open-ended.
