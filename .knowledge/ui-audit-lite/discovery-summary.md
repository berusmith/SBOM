---
phase: 1
audit_id: ui-audit-lite-2026-04-28
created: 2026-04-28
based_on_commit: 977cf02
---

# Phase 1 — Discovery Summary

## Tech stack
- React 18.3 + react-router-dom 6.26 + Vite 5.4
- Styling: Tailwind CSS 3.4 (utility-first)
- Icons: lucide-react 1.8
- HTTP: axios 1.7
- i18n: i18next 26 + react-i18next 17 (zh-Hant default; en supported)
- No UI library (Radix / HeadlessUI / shadcn) — buttons, modals, toasts, skeletons all hand-rolled in `frontend/src/components/`

## Routes (admin view, 21 total)
Public: `/login`, `/forgot-password`, `/reset-password`, `/about`
Authed: `/`, `/organizations`, `/organizations/:orgId/products`, `/products/:productId/releases`, `/releases/:releaseId`, `/releases/diff`, `/cra`, `/cra/:incidentId`, `/risk-overview`, `/policies`, `/search`, `/settings`, `/help`, `/admin/users`, `/admin/activity`, `/firmware`, `/tisax`, `/tisax/:assessmentId`, `/profile`

## Design token state
**Tokens exist** (`tailwind.config.js` lines 28–122) but adoption is partial:
- Defined: `surface-*`, `fg-*`, `brand`, `danger`/`warning`/`success`/`info`, `border-*`, `ring-focus`; `text-h{1..6}` typography scale (modular 1.2); `z-{raised,dropdown,sticky,modal,toast,tooltip}`; `max-w-page` (= 80rem); transition-duration tokens.
- Convention (per inline comment): "additive — new code and *touched* code adopt tokens; no mass-rewrite of existing utility classes."
- Reality: existing pages use raw Tailwind utilities (`bg-blue-600`, `text-2xl`, `text-gray-800`, `z-50`). Tokens not yet propagated. **In-scope for Phase 2 audit only as a P3 note (visual-design dim is excluded).**

## Automated probe results (6 priority pages, 360 + 1280 viewports)

| Signal | Hits | Notes |
|--------|:---:|-------|
| body.scrollWidth > clientWidth | 0 | last commit's `body { overflow-x: hidden }` is doing its job |
| Unlabeled inputs (placeholder-only) | 2 | Dashboard CVE-ID search, Organizations license-status filter |
| Unnamed `<button>` (no text, no aria-label) | **19** on Policies | toggle switches use `title=` only — `title` is NOT an a11y equivalent of `aria-label` |
| Tables without `<caption>` | 3 | Dashboard customer-risk, Organizations list, Risk-overview cross-tenant |
| Tables w/ `<thead>` + `th[scope]` | 3/3 | OK — semantic structure is solid where present |
| Clipped TDs on 360 mobile | yes | Organizations action column "查看/編輯/刪除" runs past viewport; Risk-overview 10-col table same shape |
| Images without alt | 0 | clean |
| `target="_blank"` without `rel="noopener"` | 0 | clean |

## Visual review highlights from screenshots
- **1280 navbar** still bleeds: at 1280 viewport (= max-w-page boundary), 11 nav links + search + user section sum > viewport; `body{overflow-x:hidden}` hides the overflow but `登出` button is partially clipped. Last commit treated the symptom (no horizontal scrollbar) but the navbar density itself is the underlying issue.
- **1280 dashboard** screenshot came back blank — re-shot screenshot timing issue, not a real bug (1920 dashboard renders fine, mobile 360 renders fine). Will re-verify in Phase 4.
- **Mobile 360 tables** (Organizations, Risk-overview): action buttons inline in last column overflow viewport; no `overflow-x-auto` wrapper around those tables → cells get clipped (because of `body{overflow-x:hidden}`, can't even scroll to see them).
- **Heading hierarchy**: H1 → H2 jumps OK on most pages; Dashboard has 5 H2s in disparate sections — semantic grouping with `<section aria-labelledby>` would tighten it but is P3.

## Phase 2 priorities

I'll focus the audit on three concrete clusters; everything else gets a quick scan.

1. **Mobile table overflow** (RWD): Organizations + Risk-overview + likely Releases/ReleaseDetail. Pattern fix: wrap tables in `overflow-x-auto`, set `min-w` on the table itself. (Same pattern Products.jsx already follows.)
2. **A11y of icon-only / toggle controls** (Interaction + A11y): the 19 unnamed buttons on Policies; same pattern likely on Releases (suppress button) + ReleaseDetail (VEX edit). Add `aria-label` and replace `title=` over-reliance.
3. **Form inputs without labels** (A11y): the 2 found by probe + likely more in modals. `htmlFor`/`<label>` retrofitting.

Everything else (focus-visible, hover, error / empty states, footer responsiveness, navbar density at 1280) gets one quick scan pass; only severe issues filed.

## Assumptions made (no questions asked)
- Policies toggle "title=停用/啟用" buttons: assumed they have NO aria-label; treating as a11y finding. (Spot-checked HTML in probe — confirmed.)
- Test data state: only one org (`POC-SEC-001a-...`) with 0 products / 0 releases / 0 vulns — empty-state coverage is good but rich-data states (long product names, many vulns, deep tables) couldn't be observed. **Audit findings tagged as `[empty-state-only]` where richer data may surface more issues.**
- Excluded from this lite audit per spec: visual design, performance, design-system token migration, dark mode, i18n correctness, prefers-reduced-motion. (Already implemented in `index.css` for the last; not auditing further.)

Moving to Phase 2 now (no stop gate).
