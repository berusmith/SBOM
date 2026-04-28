---
phase: 2
audit_id: ui-audit-lite-2026-04-28
based_on_commit: 977cf02
created: 2026-04-28
scope: RWD + Interaction + A11y (visual / performance / DS-token / dark-mode / i18n / reduced-motion explicitly excluded)
---

# Phase 2 — UI/UX Audit Lite Report

15 findings across 3 dimensions, scoped to Priority pages 1–5 with quick scan of others. Severity uses P0 (blocking) / P1 (significant) / P2 (meaningful) / P3 (nice-to-have).

---

## Findings

### UX-001 — Dashboard summary cards are clickable `<div>` not `<button>` / `<a>`
- Severity: **P1** | Category: A11y
- Page / Component: Dashboard / summary-card grid
- Location: `frontend/src/pages/Dashboard.jsx:260-264`
- Observation: 6 cards use `<div onClick>` with `cursor-pointer hover:shadow-md`. Not keyboard-focusable, not announced as "button" by screen readers, no Enter/Space activation.
- Recommendation: Change to `<button type="button">` (or `<Link>` if it's pure navigation) and let the card's full click area inherit `text-left w-full`.
  ```jsx
  <button
    type="button"
    onClick={() => c.link && navigate(c.link)}
    disabled={!c.link}
    className={`w-full text-left bg-white rounded-lg shadow p-5 flex items-center gap-4
                ${c.link ? "cursor-pointer hover:shadow-md focus:outline-none focus:ring-2 focus:ring-blue-400" : ""}`}
  >
  ```
- Effort: **S**

### UX-002 — Dashboard tables use `<tr onClick>` for row navigation (3 tables)
- Severity: **P1** | Category: A11y
- Page / Component: Dashboard
- Location: `Dashboard.jsx:437` (CVE result), `:572` (riskyComponents), `:632` (riskOverview)
- Observation: `tr.cursor-pointer` + `onClick` pattern. Already documented as a known anti-pattern in `Dashboard.jsx:40-46` (UX-007 comment) — but the fix was only applied to TopVulns. The other three tables still ship the bad pattern.
- Recommendation: Mirror the TopVulns pattern — wrap the primary cell content in a `<Link>` with `focus:outline-none focus:ring-2 focus:ring-blue-400`; remove `<tr onClick>` + `cursor-pointer`. Keep `hover:bg-gray-50` on the `<tr>` for visual continuity.
- Effort: **M** (3 tables × wrap-cell-in-link refactor)

### UX-003 — CRAIncidents `<tr onClick>` for row navigation
- Severity: **P1** | Category: A11y
- Page / Component: CRAIncidents
- Location: `frontend/src/pages/CRAIncidents.jsx:104`
- Observation: Same pattern as UX-002 — tr-onClick keyboard-inaccessible.
- Recommendation: Same fix as UX-002 (wrap incident-title cell in a `<Link>`).
- Effort: **S**

### UX-004 — RiskOverview sortable headers use `<th onClick>` not `<button>`
- Severity: **P1** | Category: A11y + Interaction
- Page / Component: RiskOverview
- Location: `frontend/src/pages/RiskOverview.jsx:103-110`
- Observation: `<th onClick>` is keyboard-inaccessible. Sort state is communicated visually via `↑↓↕` Unicode but never via `aria-sort`.
- Recommendation:
  ```jsx
  <th scope="col" aria-sort={sortKey === f.key ? (sortAsc ? "ascending" : "descending") : "none"}
      className="px-4 py-3 text-left whitespace-nowrap">
    <button type="button" onClick={() => handleSort(f.key)}
            className="font-medium text-gray-600 hover:text-gray-800 select-none focus:outline-none focus:ring-2 focus:ring-blue-400 rounded">
      {f.label}<SortIcon field={f.key} aria-hidden="true" />
    </button>
  </th>
  ```
- Effort: **S**

### UX-005 — Policies toggle buttons (19 instances) lack accessible name
- Severity: **P1** | Category: A11y
- Page / Component: Policies / Policy Rule + License Rule cards
- Location: `Policies.jsx:208-214` (policy toggle), `:295-298` (license toggle)
- Observation: Custom switch is `<button title="停用">` with an inner `<div>` but no text and no `aria-label`. `title` is mouse-hover-only, NOT exposed to assistive tech as the accessible name. Probe found 19 unnamed buttons on this page alone.
- Recommendation: Promote to a proper switch:
  ```jsx
  <button
    type="button"
    role="switch"
    aria-checked={rule.enabled}
    aria-label={`${rule.enabled ? "停用" : "啟用"} 規則「${rule.name}」`}
    onClick={() => handleToggle(rule)}
    className={`mt-0.5 w-10 h-6 rounded-full transition-colors shrink-0
                focus:outline-none focus:ring-2 focus:ring-blue-400
                ${rule.enabled ? "bg-blue-500" : "bg-gray-300"}`}
  >
  ```
- Effort: **S**

### UX-006 — Dashboard CVE-impact input has no associated `<label>`
- Severity: **P1** | Category: A11y
- Page / Component: Dashboard / CVE Impact card
- Location: `Dashboard.jsx:404-409`
- Observation: Input has placeholder-only ("輸入 CVE ID 查詢受影響版本"); the `<h2>` describes the section but isn't bound via `aria-labelledby`. Screen reader announces only the placeholder, which disappears once the user types.
- Recommendation: Add `<label className="sr-only" htmlFor="cve-impact-q">{t("dashboard.cveInputHint")}</label>` and `id="cve-impact-q"` on the input. Keep the placeholder for sighted users.
- Effort: **S**

### UX-007 — Organizations inline create form inputs have no `<label>` (3 inputs)
- Severity: **P1** | Category: A11y
- Page / Component: Organizations / inline create form
- Location: `Organizations.jsx:140-150` (name), `:157-167` (username), `:171-180` (password via `PasswordInput`)
- Observation: All three inputs use placeholder-only. The form has a `<div className="font-medium...">{t("organizations.add")}</div>` heading but nothing binds it to inputs.
- Recommendation: Add `<label className="sr-only" htmlFor="org-name">客戶名稱</label>` (and similar) to each input, with matching `id`. PasswordInput should accept an `aria-label` prop.
- Effort: **S**

### UX-008 — Navbar at 1280 still bleeds; Logout button visually clipped
- Severity: **P1** | Category: RWD
- Page / Component: Layout / nav
- Location: `frontend/src/components/Layout.jsx:78-186`
- Observation: At 1280 viewport (= `max-w-page` boundary), the 11 nav links + search + user section sum to ~1417px intrinsic width. The previous fix (commit `977cf02`) added `body { overflow-x: hidden }` which prevents the viewport scrollbar but **clips the rightmost portion of the user section** — the `登出` button is half-cut at the right edge. Visible in `before/1280_05-policies.png`.
- Recommendation: Two changes —
  1. Drop the desktop-nav breakpoint from `md:` (768px) to `lg:` (1024px) on `Layout.jsx:82` — but that still won't help at 1280, so additionally:
  2. Tighten desktop spacing once below ~1440: change the user section `gap-3` → `gap-2`, drop the `lg:w-44` widening on the search input (line 125), remove the `border` on the lang toggle (line 138) so it sits flatter.

  Combined with the existing `min-w-0 overflow-x-auto` on the nav-items div, total intrinsic width drops below 1280.
- Effort: **M** (CSS-only but needs visual test at 1280/1366/1440/1920)

### UX-009 — Risk-overview table on mobile (360) clips action / multi-column data
- Severity: **P2** | Category: RWD
- Page / Component: RiskOverview / `<table>`
- Location: `RiskOverview.jsx:99`
- Observation: The table has 9 columns; at 360px the parent `overflow-x-auto` wrapper allows scroll, but no `min-w` is set on the table so cells try to fit and wrap awkwardly. Probe found 5 clipped TDs on 360.
- Recommendation: Add `min-w-[720px]` on the table — forces horizontal scroll inside the wrapper rather than column squish. Also hide the `#` ordinal column and `修補率` cell on `< sm:` (already partially done with `hidden sm:table-cell` on `進行中事件`).
  ```jsx
  <table className="w-full text-sm min-w-[720px]">
  ```
- Effort: **S**

### UX-010 — Organizations action column uses `flex` on `<td>` causing mobile clipping
- Severity: **P2** | Category: RWD
- Page / Component: Organizations / `<td>` action cell
- Location: `Organizations.jsx:271`
- Observation: `<td className="... flex justify-end gap-3">` — flex on td. With 3 buttons at ~50px each, total ≈ 200px; at 360 the table wrapper has `min-w-[280px]` so it's borderline. Probe found 3 clipped elements in the action TD.
- Recommendation: Either bump `min-w-[280px]` → `min-w-[480px]` (forces horizontal scroll inside the `overflow-x-auto` wrapper, predictable for ALL viewports), OR collapse the three buttons into an "Actions ▾" overflow menu on `< sm:`.
- Effort: **S**

### UX-011 — Tables lack `<caption>` for screen-reader context
- Severity: **P2** | Category: A11y
- Page / Component: Dashboard (×3 tables), Organizations, RiskOverview
- Location: multiple
- Observation: All major tables have `<thead>` with `th[scope="col"]` (good) but no `<caption>`. Screen-reader users hear column headers without table-level context.
- Recommendation: Add `<caption className="sr-only">客戶風險總覽</caption>` (etc.) inside each `<table>` matching the section's `<h2>` text. 1-line change per table.
- Effort: **S**

### UX-012 — Dashboard sections lack semantic `<section aria-labelledby>` grouping
- Severity: **P3** | Category: A11y
- Page / Component: Dashboard
- Location: 5 H2-headed cards
- Observation: Each card is a bare `<div>` with `<h2>` inside. Wrapping in `<section aria-labelledby>` would let assistive tech navigate by landmark.
- Recommendation: Convert each `<div className="bg-white rounded-lg shadow ...">` containing an H2 into `<section aria-labelledby="sec-quality">` with the H2 carrying matching `id`. Pattern repeats; ROI low for a P3.
- Effort: **M** (5 sections, easy but repetitive)

### UX-013 — SortIcon Unicode arrows not hidden from screen readers; no `aria-sort`
- Severity: **P2** | Category: A11y
- Page / Component: RiskOverview / SortIcon
- Location: `RiskOverview.jsx:67-70`
- Observation: `<span>↕</span>` etc. — the arrow glyphs get announced literally ("up arrow", "left right arrow"). And the sort state is purely visual.
- Recommendation: Folded into UX-004 fix — adding `aria-sort` on the `<th>` makes the visual icon redundant for AT, so mark `<SortIcon aria-hidden="true">`.
- Effort: **S** (combined with UX-004)

### UX-014 — Number input lacks `inputMode="numeric"` mobile keyboard hint
- Severity: **P3** | Category: RWD
- Page / Component: Policies / Rule form
- Location: `Policies.jsx:407-412`
- Observation: `<input type="number" min={0}>` — on mobile, iOS shows the alphabetic keyboard with a small tweak; `inputMode="numeric"` triggers the dedicated number pad.
- Recommendation: Add `inputMode="numeric"` to the input. (And `pattern="[0-9]*"` for older iOS.)
- Effort: **S**

### UX-015 — Frontend has no `<main>` `id` for skip-to-content link target
- Severity: **P2** | Category: A11y
- Page / Component: Layout
- Location: `Layout.jsx:244` `<main>` has no `id`; no skip link in the document
- Observation: Keyboard users land on the first nav link and have to tab through ~11 nav items + search + user section before reaching page content. Standard a11y remedy is a "skip to main content" link that's visually hidden until focused.
- Recommendation:
  ```jsx
  // before <nav>
  <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:bg-white focus:text-blue-700 focus:px-3 focus:py-2 focus:rounded focus:shadow focus:z-sticky">
    跳至主內容
  </a>
  // ... and on <main>
  <main id="main" tabIndex="-1" ...>
  ```
- Effort: **S**

---

## Quick-scan findings (Priority pages 6+ / others)

These are noted but not deeply audited. None look like P0/P1.

| Page | Note | Severity |
|------|------|----------|
| FirmwareUpload | Not visited in depth; baseline screenshot looks clean | — |
| TISAX (`/tisax`) | Heading + table follow same patterns; assume similar `<tr onClick>` issues if applicable | P2 (sample needed) |
| Users (`/admin/users`) | Has form labels; OK | clean |
| Activity (`/admin/activity`) | Date filter inputs have no labels; likely UX-006-class | P2 |
| Settings (`/settings`) | Form has labels; OK | clean |
| Help (`/help`) | Static content; fine | clean |
| Profile (`/profile`) | Small page; not deeply audited | — |

---

## Summary table — severity × category

| | RWD | Interaction | A11y | Total |
|---|:---:|:---:|:---:|:---:|
| **P0** | 0 | 0 | 0 | **0** |
| **P1** | 1 (UX-008) | 0 | 7 (UX-001..007) | **8** |
| **P2** | 2 (UX-009, 010) | 0 | 4 (UX-011, 013, 015 + Activity scan) | **6** |
| **P3** | 1 (UX-014) | 0 | 1 (UX-012) | **2** |
| **Total** | **4** | **0** | **12** | **16** |

A11y dominates by design — the lite scope explicitly puts visual / interaction-state polish under "excluded". P0 zero is consistent with a working app post-Phase-5; P1 cluster is keyboard-accessibility hygiene that's mostly mechanical to fix.

## Phase 3 plan

Per spec ("P0/P1 全做; P2 effort:S 全做, M 看情況, L 跳過; P3 不做"):

- **All P1 (8)**: UX-001, 002, 003, 004, 005, 006, 007, 008
- **All P2 effort:S**: UX-009, 010, 011, 013, 015 (UX-013 is folded into UX-004)
- **P2 effort:M**: UX-012 (skip — repetitive, low ROI; revisit at commercialisation)
- **P3**: skip both (UX-014, plus the design-token migration noted in Discovery Summary)

Total fixes: ~12, batched roughly one finding per commit. Estimated effort: ~70-80 minutes of editing + verification, within Phase 3's 90-minute budget.
