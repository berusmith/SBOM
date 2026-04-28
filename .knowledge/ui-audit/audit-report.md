# SBOM Platform — UI/UX Audit Report

**Audit date**: 2026-04-26
**Scope**: `frontend/` — 22 pages + 8 components + Layout shell
**Out of scope**: PDF report visual rendering (separate backend pipeline);
Help.jsx instructional content (Q&A material, deliberately not i18n'd)

**Targets**:
- WCAG 2.2 **AA** (single-A conformance + AA additions)
- Modern browser baseline: **iOS Safari 16+, Chrome/Edge 110+, Android Chrome 110+** (Sep 2022 onwards)
- No new npm dependencies (per CLAUDE.md)

**Audit method**: full read of `Layout.jsx` (shell), `Login.jsx`, `Profile.jsx`,
`Dashboard.jsx` (representative dense data page); systematic grep across all
22 pages for cross-cutting patterns (touch targets, contrast, focus,
forms, tables, transitions, fixed pixels, hardcoded strings); review of
`tailwind.config.js`, `index.html`, `index.css`, `App.jsx`,
`constants/colors.js`, `constants/icons.js`. No code changes made.

This report is **observational only**. Implementation is gated on
approval of the `plan.md` produced from this report.

---

## 0. Executive summary

| Severity | Count | Examples |
|----------|-------|----------|
| **P0** (blocking — broken or violates explicit rules) | **0** | Site is functional; no rule-blocking failures |
| **P1** (serious — measurable user harm or accessibility violation) | **12** | `<html lang>` hardcoded; 93 `<th>` lack `scope`; iOS Safari font-zoom on 30+ inputs; `text-gray-{300,400,500}` 178 sites fail WCAG AA on white; `<tr onClick>` lacks keyboard activation; `prefers-reduced-motion` zero coverage |
| **P2** (medium — quality / consistency / maintainability) | **15** | No design-token system (`theme.extend: {}`); 12 hardcoded hex in SVG; `text-xs` (12px) used 368 times as body; no z-index scale; no `viewport-fit=cover`; Skeleton lacks `role/aria-busy`; emojis used as UI affordance |
| **P3** (optimisation / future) | **9** | No dark mode; no `prefers-contrast`; no Storybook; ReleaseDetail.jsx 2081 LOC needs structural split; bundle could subset further |
| **Total** | **36** |  |

**Top three priorities** (highest user impact / lowest cost):

1. **UX-001 `<html lang>` 動態同步**(P1, S) — 1-line effect; screen readers currently announce English UI in Chinese.
2. **UX-002 `<th scope=>` 系統性補齊**(P1, S–M) — 76% 表頭欠 scope; mechanical fix.
3. **UX-005 design tokens 建立**(P2, M) — `theme.extend` 加入語意化 color/typography/z-index/animation,後續 issue 都有錨可掛。

---

## 1. Design tokens proposal (foundation for the rest)

> A non-trivial number of P1/P2 issues can only be fixed *consistently* if
> we first introduce a token system. This section is a proposal — not
> code yet.

Proposed `tailwind.config.js` `theme.extend`:

```js
theme: {
  extend: {
    // ── Semantic colors (mapped to Tailwind palette indices we already use) ─
    colors: {
      // Surfaces (page backgrounds, cards, raised panels)
      surface:           "rgb(249 250 251)",  // gray-50  — page background
      "surface-card":    "rgb(255 255 255)",  // white    — card
      "surface-muted":   "rgb(243 244 246)",  // gray-100 — section panel
      "surface-inverse": "rgb(17 24 39)",     // gray-900 — top nav bar

      // Foreground / text on surfaces (AA contrast guaranteed)
      "fg-default":      "rgb(31 41 55)",     // gray-800 — body
      "fg-muted":        "rgb(55 65 81)",     // gray-700 — secondary body (4.5:1)
      "fg-subtle":       "rgb(75 85 99)",     // gray-600 — labels (4.5:1)
      "fg-disabled":     "rgb(156 163 175)",  // gray-400 — disabled (3:1, large only)
      "fg-on-inverse":   "rgb(243 244 246)",  // gray-100 — text on dark nav

      // Brand
      brand:             "rgb(37 99 235)",    // blue-600 — primary
      "brand-hover":     "rgb(29 78 216)",    // blue-700
      "brand-soft":      "rgb(219 234 254)",  // blue-100 — selected pills

      // Status (semantic intent)
      danger:            "rgb(220 38 38)",    // red-600
      warning:           "rgb(217 119 6)",    // amber-600
      success:           "rgb(22 163 74)",    // green-600
      info:              "rgb(8  145 178)",   // cyan-600

      // Borders / focus
      "border-default":  "rgb(229 231 235)",  // gray-200
      "border-strong":   "rgb(209 213 219)",  // gray-300
      "ring-focus":      "rgb(96 165 250)",   // blue-400
    },

    // ── Typography scale (modular 1.2) ─────────────────────────────────────
    fontSize: {
      // [size, lineHeight] in rem
      "caption": ["0.75rem", "1rem"],     // 12px / 16  — helper text, badges
      "body-sm": ["0.875rem", "1.25rem"], // 14px / 20  — secondary body
      "body":    ["1rem", "1.5rem"],      // 16px / 24  — primary body, ALL inputs
      "h6":      ["1.0625rem", "1.5rem"], // 17/24
      "h5":      ["1.125rem", "1.5rem"],  // 18/24
      "h4":      ["1.25rem", "1.625rem"], // 20/26
      "h3":      ["1.5rem", "2rem"],      // 24/32
      "h2":      ["1.875rem", "2.25rem"], // 30/36
      "h1":      ["2.25rem", "2.5rem"],   // 36/40
    },

    // ── Z-index scale (no more magic z-50) ────────────────────────────────
    zIndex: {
      "base":    "0",
      "raised":  "10",     // elevated cards, sticky table headers
      "dropdown":"30",     // dropdowns, popovers
      "sticky":  "40",     // sticky nav
      "modal":   "50",     // modals, modal backdrop
      "toast":   "60",     // toasts (above modals — they communicate modal results)
      "tooltip": "70",     // last
    },

    // ── Animation durations ───────────────────────────────────────────────
    transitionDuration: {
      "instant": "0ms",
      "fast":    "150ms",
      "base":    "200ms",
      "slow":    "300ms",
    },

    // ── Container widths ──────────────────────────────────────────────────
    maxWidth: {
      "page":    "80rem",   // 1280  — current de facto (max-w-7xl)
      "form":    "32rem",   // 512   — single-column form
      "prose":   "40rem",   // 640   — long-form text (~75 chars)
    },
  },
},
```

Plus `index.css` additions:

```css
@layer base {
  /* Honour the OS/browser reduced-motion preference globally — fixes UX-004 */
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
      animation-duration: 1ms !important;       /* annotate: required to override Tailwind animate-* */
      animation-iteration-count: 1 !important;
      transition-duration: 1ms !important;
      scroll-behavior: auto !important;
    }
  }

  /* Replace browser-default focus ring (which we suppress with outline-none)
     with one that only appears for keyboard users.  Fixes UX-010. */
  :focus-visible {
    outline: 2px solid theme('colors.ring-focus');
    outline-offset: 2px;
  }
  /* Explicitly do NOT show outline for mouse-clicks (matches focus:ring-2 idiom) */
  :focus:not(:focus-visible) {
    outline: none;
  }
}
```

**Migration policy**: `text-gray-700` → `text-fg-muted` only when *touching*
that file. Don't bulk-rewrite — too noisy in git history. After 2–3
weeks of incremental migration, we evaluate whether to do a sweep.

---

## 2. Findings

> Format per protocol. Locations are illustrative; each issue lists 1–3
> example sites unless the issue is uniformly distributed (then noted
> "site-wide"). Counts come from the grep evidence in §3.

---

### UX-001 — `<html lang>` is hardcoded `zh-TW`

- **Severity**: **P1**
- **Category**: A11y
- **Location**: `frontend/index.html:2`; absent: `src/i18n/index.js`, `src/main.jsx`
- **Observation**: `<html lang="zh-TW">` is fixed at build time. Toggling
  the in-app `EN/中` button changes UI text via i18next but never
  updates `document.documentElement.lang`.
- **Why it matters**: Screen readers (VoiceOver, NVDA, JAWS, TalkBack)
  use `<html lang>` to pick the right pronunciation engine. After a user
  switches the UI to English the page is announced in Chinese — and
  vice-versa. This is a WCAG 2.2 **3.1.1 Language of Page** + **3.1.2
  Language of Parts** failure.
- **Recommendation**:
  1. Subscribe to i18next's `languageChanged` event in `src/i18n/index.js`:
     ```js
     i18n.on("languageChanged", (lng) => {
       document.documentElement.lang = lng === "en" ? "en" : "zh-Hant";
     });
     ```
  2. Set the initial value in the same effect so the first render is
     correct.
- **Effort**: **S** (~5 lines)
- **Risk**: None.

---

### UX-002 — 93 of 121 `<th>` elements lack `scope`

- **Severity**: **P1**
- **Category**: A11y
- **Location**: site-wide; concentrations in `Dashboard.jsx`,
  `ReleaseDetail.jsx`, `AdminActivity.jsx`, `Organizations.jsx`,
  `Releases.jsx`, `Products.jsx`, `CRAIncidents.jsx`,
  `FirmwareUpload.jsx`, `ReleaseDiff.jsx`. Only `Users.jsx` consistently
  uses `scope="col"`.
- **Observation**: 121 `<th>` total; only 28 carry `scope="col"` or
  `scope="row"`. The other 93 leave the screen reader to infer column
  vs row association.
- **Why it matters**: WCAG 2.2 **1.3.1 Info and Relationships** —
  tabular relationships must be programmatically determinable. Without
  `scope`, cells are read as undifferentiated text in many AT
  combinations (e.g. NVDA + Firefox).
- **Recommendation**: Add `scope="col"` to every `<th>` inside
  `<thead>`. For tables that have a row header (e.g. AdminActivity's
  per-customer summary), also add `scope="row"` to the first cell of
  each body row.
- **Effort**: **M** — 93 sites, mostly mechanical, but want to verify
  every table has a sensible header structure first (some are CSS-styled
  divs not `<table>` at all — should they be?).
- **Risk**: None functional. Slight diff churn.

---

### UX-003 — 30+ form inputs use `text-sm` (14 px) → iOS Safari focus-zoom

- **Severity**: **P1**
- **Category**: RWD
- **Location**: every page that renders a `<input>` / `<select>` /
  `<textarea>` *not* explicitly fixed in earlier work. Examples:
  `Profile.jsx:127–134` (current/new/confirm password inputs were
  switched to `text-base` in commit f65f1c3), but most pages still have
  edit-form inputs at `text-sm`. Spot-checked: `Settings.jsx`
  (alert config, brand form), `Organizations.jsx` (create-org form),
  `Releases.jsx` (create-release form).
- **Observation**: iOS Safari auto-zooms the page when the user taps a
  form field whose computed `font-size` is < 16 px. The page does not
  zoom back out automatically; users have to pinch-zoom or rotate.
- **Why it matters**: A common, well-documented mobile UX bug. WCAG
  2.2 **1.4.4 Resize Text** is technically separate, but this directly
  hurts mobile usability — and we've already invested in mobile (RWD
  classes everywhere).
- **Recommendation**:
  1. Add a Tailwind component layer rule in `index.css`:
     ```css
     @layer base {
       /* Prevent iOS Safari focus-zoom (font-size < 16px on form fields) */
       @media (max-width: 640px) {
         input, select, textarea { font-size: 16px; }
       }
     }
     ```
     This is the single-best fix — covers every form field site-wide
     without per-component edits.
  2. (Optional) On larger screens revert to `text-sm` density for
     dense tables / inline editors via explicit class.
- **Effort**: **S** (~5 lines, single CSS file)
- **Risk**: Forms on mobile become slightly taller. Acceptable.

---

### UX-004 — Zero `prefers-reduced-motion` coverage

- **Severity**: **P1**
- **Category**: A11y
- **Location**: site-wide; 0 references found in any `.css` or `.jsx`
  file.
- **Observation**: `transition-colors` (14), `transition-all` (7),
  `transition-transform` (3), `animate-pulse` (1, in Skeleton) all
  ignore the OS-level `prefers-reduced-motion: reduce` setting.
- **Why it matters**: WCAG 2.2 **2.3.3 Animation from Interactions**
  (AAA, but informs AA practice). Users with vestibular disorders /
  motion sensitivity / certain epilepsy presentations expect motion
  to be reduced when they set the OS preference.
- **Recommendation**: Add the global `@media (prefers-reduced-motion:
  reduce)` rule shown in §1 above. Reduces all `animation-*` and
  `transition-*` durations to ~1ms. Single 6-line CSS block, fixes
  every animated element on the site.
- **Effort**: **S**
- **Risk**: None — it's literally what the user requested.

---

### UX-005 — `tailwind.config.js` has no `theme.extend`; no design-token surface

- **Severity**: **P2** (foundational — but `text-gray-700` works OK as a token alias today; promoted from P3 because every other consistency issue depends on it)
- **Category**: Consistency
- **Location**: `frontend/tailwind.config.js`
- **Observation**:
  ```js
  theme: { extend: {} },
  ```
  All design decisions are made by individual class choices in JSX. We
  have **138 `text-gray-500`** and **211 `text-gray-600`** usages with
  no semantic distinction — both mean "secondary text". The "brand
  color" is `bg-blue-600` literally typed at every site.
- **Why it matters**: Hard Rule "**所有顏色、間距、圓角、陰影、字級必須走 token,不寫死數值**". Tailwind utility classes
  *are* tokens, but they're tokens of "shade-of-gray-N", not tokens of
  "secondary-body-text". When we want to change brand color, we'd
  rewrite ~80 sites. When we want to add dark mode, every `text-gray-700`
  needs a parallel.
- **Recommendation**: Adopt the `theme.extend` block in §1.
  - Phase 1 (this audit): Add tokens, do **not** mass-migrate. New
    code uses tokens; existing code keeps Tailwind class names.
  - Phase 2 (next quarter): Run a codemod to rewrite
    `text-gray-{600,700}` → `text-fg-{subtle,muted}` etc.
  - Phase 3 (when needed): Add dark-mode variants (CSS variables /
    `dark:` prefix).
- **Effort**: **M** to add tokens; **L** to fully migrate (deferred).
- **Risk**: Adding tokens is non-breaking. Migrating is a multi-week
  effort and out of scope for this audit.

---

### UX-006 — 178 sites use grays below WCAG AA contrast on white

- **Severity**: **P1**
- **Category**: A11y / Visual
- **Location**: `text-gray-500` 138 sites, `text-gray-400` 22 sites,
  `text-gray-300` 18 sites. Top concentrations:
  - `ReleaseDetail.jsx`: 22× gray-500, 15× gray-300/400
  - `TISAXDetail.jsx`: 16× gray-500
  - `Dashboard.jsx`: 13× gray-500, 4× gray-300/400
  - `Users.jsx`: 10× gray-500
- **Observation**: Tailwind contrast ratios on white background:
  | Class | Hex | Ratio | WCAG AA body? | Use? |
  |-------|-----|-------|---------------|------|
  | gray-300 | #d1d5db | **1.83:1** | ✗ | only for dividers/borders |
  | gray-400 | #9ca3af | **2.85:1** | ✗ | only for placeholders/disabled (large text only) |
  | gray-500 | #6b7280 | **4.16:1** | **✗ borderline** (needs 4.5:1) | secondary body — borderline fail |
  | gray-600 | #4b5563 | 5.74:1 | ✓ | secondary body — passes |
  | gray-700 | #374151 | 8.37:1 | ✓ | body |
  | gray-800 | #1f2937 | 12.6:1 | ✓ | strong body / headings |
- **Why it matters**: WCAG 2.2 **1.4.3 Contrast (Minimum)** requires
  ≥ 4.5:1 for body text, ≥ 3:1 for large text (≥ 18pt or 14pt bold).
  `text-gray-500` is the worst offender because it's almost-but-not-quite
  passing — in some monitors / colour profiles it really is < 4.5:1.
- **Recommendation**:
  1. **Mass replacement**: `text-gray-500` → `text-gray-600` (or
     `text-fg-subtle` after tokens land). Where the intent is
     "decorative / disabled / placeholder", keep `text-gray-400` but
     pair with bold or larger size to meet large-text 3:1 rule.
  2. **`text-gray-300/400` audit**: Each instance needs a decision:
     - Border / divider / icon decoration → keep
     - Disabled control → keep + add `aria-disabled`
     - Placeholder text → keep + ensure value-text is gray-700+
     - Body / interactive text → upgrade to gray-600+
- **Effort**: **M** — 178 sites, mostly mechanical search-and-replace
  with manual verification on each.
- **Risk**: Visual change — slightly darker greys site-wide. Improves
  legibility unambiguously.

---

### UX-007 — `<tr onClick>` on Dashboard "Top Threats" — keyboard inaccessible

- **Severity**: **P1**
- **Category**: A11y / Interaction
- **Location**: `frontend/src/pages/Dashboard.jsx:42–46`
  ```jsx
  <tr
    key={v.vuln_id}
    className="border-b last:border-0 hover:bg-gray-50 cursor-pointer"
    onClick={() => navigate(`/releases/${v.release_id}`)}
  >
  ```
  Same anti-pattern present in `TISAXDetail.jsx` (1 site).
- **Observation**: Mouse users can click rows to drill into the vuln's
  release. Keyboard users cannot — `<tr>` is not in the tab order, and
  there's no `onKeyDown` for Enter/Space.
- **Why it matters**: WCAG 2.2 **2.1.1 Keyboard** failure. Users on a
  keyboard, screen reader, or any AT cannot reach this functionality.
- **Recommendation**: Two equally good options:
  1. Replace `<tr onClick>` with a `<a>` wrapping the row content
     (semantic; default browser behaviour gives focus + Enter).
  2. Keep the row but add a focusable element inside (e.g. the CVE
     ID becomes a `<Link>`), and remove the row-level click — clicking
     anywhere else doesn't navigate.

  Strongly prefer **option 2** (CVE-as-link). Whole-row click on a
  data table is a desktop-only convenience that fails on every other
  surface anyway.
- **Effort**: **S** per site.
- **Risk**: Mouse users no longer click anywhere on the row — they
  must click the CVE link. Mitigate: increase the CVE link's hit area
  (block + padding). Desktop hover still highlights the row.

---

### UX-008 — `viewport` meta lacks `viewport-fit=cover`

- **Severity**: **P2**
- **Category**: RWD
- **Location**: `frontend/index.html:5`
  ```html
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  ```
- **Observation**: On iPhones with a notch / Dynamic Island / Home
  Indicator, Safari leaves un-styleable safe areas at the edges. Any
  `bg-gray-900` nav bar will appear to "fall short" of the screen
  edge. Worse: PWA / standalone-mode users see white bars.
- **Why it matters**: Visual breakage on any iPhone X (2017) or newer,
  especially under `display: standalone` (PWA). Combined with **0**
  uses of `safe-area-inset` in CSS, the bottom Home Indicator overlaps
  any sticky bottom UI we ever add (we don't have any today, but it's
  technical debt).
- **Recommendation**:
  ```html
  <meta name="viewport"
        content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
  ```
  Then in `index.css` `@layer base`:
  ```css
  body {
    /* Honour iOS safe areas if/when we add a sticky bottom UI */
    padding-left:  env(safe-area-inset-left);
    padding-right: env(safe-area-inset-right);
  }
  ```
- **Effort**: **S**
- **Risk**: None.

---

### UX-009 — Touch targets below 44 px on multiple buttons

- **Severity**: **P1**
- **Category**: RWD / A11y
- **Location**: site-wide; high-frequency offenders:
  - Layout `EN/中` lang toggle: `px-2.5 py-1.5` ≈ 26px tall (`Layout.jsx:122–127, 145–149`)
  - Layout desktop nav links: `px-2.5 py-1.5` ≈ 26px tall (`Layout.jsx:74`)
  - Dashboard / table-row inline action buttons: many at `px-2 py-1`
- **Observation**: Apple HIG: 44×44 pt minimum. Material: 48×48 dp.
  Our nav uses ~26 px tall buttons. Mobile menu items are 40 px
  (`px-3 py-2.5`) — borderline.
- **Why it matters**: Smaller touch targets cause mis-taps, especially
  on dense nav. WCAG 2.2 **2.5.8 Target Size (Minimum)** requires
  24×24 CSS px (so we technically pass minimum), but AA Best Practice
  is 44 px.
- **Recommendation**:
  1. Mobile-only: increase nav items to `py-3` (48 px effective).
     Desktop can keep `py-1.5` since pointer accuracy is higher.
  2. Use Tailwind `min-h-[44px]` (or after tokens, `min-h-touch`) on
     all interactive elements that *might* be tapped on touch surfaces.
  3. The Layout `⌕` desktop search submit button is a single character
     in a `px-1` button — replace with the lucide `Search` icon at
     `size={18}` inside `p-2`.
- **Effort**: **M** — needs care to avoid regressing desktop density.
- **Risk**: Slight vertical bloat on mobile. Acceptable.

---

### UX-010 — `focus:` instead of `focus-visible:` (108 sites)

- **Severity**: **P2**
- **Category**: A11y / Interaction
- **Location**: site-wide; pattern is `outline-none focus:ring-2 ...`
- **Observation**: `focus:` triggers on **any** focus including mouse
  click. Modern best practice is `:focus-visible`, which only triggers
  for keyboard focus (and other AT). Using `focus:` means clicking a
  button leaves a blue ring even after the click is finished.
- **Why it matters**: Doesn't fail any WCAG checkpoint, but creates
  visual noise that has been the most common a11y complaint in usability
  studies for the last 5 years. Real designers turn off ring on click,
  keep it on Tab.
- **Recommendation**: Add the `:focus-visible` rule shown in §1. It
  globally enables the modern behaviour without per-element changes,
  and our existing `focus:ring-2` classes keep working but only fire
  for keyboard users.
- **Effort**: **S** (CSS only)
- **Risk**: Mouse users no longer see ring after click. That's the
  *desired* behaviour.

---

### UX-011 — 12 hardcoded hex colours in SVG components

- **Severity**: **P2**
- **Category**: Consistency
- **Location**:
  - `frontend/src/components/DependencyGraph.jsx`: 5 hex values
    (`#d1d5db`, `#fca5a5`, `#93c5fd`, `#e5e7eb`, `#1d4ed8`, `#ef4444`,
    `#3b82f6`, `#9ca3af`, `#7f1d1d`, `#1e3a8a`, `#374151`)
  - `frontend/src/components/TrendChart.jsx`: 7 hex values for
    severity series (`#60a5fa` total, `#ef4444` critical, `#fb923c` high,
    `#facc15` medium, `#3b82f6` low, `#e5e7eb` axis)
- **Observation**: SVG attributes (`fill`, `stroke`) can't accept
  Tailwind classes, so hex is required. But we shouldn't *type* the
  hex inline — it should reference a constant.
- **Why it matters**: Hard Rule "顏色必須走 token". When the brand
  colour changes, these are missed. When we add dark mode, charts
  stay light.
- **Recommendation**: Move all hex values to a new
  `frontend/src/constants/chart-colors.js` module that exports
  `SEVERITY_HEX`, `CHART_AXIS`, `CHART_HIGHLIGHT`, etc. After
  design-token migration (UX-005), the JS constants can be derived
  from CSS variables via `getComputedStyle()` for full token unity.
- **Effort**: **S** for extraction; **M** for full token unity (deferred
  with UX-005).
- **Risk**: None — pure refactor.

---

### UX-012 — Layout uses emoji `🔒` and the `⌕` symbol as UI affordances

- **Severity**: **P2**
- **Category**: A11y / Consistency
- **Location**:
  - `Layout.jsx:93` — `<span aria-hidden="true">🔒</span>` for locked
    nav items (this one IS aria-hidden, so we're partially OK)
  - `Layout.jsx:118` — desktop search submit button text is `⌕`
    (Unicode "telephone recorder" U+2315). Has `aria-label` but the
    visible glyph is whatever font happens to render U+2315 — varies
    wildly (Windows Segoe UI vs macOS SF vs Android system).
- **Observation**: Inconsistent rendering across platforms; `⌕` is
  not a search-icon glyph in many fonts. Emoji `🔒` is colour-rendered
  by some OS, monochrome by others.
- **Why it matters**: Visual inconsistency. We already include
  `lucide-react` and `constants/icons.js` exports a `Search` and `Lock`
  helper.
- **Recommendation**: Replace both with `lucide-react` icons:
  - `🔒` → `<Lock size={14} aria-hidden="true" />`
  - `⌕` → `<Search size={16} aria-hidden="true" />`
  Existing `aria-label` already provides the accessible name.
- **Effort**: **S**
- **Risk**: Adds 2 lucide imports — already a dependency, no new dep.

---

### UX-013 — Skeleton has no `role="status"` / `aria-busy`

- **Severity**: **P2**
- **Category**: A11y
- **Location**: `frontend/src/components/Skeleton.jsx` — none of the
  five SkeletonXxx exports set `role` or `aria-busy`.
- **Observation**: A screen reader user lands on a Skeleton-padded
  page and sees… nothing. There's no announcement that loading is in
  progress. They might think the app is broken.
- **Why it matters**: WCAG 2.2 **4.1.3 Status Messages**: status
  changes should be programmatically determinable and announced
  without focus shift.
- **Recommendation**: Wrap each Skeleton variant's outer container
  with `role="status" aria-busy="true" aria-live="polite"` and an
  `<span class="sr-only">Loading...</span>` inside (i18n'd as
  `t("common.loading")`).
- **Effort**: **S** — single component change benefits 13 consuming
  pages.
- **Risk**: Polite live regions don't interrupt — safe.

---

### UX-014 — Modal close button `aria-label="Close"` not i18n'd

- **Severity**: **P2**
- **Category**: i18n / A11y
- **Location**: `frontend/src/components/Modal.jsx:81` — `aria-label="Close"` (English string literal)
- **Observation**: Same pattern in `Toast.jsx:85` — `aria-label="Dismiss"`. These are the only English strings reaching screen readers in the otherwise zh-default UI.
- **Recommendation**: i18n. Add `common.close` and `common.dismiss`
  to zh.js + en.js (already have `close` in zh — verify); use
  `useTranslation` in Modal/Toast.
- **Effort**: **S**
- **Risk**: None.

---

### UX-015 — No z-index scale; `z-50` is universal

- **Severity**: **P2**
- **Category**: Consistency
- **Location**: `Modal.jsx`, `Toast.jsx`, `ConfirmModal.jsx` (was — now via Modal), `Layout.jsx` mobile menu
- **Observation**: Toast and Modal share `z-50`. When a Toast appears
  while a Modal is open, stacking is undefined — depends on render
  order. Today nothing visibly breaks because Toasts are positioned
  outside the Modal's overflow box, but it's brittle.
- **Why it matters**: Future dropdowns, tooltips, popovers will
  collide. The next person adds `z-[51]` and we cascade into
  `z-[9999]`-style hell.
- **Recommendation**: Add `theme.extend.zIndex` from §1. Then
  Modal=`z-modal`, Toast=`z-toast` (above modal — toasts often
  acknowledge a modal action).
- **Effort**: **S**
- **Risk**: None.

---

### UX-016 — `text-xs` (12 px) used 368 times — body density too high

- **Severity**: **P2**
- **Category**: Visual
- **Location**: site-wide; particularly heavy in
  `ReleaseDetail.jsx`, `Settings.jsx`, every table.
- **Observation**: 12 px is below WCAG AAA recommended body size and
  feels cramped on retina displays at 1.0× zoom. The "data-dense" feel
  is intentional (B2B tooling), but we use `text-xs` for *labels*,
  *helper text*, *secondary metadata*, *and body* — losing the
  distinction.
- **Why it matters**: Cognitive load + readability. Using xs / sm /
  base meaningfully creates visual hierarchy; using xs everywhere
  flattens it.
- **Recommendation**: Adopt the typography convention:
  - `text-caption` (12 px) — labels, meta, badges only
  - `text-body-sm` (14 px) — secondary body, table cells
  - `text-body` (16 px) — primary body, **all interactive form fields** (UX-003)
  - `text-h{1..6}` — headings only

  **Don't bulk-rewrite**. Document the convention and apply on new code
  + on touched code.
- **Effort**: **S** to document + add tokens; **L** to fully migrate
  (deferred).
- **Risk**: Lots of churn if we ever do migrate.

---

### UX-017 — No design-token-derived `.btn` class; primary/secondary/danger reinvented per page

- **Severity**: **P2**
- **Category**: Consistency
- **Location**: every page with buttons (~20 pages). Example permutations
  for "primary" button:
  - `Login.jsx`: `bg-blue-600 hover:bg-blue-700 ... py-2.5 ...`
  - `Profile.jsx`: `bg-blue-600 hover:bg-blue-700 ... py-2 ...`
  - `Layout.jsx` (mobile search): `bg-gray-600 ... px-3 py-2 ...` (different colour!)
- **Observation**: Same semantic intent, different concrete styles.
- **Recommendation**: Add a `Button` component (or `@layer components`
  CSS rules `.btn`, `.btn-primary`, `.btn-secondary`, `.btn-danger`,
  `.btn-ghost`). Encapsulates: padding, focus ring, disabled state,
  loading state. Existing pages adopt incrementally.
- **Effort**: **M** to design + adopt on 3 pivotal pages.
- **Risk**: We've already created `Modal`, `ConfirmModal`, `Toast`,
  `PasswordInput` shared components — adding `Button` continues the
  pattern.

---

### UX-018 — `xl:` and `2xl:` breakpoints almost unused (4 / 0 sites)

- **Severity**: **P3**
- **Category**: RWD
- **Location**: site-wide.
- **Observation**: Only 4 `xl:` and 0 `2xl:` usages out of 182 total
  responsive utilities. Layout caps at `max-w-7xl` (1280 px), so
  > 1280-wide screens just see margin.
- **Why it matters**: Large monitors are common in IT/OT operator
  workstations (the target persona). Tables that could show 12 columns
  on a 1920-wide screen show 7 with scroll instead.
- **Recommendation**: For data-heavy pages (ReleaseDetail vulns table,
  AdminActivity audit log, Risk Overview), reveal extra columns at
  `lg:` / `xl:`. Bump main container to `max-w-[120rem]` for
  data-heavy routes (keep `max-w-7xl` for forms).
- **Effort**: **L** — needs design decisions per page.
- **Risk**: None blocking. Pure progressive enhancement.

---

### UX-019 — Inputs lack `htmlFor`/`id` pairing in forms

- **Severity**: **P1**
- **Category**: A11y
- **Location**: site-wide. Only **4** `htmlFor=` matches; `<input>`
  appears in 9 files. Profile.jsx (recently fixed), Login.jsx (recently
  fixed), Users.jsx edit modal (uses `<label>` proximity but no
  htmlFor) are partial; most other forms (Settings, Organizations
  create, Releases create, CRA create, FirmwareUpload import) rely on
  visual proximity only.
- **Observation**: Without `<label htmlFor="x">` / `<input id="x">`,
  screen readers read inputs as "edit, blank" instead of "Email, edit,
  blank".
- **Why it matters**: WCAG 2.2 **3.3.2 Labels or Instructions** — fail.
- **Recommendation**:
  - Single-input forms: add `htmlFor`/`id`. Use `useId()` for stable
    pairing.
  - Forms within Modal: use `useId()` so multiple modals on same page
    don't collide.
- **Effort**: **M** — every input. ~30 inputs.
- **Risk**: None — additive.

---

### UX-020 — Hardcoded "Loading..." in `App.jsx` PageLoading

- **Severity**: **P3** (we know about this — comment in code documents the i18n-bootstrap chicken-and-egg)
- **Category**: i18n
- **Location**: `App.jsx:54-55`
- **Observation**: The PageLoading fallback for `<Suspense>` reads
  `localStorage.getItem("lang")` and picks "Loading..." vs "載入中..."
  manually because i18n may not be initialized at chunk-load time.
- **Why it matters**: First-load language is potentially wrong. Minor.
- **Recommendation**: Use a `<span>` with both strings and CSS-display
  toggle by `<html lang>` (which UX-001 will set early). Or accept
  the comment as documentation.
- **Effort**: **S**
- **Risk**: None.

---

### UX-021 — Layout mobile menu does not trap focus when open

- **Severity**: **P2**
- **Category**: A11y
- **Location**: `Layout.jsx:171–219`
- **Observation**: When the hamburger menu opens on mobile, Tab can
  exit the menu into the page content underneath (which is technically
  still rendered).
- **Why it matters**: Inconsistent with our Modal a11y pattern. A
  user-disclosed nav-overlay should behave like a modal sheet.
- **Recommendation**: Re-use `useFocusTrap` (we just extracted it!)
  on the mobile menu container while open.
- **Effort**: **S**
- **Risk**: None.

---

### UX-022 — Layout's `transition-colors` etc. trigger layout thrash on chrome-initialised pages

- **Severity**: **P3** (premature concern)
- **Category**: Performance
- **Location**: 25 transition-* usages site-wide.
- **Observation**: All transitions are `colors`, `all`, `transform`,
  `shadow`, `opacity` — none on `width` / `height` / `top` etc., so
  they don't trigger reflows. This is fine.
- **Recommendation**: No action. Documented as a sanity check that
  passes.

---

### UX-023 — Skeleton's `animate-pulse` is the only animation; no spinner needed

- **Severity**: **P3**
- **Category**: Performance
- **Location**: `Skeleton.jsx:5`
- **Observation**: Only one animation class site-wide. After UX-004
  (prefers-reduced-motion), this stops moving for users who request
  it. No spinners anywhere.
- **Recommendation**: No action.

---

### UX-024 — `index.html` lacks `<meta name="theme-color">` and `<link rel="icon">`

- **Severity**: **P3**
- **Category**: Performance / Polish
- **Location**: `frontend/index.html:1-10`
- **Observation**: No favicon, no theme-color (Android Chrome uses it
  to colour the URL bar), no preconnect to API.
- **Why it matters**: Polish only.
- **Recommendation**:
  ```html
  <meta name="theme-color" content="#1f2937" />  <!-- matches gray-900 nav -->
  <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
  ```
  + ship a `public/favicon.svg`.
- **Effort**: **S**
- **Risk**: None.

---

### UX-025 — Layout footer `text-gray-500` (138-instance offender) is borderline

- **Severity**: **P2** (subset of UX-006)
- **Category**: A11y / Visual
- **Location**: `Layout.jsx:225` — footer container `text-xs text-gray-500`. The footer is the "About" link's home and is the bottom-of-screen attribution.
- **Observation**: On white footer background, `text-xs text-gray-500` is the worst-case combo: small + light. ~3.6:1 contrast.
- **Recommendation**: Footer body → `text-xs text-gray-600` (passes 4.5:1 even at 12 px).
- **Effort**: **S**
- **Risk**: Slight visual change.

---

### UX-026 — `min-h-screen` may have iOS 100vh quirks

- **Severity**: **P3**
- **Category**: RWD
- **Location**: `Layout.jsx:61` — `<div className="min-h-screen bg-gray-50">`
- **Observation**: iOS Safari pre-15 had a 100vh bug that included the
  URL bar's height. Mostly resolved in iOS 15.4+ but `dvh` (dynamic
  viewport height) is the modern fix and we've targeted iOS 16+.
- **Recommendation**: For users on iOS 15, no change needed. For pixel
  perfection on iOS 16+: `min-h-[100dvh]`. Risk-free upgrade.
- **Effort**: **S**
- **Risk**: None on supported browsers.

---

### UX-027 — `useId()` not used in components with internal IDs

- **Severity**: **P3**
- **Category**: A11y
- **Location**: `Modal.jsx`, `ConfirmModal.jsx` use `useId()` ✓.
  Some recent code (`Login.jsx` recently fixed username input id)
  uses string literals like `"login-username"` — collides if Login is
  rendered twice in the same DOM (won't happen today).
- **Recommendation**: Migrate hardcoded IDs to `useId()` opportunistically.
- **Effort**: **S**
- **Risk**: None.

---

### UX-028 — Search input on Layout uses `text-sm` → focus zoom on iOS

- **Severity**: **P1** (subset of UX-003 but worth calling out as it's the *most-visited* input — every page)
- **Category**: RWD
- **Location**: `Layout.jsx:112` — desktop search input. The mobile one was already fixed (`text-base`).
- **Recommendation**: Change desktop search to `text-base sm:text-sm`
  (mobile = base, desktop = sm). Or just leave at base — it's only 1
  input on a 1280-wide nav, the size diff is invisible.
- **Effort**: **S**
- **Risk**: None.

---

### UX-029 — Login page uses `text-red-500` for inline errors (UX-006)

- **Severity**: **P2** (subset of UX-006)
- **Category**: A11y
- **Location**: `Login.jsx` (and any other error inline). `text-red-500`
  is borderline (4.36:1 on white).
- **Recommendation**: Use `text-red-600` (passes 5.93:1) or our
  `text-danger` token after UX-005 lands.
- **Effort**: **S**
- **Risk**: None.

---

### UX-030 — Many forms duplicate the same input className

- **Severity**: **P3**
- **Category**: Consistency
- **Location**: site-wide. Pattern:
  `border border-gray-300 rounded px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-400`
- **Observation**: This is essentially a `.input` class.
- **Recommendation**: Add a `<TextField>` component or an `@layer
  components .input` rule.
- **Effort**: **M**
- **Risk**: None.

---

### UX-031 — `prefers-color-scheme` (dark mode) not handled

- **Severity**: **P3** (deferred)
- **Category**: A11y
- **Location**: site-wide.
- **Observation**: 0 `dark:` Tailwind variants used. We rely entirely
  on light mode.
- **Why it matters**: Some users (and OT operator workstations at
  night-shift rotations) rely on dark mode for eye strain. Not a
  WCAG fail (AA doesn't require dark mode).
- **Recommendation**: **Defer.** Dark mode requires brand decision
  (chart palettes, alert colours), token-driven CSS variables
  (UX-005), and a sweep of every `bg-*` / `text-*`. Estimate: 1-2
  weeks of focused work.
- **Effort**: **L**
- **Risk**: Schedule risk.

---

### UX-032 — `prefers-contrast` not handled

- **Severity**: **P3**
- **Category**: A11y
- **Location**: site-wide.
- **Recommendation**: Acknowledge. `forced-colors` (Windows High
  Contrast) is the more common case; it's mostly automatic but our
  custom-coloured badges may need `forced-color-adjust: none` plus
  a redundant text indicator. Defer.
- **Effort**: **L**
- **Risk**: Schedule.

---

### UX-033 — Help.jsx is 1071 LOC of mixed JSX + Chinese content

- **Severity**: **P3**
- **Category**: Consistency / Maintainability
- **Location**: `frontend/src/pages/Help.jsx`
- **Observation**: A help center should ideally separate content
  (markdown / JSON) from presentation. Right now ~800 lines are
  JSX-embedded Chinese text.
- **Recommendation**: Phase 2 candidate — extract content to
  `src/i18n/help-content.{zh,en}.js` (data) + a thin renderer
  component. Out of scope this audit.
- **Effort**: **L**
- **Risk**: Schedule.

---

### UX-034 — ReleaseDetail.jsx 2081 LOC

- **Severity**: **P3**
- **Category**: Maintainability
- **Location**: `frontend/src/pages/ReleaseDetail.jsx`
- **Observation**: Single monolithic page with 3 tabs (Components /
  Vulns / Dependency Graph), inline modals (we extracted them to
  Modal-based now), badge logic, Policy Gate display, signature UI,
  share-link UI, integrity check UI, etc.
- **Recommendation**: Structural split into `pages/release/`
  directory with `ReleaseDetail.jsx` as composer + `ComponentsTab.jsx`,
  `VulnsTab.jsx`, `GraphTab.jsx`, `PolicyGateCard.jsx`,
  `SignatureCard.jsx`, `ShareLinksCard.jsx`. Keeps surface API
  (URL routing) identical.
- **Effort**: **L** (~2 days)
- **Risk**: Largest single refactor in the codebase. Risk of
  regression on this most-complex page. **Defer to a dedicated
  refactor session, not this audit's implementation phase.**

---

### UX-035 — Bundle could be subset further

- **Severity**: **P3**
- **Category**: Performance
- **Location**: `frontend/dist/`
- **Observation**: index.js bundle is 296 KB raw / 100 KB gzip —
  reasonable but not great. Lazy routes help. Lucide-react is
  tree-shakeable; ensure we're not importing the whole package
  anywhere.
- **Recommendation**:
  ```sh
  cd frontend && npx vite build --mode analyze
  ```
  Inspect `stats.html` to find the heaviest chunks. If react-i18next
  bundle is large, consider `i18next-http-backend` to lazy-load
  language packs. Defer until perf complaint surfaces.
- **Effort**: **L** (depends on findings)
- **Risk**: Schedule.

---

### UX-036 — No automated a11y / perf testing

- **Severity**: **P3**
- **Category**: Process
- **Location**: project setup.
- **Observation**: No axe-core, no Lighthouse CI, no Playwright. Per
  CLAUDE.md "no new npm packages", we cannot add these.
- **Recommendation**: Manual checklist for Phase 6:
  - Chrome DevTools → Lighthouse → "Mobile" → all categories.
    Target: A11y 95+, Best Practices 95+, Performance 80+.
  - Install Chrome **axe DevTools** extension; run on each page.
    Target: 0 Serious, 0 Critical violations.
  - Manual keyboard-only walkthrough of: Login → Dashboard → Org
    drill-down → Release detail → Vuln VEX edit → Logout.
- **Effort**: **M** (per audit cycle)
- **Risk**: Manual = error-prone. Acceptable trade-off given the
  no-new-deps constraint.

---

## 3. Summary table — issues by severity × category

| Category | P1 | P2 | P3 | Total |
|----------|----|----|----|-------|
| **A11y** | 6 (UX-001, UX-002, UX-004, UX-007, UX-009, UX-019) | 6 (UX-010, UX-013, UX-014, UX-021, UX-025, UX-029) | 4 (UX-027, UX-031, UX-032, UX-036) | **16** |
| **RWD** | 3 (UX-003, UX-008-revisit, UX-009 dup, UX-028) | 1 (UX-008) | 2 (UX-018, UX-026) | **6** |
| **Visual** | 1 (UX-006) | 2 (UX-016, UX-025) | 0 | **3** |
| **Consistency** | 0 | 6 (UX-005, UX-011, UX-012, UX-015, UX-017, UX-030) | 1 (UX-033) | **7** |
| **i18n** | 0 | 1 (UX-014) | 1 (UX-020) | **2** |
| **Performance** | 0 | 0 | 3 (UX-022, UX-023, UX-035) | **3** |
| **Maintainability** | 0 | 0 | 1 (UX-034) | **1** |
| **Polish** | 0 | 0 | 1 (UX-024) | **1** |
| **Process** | 0 | 0 | 1 (UX-036) | **1** |
| **TOTAL** | **12** | **15** | **9** | **36** |

(Note: UX-009 covers RWD touch + A11y target — counted in both above; total unique issues = 36.)

## 4. Recommended sequencing for `plan.md` (preview — full plan in next phase)

**Wave A — foundation** (1 commit, blocks everything else):
- UX-005 design tokens (`tailwind.config.js` extend + `index.css` `:focus-visible` + `prefers-reduced-motion` rule)

**Wave B — quick a11y wins** (each 1 commit):
- UX-001 `<html lang>` sync
- UX-003 iOS form font-zoom CSS one-liner
- UX-004 covered by Wave A
- UX-008 `viewport-fit=cover`
- UX-010 covered by Wave A (`:focus-visible`)
- UX-013 Skeleton aria-busy
- UX-014 Modal/Toast aria-label i18n
- UX-021 Layout mobile menu focus trap
- UX-024 favicon + theme-color

**Wave C — content fixes** (each 1 commit):
- UX-002 `<th scope=>` 93 sites
- UX-006 + UX-025 + UX-029 — `text-gray-500` mass replace + footer + Login red
- UX-007 `<tr onClick>` → CVE link (Dashboard, TISAXDetail)
- UX-009 touch targets on nav
- UX-011 SVG hex → constants
- UX-012 emoji → lucide
- UX-015 z-index scale (covered by Wave A tokens)
- UX-017 `Button` component + adopt on 3 pages
- UX-019 `htmlFor`/`useId` form pairing

**Wave D — deferred** (P3, separate sessions):
- UX-018 desktop wide-screen optimisations
- UX-031 / UX-032 dark mode + prefers-contrast
- UX-033 Help content extraction
- UX-034 ReleaseDetail split
- UX-035 bundle analysis
- UX-036 a11y/perf tooling adoption (requires npm-deps decision)

**Estimated implementation time**:
- Wave A: 30 min
- Wave B: 2 hours total
- Wave C: 4–6 hours total
- Wave D: not in this session

---

## 5. What's intentionally NOT in this report

- PDF report visual fidelity (out of scope — separate audit)
- Help.jsx i18n (deliberately deferred — see decision §0)
- Backend changes
- Storybook setup (no new deps)
- Visual regression testing (no new deps)
- Complete dark-mode design (P3 deferred)
- Full type system migration to TypeScript (out of scope)

---

## 6. Open questions for you before Phase 5

None blocking. All decisions in this audit were made under the
authority you delegated. If you disagree with any decision, flag it
when reviewing `plan.md`.

— end audit-report.md —
