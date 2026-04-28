# SBOM Platform — UI/UX Implementation Plan

**Source**: `audit-report.md` (this session)
**Status**: AWAITING APPROVAL. No code will change until user replies "go".
**Total scope**: 22 issues to address (P1+P2 from waves A–C).
**Deferred**: 9 P3 issues (wave D, separate sessions).
**Estimated time**: ~7 hours of focused work.

This plan is structured into **waves** (A → D). Each wave is one or
more **issues** (UX-NNN). Each issue ⇒ one **commit** with the issue
ID in the message.

---

## Pre-flight checks

Before any commit:
- [ ] Working tree clean (`git status` shows nothing)
- [ ] All 9 prior session commits visible (`git log --oneline -10` shows
      `f65f1c3 i18n round 4` at top)
- [ ] Frontend builds (`npm run build` clean)
- [ ] Backend regression green (`python test_all.py` 54/54)

---

## Wave A — Foundation (1 commit, blocks Wave B–C)

These changes add the design-token surface that subsequent fixes
reference. Without this, Wave B–C either has to inline values
(violating the Hard Rule) or duplicate work.

### A1. UX-005 + UX-004 + UX-010 — design tokens + prefers-reduced-motion + focus-visible

**Files touched**:
- `frontend/tailwind.config.js` (theme.extend)
- `frontend/src/index.css` (@layer base — global rules)

**Diff size**: ~80 lines added, 2 lines changed.

**Approach**: paste the proposed `theme.extend` block from
`audit-report.md` §1; add the `prefers-reduced-motion` and
`:focus-visible` `@layer base` rules.

**Verification per commit**:
- `npm run build` succeeds (no Tailwind class is broken — we're
  *adding* not replacing)
- Open dev server, inspect a button: hover should still show ring;
  click + tab away should not show ring on the click target (because
  `:focus-visible` only fires for keyboard).
- Open System Preferences → Accessibility → Display → "Reduce Motion"
  on. Reload page. The Skeleton's `animate-pulse` should stop animating.

**Risk**: very low. Adding tokens doesn't break utility classes
already in use. The two CSS rules are additive.

**Rollback**: `git revert <hash>` — single commit, single revert.

**Effort**: S (~30 min including verification)

**Commit message**:
```
ui(tokens): add design tokens, prefers-reduced-motion, focus-visible (UX-004, UX-005, UX-010)

Adds the foundation that Wave B–C of the UI/UX audit depends on:

1. tailwind.config.js theme.extend gains semantic tokens for
   colors (surface/fg-*/brand/danger/warning/success/info/border-*),
   typography (caption/body/h1-h6 modular 1.2 scale),
   z-index (base/raised/dropdown/sticky/modal/toast/tooltip),
   transition durations (instant/fast/base/slow),
   container widths (page/form/prose).

2. index.css gains a @layer base block with two cross-cutting rules:
   - @media (prefers-reduced-motion: reduce) { ... }
     Globally honours the OS Reduce Motion setting (UX-004).
     transition-* and animation-* both clamped to 1ms.
   - :focus-visible { outline: 2px solid token; outline-offset: 2px; }
     :focus:not(:focus-visible) { outline: none; }
     Keyboard users get the ring; mouse-clickers don't (UX-010).

Migration policy: tokens coexist with raw Tailwind classes.  New code
and touched code use tokens (text-fg-muted, bg-surface-card, z-modal);
existing code stays as-is until naturally re-touched.  No mass migration.

Verification: npm run build clean, manual test of focus ring + reduced
motion in dev server.
```

---

## Wave B — Quick a11y wins (8 commits, can be parallel reviewed)

Independent fixes that don't touch each other. Each commit is small
(< 50 lines).

### B1. UX-001 — `<html lang>` dynamic sync

**Files**: `frontend/src/i18n/index.js`

**Approach**:
```js
i18n.on("languageChanged", (lng) => {
  document.documentElement.lang = lng === "en" ? "en" : "zh-Hant";
});
// Also set initial value:
document.documentElement.lang = i18n.language === "en" ? "en" : "zh-Hant";
```

**Verification**: open DevTools → switch lang → inspect `<html lang>`.

**Effort**: S (~5 min)

**Risk**: None.

---

### B2. UX-003 + UX-028 — iOS Safari focus-zoom prevention

**Files**: `frontend/src/index.css`

**Approach**: `@layer base { @media (max-width: 640px) { input, select, textarea { font-size: 16px; } } }`

**Verification**: open Chrome DevTools device toolbar → iPhone SE
(375 wide). Tap any input. Page should NOT zoom in.

**Effort**: S (~5 min)

**Risk**: Mobile inputs slightly taller. Acceptable.

---

### B3. UX-008 — viewport-fit=cover

**Files**: `frontend/index.html`, `frontend/src/index.css` (safe-area
padding on body)

**Effort**: S (~5 min)

**Risk**: None.

---

### B4. UX-013 — Skeleton aria-busy / role="status"

**Files**: `frontend/src/components/Skeleton.jsx`

**Approach**: wrap each variant's outer div with
`role="status" aria-busy="true" aria-live="polite"` and an
`<span className="sr-only">{t("common.loading")}</span>` inside.

**Note**: Skeleton.jsx currently has no useTranslation. Add it. If
the t() at top-level breaks Suspense, fall back to literal "Loading…".

**Verification**: VoiceOver / NVDA on the Dashboard → expect "Loading,
busy" announcement during initial load.

**Effort**: S (~15 min)

**Risk**: None.

---

### B5. UX-014 — Modal/Toast aria-label i18n

**Files**: `frontend/src/components/Modal.jsx`, `frontend/src/components/Toast.jsx`

**Approach**: `aria-label="Close"` → `aria-label={t("common.close")}`.
Same for Toast's "Dismiss" → add `common.dismiss` to zh.js + en.js.

**Verification**: switch UI to EN, inspect the Modal X button — its
aria-label should be "Close"; switch to ZH → "關閉".

**Effort**: S (~10 min)

**Risk**: None.

---

### B6. UX-021 — Layout mobile menu focus trap

**Files**: `frontend/src/components/Layout.jsx`

**Approach**:
```jsx
const menuContainerRef = useRef(null);
useFocusTrap({
  active: menuOpen,
  containerRef: menuContainerRef,
  onEscape: () => setMenuOpen(false),
});
// ...
<div ref={menuContainerRef} id="mobile-menu" ...>
```

**Verification**: open mobile menu via DevTools mobile view → Tab →
should cycle within menu items + search.

**Effort**: S (~10 min)

**Risk**: None — uses our extracted hook.

---

### B7. UX-024 — favicon + theme-color

**Files**: `frontend/index.html`, new `frontend/public/favicon.svg`
(simple SBOM "shield" SVG inline)

**Approach**: 12-line inline SVG with the brand blue.

**Verification**: browser tab shows favicon; on Android Chrome the
URL bar tints `#1f2937`.

**Effort**: S (~10 min)

**Risk**: None.

---

### B8. UX-020 — PageLoading i18n cleanup (optional polish)

**Files**: `frontend/src/App.jsx`

**Approach**: Use `<html lang>` (set by B1) to choose label, not
localStorage:
```jsx
const lang = document.documentElement.lang || "zh-Hant";
const label = lang.startsWith("en") ? "Loading..." : "載入中...";
```

**Verification**: cosmetic.

**Effort**: S (~3 min)

**Risk**: None.

---

## Wave C — Content fixes (10 commits)

Larger surface area; each touches multiple files.

### C1. UX-002 — `<th scope=>` 93 sites

**Files**: ~10 page files containing tables.

**Approach**: AST-light search/replace. Pattern:
- `<th className="..."` (no scope) inside `<thead>` → `<th scope="col" className="..."`
- For tables with row-headers (AdminActivity per-org summary), add
  `scope="row"` to first cell.

**Verification**: `grep -rEh '<th\b[^>]*scope=' --include="*.jsx" .  | wc -l`
should = 121 (matches total `<th>` count).

**Effort**: M (~45 min, per-file verification)

**Risk**: Pure additive. Zero functional change.

---

### C2. UX-006 + UX-025 + UX-029 — gray-500/400/300 contrast sweep

**Files**: ~15 page files.

**Approach**: Two-pass:
1. **Mechanical**: replace `text-gray-500` → `text-gray-600` everywhere
   it appears as text colour (NOT for icon `lucide` or border colours
   — those will be flagged separately).
2. **Manual review**: each `text-gray-300` and `text-gray-400` site.
   - If decoration / placeholder / disabled → keep but ensure
     `aria-disabled` / sized 18px+ to meet large-text 3:1.
   - If body / label → upgrade to gray-600.
3. Footer (`Layout.jsx:225`) and `text-red-500` (Login error) →
   `gray-600` / `red-600` respectively.

**Verification**: spot-check via Chrome DevTools "Rendering" tab →
Emulate vision deficiency → "Tritanopia". Look for low-contrast text.

**Effort**: M (~1 hour for sweep + visual review)

**Risk**: Slightly darker UI. Visually improves legibility. Some
visual regression possible — keep changeset focused (tested on Login,
Dashboard, Profile, Settings before bulk sweep).

---

### C3. UX-007 — `<tr onClick>` → CVE link

**Files**: `frontend/src/pages/Dashboard.jsx` (TopVulns), `frontend/src/pages/TISAXDetail.jsx`

**Approach**: Remove `onClick` from `<tr>`; wrap `v.cve_id` cell in
`<Link to={...}>`. Keep `hover:bg-gray-50` for visual feedback.

**Verification**:
- Mouse: clicking CVE navigates to release detail. Clicking row
  background does not. (Acceptable — narrows hit area for keyboard
  parity.)
- Keyboard: Tab through table → CVE links are focusable → Enter
  navigates.
- Screen reader: announces "link, CVE-2021-44228".

**Effort**: S (~20 min)

**Risk**: Mouse users no longer click row background. Mitigated by
the visible link.

---

### C4. UX-009 — touch targets

**Files**: `frontend/src/components/Layout.jsx`

**Approach**:
- Lang toggle: `py-1.5` → `py-2 sm:py-1.5` (mobile gets 32px, desktop
  keeps density)
- Mobile nav links already at `py-2.5` (40px) — bump to `py-3` (48px)
- Desktop search submit `⌕` button (also UX-012): becomes lucide
  `<Search size={16}/>` inside `p-2` (32px) — desktop OK.

**Verification**: DevTools device toolbar → iPhone SE → tap lang
toggle 5 times. Should hit every time.

**Effort**: S (~15 min)

**Risk**: Slight nav bloat on mobile. Acceptable.

---

### C5. UX-011 — SVG hex → constants

**Files**: `frontend/src/components/DependencyGraph.jsx`,
`frontend/src/components/TrendChart.jsx`, new
`frontend/src/constants/chart-colors.js`

**Approach**: extract every hex literal to named constants.
chart-colors.js exports `SEVERITY_HEX` (matches Tailwind palette
indices), `CHART_AXIS_GRID`, `CHART_FOCUS_RING`, etc.

**Verification**: visual diff before/after — charts identical.

**Effort**: S (~20 min)

**Risk**: Pure refactor.

---

### C6. UX-012 — emoji → lucide

**Files**: `frontend/src/components/Layout.jsx` (🔒 nav lock + ⌕
search submit)

**Approach**: replace 🔒 with `<Lock size={14}/>`; replace ⌕ with
`<Search size={16}/>`. Both with `aria-hidden="true"` since aria-label
provides semantic name.

**Verification**: visual — the lock looks like a lock; the search
button looks like a search icon.

**Effort**: S (~10 min)

**Risk**: None.

---

### C7. UX-015 — z-index scale adoption

**Files**: `frontend/src/components/Modal.jsx`, `frontend/src/components/Toast.jsx`

**Approach**: `z-50` → `z-modal` and `z-toast` (after A1's tokens).

**Verification**: trigger Toast while Modal open — Toast should sit
above. (Today they're both `z-50`; render order decides.)

**Effort**: S (~5 min — just class rename)

**Risk**: None.

---

### C8. UX-017 — Button component (light adoption)

**Files**: new `frontend/src/components/Button.jsx`; adopt on
**3 pivot pages only**: `Login.jsx`, `Profile.jsx`, `Layout.jsx`.

**Approach**:
```jsx
// Variants: primary | secondary | danger | ghost
// Sizes: sm | md | lg
// Composes loading state, disabled, focus ring (consumes tokens).
```

**Verification**: visual diff — buttons unchanged.

**Effort**: M (~45 min — design + 3-page adoption)

**Risk**: M — Button design is opinionated. If someone disagrees,
might need to revisit.

---

### C9. UX-019 — form htmlFor / useId pairing

**Files**: ~6 page files with form inputs lacking pairing.

**Approach**: Add `useId()` per form, generate IDs, wire `<label
htmlFor>` and `<input id>`. Already done on Login / Profile / Modal-
based forms — sweep the rest.

**Verification**: each form: click the label → cursor focuses the
matching input (browser default behaviour).

**Effort**: M (~1 hour, ~30 inputs)

**Risk**: None — additive.

---

### C10. UX-027 — useId() for hardcoded IDs (opportunistic)

**Files**: anywhere a string-literal ID is paired with htmlFor.

**Approach**: rolled into C9 if convenient; otherwise its own commit.

**Effort**: S (folded into C9)

**Risk**: None.

---

## Wave D — Deferred (P3, separate session)

Listed here for visibility; **NOT** included in this session's
implementation.

| Issue | Title | Why deferred |
|-------|-------|--------------|
| UX-018 | xl:/2xl: desktop wide-screen | Needs design decisions per page |
| UX-031 | Dark mode | Brand decision + 1-2 weeks work |
| UX-032 | prefers-contrast / forced-colors | Needs Windows High Contrast testing access |
| UX-033 | Help.jsx content extraction | 1071 LOC refactor |
| UX-034 | ReleaseDetail.jsx structural split | Largest refactor in codebase, separate session |
| UX-035 | Bundle subset analysis | Awaiting perf complaint |
| UX-036 | Automated a11y/perf tooling | Requires npm-deps decision (CLAUDE.md says no) |
| UX-022 | transition-* perf | Already passing — sanity-check noted |
| UX-026 | dvh vs vh | iOS 16+ only; deferred to next visual polish pass |

---

## Risk register

| Risk | Mitigation |
|------|------------|
| Wave A's `:focus-visible` rule changes existing focus behaviour. | Verified during A1 commit on dev server. If anyone disagrees with click-no-ring, single revert. |
| Wave C's gray sweep changes visible UI on every page. | Stage in 1 commit per page (or per feature area), not in a single mega-commit. |
| Wave C's Button component might be over-designed. | Limit adoption to 3 pages first. If someone disagrees, only those 3 to revert. |
| Mobile menu focus trap might trap user before they can click "X". | The `useFocusTrap` already handles Escape; the X close button is part of the trap. Tested in Modal already. |
| `<tr onClick>` change reduces mouse hit area. | Keep `cursor-pointer` + `hover:bg-gray-50` for visual feedback; emphasise the CVE link is the affordance. |

---

## Rollback strategy

- Each commit is reversible via `git revert <hash>`.
- No commit touches > 15 files.
- No commit changes the public component API (Modal, ConfirmModal,
  Toast, PasswordInput keep their props).
- Token additions (Wave A) are non-breaking — existing classes still
  work.
- If Wave C's gray sweep is unwelcome, individual files can be reverted.

---

## What I will NOT do without explicit approval

- Adopt Button on more than 3 pages in C8 (full sweep is its own task).
- Mass-migrate `text-gray-N` → `text-fg-*` tokens (the
  audit-report.md's policy is "use tokens in new/touched code only").
- Touch ReleaseDetail.jsx structurally (UX-034 deferred).
- Touch Help.jsx content (UX-033 deferred).
- Add any npm dependency.
- Make changes outside the `frontend/` directory.
- Run `git push` (per system rules — push only on explicit ask).

---

## Time estimate

| Wave | Effort | Cumulative |
|------|--------|------------|
| Pre-flight | 5 min | 5 min |
| Wave A (1 commit) | 30 min | 35 min |
| Wave B (8 commits) | 1.5 hours | 2 hours |
| Wave C (8–10 commits) | 4 hours | 6 hours |
| Phase 6 verification (manual checklist) | 1 hour | 7 hours |
| **Total session-realistic** | **~7 hours** |  |

If context-budget runs out before completion, the natural stopping
point is end-of-Wave-B (which delivers ~all the easy a11y wins; Wave
C's content sweeps can resume next session).

---

## Approval gate

Reply **"go A"** to authorise Wave A only.
Reply **"go A+B"** to authorise A + B.
Reply **"go all"** to authorise A + B + C.
Reply **"hold"** to pause — I will explain anything unclear.
Reply **"modify X..."** to change the plan before proceeding.

— end plan.md —
