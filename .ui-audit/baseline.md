# UI/UX Baseline — 2026-04-28

> 首次執行 `.ui-audit/` protocol 時建立,代表 iteration 3 進場前的狀態。
> 既往兩輪 UI 審視紀錄保留在 `.knowledge/ui-audit/` 與 `.knowledge/ui-audit-lite/`。
> 本檔之後是「比對基準」 — 不再修改,直到下一次 baseline 重設。

## 1. Iteration history

| Round | Date | Scope | Findings | Resolved | Where |
|------|------|-------|----------|----------|-------|
| Wave A/B/C (Iteration 1) | 2026-04-26 | Full audit | 36 (12 P1, 15 P2, 9 P3) | 22 (P1+P2 ≤ M effort) | `.knowledge/ui-audit/` |
| UI-Audit-Lite (Iteration 2) | 2026-04-28 | Priority-5 pages × RWD/Interaction/A11y | 16 | 13 | `.knowledge/ui-audit-lite/` |
| **Iteration 3 (this audit)** | **2026-04-28+** | Calibration + stress-test (taste-first) | — | — | `.ui-audit/` |

## 2. Tech stack snapshot

- React 18.3 + Vite 5.4 + Tailwind 3.4 + react-router-dom 6.26
- i18next 26 + react-i18next 17 (zh + en)
- lucide-react 1.8 (icons — only allowed source)
- axios 1.7
- No TypeScript, no Storybook, no Playwright/Cypress (CLAUDE.md hard constraint: no new npm deps)
- Charts/graphs: pure inline SVG (CLAUDE.md hard constraint)

## 3. Design system maturity

### Tokens (`tailwind.config.js theme.extend`)
- **Colour**: `surface`/-card/-muted/-inverse · `fg-default`/-muted/-subtle/-disabled/-on-inverse · `brand`/-hover/-soft · `danger`/`warning`/`success`/`info` · `border-default`/-strong · `ring-focus`
- **Type**: modular 1.2 — `caption` 12 / `body-sm` 14 / `body` 16 / `h6`–`h1` 17–36 (size + line-height paired)
- **Z-index**: `base`/`raised`/`dropdown`/`sticky`/`modal`/`toast`/`tooltip` (0/10/30/40/50/60/70)
- **Transition duration**: `instant` / `fast` 150 / `base` 200 / `slow` 300
- **Max-width**: `page` 1280 / `form` 512 / `prose` 640

### Global CSS (`index.css`)
- `@media (prefers-reduced-motion: reduce)` neutralises animation/transition globally (UX-004)
- `:focus-visible` outline 2px / offset 2px on `ring-focus` (UX-010)
- `body { overflow-x: hidden }` defence-in-depth against navbar bleed (UX-008/009 follow-up)
- `body { padding env(safe-area-inset-*) }` paired with `viewport-fit=cover`
- `@media (max-width: 640px) input { font-size: 16px }` kills iOS Safari focus-zoom (UX-003/028)

### `index.html`
- `<html lang="zh-TW">` — synced live by i18n `languageChanged` listener (UX-001)
- `<meta name="viewport" ... viewport-fit=cover>`
- `<meta name="theme-color" content="#111827">` (matches dark nav)
- `<link rel="icon" href="/favicon.svg">`

### Reusable components
| Component | Purpose | Status |
|-----------|---------|--------|
| `Button` | primary/secondary/danger/ghost × sm/md/lg + loading/icon, focus-visible ring | shipped (UX-017) |
| `Modal` | `role=dialog` + focus trap + Esc + i18n close + restore-focus | shipped |
| `ConfirmModal` | composes `Modal` + confirm/cancel + optional type-to-confirm | shipped |
| `Toast` + `ToastProvider` | aria-live, dismissable, durations | shipped |
| `Skeleton` | `role=status` `aria-busy`, motion-reduce safe | shipped (UX-013) |
| `PasswordInput` | show/hide toggle + label/aria | shipped |
| `Layout` | nav + skip-link + mobile menu focus trap (UX-021) + footer | shipped |
| `DependencyGraph` | inline SVG, hex from `chart-colors.js` | shipped (UX-011) |
| `TrendChart` | inline SVG line/area, hex from `chart-colors.js` | shipped (UX-011) |
| `useFocusTrap` | shared hook (Modal + mobile menu) | shipped |

## 4. Quantitative state (probed 2026-04-28, post-iteration-2)

| Metric | Iter 1 baseline | Now | Trend |
|--------|----------------:|----:|-------|
| `<th>` without `scope=` | 93 | **0** | ✅ fully migrated |
| `<th scope=...>` total | 28 | 114 | +307% |
| `<label htmlFor=...>` | 4 | 38 | +850% |
| `text-gray-500` (4.16:1 borderline) | 138 | **3** | ✅ migrated to gray-600 |
| `text-gray-300/400` (decorative-only) | 40 | 44 | flat |
| `text-xs` (12px body density) | 368 | 358 | -3% (still high) |
| `tabular-nums` / `font-variant-numeric` | 0 | **0** | ❌ not started |
| `aria-(label\|labelledby\|describedby)` | n/a | 18 (across 7 files) | improving |
| `dark:` variants | 0 | **0** | deferred |

## 5. Browser baseline (assumed)

iOS Safari 16+ · Chrome/Edge 110+ · Android Chrome 110+ (Sep 2022 onwards).
Set during Iteration 1; no new constraints introduced since.

## 6. Known unresolved (carried over to iteration 3)

| ID | Severity | Reason | Owner |
|----|----------|--------|-------|
| UX-031 | P3 | Dark mode — large effort, brand decision dependency | deferred |
| UX-032 | P3 | `prefers-contrast` / Windows High Contrast | deferred |
| UX-033 | P3 | `Help.jsx` 1071 LOC content extraction | deferred |
| UX-034 | P3 | `ReleaseDetail.jsx` 2081 LOC structural split | dedicated session needed |
| UX-035 | P3 | Bundle subset analysis | deferred (no perf complaint) |
| UX-036 | P3 | Automated a11y/perf tooling — blocked by no-new-deps | manual checklist used |
| UX-012-lite | P2 | Dashboard `<section aria-labelledby>` × 5 | low ROI, skipped |
| Token migration | (foundational) | additive-only policy; raw `text-gray-*` etc. still dominant | intentional |
