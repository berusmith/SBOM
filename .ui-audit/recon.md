---
phase: 1
iteration: 3
audit_id: ui-audit-iteration-3
based_on_commit: 6f0f018
created: 2026-04-28
---

# Phase 1 — Recon (iteration 3)

## 1. Tech stack

| Layer | Tool | Version | Notes |
|-------|------|---------|-------|
| Framework | React | 18.3.1 | Function components + hooks; `lazy` + `Suspense` for routes |
| Build | Vite | 5.4.8 | dev :3000, proxies `/api` → `:9100` |
| Styling | Tailwind CSS | 3.4.13 | Token-extended (see `baseline.md §3`) |
| Routing | react-router-dom | 6.26.2 | Future flags `v7_startTransition` + `v7_relativeSplatPath` ON |
| i18n | i18next + react-i18next | 26 / 17 | zh-TW + en; bridges `<html lang>` (UX-001) |
| Icons | lucide-react | 1.8.0 | tree-shakeable; only allowed icon source |
| HTTP | axios | 1.7.7 | JWT injected via interceptor; `localStorage.token` |
| State | React local hooks | — | No Redux/Zustand. Cross-cutting state: `Toast` context only. |

**Forbidden** (CLAUDE.md hard constraints):
- New npm deps
- TypeScript migration
- Storybook / visual regression / axe-core
- Charting libraries (Chart.js, Recharts) — must remain pure SVG

## 2. Directory shape

```
frontend/src/
├─ main.jsx, App.jsx          # entry, routing, RequireAuth/RequireAdmin guards
├─ index.css                   # global @layer base rules (UX-003/004/008/010/028)
├─ pages/                      # 25 pages (Login + 24 in-app)
├─ components/                 # 10 shared (see baseline §3)
├─ hooks/useFocusTrap.js       # Modal + mobile menu reuse
├─ utils/                      # date / plan / validate / errors
├─ constants/                  # colors / icons / chart-colors
├─ api/client.js               # axios + JWT interceptor
└─ i18n/                       # zh.js / en.js / index.js
```

**Page complexity (LOC)**:
- `ReleaseDetail.jsx` 2081 — 3 tabs, 13+ inline modals/cards (UX-034 split target)
- `Help.jsx` 1071 — intentionally not i18n'd (UX-033 extract target)
- `Dashboard.jsx` 625 — CRA countdown + 6 cards + 5 sections
- `Policies.jsx` 509 — rule cards + license cards + edit modals
- `TISAXDetail.jsx`, `Settings.jsx`, `AdminActivity.jsx` ≈ 300–400 each
- Auth pages (Login/Profile/ForgotPassword) ≈ 100–200

## 3. Design system status

(see `baseline.md §3` for full snapshot)

**Adoption rate** (semantic-token vs raw-Tailwind utility):
- Colour tokens (`surface/fg/brand/semantic`): **~5% adoption** — most pages still use `text-gray-700`, `bg-blue-600`. Per UX-005 additive-only policy, this is intentional.
- Typography tokens (`text-body`, `text-caption`): **~0% adoption** — pages use raw `text-sm`, `text-xs`. This iteration is good time to seed examples on touched pages.
- Z-index tokens: **100% adoption** (only Modal/Toast use them; new code adopts).
- `:focus-visible`: **100% global coverage** via `index.css`. Per-component `focus:ring-2` continues to layer on top.
- `prefers-reduced-motion`: **100% global coverage** via `index.css`.
- Animation: only Skeleton's `animate-pulse` + Button spinner use `animate-spin` (both `motion-reduce` aware).

## 4. Content profile

- **Languages**: zh-Hant (default) + en. Estimated 70/30 zh/en use.
- **Mixed content within strings**: CVE IDs (`CVE-2024-12345`), CWE codes, EPSS percentages (`23.4%`), version strings (`1.2.3+build.42`), PURL strings (`pkg:npm/@scope/name@version` can hit 100+ chars).
- **Long-tail extremes** likely encountered in real data:
  - Component name: 100+ chars (Maven `groupId:artifactId`); some PURLs exceed table cell width
  - Vulnerability description (NVD): 200–2000 chars; rendered in Modal
  - Customer / product name: free-form, may hit 50+ chars
  - Username (email-style): may overflow nav (already capped via `max-w-[8rem] truncate` in Layout)
- **Numbers**: integers, percentages (1 decimal), EPSS (3 decimals), days (+/-/0). NOT using `tabular-nums` — visible jitter in lists with frequent updates.
- **Empty / error states**: covered in some pages (Dashboard `noVulns`, `noStats`); inconsistent in others (will audit Phase 5).
- **Hardcoded English / zh strings observed in JSX** (need full Phase 5 scan):
  - `Dashboard.jsx:574-580` — riskOverview thead 客戶/產品/總漏洞 hardcoded zh
  - `index.html:13` — `<title>SBOM Management Platform</title>` not localised
  - other pages TBD

## 5. User profile (inferred — NOT confirmed)

| Persona | Plan | Devices | Tasks |
|---------|------|---------|-------|
| **Admin (consultant)** | n/a (cross-org) | 1280–2560 desktop, occasional iPad | manage all orgs / users / settings, audit log review |
| **Customer admin** | starter–professional | 1366/1920 desktop (office) | own products/releases, vuln triage, CRA reporting |
| **Viewer (auditor)** | per-org | 1280 desktop | read-only review; share-link consumers |
| **Mobile review** | any | 360–428 phone | quick check on-the-go (rare); CRA escalation alerts |

**Locale**: zh-Hant primary. Some German / English customers expected (CRA = EU regulation).
**A11y need**: B2B desktop tooling — keyboard power users, occasional older operators in OT environments. No specific blind/low-vision user known *yet*, but compliance posture matters when sold to regulated industries.
**Time pressure**: high — vuln triage during incident response is a real high-stress scenario; UI clarity + speed > visual polish during those moments.

## 6. Iteration 1 + 2 effects observed in code (sanity-spot)

- `<html lang>` synced via i18n `languageChanged` listener — claimed in audit-report.md, will verify Phase 5
- `<th scope>` ubiquitous — 0 bare `<th>` left, 114 with scope (count via grep)
- iOS focus-zoom killed via global CSS rule (`index.css:80-86`)
- `prefers-reduced-motion` global (`index.css:24-34`)
- `:focus-visible` global (`index.css:36-42`)
- Skip-to-main link present (`Layout.jsx:78-83`)
- Mobile menu focus trap (`Layout.jsx:34-38`)
- `Button` component shipped + adopted on auth pages
- `Modal` shipped with i18n close, focus trap, restore-focus
- Skeleton has `role="status"` + `aria-busy="true"` — verified via Read
- `chart-colors.js` exists; `DependencyGraph.jsx` + `TrendChart.jsx` consume it (no inline hex)

## 7. What I deliberately have NOT yet examined (deferred to Phase 5)

To avoid premature opinions:
- Per-page visual rhythm + spacing rhythm
- Empty / error state copy quality (aside from existence)
- Microinteraction timing on table rows / button presses
- Form validation UX (when does error show? clear?)
- Bundle size (defer to Phase 9 if perf complaint surfaces)
- Touch experience on actual mobile (assertion-matrix.json gives partial data; a real device walk needed)
- TISAX module shippability

## 8. Open questions for the user

If you don't answer, I'll proceed with the assumption listed in §9.

1. **Real-user pain points?** — Has anyone complained about specific UX issues recently? (e.g. "我在 1366 螢幕看不到登出鈕"、"夜班工程師希望黑底"、"漏洞描述太長看不完")
2. **Device mix in real usage** — desktop-only, or meaningful mobile? Want me to focus stress test on 1280–1920 (assume yes) or treat 360 as equally important?
3. **Dark mode decision** — UX-031 was deferred. Plan / scope it this iteration? Or stay deferred?
4. **Brand colour finality** — `blue-600` (#2563eb) is the brand token. Final or placeholder?
5. **TISAX module scope** — `TISAXAssessments` / `TISAXDetail` pages exist; `docs/TISAX_MODULE_PLAN.md` says "planned". Audit them, or skip them this iteration as work-in-progress?
6. **Help.jsx content extraction** — UX-033 was deferred. Scope this iteration?
7. **ReleaseDetail split** — UX-034 was deferred. Scope this iteration (high-risk refactor)?
8. **Information density preference** — current `text-xs` 358 occurrences signals "data-dense B2B" intent. Aspiration: stay dense (Linear / Plane) or loosen (Notion / Vercel)? Affects every typography decision below.

## 9. Reasonable assumptions (used if you don't answer §8)

- Desktop-primary; mobile is "review on the go" not "full workflow". Stress test will weight 1280/1366/1920 heavier than 360/390 — but I will still spot-test 360.
- Brand colour stays `blue-600`; no rebrand this iteration.
- Dark mode stays deferred *as implementation* — but I will produce a *migration shape* (token-level plan only) so iteration 4 can ship if approved.
- TISAX pages in scope (assume they ship today; if any are stub I'll mark "deferred").
- Help.jsx content stays inline; UX-033 stays deferred.
- ReleaseDetail.jsx stays monolithic; UX-034 stays deferred.
- Density aspiration is "Linear-tight" — i.e. dense, but every density choice must be intentional (caption vs body-sm vs body), not arbitrary.

## 10. Focus areas for this iteration (deeper than iter 1+2)

1. **Visual rhythm + density taste** (Phase 2 + 6)
   Past audits ensured mechanics; this audit asks "*does the dashboard feel like Linear/Stripe or like jQuery 2014?*". Specifically:
   - Card padding rhythm (5? 6? 8? mixed?)
   - Table row height + cell padding consistency
   - Spacing between sections (`mt-4` vs `mt-6` vs `mt-8`)
   - Colour temperature in dark navbar
   - Number jitter (no `tabular-nums`)
2. **Microinteraction polish** (Phase 4)
   - Button press feedback (active state vs hover only)
   - Hover transitions on rows / cards (`transition-colors duration-base`?)
   - Skeleton-to-content swap timing
   - Toast appearance / dismissal motion
3. **Empty / error / loading state design** (Phase 4 §5)
   - Are empty states helpful or just "no data"?
   - Error states distinguish network / permission / validation?
   - Are loading states informative (what's loading, ETA)?
4. **Real-content stress test** (Phase 4 §1)
   - 50-char usernames in nav
   - 200-char component names in tables
   - 5000-row vuln tables
   - Long PURL truncation
5. **Cross-device behaviour at extremes** (Phase 4 §2)
   - 360 px (Galaxy Fold-ish) — does Dashboard read?
   - 1920+ — does whitespace feel intentional or empty?
6. **Information architecture review** (Phase 5)
   - Dashboard 6 cards + 5 sections — too much? Right priority order?
   - ReleaseDetail tabs ordering
   - Settings layout
7. **Dark mode migration path** (Phase 6 plan, NOT implementation)
   - Identify what % of `bg-*`/`text-*` need parallel tokens
   - Identify chart-colour palette dual-mode shape
8. **Tabular numerals** (small but high-impact polish)
   - 0 occurrences today; trivial token addition
