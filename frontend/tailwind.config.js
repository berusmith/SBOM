/** @type {import('tailwindcss').Config} */
//
// Design-token surface for SBOM Platform.  Coexists with raw Tailwind
// utilities — see audit-report.md UX-005 for rationale and migration policy:
//   * tokens are additive (Tailwind defaults still work everywhere)
//   * new code and *touched* code adopt tokens
//   * no mass-rewrite of existing utility classes
//
// Naming convention:
//   surface-*   : page / card / panel backgrounds
//   fg-*        : text colours guaranteed to meet WCAG AA on white
//   brand / brand-hover / brand-soft : the only "primary" colour
//   danger / warning / success / info : semantic intents (NOT raw red/yellow)
//   border-*    : strokes
//   ring-focus  : the colour used for :focus-visible outlines (see index.css)
//
// Typography scale: modular 1.2 ratio.  Use names not raw sizes:
//   text-caption  12px (helper / badges only)
//   text-body-sm  14px (table cells, secondary body)
//   text-body     16px (primary body, ALL form fields — iOS Safari focus zoom)
//   text-h{1..6}  for headings
//
// Z-index scale: never write z-50 again.
//   z-raised  10 — sticky table headers, elevated cards
//   z-dropdown 30 — popovers
//   z-sticky  40 — sticky nav
//   z-modal   50 — modal + backdrop
//   z-toast   60 — above modal (toasts often acknowledge a modal action)
//   z-tooltip 70 — last
//
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Surfaces
        surface:           "rgb(249 250 251)",  // gray-50
        "surface-card":    "rgb(255 255 255)",  // white
        "surface-muted":   "rgb(243 244 246)",  // gray-100
        "surface-inverse": "rgb(17 24 39)",     // gray-900 — top nav

        // Foreground (AA-compliant on white surface)
        "fg-default":      "rgb(31 41 55)",     // gray-800 — body
        "fg-muted":        "rgb(55 65 81)",     // gray-700 — secondary body
        "fg-subtle":       "rgb(75 85 99)",     // gray-600 — labels (4.5:1)
        "fg-disabled":     "rgb(156 163 175)",  // gray-400 — large-text only
        "fg-on-inverse":   "rgb(243 244 246)",  // gray-100 — text on dark nav

        // Brand
        brand:             "rgb(37 99 235)",    // blue-600
        "brand-hover":     "rgb(29 78 216)",    // blue-700
        "brand-soft":      "rgb(219 234 254)",  // blue-100

        // Status (semantic)
        danger:            "rgb(220 38 38)",    // red-600
        warning:           "rgb(217 119 6)",    // amber-600
        success:           "rgb(22 163 74)",    // green-600
        info:              "rgb(8 145 178)",    // cyan-600

        // Borders & focus ring
        "border-default":  "rgb(229 231 235)",  // gray-200
        "border-strong":   "rgb(209 213 219)",  // gray-300
        "ring-focus":      "rgb(96 165 250)",   // blue-400
      },

      fontSize: {
        // [size, lineHeight] in rem — modular 1.2 scale
        "caption": ["0.75rem",   "1rem"],
        "body-sm": ["0.875rem",  "1.25rem"],
        "body":    ["1rem",      "1.5rem"],
        "h6":      ["1.0625rem", "1.5rem"],
        "h5":      ["1.125rem",  "1.5rem"],
        "h4":      ["1.25rem",   "1.625rem"],
        "h3":      ["1.5rem",    "2rem"],
        "h2":      ["1.875rem",  "2.25rem"],
        "h1":      ["2.25rem",   "2.5rem"],
      },

      zIndex: {
        "base":     "0",
        "raised":   "10",
        "dropdown": "30",
        "sticky":   "40",
        "modal":    "50",
        "toast":    "60",
        "tooltip":  "70",
      },

      transitionDuration: {
        "instant": "0ms",
        "fast":    "150ms",
        "base":    "200ms",
        "slow":    "300ms",
      },

      maxWidth: {
        "page":  "80rem",   // 1280 — current de facto (= max-w-7xl)
        "form":  "32rem",   // 512  — single-column form
        "prose": "40rem",   // 640  — long-form text (~75 chars)
      },
    },
  },
  plugins: [],
};
