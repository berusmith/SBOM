// Chart colour constants — extracted from inline SVG hex (UX-011).
//
// SVG attributes (fill, stroke) cannot accept Tailwind utility classes,
// so we cannot directly consume design tokens via class names.  Instead
// every SVG-rendering component imports from this module so that:
//   1. The "what" (semantic name) and the "where used" stay separate.
//   2. A future migration to derive these from CSS variables (with
//      getComputedStyle) is local to one file.
//   3. We can never again accidentally use #ef4444 for "danger" in
//      one chart and #dc2626 in another — the names enforce single
//      source of truth.
//
// Hex values mirror Tailwind palette indices we already use elsewhere
// so charts stay visually aligned with the badge / state colours
// rendered via Tailwind utilities (constants/colors.js).

// ── Severity-aligned hexes (mirror Tailwind palette)
//    Use for: chart series, dot/line colour, bar fill where the
//    series semantically maps to a vulnerability severity.
export const SEVERITY_HEX = {
  total:    "#60a5fa",   // blue-400  — the aggregated "all unresolved"
  critical: "#ef4444",   // red-500
  high:     "#fb923c",   // orange-400
  medium:   "#facc15",   // yellow-400
  low:      "#3b82f6",   // blue-500
  info:     "#9ca3af",   // gray-400
};

// ── Dependency-graph node fills (DependencyGraph.jsx)
//    Three-state colour: vulnerable / root-package / regular.
export const GRAPH_NODE_FILL = {
  vulnerable: "#fca5a5",  // red-300   — node has at least one critical/high vuln
  root:       "#93c5fd",  // blue-300  — root SBOM component
  regular:    "#e5e7eb",  // gray-200  — transitive dependency
};

// ── Dependency-graph node strokes (matches fills with stronger contrast)
export const GRAPH_NODE_STROKE = {
  selected:   "#1d4ed8",  // blue-700  — currently focused
  vulnerable: "#ef4444",  // red-500
  root:       "#3b82f6",  // blue-500
  regular:    "#9ca3af",  // gray-400
};

// ── Dependency-graph text fills (must contrast against node fill)
export const GRAPH_NODE_TEXT = {
  vulnerable: "#7f1d1d",  // red-900
  root:       "#1e3a8a",  // blue-900
  regular:    "#374151",  // gray-700
  meta:       "#9ca3af",  // gray-400 — version sub-label
};

// ── Edge / connector strokes
export const GRAPH_EDGE_STROKE = "#d1d5db";   // gray-300

// ── Chart axis & grid (TrendChart.jsx)
export const CHART_AXIS_STROKE = "#e5e7eb";   // gray-200 — main axis lines
export const CHART_GRID_STROKE = "#f3f4f6";   // gray-100 — horizontal gridlines
export const CHART_TICK_LABEL  = "#9ca3af";   // gray-400 — axis tick labels
export const CHART_LABEL_HOVER = "#374151";   // gray-700 — x-axis label when hovered
