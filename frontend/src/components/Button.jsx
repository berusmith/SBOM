import { forwardRef } from "react";

/**
 * Reusable button that captures the platform's recurring patterns —
 * primary action / cancel / destructive / borderless ghost — across
 * five sizes and four variants in one place.  Migrating ad-hoc
 * <button className="..."> sites to <Button> standardises:
 *
 *   - touch-target height (sm = 36px, md = 40px, lg = 44px Apple HIG)
 *   - focus ring (2px outline-offset, ring colour matches variant)
 *   - hover/active/disabled states (no jarring opacity flash)
 *   - loading state (spinner + busy=true + click no-op)
 *
 * Adopt incrementally — do not mass-rewrite every <button> at once.
 * Pivot pages first (Login / Profile), then forms, then misc CTAs.
 *
 * Props:
 *   variant   primary | secondary | danger | ghost   (default primary)
 *   size      sm | md | lg                            (default md)
 *   loading   boolean — shows spinner + disables the click
 *   fullWidth boolean — w-full
 *   icon      ReactNode rendered before children (e.g. <Save size={14}/>)
 *
 * Any other native <button> attribute (type, onClick, aria-*, name, ...)
 * is forwarded.  type defaults to "button" — explicit so an unwary
 * <Button> inside a form does not accidentally submit.
 */

// UX-3.022 — every variant gets an active: state so a press has visible
// feedback (was: hover changed colour, click did nothing visible). active:bg
// pushes one shade darker; active:scale-[0.98] subtly squashes the button by
// 2%. The global prefers-reduced-motion rule drops transition-duration to
// 1ms which makes the scale snap instantly for motion-sensitive users.
const VARIANT = {
  primary:   "bg-blue-600 text-white hover:bg-blue-700 active:bg-blue-800 focus-visible:ring-blue-400 disabled:hover:bg-blue-600 disabled:active:bg-blue-600",
  secondary: "border border-gray-300 text-gray-700 bg-white hover:bg-gray-50 active:bg-gray-100 focus-visible:ring-blue-400 disabled:hover:bg-white disabled:active:bg-white",
  danger:    "bg-red-600 text-white hover:bg-red-700 active:bg-red-800 focus-visible:ring-red-400 disabled:hover:bg-red-600 disabled:active:bg-red-600",
  ghost:     "text-gray-700 hover:bg-gray-100 active:bg-gray-200 focus-visible:ring-blue-400 disabled:hover:bg-transparent disabled:active:bg-transparent",
};

const SIZE = {
  sm: "h-9 px-3 text-sm",
  md: "h-10 px-4 text-sm",
  lg: "h-11 px-5 text-base",   // 44px = Apple HIG min touch target
};

export const Button = forwardRef(function Button(
  {
    variant = "primary",
    size = "md",
    loading = false,
    fullWidth = false,
    icon = null,
    disabled = false,
    type = "button",
    className = "",
    children,
    ...rest
  },
  ref
) {
  const isDisabled = disabled || loading;
  const cls = [
    "inline-flex items-center justify-center gap-2 rounded font-medium",
    // UX-3.022 — transition both transform (active scale) and colors so the
    // press feels physical. `active:scale-[0.98]` is fine for motion-reduce
    // users because the global prefers-reduced-motion rule clamps duration
    // to 1ms, making the scale-down effectively instantaneous.
    "transition-[transform,colors] duration-fast active:scale-[0.98] disabled:active:scale-100",
    "focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-1",
    "disabled:opacity-50 disabled:cursor-not-allowed",
    SIZE[size] || SIZE.md,
    VARIANT[variant] || VARIANT.primary,
    fullWidth ? "w-full" : "",
    className,
  ].filter(Boolean).join(" ");

  return (
    <button
      ref={ref}
      type={type}
      disabled={isDisabled}
      aria-busy={loading || undefined}
      className={cls}
      {...rest}
    >
      {loading ? (
        <Spinner />
      ) : (
        icon && <span className="shrink-0" aria-hidden="true">{icon}</span>
      )}
      {children}
    </button>
  );
});

function Spinner() {
  return (
    <svg
      className="animate-spin h-4 w-4 motion-reduce:animate-none"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" opacity="0.25" />
      <path d="M4 12a8 8 0 0 1 8-8" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}
