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

const VARIANT = {
  primary:   "bg-blue-600 text-white hover:bg-blue-700 focus-visible:ring-blue-400 disabled:hover:bg-blue-600",
  secondary: "border border-gray-300 text-gray-700 bg-white hover:bg-gray-50 focus-visible:ring-blue-400 disabled:hover:bg-white",
  danger:    "bg-red-600 text-white hover:bg-red-700 focus-visible:ring-red-400 disabled:hover:bg-red-600",
  ghost:     "text-gray-700 hover:bg-gray-100 focus-visible:ring-blue-400 disabled:hover:bg-transparent",
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
    "transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-1",
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
