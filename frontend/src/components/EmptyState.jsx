/**
 * EmptyState — consistent shell for "no data yet" / "no results" / "all clear"
 * surfaces. Phase 2 calibration vs Linear / Stripe noted that bare "沒有資料"
 * single-line empty states miss the chance to (a) explain *why* it's empty,
 * (b) tell the user the next step. EmptyState provides the structure;
 * callers pass in the i18n'd title / description / action.
 *
 * Usage:
 *   <EmptyState
 *     icon={<CheckCircle2 size={32} aria-hidden="true" />}
 *     title={t("dashboard.noVulns")}
 *     description={t("dashboard.noVulnsDesc")}
 *     action={<Link to="...">{t("...")}</Link>}
 *   />
 *
 * Designed to render inside an existing card (it has no background of its
 * own), so the host's bg / shadow flow through unchanged. Centred layout,
 * generous vertical padding, mid-gray icon, gray-800 title, gray-600
 * description, action below.
 *
 * `compact` shrinks the vertical padding for use inside dense table cells
 * or modal bodies where the surrounding context already provides padding.
 */
export function EmptyState({ icon, title, description, action, compact = false, className = "" }) {
  return (
    <div className={`text-center px-4 ${compact ? "py-4" : "py-8"} ${className}`}>
      {icon && (
        <div className="mx-auto mb-3 text-gray-400 flex items-center justify-center">
          {icon}
        </div>
      )}
      {title && <p className="font-medium text-gray-800 mb-1">{title}</p>}
      {description && (
        <p className="text-sm text-gray-600 mb-4 max-w-sm mx-auto">{description}</p>
      )}
      {action && <div>{action}</div>}
    </div>
  );
}
