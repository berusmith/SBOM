// Error-formatting helpers for the SBOM frontend.
//
// Pattern repeated across ~50 sites:
//   toast.error("XX 失敗:" + (err.response?.data?.detail || err.message));
//
// `formatApiError(err, action)` replaces that — it pulls FastAPI's `detail`
// (which is i18n'd on the backend for user-facing 4xx responses) and falls
// back to the generic message + axios error string. Pass the localized
// action label as the first argument.
//
// Usage with i18n:
//   import { useTranslation } from "react-i18next";
//   import { formatApiError } from "../utils/errors";
//   const { t } = useTranslation();
//   ...
//   } catch (err) {
//     toast.error(formatApiError(err, t("errors.createFailed")));
//   }

export function formatApiError(err, action) {
  const detail = err?.response?.data?.detail;
  const fallback = err?.message || "Unknown error";
  const detailText =
    typeof detail === "string"
      ? detail
      : detail
        ? JSON.stringify(detail)
        : fallback;
  if (!action) return detailText;
  return `${action}: ${detailText}`;
}

// Small convenience for pages that do not (yet) use i18n.
export function pickErrorDetail(err, fallback = "Unknown error") {
  const detail = err?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (detail) return JSON.stringify(detail);
  return err?.message || fallback;
}
