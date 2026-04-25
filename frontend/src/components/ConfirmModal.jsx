import { useEffect, useRef, useState, useId } from "react";
import { useTranslation } from "react-i18next";

/**
 * Accessible confirm dialog.
 *
 * a11y features:
 *   - role="dialog" + aria-modal="true" so screen readers announce it as a modal
 *   - aria-labelledby points at the heading; aria-describedby at the message
 *   - Focus is moved to the type-to-confirm input (when present) or the cancel
 *     button (which is the safe default — pressing Enter cancels rather than
 *     destructively confirming).
 *   - Tab cycles within the dialog (focus trap); Shift+Tab from the first
 *     focusable element wraps to the last and vice versa.
 *   - Escape closes the dialog (delegates to onCancel).
 *   - Body scroll is locked while open so background content doesn't drift.
 *   - On close, focus returns to the element that opened the dialog (the
 *     last-focused element when the modal mounted).
 *
 * RWD:
 *   - Uses w-full sm:max-w-md so on mobile it fills the screen with margin,
 *     on desktop it caps at a comfortable width.
 *   - Buttons stack vertically on the smallest screens to prevent overflow.
 *
 * Backwards-compatible: existing call sites with the old props keep working;
 * the default Chinese strings are now translated when i18n keys are present.
 */
export function ConfirmModal({
  isOpen,
  title,
  message,
  confirmText,
  cancelText,
  isDangerous = false,
  requireTypeName = null,   // if set, user must type this string to enable confirm
  onConfirm,
  onCancel,
}) {
  const { t } = useTranslation();
  const [typed, setTyped] = useState("");
  const containerRef = useRef(null);
  const inputRef = useRef(null);
  const cancelBtnRef = useRef(null);
  const previouslyFocusedRef = useRef(null);
  const titleId = useId();
  const messageId = useId();

  const resolvedConfirm = confirmText ?? t("common.confirm");
  const resolvedCancel = cancelText ?? t("common.cancel");

  // ── Lifecycle: clear typed value, capture previous focus, lock scroll ────
  useEffect(() => {
    if (!isOpen) return;
    setTyped("");
    previouslyFocusedRef.current = document.activeElement;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    // Defer focus until after render so refs are wired.
    const focusTimer = window.setTimeout(() => {
      if (inputRef.current) {
        inputRef.current.focus();
      } else if (cancelBtnRef.current) {
        cancelBtnRef.current.focus();
      }
    }, 0);

    return () => {
      window.clearTimeout(focusTimer);
      document.body.style.overflow = prevOverflow;
      // Restore focus to whatever the user was on before the dialog opened,
      // unless that node has been unmounted (defensive — querySelector check).
      const prev = previouslyFocusedRef.current;
      if (prev && document.body.contains(prev) && typeof prev.focus === "function") {
        prev.focus();
      }
    };
  }, [isOpen]);

  // ── Keyboard: Escape to cancel; Tab cycles within the dialog ─────────────
  useEffect(() => {
    if (!isOpen) return;
    const handleKey = (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onCancel?.();
        return;
      }
      if (e.key !== "Tab" || !containerRef.current) return;
      // Build the focusable list each keystroke — cheap and avoids stale state.
      const focusables = containerRef.current.querySelectorAll(
        'input, button, [href], select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [isOpen, onCancel]);

  if (!isOpen) return null;

  const canConfirm = !requireTypeName || typed === requireTypeName;

  const handleConfirm = () => {
    if (!canConfirm) return;
    onConfirm?.();
    onCancel?.();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4">
      {/* Backdrop — click to dismiss.  aria-hidden so it isn't read out. */}
      <div
        className="absolute inset-0 bg-black/40"
        aria-hidden="true"
        onClick={() => onCancel?.()}
      />
      <div
        ref={containerRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={messageId}
        className="relative bg-white rounded-lg shadow-xl p-5 sm:p-6 w-full sm:max-w-md max-h-[90vh] overflow-y-auto"
      >
        <h2 id={titleId} className="text-lg font-bold text-gray-800 mb-2">{title}</h2>
        <p id={messageId} className="text-sm text-gray-700 mb-4 whitespace-pre-wrap">
          {message}
        </p>

        {requireTypeName && (
          <div className="mb-5">
            <label className="block text-xs text-gray-700 mb-1.5" htmlFor={`${titleId}-type`}>
              {t("confirm.typeToConfirm", { name: requireTypeName })}
            </label>
            <input
              ref={inputRef}
              id={`${titleId}-type`}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              placeholder={requireTypeName}
              autoComplete="off"
              className="w-full border border-gray-300 rounded px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-red-400 focus:border-red-400"
            />
          </div>
        )}

        <div className="flex flex-col-reverse sm:flex-row gap-2 sm:gap-3 sm:justify-end">
          <button
            ref={cancelBtnRef}
            type="button"
            onClick={() => onCancel?.()}
            className="px-4 py-2.5 text-sm rounded border border-gray-300 text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:ring-offset-1"
          >
            {resolvedCancel}
          </button>
          <button
            type="button"
            disabled={!canConfirm}
            onClick={handleConfirm}
            className={`px-4 py-2.5 text-sm rounded text-white font-medium transition-opacity focus:outline-none focus:ring-2 focus:ring-offset-1 ${
              isDangerous
                ? "bg-red-600 hover:bg-red-700 focus:ring-red-400"
                : "bg-blue-600 hover:bg-blue-700 focus:ring-blue-400"
            } disabled:opacity-40 disabled:cursor-not-allowed`}
          >
            {resolvedConfirm}
          </button>
        </div>
      </div>
    </div>
  );
}
