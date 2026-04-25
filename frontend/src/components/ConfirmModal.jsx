import { useEffect, useRef, useState, useId } from "react";
import { useTranslation } from "react-i18next";
import { Modal } from "./Modal";

/**
 * Confirm-an-action dialog built on top of <Modal>.  Modal handles the
 * a11y / RWD / focus-trap concerns; this component layers in:
 *   - confirm + cancel button row (with destructive variant)
 *   - optional "type the resource name to enable confirm" guard for
 *     dangerous deletions
 *   - i18n'd defaults for confirm / cancel text
 *
 * Initial focus is intentionally on the cancel button (or the type-to-confirm
 * input when present).  Pressing Enter on focus then cancels rather than
 * destructively confirming — the safer default.
 */
export function ConfirmModal({
  isOpen,
  title,
  message,
  confirmText,
  cancelText,
  isDangerous = false,
  requireTypeName = null,
  onConfirm,
  onCancel,
}) {
  const { t } = useTranslation();
  const [typed, setTyped] = useState("");
  const inputRef = useRef(null);
  const cancelBtnRef = useRef(null);
  const messageId = useId();

  const resolvedConfirm = confirmText ?? t("common.confirm");
  const resolvedCancel = cancelText ?? t("common.cancel");
  const canConfirm = !requireTypeName || typed === requireTypeName;

  // Reset the typed value each time the dialog opens.
  useEffect(() => {
    if (isOpen) setTyped("");
  }, [isOpen]);

  const handleConfirm = () => {
    if (!canConfirm) return;
    onConfirm?.();
    onCancel?.();
  };

  return (
    <Modal
      isOpen={isOpen}
      title={title}
      onClose={onCancel}
      size="md"
      showCloseButton={false}      // confirm dialogs use the cancel button only
      ariaDescribedBy={messageId}
      // Focus the type-to-confirm input first (if present); otherwise the
      // cancel button — never the destructive button.
      initialFocusRef={requireTypeName ? inputRef : cancelBtnRef}
    >
      <p id={messageId} className="text-sm text-gray-700 mb-4 whitespace-pre-wrap">
        {message}
      </p>

      {requireTypeName && (
        <div className="mb-5">
          <label
            className="block text-xs text-gray-700 mb-1.5"
            htmlFor={`${messageId}-type`}
          >
            {t("confirm.typeToConfirm", { name: requireTypeName })}
          </label>
          <input
            ref={inputRef}
            id={`${messageId}-type`}
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
    </Modal>
  );
}
