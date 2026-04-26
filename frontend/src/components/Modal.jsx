import { useRef, useId } from "react";
import { useTranslation } from "react-i18next";
import { X } from "lucide-react";
import { useFocusTrap } from "../hooks/useFocusTrap";

/**
 * Accessible modal wrapper.  Handles every detail of the WAI-ARIA modal
 * pattern so callers don't have to:
 *   - role="dialog" + aria-modal="true" + aria-labelledby
 *   - Tab cycles within the dialog (focus trap — via useFocusTrap hook)
 *   - Escape closes (calls onClose)
 *   - Initial focus moves to the first focusable element after mount
 *   - On close, focus returns to whatever opened the dialog
 *   - Body scroll is locked while open
 *   - Backdrop click closes (configurable via closeOnBackdrop)
 *
 * RWD:
 *   - Full-width on mobile with comfortable padding
 *   - Caps at sm:max-w-md by default; pass `size="lg"` or `size="xl"` for
 *     wider content (forms with two columns, etc.)
 *   - max-h-[90vh] with overflow-y-auto so long content stays scrollable
 *
 * Usage:
 *   <Modal isOpen={open} title="Edit user" onClose={() => setOpen(false)}>
 *     <form>...</form>
 *   </Modal>
 *
 * For the common confirm-an-action pattern, use ConfirmModal — it composes
 * this Modal and adds the confirm/cancel button row + optional type-to-confirm.
 */
const SIZE_CLASSES = {
  sm: "sm:max-w-sm",
  md: "sm:max-w-md",
  lg: "sm:max-w-2xl",
  xl: "sm:max-w-4xl",
};

export function Modal({
  isOpen,
  title,
  onClose,
  children,
  size = "md",
  closeOnBackdrop = true,
  showCloseButton = true,
  initialFocusRef,        // optional: ref to element to focus first
  ariaDescribedBy,        // optional: id of element describing the dialog
}) {
  const { t } = useTranslation();
  const containerRef = useRef(null);
  const titleId = useId();

  // a11y: focus trap, Escape-to-close, body-scroll lock, restore focus on
  // close — all delegated to the shared useFocusTrap hook so dropdowns /
  // popovers can reuse the same primitive later.
  useFocusTrap({
    active: isOpen,
    containerRef,
    onEscape: onClose,
    initialFocusRef,
  });

  if (!isOpen) return null;

  const sizeClass = SIZE_CLASSES[size] ?? SIZE_CLASSES.md;

  return (
    <div className="fixed inset-0 z-modal flex items-center justify-center px-4 py-4">
      <div
        className="absolute inset-0 bg-black/40"
        aria-hidden="true"
        onClick={() => closeOnBackdrop && onClose?.()}
      />
      <div
        ref={containerRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={ariaDescribedBy}
        tabIndex={-1}
        className={`relative bg-white rounded-lg shadow-xl w-full ${sizeClass} max-h-[90vh] overflow-y-auto focus:outline-none`}
      >
        <div className="flex items-start justify-between p-5 sm:p-6 pb-3">
          <h2 id={titleId} className="text-lg font-bold text-gray-800">{title}</h2>
          {showCloseButton && (
            <button
              type="button"
              onClick={() => onClose?.()}
              aria-label={t("common.close")}
              className="-mr-1 -mt-1 p-1.5 rounded text-gray-700 hover:text-gray-900 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-400"
            >
              <X size={18} aria-hidden="true" />
            </button>
          )}
        </div>
        <div className="px-5 sm:px-6 pb-5 sm:pb-6">
          {children}
        </div>
      </div>
    </div>
  );
}
