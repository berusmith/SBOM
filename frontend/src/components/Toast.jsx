import { createContext, useCallback, useContext, useState } from "react";
import { useTranslation } from "react-i18next";
import { Check, X, AlertTriangle, Info } from "lucide-react";

const ToastContext = createContext(null);

const ICONS = {
  success: <Check size={16} aria-hidden="true" />,
  error:   <X size={16} aria-hidden="true" />,
  warning: <AlertTriangle size={16} aria-hidden="true" />,
  info:    <Info size={16} aria-hidden="true" />,
};

const STYLES = {
  success: "bg-green-600",
  error:   "bg-red-600",
  warning: "bg-yellow-500",
  info:    "bg-blue-600",
};

// Errors and warnings stick around longer so the user has time to read them
// before they auto-dismiss.  Success / info auto-dismiss faster.
const DURATIONS = {
  success: 3500,
  info:    4000,
  warning: 6000,
  error:   6500,
};

export function ToastProvider({ children }) {
  const { t } = useTranslation();
  const [toasts, setToasts] = useState([]);

  const show = useCallback((message, type = "info") => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev, { id, message, type }]);
    const ttl = DURATIONS[type] ?? 4000;
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, ttl);
  }, []);

  const dismiss = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={show}>
      {children}
      {/*
        a11y notes:
          - role="status" + aria-live="polite" makes screen readers announce
            new toasts without interrupting the user.
          - aria-atomic="true" so each toast is read in full when added.

        RWD notes:
          - On mobile (< sm breakpoint) we anchor to the bottom-center edges
            with a small inset, so toasts don't collide with the right edge
            (which on iOS Safari can land under the swipe-to-go-back gesture).
          - On sm+ we keep the bottom-right anchoring but with breathing room.
          - max-w covers a single phone width (calc) on mobile and a fixed
            comfortable width on desktop.
      */}
      <div
        role="status"
        aria-live="polite"
        aria-atomic="true"
        className="fixed z-50 flex flex-col gap-2 pointer-events-none
                   bottom-4 left-4 right-4 sm:left-auto sm:right-5 sm:bottom-5"
      >
        {toasts.map(t => (
          <div
            key={t.id}
            className={`flex items-start gap-3 px-4 py-3 rounded-lg shadow-lg text-white text-sm w-full sm:max-w-sm pointer-events-auto ${STYLES[t.type]}`}
          >
            <span className="font-bold mt-0.5 shrink-0">{ICONS[t.type]}</span>
            <span className="flex-1 leading-snug break-words">{t.message}</span>
            <button
              type="button"
              onClick={() => dismiss(t.id)}
              aria-label={t("common.dismiss")}
              className="ml-1 opacity-70 hover:opacity-100 shrink-0 text-base leading-none focus:outline-none focus:ring-2 focus:ring-white/60 rounded"
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const show = useContext(ToastContext);
  if (!show) throw new Error("useToast must be used within ToastProvider");
  return {
    success: (msg) => show(msg, "success"),
    error:   (msg) => show(msg, "error"),
    warning: (msg) => show(msg, "warning"),
    info:    (msg) => show(msg, "info"),
  };
}
