import { createContext, useCallback, useContext, useMemo, useState } from "react";
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

// UX-3.023b — must match the toast leaving transition class duration below
// (`duration-fast` = 150ms in tailwind.config.js).
const EXIT_MS = 150;

export function ToastProvider({ children }) {
  const { t } = useTranslation();
  const [toasts, setToasts] = useState([]);

  const startExit = useCallback((id) => {
    setToasts(prev => prev.map(t => t.id === id ? { ...t, leaving: true } : t));
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, EXIT_MS);
  }, []);

  const show = useCallback((message, type = "info") => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev, { id, message, type, leaving: false }]);
    const ttl = DURATIONS[type] ?? 4000;
    setTimeout(() => startExit(id), ttl);
  }, [startExit]);

  const dismiss = useCallback((id) => {
    startExit(id);
  }, [startExit]);

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
        className="fixed z-toast flex flex-col gap-2 pointer-events-none
                   bottom-4 left-4 right-4 sm:left-auto sm:right-5 sm:bottom-5"
      >
        {/* Use `toast` not `t` for the iter var so it doesn't shadow the
            useTranslation hook's t() function. */}
        {toasts.map(toast => (
          <div
            key={toast.id}
            // UX-3.023b — `animate-toast-enter` runs once on mount (slide+fade in).
            // `transition-[opacity,transform] duration-fast` handles exit via the
            // `leaving` flag flipping the opacity / translate-y classes.
            // Adopts shadow-elev-5 (Wave A) replacing shadow-lg.
            className={`flex items-start gap-3 px-4 py-3 rounded-lg shadow-elev-5 text-white text-sm w-full sm:max-w-sm pointer-events-auto animate-toast-enter transition-[opacity,transform] duration-fast ease-out ${STYLES[toast.type]} ${toast.leaving ? "opacity-0 translate-y-1" : ""}`}
          >
            <span className="font-bold mt-0.5 shrink-0">{ICONS[toast.type]}</span>
            <span className="flex-1 leading-snug break-words">{toast.message}</span>
            <button
              type="button"
              onClick={() => dismiss(toast.id)}
              aria-label={t("common.dismiss")}
              className="ml-1 -mr-1 opacity-70 hover:opacity-100 shrink-0 p-1 rounded focus:outline-none focus:ring-2 focus:ring-white/60"
            >
              {/* UX-3.011 — replace the literal × character with the lucide X icon
                  so it matches Modal close (also lucide X) and renders identically
                  on every platform. */}
              <X size={14} aria-hidden="true" />
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
  // Memoise so the returned object reference is stable across renders.
  // Without this, every render would yield a new {success, error, warning,
  // info} literal — that breaks consumers that put `toast` into useEffect
  // or useCallback dependency arrays (the Dashboard infinite-refetch bug
  // shipped in iter 3 commit 445c308 was a victim of this).  show() itself
  // is already stable (useCallback inside ToastProvider), so memoising on
  // [show] yields a forever-stable result.
  return useMemo(() => ({
    success: (msg) => show(msg, "success"),
    error:   (msg) => show(msg, "error"),
    warning: (msg) => show(msg, "warning"),
    info:    (msg) => show(msg, "info"),
  }), [show]);
}
