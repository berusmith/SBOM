import { createContext, useCallback, useContext, useState } from "react";
import { Check, X, AlertTriangle, Info } from "lucide-react";

const ToastContext = createContext(null);

const ICONS = {
  success: <Check size={16} />,
  error:   <X size={16} />,
  warning: <AlertTriangle size={16} />,
  info:    <Info size={16} />,
};

const STYLES = {
  success: "bg-green-600",
  error:   "bg-red-600",
  warning: "bg-yellow-500",
  info:    "bg-blue-600",
};

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const show = useCallback((message, type = "info") => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 4000);
  }, []);

  const dismiss = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={show}>
      {children}
      <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 pointer-events-none">
        {toasts.map(t => (
          <div
            key={t.id}
            className={`flex items-start gap-3 px-4 py-3 rounded-lg shadow-lg text-white text-sm max-w-sm pointer-events-auto ${STYLES[t.type]}`}
          >
            <span className="font-bold mt-0.5 shrink-0">{ICONS[t.type]}</span>
            <span className="flex-1 leading-snug">{t.message}</span>
            <button
              onClick={() => dismiss(t.id)}
              className="ml-1 opacity-70 hover:opacity-100 shrink-0 text-base leading-none"
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
