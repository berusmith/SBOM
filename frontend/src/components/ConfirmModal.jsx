import { useEffect } from "react";

export function ConfirmModal({
  isOpen,
  title,
  message,
  confirmText = "確認",
  cancelText = "取消",
  isDangerous = false,
  onConfirm,
  onCancel,
}) {
  useEffect(() => {
    if (!isOpen) return;
    const handleEsc = (e) => {
      if (e.key === "Escape") onCancel?.();
    };
    document.addEventListener("keydown", handleEsc);
    return () => document.removeEventListener("keydown", handleEsc);
  }, [isOpen, onCancel]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Background overlay */}
      <div
        className="absolute inset-0 bg-black/40"
        onClick={() => onCancel?.()}
      />

      {/* Modal */}
      <div className="relative bg-white rounded-lg shadow-xl p-6 max-w-sm w-[90%] sm:w-full">
        <h2 className="text-lg font-bold text-gray-800 mb-2">{title}</h2>
        <p className="text-sm text-gray-600 mb-6 whitespace-pre-wrap">{message}</p>

        <div className="flex gap-3 justify-end">
          <button
            onClick={() => onCancel?.()}
            className="px-4 py-2 text-sm rounded border border-gray-300 text-gray-700 hover:bg-gray-50"
          >
            {cancelText}
          </button>
          <button
            onClick={() => {
              onConfirm?.();
              onCancel?.();
            }}
            className={`px-4 py-2 text-sm rounded text-white font-medium ${
              isDangerous
                ? "bg-red-600 hover:bg-red-700"
                : "bg-blue-600 hover:bg-blue-700"
            }`}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}
