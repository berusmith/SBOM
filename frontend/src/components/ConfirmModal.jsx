import { useEffect, useState } from "react";

export function ConfirmModal({
  isOpen,
  title,
  message,
  confirmText = "確認",
  cancelText = "取消",
  isDangerous = false,
  requireTypeName = null,   // if set, user must type this string to enable confirm
  onConfirm,
  onCancel,
}) {
  const [typed, setTyped] = useState("");

  useEffect(() => {
    if (!isOpen) { setTyped(""); return; }
    const handleEsc = (e) => { if (e.key === "Escape") onCancel?.(); };
    document.addEventListener("keydown", handleEsc);
    return () => document.removeEventListener("keydown", handleEsc);
  }, [isOpen, onCancel]);

  if (!isOpen) return null;

  const canConfirm = !requireTypeName || typed === requireTypeName;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/40" onClick={() => onCancel?.()} />
      <div className="relative bg-white rounded-lg shadow-xl p-6 max-w-sm w-[90%] sm:w-full">
        <h2 className="text-lg font-bold text-gray-800 mb-2">{title}</h2>
        <p className="text-sm text-gray-600 mb-4 whitespace-pre-wrap">{message}</p>

        {requireTypeName && (
          <div className="mb-5">
            <p className="text-xs text-gray-500 mb-1.5">
              請輸入 <span className="font-mono font-semibold text-gray-700">{requireTypeName}</span> 以確認刪除
            </p>
            <input
              autoFocus
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              placeholder={requireTypeName}
              className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-400"
            />
          </div>
        )}

        <div className="flex gap-3 justify-end">
          <button
            onClick={() => onCancel?.()}
            className="px-4 py-2 text-sm rounded border border-gray-300 text-gray-700 hover:bg-gray-50"
          >
            {cancelText}
          </button>
          <button
            disabled={!canConfirm}
            onClick={() => { if (canConfirm) { onConfirm?.(); onCancel?.(); } }}
            className={`px-4 py-2 text-sm rounded text-white font-medium transition-opacity ${
              isDangerous ? "bg-red-600 hover:bg-red-700" : "bg-blue-600 hover:bg-blue-700"
            } disabled:opacity-40 disabled:cursor-not-allowed`}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}
