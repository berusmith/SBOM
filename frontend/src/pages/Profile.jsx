import { useState } from "react";
import api from "../api/client";

export default function Profile() {
  const username = localStorage.getItem("username") || "—";
  const role = localStorage.getItem("role") || "viewer";
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState(null);

  const flash = (type, text) => {
    setMsg({ type, text });
    setTimeout(() => setMsg(null), 4000);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (next !== confirm) return flash("error", "兩次輸入的新密碼不一致");
    if (next.length < 8) return flash("error", "新密碼至少 8 個字元");
    setLoading(true);
    try {
      await api.post("/auth/change-password", { current_password: cur, new_password: next });
      setCur(""); setNext(""); setConfirm("");
      flash("success", "密碼已更新");
    } catch (err) {
      flash("error", err.response?.data?.detail || "更新失敗");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-lg">
      <h1 className="text-xl font-bold text-gray-800 mb-6">帳號設定</h1>

      <div className="bg-white rounded-xl border border-gray-200 p-5 mb-5">
        <div className="text-sm text-gray-500 mb-1">登入帳號</div>
        <div className="font-medium text-gray-800">{username}</div>
        <div className="text-sm text-gray-500 mt-3 mb-1">角色</div>
        <span className={`px-2 py-0.5 rounded text-xs font-medium ${role === "admin" ? "bg-purple-100 text-purple-700" : "bg-blue-100 text-blue-700"}`}>
          {role === "admin" ? "管理員" : "客戶帳號"}
        </span>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 p-5">
        <h2 className="font-semibold text-gray-700 mb-4">修改密碼</h2>

        {msg && (
          <div className={`mb-4 px-4 py-3 rounded text-sm ${msg.type === "success" ? "bg-green-50 text-green-700 border border-green-200" : "bg-red-50 text-red-700 border border-red-200"}`}>
            {msg.text}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="text-xs text-gray-500 block mb-1">目前密碼</label>
            <input type="password" value={cur} onChange={e => setCur(e.target.value)} required
              className="border rounded px-3 py-2 w-full text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
          </div>
          <div>
            <label className="text-xs text-gray-500 block mb-1">新密碼（至少 8 字元）</label>
            <input type="password" value={next} onChange={e => setNext(e.target.value)} required
              className="border rounded px-3 py-2 w-full text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
          </div>
          <div>
            <label className="text-xs text-gray-500 block mb-1">確認新密碼</label>
            <input type="password" value={confirm} onChange={e => setConfirm(e.target.value)} required
              className="border rounded px-3 py-2 w-full text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
          </div>
          <button type="submit" disabled={loading}
            className="w-full bg-blue-600 text-white px-4 py-2 rounded text-sm hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed mt-1">
            {loading ? "更新中..." : "更新密碼"}
          </button>
        </form>
      </div>
    </div>
  );
}
