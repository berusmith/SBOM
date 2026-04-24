import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/client";

export default function Profile() {
  const navigate = useNavigate();
  const username = localStorage.getItem("username") || "—";
  const role = localStorage.getItem("role") || "viewer";

  const [email, setEmail] = useState("");
  const [emailEditing, setEmailEditing] = useState(false);
  const [emailSaving, setEmailSaving] = useState(false);

  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState(null);

  useEffect(() => {
    api.get("/auth/me").then((r) => setEmail(r.data.email || "")).catch(() => {});
  }, []);

  const flash = (type, text) => {
    setMsg({ type, text });
    setTimeout(() => setMsg(null), 4000);
  };

  const handleLogout = async () => {
    try { await api.post("/auth/logout"); } catch { /* ignore */ }
    localStorage.removeItem("token");
    localStorage.removeItem("role");
    localStorage.removeItem("org_id");
    localStorage.removeItem("username");
    navigate("/login", { replace: true });
  };

  const handleEmailSave = async () => {
    setEmailSaving(true);
    try {
      const r = await api.patch("/auth/profile", { email: email.trim() || null });
      setEmail(r.data.email || "");
      setEmailEditing(false);
      flash("success", "Email 已更新");
    } catch (err) {
      flash("error", err.response?.data?.detail || "更新失敗");
    } finally {
      setEmailSaving(false);
    }
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

      {msg && (
        <div className={`mb-4 px-4 py-3 rounded text-sm ${msg.type === "success" ? "bg-green-50 text-green-700 border border-green-200" : "bg-red-50 text-red-700 border border-red-200"}`}>
          {msg.text}
        </div>
      )}

      {/* Info */}
      <div className="bg-white rounded-xl border border-gray-200 p-5 mb-5 space-y-4">
        <div>
          <div className="text-xs text-gray-500 mb-1">登入帳號</div>
          <div className="font-medium text-gray-800">{username}</div>
        </div>
        <div>
          <div className="text-xs text-gray-500 mb-1">角色</div>
          <span className={`px-2 py-0.5 rounded text-xs font-medium ${role === "admin" ? "bg-purple-100 text-purple-700" : "bg-blue-100 text-blue-700"}`}>
            {role === "admin" ? "管理員" : "客戶帳號"}
          </span>
        </div>
        <div>
          <div className="text-xs text-gray-500 mb-1">Email（用於密碼重設）</div>
          {emailEditing ? (
            <div className="flex gap-2 items-center">
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)}
                placeholder="your@email.com"
                className="flex-1 border rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
              <button onClick={handleEmailSave} disabled={emailSaving}
                className="px-3 py-1.5 bg-blue-600 text-white rounded text-xs hover:bg-blue-700 disabled:opacity-50">
                {emailSaving ? "儲存..." : "儲存"}
              </button>
              <button onClick={() => setEmailEditing(false)}
                className="px-3 py-1.5 border rounded text-xs text-gray-600 hover:bg-gray-100">取消</button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-700">{email || <span className="text-gray-400 italic">未設定</span>}</span>
              <button onClick={() => setEmailEditing(true)}
                className="text-xs text-blue-600 hover:underline">編輯</button>
            </div>
          )}
        </div>
      </div>

      {/* Change password */}
      <div className="bg-white rounded-xl border border-gray-200 p-5 mb-5">
        <h2 className="font-semibold text-gray-700 mb-4">修改密碼</h2>
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
            className="w-full bg-blue-600 text-white px-4 py-2 rounded text-sm hover:bg-blue-700 disabled:opacity-50 mt-1">
            {loading ? "更新中..." : "更新密碼"}
          </button>
        </form>
      </div>

      {/* Logout */}
      <div className="bg-white rounded-xl border border-gray-200 p-5">
        <h2 className="font-semibold text-gray-700 mb-2">登出</h2>
        <p className="text-xs text-gray-500 mb-3">登出後 Token 立即失效，需重新登入。</p>
        <button onClick={handleLogout}
          className="px-4 py-2 bg-red-50 text-red-600 border border-red-200 rounded text-sm hover:bg-red-100">
          登出此帳號
        </button>
      </div>
    </div>
  );
}
