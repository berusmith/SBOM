import { useState } from "react";
import { Link } from "react-router-dom";
import api from "../api/client";

export default function ForgotPassword() {
  const [username, setUsername] = useState("");
  const [sent, setSent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username.trim()) return;
    setLoading(true);
    setError("");
    try {
      await api.post("/auth/forgot-password", { username: username.trim() });
      setSent(true);
    } catch {
      setError("請求失敗，請稍後再試");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="bg-white rounded-xl shadow p-8 w-full max-w-sm">
        <h1 className="text-xl font-bold text-gray-800 mb-2">忘記密碼</h1>
        {sent ? (
          <div className="text-sm text-gray-700 space-y-3">
            <p className="text-green-700 font-medium">已送出！</p>
            <p>若帳號存在且已設定 Email，您將在幾分鐘內收到重設連結（30 分鐘有效）。</p>
            <Link to="/login" className="text-blue-600 hover:underline text-sm">← 返回登入</Link>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <p className="text-sm text-gray-600">請輸入您的帳號（Email），系統將寄送重設連結。</p>
            {error && <p className="text-sm text-red-600">{error}</p>}
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="帳號 / Email"
              required
              className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
            />
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-blue-600 text-white py-2 rounded text-sm font-medium hover:bg-blue-700 disabled:opacity-50"
            >
              {loading ? "送出中..." : "送出重設連結"}
            </button>
            <div className="text-center">
              <Link to="/login" className="text-xs text-gray-500 hover:underline">← 返回登入</Link>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
