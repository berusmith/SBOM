import { useId, useState } from "react";
import { useNavigate, useSearchParams, Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import api from "../api/client";
import { Button } from "../components/Button";

export default function ResetPassword() {
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const token = params.get("token") || "";
  const navigate = useNavigate();

  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const newPwId = useId();
  const confirmPwId = useId();

  if (!token) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
        <div className="bg-white rounded-xl shadow p-8 w-full max-w-sm text-center">
          <p className="text-red-600 font-medium mb-4">連結無效或已過期</p>
          <Link to="/forgot-password" className="text-blue-600 hover:underline text-sm">重新申請</Link>
        </div>
      </div>
    );
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (newPassword.length < 8) { setError("密碼至少 8 個字元"); return; }
    if (newPassword !== confirm) { setError("兩次密碼不一致"); return; }
    setLoading(true);
    setError("");
    try {
      await api.post("/auth/reset-password", { token, new_password: newPassword });
      navigate("/login", { state: { message: "密碼已重設，請重新登入" } });
    } catch (err) {
      setError(err.response?.data?.detail || "重設失敗，連結可能已過期");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="bg-white rounded-xl shadow p-8 w-full max-w-sm">
        <h1 className="text-xl font-bold text-gray-800 mb-6">{t("passwordReset.resetTitle")}</h1>
        <form onSubmit={handleSubmit} className="space-y-4">
          {error && <p className="text-sm text-red-600">{error}</p>}
          <div>
            <label htmlFor={newPwId} className="block text-xs font-medium text-gray-600 mb-1">新密碼（至少 8 個字元）</label>
            <input
              id={newPwId}
              type="password"
              autoComplete="new-password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
            />
          </div>
          <div>
            <label htmlFor={confirmPwId} className="block text-xs font-medium text-gray-600 mb-1">確認新密碼</label>
            <input
              id={confirmPwId}
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              required
              className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
            />
          </div>
          <Button type="submit" loading={loading} fullWidth size="lg">
            {loading ? "重設中..." : "確認重設"}
          </Button>
        </form>
      </div>
    </div>
  );
}
