import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/client";
import { PasswordInput } from "../components/PasswordInput";
import { validate, validators } from "../utils/validate";

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();

    // Client-side validation
    const validationErrors = validate(
      { username: validators.required, password: validators.required },
      { username, password }
    );
    if (Object.values(validationErrors).some(e => e)) {
      setErrors(validationErrors);
      return;
    }

    setError("");
    setErrors({});
    setLoading(true);
    try {
      const res = await api.post("/auth/login", { username, password });
      localStorage.setItem("token", res.data.access_token);
      const me = await api.get("/auth/me");
      localStorage.setItem("role", me.data.role || "viewer");
      localStorage.setItem("org_id", me.data.org_id || "");
      localStorage.setItem("username", me.data.username || username);
      if (me.data.role !== "admin" && me.data.org_id) {
        navigate(`/organizations/${me.data.org_id}/products`, { replace: true });
      } else {
        navigate("/", { replace: true });
      }
    } catch (err) {
      setError(err.response?.data?.detail || "登入失敗");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center">
      <div className="bg-white rounded-xl shadow-lg p-8 w-full max-w-sm mx-4 sm:mx-0">
        <h1 className="text-xl font-bold text-gray-800 mb-1">SBOM Platform</h1>
        <p className="text-sm text-gray-600 mb-6">請登入以繼續</p>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">帳號</label>
            <input
              type="text"
              value={username}
              onChange={(e) => {
                setUsername(e.target.value);
                if (errors.username) setErrors(prev => ({...prev, username: null}));
              }}
              autoFocus
              className={`w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 ${
                errors.username ? "border-red-400 focus:ring-red-400" : "border-gray-300 focus:ring-blue-400"
              }`}
            />
            {errors.username && <p className="text-xs text-red-500 mt-1">{errors.username}</p>}
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">密碼</label>
            <PasswordInput
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                if (errors.password) setErrors(prev => ({...prev, password: null}));
              }}
              error={errors.password}
            />
          </div>
          {error && <p className="text-sm text-red-500">{error}</p>}
          <button
            type="submit"
            disabled={loading}
            className={`w-full py-2.5 rounded text-sm text-white font-medium ${loading ? "bg-gray-400" : "bg-blue-600 hover:bg-blue-700"}`}
          >
            {loading ? "登入中..." : "登入"}
          </button>
        </form>
      </div>
    </div>
  );
}
