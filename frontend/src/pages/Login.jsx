import { useEffect, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import api from "../api/client";
import { PasswordInput } from "../components/PasswordInput";
import { validate, validators } from "../utils/validate";

export default function Login() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [oidcEnabled, setOidcEnabled] = useState(false);

  // Check OIDC availability on mount
  useEffect(() => {
    api.get("/auth/oidc/config").then(r => setOidcEnabled(r.data.enabled)).catch(() => {});
  }, []);

  // Handle SSO callback: backend redirects with token in URL FRAGMENT
  // (#sso_token=xxx).  Fragments are not sent to servers / not logged by
  // proxies / not in Referer, so the JWT never leaves the browser.
  useEffect(() => {
    const hash = window.location.hash;
    if (!hash || !hash.includes("sso_token=")) return;
    const params = new URLSearchParams(hash.slice(1));
    const ssoToken = params.get("sso_token");
    if (!ssoToken) return;
    // Wipe the fragment from the address bar before doing anything else.
    window.history.replaceState(null, "", window.location.pathname);
    localStorage.setItem("token", ssoToken);
    api.get("/auth/me")
      .then(me => {
        localStorage.setItem("role", me.data.role || "viewer");
        localStorage.setItem("org_id", me.data.org_id || "");
        localStorage.setItem("username", me.data.username || "");
        localStorage.setItem("plan", me.data.plan || "starter");
        if (me.data.role !== "admin" && me.data.org_id) {
          navigate(`/organizations/${me.data.org_id}/products`, { replace: true });
        } else {
          navigate("/", { replace: true });
        }
      })
      .catch(() => {
        localStorage.removeItem("token");
        setError(t("login.ssoFailed"));
      });
  }, [navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
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
      setError(err.response?.data?.detail || t("login.error"));
    } finally {
      setLoading(false);
    }
  };

  const handleSsoLogin = () => {
    // Redirect directly to backend OIDC initiation endpoint
    window.location.href = "/api/auth/oidc/login";
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center">
      <div className="bg-white rounded-xl shadow-lg p-8 w-full max-w-sm mx-4 sm:mx-0">
        <h1 className="text-xl font-bold text-gray-800 mb-1">SBOM Platform</h1>
        <p className="text-sm text-gray-600 mb-6">{t("login.subtitle")}</p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="login-username" className="block text-sm font-medium text-gray-700 mb-1">
              {t("login.username")}
            </label>
            <input
              id="login-username"
              name="username"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => {
                setUsername(e.target.value);
                if (errors.username) setErrors(prev => ({...prev, username: null}));
              }}
              autoFocus
              aria-invalid={errors.username ? "true" : "false"}
              aria-describedby={errors.username ? "login-username-err" : undefined}
              className={`w-full border rounded px-3 py-2 text-base focus:outline-none focus:ring-2 ${
                errors.username ? "border-red-400 focus:ring-red-400" : "border-gray-300 focus:ring-blue-400"
              }`}
            />
            {errors.username && (
              <p id="login-username-err" className="text-xs text-red-600 mt-1">{errors.username}</p>
            )}
          </div>
          <div>
            <label htmlFor="login-password" className="block text-sm font-medium text-gray-700 mb-1">{t("login.password")}</label>
            <PasswordInput
              id="login-password"
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
            {loading ? t("login.loggingIn") : t("login.submit")}
          </button>
          <div className="text-right mt-2">
            <Link to="/forgot-password" className="text-xs text-gray-700 hover:text-blue-600 hover:underline">
              {t("login.forgotPassword")}
            </Link>
          </div>
        </form>

        {oidcEnabled && (
          <>
            <div className="relative my-5">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-200" />
              </div>
              <div className="relative flex justify-center text-xs text-gray-400">
                <span className="bg-white px-2">{t("login.orDivider")}</span>
              </div>
            </div>
            <button
              onClick={handleSsoLogin}
              className="w-full py-2.5 rounded text-sm font-medium border border-gray-300 text-gray-700 hover:bg-gray-50 flex items-center justify-center gap-2"
            >
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
              {t("login.ssoButton")}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
