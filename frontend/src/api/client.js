import axios from "axios";

const api = axios.create({
  baseURL: "/api",
  headers: { "Content-Type": "application/json" },
});

// localStorage keys we set during login / SSO callback.  Centralised here so
// the 401 handler below can wipe ALL of them — leaving any of these around
// after a session expiry confuses Layout (stale username/role) and leaks
// stale identity hints into bug reports.
const SESSION_KEYS = ["token", "role", "org_id", "username", "plan"];

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      // Clear ALL session state, not just the token, before redirecting.
      // Leaving role/org_id/username behind makes the next /login render
      // briefly think a user is signed in.
      SESSION_KEYS.forEach((k) => localStorage.removeItem(k));

      // Avoid a redirect loop if the 401 happened on a request from the
      // login page itself (e.g. the OIDC config probe).  Public routes that
      // don't need auth should never trigger this anyway, but be defensive.
      const path = window.location.pathname;
      const onPublicRoute = ["/login", "/forgot-password", "/reset-password", "/about"]
        .some((p) => path === p || path.startsWith(p + "/"));
      if (!onPublicRoute) {
        window.location.href = "/login";
      }
    }
    return Promise.reject(err);
  }
);

export default api;
