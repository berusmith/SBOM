import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { getPlan, hasPlan, PLAN_LABEL, PLAN_COLOR } from "../utils/plan";

const ALL_NAV = [
  { path: "/",               key: "dashboard",    adminOnly: false, minPlan: null },
  { path: "/organizations",  key: "customers",    adminOnly: true,  minPlan: null },
  { path: "/risk-overview",  key: "riskOverview", adminOnly: false, minPlan: null },
  { path: "/policies",       key: "policy",       adminOnly: false, minPlan: null },
  { path: "/cra",            key: "cra",          adminOnly: false, minPlan: "standard" },
  { path: "/tisax",          key: "tisax",        adminOnly: false, minPlan: "professional" },
  { path: "/firmware",       key: "firmware",     adminOnly: false, minPlan: null },
  { path: "/admin/users",    key: "users",        adminOnly: true,  minPlan: null },
  { path: "/admin/activity", key: "auditLog",     adminOnly: true,  minPlan: null },
  { path: "/settings",       key: "settings",     adminOnly: true,  minPlan: null },
  { path: "/help",           key: "help",         adminOnly: false, minPlan: null },
];

export default function Layout({ children }) {
  const location = useLocation();
  const navigate = useNavigate();
  const { t, i18n } = useTranslation();
  const [searchQ, setSearchQ] = useState("");
  const [menuOpen, setMenuOpen] = useState(false);
  const role = localStorage.getItem("role") || "viewer";
  const currentPlan = getPlan();
  const navItems = ALL_NAV.filter(item => !item.adminOnly || role === "admin");
  const lockedItems = navItems.filter(item => item.minPlan && !hasPlan(item.minPlan));
  const visibleItems = navItems.filter(item => !item.minPlan || hasPlan(item.minPlan));

  const handleSearch = (e) => {
    e.preventDefault();
    if (!searchQ.trim()) return;
    navigate(`/search?q=${encodeURIComponent(searchQ.trim())}`);
    setSearchQ("");
    setMenuOpen(false);
  };

  const toggleLang = () => {
    const next = i18n.language === "zh" ? "en" : "zh";
    i18n.changeLanguage(next);
    localStorage.setItem("lang", next);
  };

  const username = localStorage.getItem("username") || "";

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("role");
    localStorage.removeItem("org_id");
    localStorage.removeItem("username");
    navigate("/login", { replace: true });
  };

  const isActive = (path) =>
    path === "/" ? location.pathname === "/" : location.pathname.startsWith(path);

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-gray-900 text-white">
        <div className="max-w-7xl mx-auto px-4">
          {/* Top bar */}
          <div className="flex items-center h-14 gap-3">
            <span className="font-bold text-base tracking-tight shrink-0">SBOM Platform</span>

            {/* Desktop nav */}
            <div className="hidden md:flex gap-1 ml-2">
              {visibleItems.map((item) => (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`px-2.5 py-1.5 rounded text-sm transition-colors whitespace-nowrap ${
                    isActive(item.path)
                      ? "bg-blue-600 text-white"
                      : "text-gray-300 hover:text-white hover:bg-gray-700"
                  }`}
                >
                  {t(`nav.${item.key}`)}
                </Link>
              ))}
              {lockedItems.map((item) => (
                <span
                  key={item.path}
                  title={`需要 ${item.minPlan === "standard" ? "Standard" : "Professional"} 方案`}
                  className="px-2.5 py-1.5 rounded text-sm text-gray-600 cursor-not-allowed flex items-center gap-1 whitespace-nowrap"
                >
                  🔒 {t(`nav.${item.key}`)}
                </span>
              ))}
            </div>

            {/* Desktop search + lang toggle + user */}
            <form onSubmit={handleSearch} className="hidden md:flex items-center gap-1 ml-auto">
              <input
                value={searchQ}
                onChange={(e) => setSearchQ(e.target.value)}
                placeholder={t("nav.search")}
                className="bg-gray-700 text-white text-sm rounded px-3 py-1.5 w-36 lg:w-44 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-400"
              />
              <button type="submit" className="text-gray-600 hover:text-white px-1 text-sm">⌕</button>
            </form>
            <div className="hidden md:flex items-center gap-3 shrink-0">
              <button
                onClick={toggleLang}
                className="text-xs text-gray-400 hover:text-white border border-gray-600 hover:border-gray-400 px-2.5 py-1.5 rounded transition-colors"
                title="Switch language / 切換語言"
              >
                {i18n.language === "zh" ? "EN" : "中"}
              </button>
              <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${PLAN_COLOR[currentPlan]}`}>
                {PLAN_LABEL[currentPlan]}
              </span>
              <Link to="/profile" className="text-sm text-gray-300 hover:text-white transition-colors">
                {username || t("nav.account")}
              </Link>
              <button
                onClick={handleLogout}
                className="text-sm text-gray-600 hover:text-white transition-colors"
              >
                {t("nav.logout")}
              </button>
            </div>

            {/* Mobile hamburger */}
            <div className="md:hidden flex items-center gap-2 ml-auto">
              <button
                onClick={toggleLang}
                className="text-xs text-gray-400 hover:text-white border border-gray-600 px-2.5 py-1.5 rounded"
              >
                {i18n.language === "zh" ? "EN" : "中"}
              </button>
              <button
                onClick={() => setMenuOpen(!menuOpen)}
                className="text-gray-300 hover:text-white p-2.5 rounded"
                aria-label="選單"
              >
                {menuOpen ? (
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                ) : (
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                  </svg>
                )}
              </button>
            </div>
          </div>

          {/* Mobile menu */}
          {menuOpen && (
            <div className="md:hidden border-t border-gray-700 py-3 space-y-1">
              {navItems.map((item) => (
                <Link
                  key={item.path}
                  to={item.path}
                  onClick={() => setMenuOpen(false)}
                  className={`block px-3 py-2.5 rounded text-sm ${
                    isActive(item.path)
                      ? "bg-blue-600 text-white"
                      : "text-gray-300 hover:text-white hover:bg-gray-700"
                  }`}
                >
                  {t(`nav.${item.key}`)}
                </Link>
              ))}
              <form onSubmit={handleSearch} className="flex gap-2 px-3 pt-2">
                <input
                  value={searchQ}
                  onChange={(e) => setSearchQ(e.target.value)}
                  placeholder={t("nav.search")}
                  className="bg-gray-700 text-white text-sm rounded px-3 py-2 flex-1 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-400"
                />
                <button type="submit" className="bg-gray-600 text-white px-3 py-2 rounded text-sm">
                  {t("common.search")}
                </button>
              </form>
              <Link
                to="/profile"
                onClick={() => setMenuOpen(false)}
                className="block px-3 py-2.5 text-sm text-gray-300 hover:text-white hover:bg-gray-700 rounded"
              >
                {username || t("nav.account")}
              </Link>
              <button
                onClick={handleLogout}
                className="block w-full text-left px-3 py-2.5 text-sm text-gray-600 hover:text-white hover:bg-gray-700 rounded"
              >
                {t("nav.logout")}
              </button>
            </div>
          )}
        </div>
      </nav>
      <main className="max-w-7xl mx-auto px-3 sm:px-4 md:px-6 py-4 sm:py-6">{children}</main>
    </div>
  );
}
