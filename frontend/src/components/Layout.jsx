import { useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { Lock, Search } from "lucide-react";
import { getPlan, hasPlan, PLAN_LABEL, PLAN_COLOR } from "../utils/plan";
import { useFocusTrap } from "../hooks/useFocusTrap";

// UX-3.015 — pages that benefit from a wider container on big screens.
// Data-heavy pages (risk overview, audit log) get max-w-page-wide (1536)
// instead of the default max-w-page (1280, == max-w-7xl) so monitors
// > 1280 actually use the space. Form / narrow pages stay at 7xl.
const WIDE_ROUTES = new Set([
  "/risk-overview",
  "/admin/activity",
]);

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
  const mobileMenuRef = useRef(null);

  // UX-021 — when the mobile hamburger menu is open, treat it like a
  // modal sheet: trap Tab focus within it, close on Escape, lock body
  // scroll, restore focus to the hamburger button on close.  Re-uses the
  // shared useFocusTrap hook (same one Modal/ConfirmModal use).
  useFocusTrap({
    active: menuOpen,
    containerRef: mobileMenuRef,
    onEscape: () => setMenuOpen(false),
  });
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

  const handleLogout = async () => {
    try { await import("../api/client").then(m => m.default.post("/auth/logout")); } catch { /* ignore */ }
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
      {/* UX-015: skip-to-main link.  Visually hidden until focused so
          keyboard users can jump past the 11-link nav + search + user
          cluster on every page. */}
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:bg-white focus:text-blue-700 focus:px-3 focus:py-2 focus:rounded focus:shadow"
      >
        {t("nav.skipToMain", { defaultValue: "跳至主內容" })}
      </a>
      <nav className="bg-slate-900 text-white">
        <div className="max-w-7xl mx-auto px-4">
          {/* Top bar */}
          <div className="flex items-center h-14 gap-3">
            <span className="font-bold text-base tracking-tight shrink-0">SBOM Platform</span>

            {/* Desktop nav — `min-w-0 overflow-x-auto` lets this section
                shrink below the sum of its children's intrinsic widths
                and gives the items a horizontal scroll inside the navbar
                (instead of bleeding past `max-w-7xl` and forcing the
                viewport into a horizontal scroll on screens narrower
                than ~1417px, e.g. 1366×768 / 1440×900). */}
            <div className="hidden md:flex gap-1 ml-2 min-w-0 overflow-x-auto">
              {visibleItems.map((item) => (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`px-2.5 py-1.5 rounded text-sm transition-colors whitespace-nowrap ${
                    isActive(item.path)
                      ? "bg-blue-600 text-white"
                      : "text-slate-300 hover:text-white hover:bg-slate-700"
                  }`}
                >
                  {t(`nav.${item.key}`)}
                </Link>
              ))}
              {lockedItems.map((item) => (
                <span
                  key={item.path}
                  role="link"
                  aria-disabled="true"
                  title={t("nav.lockedHint", {
                    plan: item.minPlan === "standard" ? "Standard" : "Professional",
                  })}
                  className="px-2.5 py-1.5 rounded text-sm text-slate-500 cursor-not-allowed flex items-center gap-1 whitespace-nowrap"
                >
                  <Lock size={12} aria-hidden="true" />
                  <span>{t(`nav.${item.key}`)}</span>
                </span>
              ))}
            </div>

            {/* Desktop search + lang toggle + user — UX-008: tighten gap/widths
                so the whole right cluster fits inside max-w-page (1280) without
                bleeding past `登出`.  Search input no longer widens at lg:; gap
                shrinks from 3 to 2; lang button loses its border (still has
                hover state).  Total intrinsic width drops below the 1280
                threshold so the user section is no longer clipped at 1280. */}
            <form
              onSubmit={handleSearch}
              role="search"
              className="hidden md:flex items-center gap-1 ml-auto"
            >
              <label htmlFor="nav-search" className="sr-only">{t("nav.search")}</label>
              <input
                id="nav-search"
                type="search"
                value={searchQ}
                onChange={(e) => setSearchQ(e.target.value)}
                placeholder={t("nav.search")}
                className="bg-slate-700 text-white text-sm rounded px-3 py-1.5 w-32 xl:w-44 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-400"
              />
              <button
                type="submit"
                aria-label={t("common.search")}
                className="text-slate-300 hover:text-white p-2 rounded focus:outline-none focus:ring-2 focus:ring-blue-400"
              >
                <Search size={16} aria-hidden="true" />
              </button>
            </form>
            <div className="hidden md:flex items-center gap-2 min-w-0">
              <button
                onClick={toggleLang}
                className="text-xs text-slate-400 hover:text-white px-2 py-1.5 rounded hover:bg-slate-700 transition-colors"
                title="Switch language / 切換語言"
              >
                {i18n.language === "zh" ? "EN" : "中"}
              </button>
              <span className={`text-xs px-2 py-0.5 rounded-full font-medium shrink-0 ${PLAN_COLOR[currentPlan]}`}>
                {PLAN_LABEL[currentPlan]}
              </span>
              <Link to="/profile" className="text-sm text-slate-300 hover:text-white transition-colors max-w-[8rem] truncate">
                {username || t("nav.account")}
              </Link>
              <button
                onClick={handleLogout}
                className="text-sm text-slate-300 hover:text-white transition-colors shrink-0"
              >
                {t("nav.logout")}
              </button>
            </div>

            {/* Mobile hamburger */}
            <div className="md:hidden flex items-center gap-2 ml-auto">
              {/* UX-009 — mobile lang toggle bumped to py-2 (~32px) +
                  min-w-touch (44px) so the touch target meets Apple HIG. */}
              <button
                onClick={toggleLang}
                aria-label={i18n.language === "zh" ? "Switch to English" : "切換為中文"}
                className="text-xs text-slate-400 hover:text-white border border-slate-600 px-3 py-2 min-w-[44px] rounded focus:outline-none focus:ring-2 focus:ring-blue-400"
              >
                {i18n.language === "zh" ? "EN" : "中"}
              </button>
              <button
                onClick={() => setMenuOpen(!menuOpen)}
                className="text-slate-300 hover:text-white p-2.5 rounded focus:outline-none focus:ring-2 focus:ring-blue-400"
                aria-label={menuOpen ? t("nav.closeMenu") : t("nav.openMenu")}
                aria-expanded={menuOpen}
                aria-controls="mobile-menu"
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
            <div
              id="mobile-menu"
              ref={mobileMenuRef}
              className="md:hidden border-t border-slate-700 py-3 space-y-1"
            >
              {navItems.map((item) => (
                <Link
                  key={item.path}
                  to={item.path}
                  onClick={() => setMenuOpen(false)}
                  className={`block px-3 py-3 rounded text-sm ${
                    isActive(item.path)
                      ? "bg-blue-600 text-white"
                      : "text-slate-300 hover:text-white hover:bg-slate-700"
                  }`}
                >
                  {t(`nav.${item.key}`)}
                </Link>
              ))}
              {/*
                On mobile we use text-base (16px) explicitly so iOS Safari
                doesn't auto-zoom on focus.  text-sm (14px) triggers the zoom.
              */}
              <form onSubmit={handleSearch} role="search" className="flex gap-2 px-3 pt-2">
                <label htmlFor="mobile-nav-search" className="sr-only">{t("nav.search")}</label>
                <input
                  id="mobile-nav-search"
                  type="search"
                  value={searchQ}
                  onChange={(e) => setSearchQ(e.target.value)}
                  placeholder={t("nav.search")}
                  className="bg-slate-700 text-white text-base rounded px-3 py-2 flex-1 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-400"
                />
                <button type="submit" className="bg-gray-600 text-white px-3 py-2 rounded text-sm">
                  {t("common.search")}
                </button>
              </form>
              <Link
                to="/profile"
                onClick={() => setMenuOpen(false)}
                className="block px-3 py-3 text-sm text-slate-300 hover:text-white hover:bg-slate-700 rounded"
              >
                {username || t("nav.account")}
              </Link>
              <button
                onClick={handleLogout}
                className="block w-full text-left px-3 py-3 text-sm text-slate-300 hover:text-white hover:bg-slate-700 rounded focus:outline-none focus:ring-2 focus:ring-blue-400"
              >
                {t("nav.logout")}
              </button>
            </div>
          )}
        </div>
      </nav>
      {/* UX-3.015 — wide layout on data-heavy routes; narrow elsewhere. The
          navbar above stays at max-w-7xl so the product chrome is consistent
          across pages — main is the only thing that breathes wider. */}
      <main
        id="main"
        tabIndex="-1"
        className={`${WIDE_ROUTES.has(location.pathname) ? "max-w-page-wide" : "max-w-7xl"} mx-auto px-3 sm:px-4 md:px-6 py-4 sm:py-6 focus:outline-none`}
      >
        {children}
      </main>

      <footer className="border-t border-gray-200 bg-white mt-8">
        <div className="max-w-7xl mx-auto px-4 py-4 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-gray-600">
          <span>SBOM Platform · v2.0.0</span>
          <div className="flex items-center gap-3">
            <Link to="/about" className="hover:text-gray-800 hover:underline">
              {t("nav.openSourceNotices") /* falls back to key if missing */}
            </Link>
            <span>·</span>
            <a
              href="/api/notice"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-gray-800 hover:underline"
              title="Raw NOTICE.md"
            >
              NOTICE.md
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
