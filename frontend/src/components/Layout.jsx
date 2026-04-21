import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";

const navItems = [
  { path: "/",              label: "儀表板" },
  { path: "/organizations", label: "客戶管理" },
  { path: "/risk-overview", label: "風險總覽" },
  { path: "/policies",      label: "Policy" },
  { path: "/cra",           label: "🚨 CRA 事件" },
  { path: "/settings",      label: "通知設定" },
  { path: "/help",          label: "說明" },
];

export default function Layout({ children }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [searchQ, setSearchQ] = useState("");
  const [menuOpen, setMenuOpen] = useState(false);

  const handleSearch = (e) => {
    e.preventDefault();
    if (!searchQ.trim()) return;
    navigate(`/search?q=${encodeURIComponent(searchQ.trim())}`);
    setSearchQ("");
    setMenuOpen(false);
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
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
              {navItems.map((item) => (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`px-2.5 py-1.5 rounded text-sm transition-colors whitespace-nowrap ${
                    isActive(item.path)
                      ? "bg-blue-600 text-white"
                      : "text-gray-300 hover:text-white hover:bg-gray-700"
                  }`}
                >
                  {item.label}
                </Link>
              ))}
            </div>

            {/* Desktop search */}
            <form onSubmit={handleSearch} className="hidden md:flex items-center gap-1 ml-auto">
              <input
                value={searchQ}
                onChange={(e) => setSearchQ(e.target.value)}
                placeholder="搜尋元件..."
                className="bg-gray-700 text-white text-sm rounded px-3 py-1.5 w-36 lg:w-44 placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-blue-400"
              />
              <button type="submit" className="text-gray-400 hover:text-white px-1 text-sm">⌕</button>
            </form>
            <button
              onClick={handleLogout}
              className="hidden md:block text-sm text-gray-400 hover:text-white transition-colors shrink-0"
            >
              登出
            </button>

            {/* Mobile: search icon + hamburger */}
            <div className="md:hidden flex items-center gap-2 ml-auto">
              <button
                onClick={() => setMenuOpen(!menuOpen)}
                className="text-gray-300 hover:text-white p-1 rounded"
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
                  {item.label}
                </Link>
              ))}
              <form onSubmit={handleSearch} className="flex gap-2 px-3 pt-2">
                <input
                  value={searchQ}
                  onChange={(e) => setSearchQ(e.target.value)}
                  placeholder="搜尋元件..."
                  className="bg-gray-700 text-white text-sm rounded px-3 py-2 flex-1 placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-blue-400"
                />
                <button type="submit" className="bg-gray-600 text-white px-3 py-2 rounded text-sm">搜尋</button>
              </form>
              <button
                onClick={handleLogout}
                className="block w-full text-left px-3 py-2.5 text-sm text-gray-400 hover:text-white hover:bg-gray-700 rounded"
              >
                登出
              </button>
            </div>
          )}
        </div>
      </nav>
      <main className="max-w-7xl mx-auto px-3 sm:px-4 py-4 sm:py-6">{children}</main>
    </div>
  );
}
