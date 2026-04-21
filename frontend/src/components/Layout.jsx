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

  const handleSearch = (e) => {
    e.preventDefault();
    if (!searchQ.trim()) return;
    navigate(`/search?q=${encodeURIComponent(searchQ.trim())}`);
    setSearchQ("");
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    navigate("/login", { replace: true });
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-gray-900 text-white">
        <div className="max-w-7xl mx-auto px-4 flex items-center h-14 gap-8">
          <span className="font-bold text-lg tracking-tight">SBOM Platform</span>
          <div className="flex gap-2">
            {navItems.map((item) => (
              <Link
                key={item.path}
                to={item.path}
                className={`px-3 py-1.5 rounded text-sm transition-colors ${
                  (item.path === "/" ? location.pathname === "/" : location.pathname.startsWith(item.path))
                    ? "bg-blue-600 text-white"
                    : "text-gray-300 hover:text-white hover:bg-gray-700"
                }`}
              >
                {item.label}
              </Link>
            ))}
          </div>
          <form onSubmit={handleSearch} className="ml-auto flex items-center gap-1">
            <input
              value={searchQ}
              onChange={(e) => setSearchQ(e.target.value)}
              placeholder="搜尋元件..."
              className="bg-gray-700 text-white text-sm rounded px-3 py-1 w-44 placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-blue-400"
            />
            <button type="submit" className="text-gray-400 hover:text-white px-1 text-sm">⌕</button>
          </form>
          <button
            onClick={handleLogout}
            className="text-sm text-gray-400 hover:text-white transition-colors"
          >
            登出
          </button>
        </div>
      </nav>
      <main className="max-w-7xl mx-auto px-4 py-6">{children}</main>
    </div>
  );
}
