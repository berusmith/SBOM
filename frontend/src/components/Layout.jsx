import { Link, useLocation, useNavigate } from "react-router-dom";

const navItems = [
  { path: "/",             label: "儀表板" },
  { path: "/organizations", label: "客戶管理" },
  { path: "/cra",          label: "🚨 CRA 事件" },
];

export default function Layout({ children }) {
  const location = useLocation();
  const navigate = useNavigate();

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
          <button
            onClick={handleLogout}
            className="ml-auto text-sm text-gray-400 hover:text-white transition-colors"
          >
            登出
          </button>
        </div>
      </nav>
      <main className="max-w-7xl mx-auto px-4 py-6">{children}</main>
    </div>
  );
}
