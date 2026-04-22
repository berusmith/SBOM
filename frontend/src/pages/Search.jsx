import { useEffect, useState } from "react";
import { useNavigate, useSearchParams, Link } from "react-router-dom";
import api from "../api/client";
import { SEVERITY_COLOR } from "../constants/colors";

export default function Search() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [input, setInput] = useState(searchParams.get("q") || "");
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const doSearch = async (q) => {
    if (!q.trim()) return;
    setLoading(true);
    try {
      const res = await api.get("/search/components", { params: { q } });
      setResults(res.data);
    } catch {
      setResults({ query: q, total: 0, results: [] });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const q = searchParams.get("q");
    if (q) { setInput(q); doSearch(q); }
  }, []);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!input.trim()) return;
    setSearchParams({ q: input.trim() });
    doSearch(input.trim());
  };

  return (
    <div>
      <h2 className="text-lg font-semibold text-gray-800 mb-4">全局元件搜尋</h2>

      <form onSubmit={handleSubmit} className="flex gap-2 mb-6">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="輸入元件名稱，例如：log4j、openssl、spring"
          className="flex-1 border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
          autoFocus
        />
        <button
          type="submit"
          disabled={loading}
          className={`px-5 py-2 rounded text-sm text-white font-medium ${loading ? "bg-gray-400" : "bg-blue-600 hover:bg-blue-700"}`}
        >
          {loading ? "搜尋中..." : "搜尋"}
        </button>
      </form>

      {results && (
        <>
          <p className="text-sm text-gray-500 mb-3">
            搜尋「<span className="font-medium text-gray-700">{results.query}</span>」找到 <span className="font-medium">{results.total}</span> 筆結果
          </p>

          {results.total === 0 ? (
            <div className="bg-white rounded-lg shadow p-8 text-center text-gray-400">
              未找到符合的元件
            </div>
          ) : (
            <div className="bg-white rounded-lg shadow overflow-hidden">
              <div className="overflow-x-auto">
              <table className="w-full text-sm min-w-[640px]">
                <thead className="bg-gray-50 text-gray-500 text-left">
                  <tr>
                    <th className="px-4 py-3">元件名稱</th>
                    <th className="px-4 py-3">版本</th>
                    <th className="px-4 py-3">客戶</th>
                    <th className="px-4 py-3">產品</th>
                    <th className="px-4 py-3">版本號</th>
                    <th className="px-4 py-3">漏洞數</th>
                    <th className="px-4 py-3">最高風險</th>
                    <th className="px-4 py-3">KEV</th>
                  </tr>
                </thead>
                <tbody>
                  {results.results.map((r) => (
                    <tr key={r.component_id} className="border-t hover:bg-gray-50">
                      <td className="px-4 py-2 font-medium text-gray-800">{r.component_name}</td>
                      <td className="px-4 py-2 text-gray-500 font-mono text-xs">{r.component_version || "—"}</td>
                      <td className="px-4 py-2 text-gray-600">{r.org_name}</td>
                      <td className="px-4 py-2 text-gray-600">{r.product_name}</td>
                      <td className="px-4 py-2">
                        <Link
                          to={`/releases/${r.release_id}`}
                          className="text-blue-600 hover:underline"
                        >
                          {r.release_version}
                        </Link>
                      </td>
                      <td className="px-4 py-2 text-gray-700">{r.vuln_count || "—"}</td>
                      <td className="px-4 py-2">
                        {r.highest_severity ? (
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_COLOR[r.highest_severity]}`}>
                            {r.highest_severity}
                          </span>
                        ) : "—"}
                      </td>
                      <td className="px-4 py-2">
                        {r.kev_count > 0 && (
                          <span className="px-1.5 py-0.5 rounded text-white bg-red-600 font-bold" style={{fontSize:"10px"}}>
                            {r.kev_count} KEV
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
