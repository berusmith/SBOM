import { useEffect, useState } from "react";
import { useNavigate, useSearchParams, Link } from "react-router-dom";
import api from "../api/client";
import { SEVERITY_COLOR } from "../constants/colors";

export default function Search() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [input, setInput] = useState(searchParams.get("q") || "");
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [searchError, setSearchError] = useState(null);

  const doSearch = async (q) => {
    if (!q.trim()) return;
    setLoading(true);
    setSearchError(null);
    try {
      const res = await api.get("/search/components", { params: { q } });
      setResults(res.data);
    } catch {
      setResults(null);
      setSearchError("搜尋失敗，請確認後端服務是否正常運作");
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
    const q = input.trim();
    if (!q) return;
    if (q.length < 2) { setSearchError("請輸入至少 2 個字元"); setResults(null); return; }
    setSearchParams({ q });
    doSearch(q);
  };

  return (
    <div>
      <h2 className="text-lg font-semibold text-gray-800 mb-4">全局元件搜尋</h2>

      <form onSubmit={handleSubmit} className="flex gap-2 mb-6">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="輸入元件名稱，例如：log4j、openssl、spring"
          className="flex-1 border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
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

      {searchError && (
        <div className="text-center py-8">
          <div className="text-red-500 font-medium">{searchError}</div>
          <button onClick={() => doSearch(input)} className="mt-2 text-sm text-blue-600 hover:underline">重試</button>
        </div>
      )}

      {results && (
        <>
          <p className="text-sm text-gray-600 mb-3">
            搜尋「<span className="font-medium text-gray-700">{results.query}</span>」找到 <span className="font-medium">{results.total}</span> 筆結果
          </p>

          {results.total === 0 ? (
            <div className="bg-white rounded-lg shadow p-8 text-center text-gray-600">
              未找到符合的元件
            </div>
          ) : (
            <div className="bg-white rounded-lg shadow overflow-hidden">
              <div className="overflow-x-auto">
              <table className="w-full text-sm min-w-[320px]">
                <thead className="bg-gray-50 text-gray-600 text-left">
                  <tr>
                    <th scope="col" className="px-4 py-3">元件名稱</th>
                    <th scope="col" className="px-4 py-3 hidden sm:table-cell">版本</th>
                    <th scope="col" className="px-4 py-3 hidden md:table-cell">客戶</th>
                    <th scope="col" className="px-4 py-3 hidden md:table-cell">產品</th>
                    <th scope="col" className="px-4 py-3 hidden sm:table-cell">版本號</th>
                    <th scope="col" className="px-4 py-3">漏洞數</th>
                    <th scope="col" className="px-4 py-3">最高風險</th>
                    <th scope="col" className="px-4 py-3">KEV</th>
                  </tr>
                </thead>
                <tbody>
                  {results.results.map((r) => (
                    <tr key={r.component_id} className="border-t hover:bg-gray-50">
                      <td className="px-4 py-2 font-medium text-gray-800">{r.component_name}</td>
                      <td className="px-4 py-2 text-gray-600 font-mono text-xs hidden sm:table-cell">{r.component_version || "—"}</td>
                      <td className="px-4 py-2 text-gray-600 hidden md:table-cell">{r.org_name}</td>
                      <td className="px-4 py-2 text-gray-600 hidden md:table-cell">{r.product_name}</td>
                      <td className="px-4 py-2 hidden sm:table-cell">
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
                          <span className="px-1.5 py-0.5 rounded text-white bg-red-600 font-bold text-xs">
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
