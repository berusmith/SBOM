import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import api from "../api/client";

export default function Releases() {
  const { productId } = useParams();
  const navigate = useNavigate();
  const [releases, setReleases] = useState([]);
  const [productName, setProductName] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [version, setVersion] = useState("");
  const [loading, setLoading] = useState(false);
  const [showDiff, setShowDiff] = useState(false);
  const [diffFrom, setDiffFrom] = useState("");
  const [diffTo, setDiffTo] = useState("");
  const [trendData, setTrendData] = useState([]);

  const fetchData = () => {
    api.get(`/products/${productId}/releases`).then((res) => {
      setReleases(res.data.releases || []);
      setProductName(res.data.product_name || "");
    }).catch(() => {});
    api.get(`/products/${productId}/vuln-trend`).then((res) => setTrendData(res.data)).catch(() => {});
  };

  useEffect(() => { fetchData(); }, [productId]);

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!version.trim()) return;
    setLoading(true);
    try {
      await api.post(`/products/${productId}/releases`, { version });
      setVersion("");
      setShowForm(false);
      fetchData();
    } catch (err) {
      alert("建立失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (r) => {
    if (!window.confirm(`確定要刪除版本「${r.version}」？此操作將同時刪除 SBOM 檔案及所有漏洞資料，無法還原。`)) return;
    try {
      await api.delete(`/releases/${r.id}`);
      fetchData();
    } catch (err) {
      alert("刪除失敗：" + (err.response?.data?.detail || err.message));
    }
  };

  return (
    <div>
      <div className="flex items-center gap-2 mb-1">
        <button onClick={() => navigate("/organizations")} className="text-blue-600 hover:underline text-sm">
          客戶管理
        </button>
        <span className="text-gray-400">/</span>
        <span className="text-sm text-gray-600">{productName || productId}</span>
      </div>

      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-800">版本列表</h1>
        <div className="flex gap-2">
          {releases.length >= 2 && (
            <button
              onClick={() => setShowDiff(!showDiff)}
              className="bg-indigo-600 text-white px-4 py-2 rounded hover:bg-indigo-700 text-sm"
            >
              版本比對
            </button>
          )}
          <button
            onClick={() => setShowForm(!showForm)}
            className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 text-sm"
          >
            + 新增版本
          </button>
        </div>
      </div>

      {showForm && (
        <form onSubmit={handleCreate} className="bg-white rounded-lg shadow p-4 mb-4 flex flex-col sm:flex-row gap-2">
          <input
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            placeholder="版本號（如：v1.0.1）"
            className="border rounded px-3 py-2 flex-1 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
          />
          <div className="flex gap-2">
            <button type="submit" disabled={loading}
              className="flex-1 sm:flex-none bg-blue-600 text-white px-4 py-2 rounded text-sm hover:bg-blue-700 disabled:opacity-50">
              {loading ? "建立中..." : "確認"}
            </button>
            <button type="button" onClick={() => setShowForm(false)}
              className="flex-1 sm:flex-none text-gray-500 px-4 py-2 rounded text-sm hover:bg-gray-100 border">
              取消
            </button>
          </div>
        </form>
      )}

      {trendData.filter(d => d.total > 0).length >= 2 && (
        <TrendChart data={trendData} />
      )}

      {showDiff && (
        <div className="bg-white rounded-lg shadow p-4 mb-4">
          <p className="text-sm font-medium text-gray-700 mb-3">選擇要比對的兩個版本</p>
          <div className="flex gap-3 items-center flex-wrap">
            <select value={diffFrom} onChange={(e) => setDiffFrom(e.target.value)}
              className="border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400">
              <option value="">— 舊版本 —</option>
              {releases.map((r) => <option key={r.id} value={r.id}>{r.version}</option>)}
            </select>
            <span className="text-gray-400">→</span>
            <select value={diffTo} onChange={(e) => setDiffTo(e.target.value)}
              className="border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400">
              <option value="">— 新版本 —</option>
              {releases.map((r) => <option key={r.id} value={r.id}>{r.version}</option>)}
            </select>
            <button
              disabled={!diffFrom || !diffTo || diffFrom === diffTo}
              onClick={() => navigate(`/releases/diff?product=${productId}&from=${diffFrom}&to=${diffTo}`)}
              className="px-4 py-2 bg-indigo-600 text-white rounded text-sm hover:bg-indigo-700 disabled:opacity-40"
            >
              開始比對
            </button>
            <button onClick={() => setShowDiff(false)} className="text-sm text-gray-400 hover:text-gray-600">取消</button>
          </div>
        </div>
      )}

      <div className="bg-white rounded-lg shadow overflow-hidden">
        {releases.length === 0 ? (
          <div className="p-8 text-center text-gray-400">尚無版本，點擊「新增版本」開始</div>
        ) : (
          <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[520px]">
            <thead className="bg-gray-50 text-gray-500 text-left">
              <tr>
                <th className="px-4 py-3">版本號</th>
                <th className="px-4 py-3">建立時間</th>
                <th className="px-4 py-3">SBOM</th>
                <th className="px-4 py-3">漏洞</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {releases.map((r) => (
                <tr key={r.id} className="border-t hover:bg-gray-50">
                  <td className="px-4 py-3 font-medium text-gray-800">
                    {r.version}
                    {r.locked && <span className="ml-1.5 text-gray-400 text-xs">🔒</span>}
                  </td>
                  <td className="px-4 py-3 text-gray-500">
                    {new Date(r.created_at).toLocaleDateString("zh-TW")}
                  </td>
                  <td className="px-4 py-3">
                    {r.has_sbom ? (
                      <span className="text-green-600 text-xs">已上傳</span>
                    ) : (
                      <span className="text-gray-400 text-xs">未上傳</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {r.vuln_total > 0 ? (
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {r.vuln_critical > 0 && (
                          <span className="px-1.5 py-0.5 rounded text-xs font-bold bg-red-100 text-red-700">C:{r.vuln_critical}</span>
                        )}
                        {r.vuln_high > 0 && (
                          <span className="px-1.5 py-0.5 rounded text-xs font-bold bg-orange-100 text-orange-700">H:{r.vuln_high}</span>
                        )}
                        <span className="text-xs text-gray-400">共{r.vuln_total}</span>
                      </div>
                    ) : (
                      <span className="text-xs text-gray-300">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right flex justify-end gap-3">
                    <button
                      onClick={() => navigate(`/releases/${r.id}`)}
                      className="text-blue-600 hover:underline text-xs"
                    >
                      詳細
                    </button>
                    <button
                      onClick={() => handleDelete(r)}
                      className="text-red-500 hover:underline text-xs"
                    >
                      刪除
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </div>
    </div>
  );
}

function TrendChart({ data }) {
  const [hovered, setHovered] = useState(null);
  const W = 500, H = 160;
  const PL = 32, PR = 16, PT = 12, PB = 36;
  const cW = W - PL - PR;
  const cH = H - PT - PB;
  const maxVal = Math.max(...data.map((d) => d.total), 1);

  const xp = (i) => PL + (data.length < 2 ? cW / 2 : (i / (data.length - 1)) * cW);
  const yp = (v) => PT + cH - (v / maxVal) * cH;

  const LINES = [
    { field: "total",    color: "#60a5fa", label: "Total (未解決)", dot: 3 },
    { field: "critical", color: "#ef4444", label: "Critical",       dot: 2.5 },
    { field: "high",     color: "#fb923c", label: "High",           dot: 2 },
    { field: "medium",   color: "#facc15", label: "Medium",         dot: 2 },
  ];

  const yTicks = [0, Math.round(maxVal / 2), maxVal];

  return (
    <div className="bg-white rounded-lg shadow p-4 mb-4">
      <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
        <div>
          <h3 className="text-sm font-semibold text-gray-700">各版本漏洞趨勢</h3>
          <p className="text-xs text-gray-400">僅計算未解決漏洞（排除 fixed / not_affected）</p>
        </div>
        <div className="flex flex-wrap gap-3 text-xs text-gray-500">
          {LINES.map(({ color, label }) => (
            <span key={label} className="flex items-center gap-1">
              <svg width="14" height="4"><line x1="0" y1="2" x2="14" y2="2" stroke={color} strokeWidth="2" strokeLinecap="round"/></svg>
              {label}
            </span>
          ))}
        </div>
      </div>
      <div className="relative">
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: "150px" }}>
          {/* Y gridlines + labels */}
          <line x1={PL} y1={PT} x2={PL} y2={PT + cH} stroke="#e5e7eb" strokeWidth="1"/>
          {yTicks.map((v) => (
            <g key={v}>
              <line x1={PL} y1={yp(v)} x2={W - PR} y2={yp(v)} stroke="#f3f4f6" strokeWidth="1"/>
              <text x={PL - 4} y={yp(v) + 3} textAnchor="end" fontSize="8" fill="#9ca3af">{v}</text>
            </g>
          ))}
          {/* X axis */}
          <line x1={PL} y1={PT + cH} x2={W - PR} y2={PT + cH} stroke="#e5e7eb" strokeWidth="1"/>
          {/* Lines */}
          {LINES.map(({ field, color }) => {
            const pts = data.map((d, i) => `${xp(i)},${yp(d[field] || 0)}`).join(" ");
            return <polyline key={field} points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" opacity="0.85"/>;
          })}
          {/* Dots + X labels + hover zones */}
          {data.map((d, i) => (
            <g key={i} onMouseEnter={() => setHovered(i)} onMouseLeave={() => setHovered(null)} style={{ cursor: "pointer" }}>
              {/* Invisible wide hit area */}
              <rect x={xp(i) - 14} y={PT} width={28} height={cH} fill="transparent"/>
              {hovered === i && <line x1={xp(i)} y1={PT} x2={xp(i)} y2={PT + cH} stroke="#e5e7eb" strokeWidth="1" strokeDasharray="3,2"/>}
              {LINES.map(({ field, color, dot }) => (
                d[field] > 0 && <circle key={field} cx={xp(i)} cy={yp(d[field])} r={hovered === i ? dot + 1 : dot} fill={color}/>
              ))}
              <circle cx={xp(i)} cy={yp(d.total || 0)} r={hovered === i ? 4 : 3} fill="#60a5fa"/>
              <text x={xp(i)} y={H - 4} textAnchor="middle" fontSize="7.5" fill={hovered === i ? "#374151" : "#9ca3af"} fontWeight={hovered === i ? "600" : "400"}>
                {d.version.length > 8 ? d.version.slice(0, 8) + "…" : d.version}
              </text>
            </g>
          ))}
        </svg>
        {/* Tooltip */}
        {hovered !== null && (() => {
          const d = data[hovered];
          const pct = hovered / Math.max(data.length - 1, 1);
          return (
            <div
              className="absolute top-0 pointer-events-none bg-gray-900 text-white text-xs rounded-lg px-3 py-2 shadow-xl z-10 whitespace-nowrap"
              style={{ left: `${Math.min(Math.max(pct * 100, 5), 80)}%`, transform: "translateX(-50%)" }}
            >
              <div className="font-semibold mb-1">{d.version}</div>
              <div className="space-y-0.5">
                <div className="flex gap-2 justify-between"><span className="text-gray-400">未解決總計</span><span className="font-bold text-blue-300">{d.total}</span></div>
                {d.critical > 0 && <div className="flex gap-2 justify-between"><span className="text-red-400">Critical</span><span>{d.critical}</span></div>}
                {d.high > 0 && <div className="flex gap-2 justify-between"><span className="text-orange-400">High</span><span>{d.high}</span></div>}
                {d.medium > 0 && <div className="flex gap-2 justify-between"><span className="text-yellow-300">Medium</span><span>{d.medium}</span></div>}
                {d.low > 0 && <div className="flex gap-2 justify-between"><span className="text-blue-300">Low</span><span>{d.low}</span></div>}
              </div>
            </div>
          );
        })()}
      </div>
    </div>
  );
}
