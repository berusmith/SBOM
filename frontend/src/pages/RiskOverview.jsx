import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import api from "../api/client";
import { SkeletonTable } from "../components/Skeleton";

function RiskBadge({ score }) {
  if (score >= 30) return <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-red-100 text-red-700">極高</span>;
  if (score >= 15) return <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-orange-100 text-orange-700">高</span>;
  if (score >= 5)  return <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-yellow-100 text-yellow-700">中</span>;
  if (score > 0)   return <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-blue-100 text-blue-700">低</span>;
  return <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-green-100 text-green-700">無</span>;
}

function PatchBar({ rate }) {
  const color = rate >= 80 ? "bg-green-500" : rate >= 40 ? "bg-yellow-400" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 rounded-full bg-gray-100 overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${rate}%` }} />
      </div>
      <span className="text-xs text-gray-600 w-10 text-right">{rate}%</span>
    </div>
  );
}

const SORT_FIELDS = [
  { key: "risk_score",         label: "風險分數" },
  { key: "unpatched_critical", label: "未修 Critical" },
  { key: "unpatched_high",     label: "未修 High" },
  { key: "total_vulns",        label: "漏洞總數" },
  { key: "patch_rate",         label: "修補率" },
  { key: "org_name",           label: "客戶名稱" },
];

export default function RiskOverview() {
  const { t } = useTranslation();
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [sortKey, setSortKey] = useState("risk_score");
  const [sortAsc, setSortAsc] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    api.get("/stats/risk-overview")
      .then((r) => setRows(r.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const handleSort = (key) => {
    if (sortKey === key) setSortAsc(!sortAsc);
    else { setSortKey(key); setSortAsc(false); }
  };

  const sorted = [...rows].sort((a, b) => {
    const va = a[sortKey], vb = b[sortKey];
    if (typeof va === "string") return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
    return sortAsc ? va - vb : vb - va;
  });

  const totalUnpatchedCritical = rows.reduce((s, r) => s + r.unpatched_critical, 0);
  const totalUnpatchedHigh = rows.reduce((s, r) => s + r.unpatched_high, 0);
  const totalVulns = rows.reduce((s, r) => s + r.total_vulns, 0);
  const totalIncidents = rows.reduce((s, r) => s + r.active_incidents, 0);

  const SortIcon = ({ field }) => {
    if (sortKey !== field) return <span className="text-gray-300 ml-1">↕</span>;
    return <span className="text-blue-500 ml-1">{sortAsc ? "↑" : "↓"}</span>;
  };

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-800 mb-6">{t("riskOverview.title")}</h1>

      {/* Summary bar */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-4 mb-6">
        {[
          { label: "未修補 Critical", value: totalUnpatchedCritical, color: "bg-red-500" },
          { label: "未修補 High",     value: totalUnpatchedHigh,     color: "bg-orange-500" },
          { label: "漏洞總數",        value: totalVulns,             color: "bg-gray-500" },
          { label: "進行中事件",      value: totalIncidents,         color: totalIncidents > 0 ? "bg-red-600" : "bg-green-500" },
        ].map((c) => (
          <div key={c.label} className="bg-white rounded-lg shadow p-4 flex items-center gap-3">
            <div className={`${c.color} w-11 h-11 rounded-lg flex items-center justify-center text-white font-bold text-lg shrink-0`}>
              {c.value}
            </div>
            <span className="text-sm text-gray-600 font-medium">{c.label}</span>
          </div>
        ))}
      </div>

      {loading ? (
        <SkeletonTable rows={4} cols={6} />
      ) : rows.length === 0 ? (
        <div className="bg-white rounded-lg shadow p-8 text-center text-gray-600">尚無客戶資料</div>
      ) : (
        <div className="bg-white rounded-lg shadow overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b">
              <tr>
                <th scope="col" className="px-4 py-3 text-left text-gray-600 font-medium w-8">#</th>
                {SORT_FIELDS.map((f) => (
                  <th scope="col" key={f.key}
                    onClick={() => handleSort(f.key)}
                    className="px-4 py-3 text-left text-gray-600 font-medium cursor-pointer hover:text-gray-800 select-none whitespace-nowrap"
                  >
                    {f.label}<SortIcon field={f.key} />
                  </th>
                ))}
                <th scope="col" className="px-4 py-3 text-left text-gray-600 font-medium whitespace-nowrap">修補率</th>
                <th scope="col" className="px-4 py-3 text-left text-gray-600 font-medium hidden sm:table-cell">進行中事件</th>
                <th scope="col" className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {sorted.map((row, i) => (
                <tr key={row.org_id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 text-gray-600 text-xs">{i + 1}</td>
                  <td className="px-4 py-3 font-medium text-gray-800">
                    <RiskBadge score={row.risk_score} />
                    <span className="ml-2 text-gray-600 text-xs">{row.risk_score}</span>
                  </td>
                  <td className="px-4 py-3">
                    {row.unpatched_critical > 0
                      ? <span className="font-bold text-red-600">{row.unpatched_critical}</span>
                      : <span className="text-gray-600">0</span>}
                  </td>
                  <td className="px-4 py-3">
                    {row.unpatched_high > 0
                      ? <span className="font-semibold text-orange-500">{row.unpatched_high}</span>
                      : <span className="text-gray-600">0</span>}
                  </td>
                  <td className="px-4 py-3 text-gray-600">{row.total_vulns}</td>
                  <td className="px-4 py-3 font-medium text-gray-800 max-w-[140px] sm:max-w-none truncate">{row.org_name}</td>
                  <td className="px-4 py-3 min-w-[140px]">
                    <PatchBar rate={row.patch_rate} />
                  </td>
                  <td className="px-4 py-3 hidden sm:table-cell">
                    {row.active_incidents > 0
                      ? <span className="px-2 py-0.5 rounded-full text-xs bg-red-100 text-red-700 font-semibold">{row.active_incidents} 件</span>
                      : <span className="text-gray-600 text-xs">—</span>}
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => navigate(`/organizations/${row.org_id}/products`)}
                      className="text-xs text-blue-600 hover:underline"
                    >
                      查看
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="px-4 py-2 text-xs text-gray-600 border-t">
            風險分數 = 未修補 Critical × 10 + 未修補 High × 3 + 進行中事件 × 5
          </div>
        </div>
      )}
    </div>
  );
}
