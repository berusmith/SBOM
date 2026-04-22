import { useEffect, useState } from "react";
import api from "../api/client";

const EVENT_LABELS = {
  login_ok: "登入成功",
  login_fail: "登入失敗",
  sbom_upload: "SBOM 上傳",
  vuln_scan: "漏洞掃描",
  report_download: "報告下載",
  user_created: "帳號建立",
  user_updated: "帳號更新",
};

const EVENT_COLORS = {
  login_ok: "bg-green-100 text-green-700",
  login_fail: "bg-red-100 text-red-700",
  sbom_upload: "bg-blue-100 text-blue-700",
  vuln_scan: "bg-purple-100 text-purple-700",
  report_download: "bg-yellow-100 text-yellow-700",
  user_created: "bg-gray-100 text-gray-700",
  user_updated: "bg-gray-100 text-gray-700",
};

function fmtDate(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleString("zh-TW", { hour12: false });
}

export default function AdminActivity() {
  const [summary, setSummary] = useState([]);
  const [events, setEvents] = useState([]);
  const [filterOrg, setFilterOrg] = useState("");
  const [filterType, setFilterType] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      api.get("/admin/activity/summary"),
      api.get("/admin/activity", { params: { limit: 200 } }),
    ]).then(([s, e]) => {
      setSummary(s.data);
      setEvents(e.data);
    }).finally(() => setLoading(false));
  }, []);

  const filtered = events.filter(e => {
    if (filterOrg && e.org_id !== filterOrg) return false;
    if (filterType && e.event_type !== filterType) return false;
    return true;
  });

  const orgs = [...new Map(events.filter(e => e.org_id).map(e => [e.org_id, e.org_name])).entries()];

  if (loading) return <div className="text-gray-500 p-6">載入中...</div>;

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-gray-800">客戶使用紀錄</h1>

      {/* Summary table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <div className="px-5 py-3 border-b border-gray-100">
          <h2 className="font-semibold text-gray-700 text-sm">各客戶使用概況</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-50 text-gray-500 text-xs">
                <th className="px-4 py-2 text-left">客戶</th>
                <th className="px-4 py-2 text-right">登入次數</th>
                <th className="px-4 py-2 text-right">SBOM 上傳</th>
                <th className="px-4 py-2 text-right">漏洞掃描</th>
                <th className="px-4 py-2 text-right">報告下載</th>
                <th className="px-4 py-2 text-left">最後登入</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {summary.map(row => (
                <tr key={row.org_id} className="hover:bg-gray-50">
                  <td className="px-4 py-2 font-medium text-gray-800">{row.org_name}</td>
                  <td className="px-4 py-2 text-right text-gray-600">{row.login_count}</td>
                  <td className="px-4 py-2 text-right text-gray-600">{row.sbom_uploads}</td>
                  <td className="px-4 py-2 text-right text-gray-600">{row.vuln_scans}</td>
                  <td className="px-4 py-2 text-right text-gray-600">{row.report_downloads}</td>
                  <td className="px-4 py-2 text-gray-500 text-xs">{fmtDate(row.last_login)}</td>
                </tr>
              ))}
              {summary.length === 0 && (
                <tr><td colSpan={6} className="px-4 py-6 text-center text-gray-400">尚無使用紀錄</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Event feed */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <div className="px-5 py-3 border-b border-gray-100 flex items-center gap-3 flex-wrap">
          <h2 className="font-semibold text-gray-700 text-sm">詳細活動紀錄</h2>
          <select
            value={filterOrg}
            onChange={e => setFilterOrg(e.target.value)}
            className="ml-auto border border-gray-200 rounded px-2 py-1 text-xs text-gray-600"
          >
            <option value="">所有客戶</option>
            {orgs.map(([id, name]) => <option key={id} value={id}>{name}</option>)}
          </select>
          <select
            value={filterType}
            onChange={e => setFilterType(e.target.value)}
            className="border border-gray-200 rounded px-2 py-1 text-xs text-gray-600"
          >
            <option value="">所有事件</option>
            {Object.entries(EVENT_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-50 text-gray-500 text-xs">
                <th className="px-4 py-2 text-left">時間</th>
                <th className="px-4 py-2 text-left">使用者</th>
                <th className="px-4 py-2 text-left">客戶</th>
                <th className="px-4 py-2 text-left">事件</th>
                <th className="px-4 py-2 text-left">資源</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {filtered.map(e => (
                <tr key={e.id} className="hover:bg-gray-50">
                  <td className="px-4 py-2 text-gray-500 text-xs whitespace-nowrap">{fmtDate(e.created_at)}</td>
                  <td className="px-4 py-2 text-gray-700 font-medium">{e.username}</td>
                  <td className="px-4 py-2 text-gray-600">{e.org_name || "-"}</td>
                  <td className="px-4 py-2">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${EVENT_COLORS[e.event_type] || "bg-gray-100 text-gray-600"}`}>
                      {EVENT_LABELS[e.event_type] || e.event_type}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-gray-500 text-xs">{e.resource_label || "-"}</td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-6 text-center text-gray-400">無符合的紀錄</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
