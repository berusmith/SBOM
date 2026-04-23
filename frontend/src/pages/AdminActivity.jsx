import { useEffect, useState } from "react";
import api from "../api/client";
import { AUDIT_EVENT_COLOR, DEFAULT_BADGE } from "../constants/colors";
import { SkeletonTable } from "../components/Skeleton";
import { formatDateTime, formatDateForFilename } from "../utils/date";

const EVENT_LABELS = {
  login_ok:        "登入成功",
  login_fail:      "登入失敗",
  sbom_upload:     "SBOM 上傳",
  vuln_scan:       "漏洞掃描",
  report_download: "報告下載",
  user_created:    "帳號建立",
  user_updated:    "帳號更新",
  user_deleted:    "帳號刪除",
  vex_update:      "VEX 狀態更新",
  lock:            "版本鎖定",
  unlock:          "版本解鎖",
  policy_created:  "Policy 新增",
  policy_updated:  "Policy 更新",
  policy_deleted:  "Policy 刪除",
  cra_created:     "CRA 事件建立",
  cra_advanced:    "CRA 狀態推進",
  cra_closed:      "CRA 事件關閉",
};


function fmtDate(iso) {
  if (!iso) return "-";
  return formatDateTime(iso).replace("—", "-");
}

function exportCsv(events) {
  const header = ["時間", "使用者", "客戶", "事件類型", "資源", "IP"];
  const rows = events.map(e => [
    fmtDate(e.created_at),
    e.username,
    e.org_name || "",
    EVENT_LABELS[e.event_type] || e.event_type,
    e.resource_label || "",
    e.ip_address || "",
  ]);
  const csv = [header, ...rows].map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n");
  const blob = new Blob(["﻿" + csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `audit_log_${formatDateForFilename()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function AdminActivity() {
  const [summary, setSummary] = useState([]);
  const [events, setEvents] = useState([]);
  const [filterOrg, setFilterOrg] = useState("");
  const [filterType, setFilterType] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [loading, setLoading] = useState(true);
  const [fetching, setFetching] = useState(false);

  const loadSummary = () =>
    api.get("/admin/activity/summary").then(r => setSummary(r.data)).catch(() => {});

  const loadEvents = (params = {}) => {
    setFetching(true);
    const p = { limit: 200, ...params };
    if (!p.org_id) delete p.org_id;
    if (!p.event_type) delete p.event_type;
    if (!p.date_from) delete p.date_from;
    if (!p.date_to) delete p.date_to;
    return api.get("/admin/activity", { params: p })
      .then(r => setEvents(r.data))
      .catch(() => {})
      .finally(() => setFetching(false));
  };

  useEffect(() => {
    Promise.all([loadSummary(), loadEvents()]).finally(() => setLoading(false));
  }, []);

  const handleFilter = () => {
    loadEvents({ org_id: filterOrg, event_type: filterType, date_from: dateFrom, date_to: dateTo });
  };

  const handleReset = () => {
    setFilterOrg(""); setFilterType(""); setDateFrom(""); setDateTo("");
    loadEvents({});
  };

  const orgs = [...new Map(events.filter(e => e.org_id).map(e => [e.org_id, e.org_name])).entries()];
  const allEventTypes = [...new Set(events.map(e => e.event_type))].sort();

  if (loading) return <div className="p-6"><SkeletonTable rows={8} cols={5} /></div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-gray-800">稽核日誌</h1>
          <p className="text-xs text-gray-600 mt-0.5">所有重要操作的完整紀錄，供合規稽核使用</p>
        </div>
        <button
          onClick={() => exportCsv(events)}
          disabled={events.length === 0}
          className="px-4 py-2 text-sm bg-emerald-600 hover:bg-emerald-700 text-white rounded disabled:opacity-40"
        >
          匯出 CSV
        </button>
      </div>

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
                <th className="px-4 py-2 text-right hidden sm:table-cell">漏洞掃描</th>
                <th className="px-4 py-2 text-right hidden sm:table-cell">報告下載</th>
                <th className="px-4 py-2 text-left">最後登入</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {summary.map(row => (
                <tr key={row.org_id} className="hover:bg-gray-50">
                  <td className="px-4 py-2 font-medium text-gray-800">{row.org_name}</td>
                  <td className="px-4 py-2 text-right text-gray-600">{row.login_count}</td>
                  <td className="px-4 py-2 text-right text-gray-600">{row.sbom_uploads}</td>
                  <td className="px-4 py-2 text-right text-gray-600 hidden sm:table-cell">{row.vuln_scans}</td>
                  <td className="px-4 py-2 text-right text-gray-600 hidden sm:table-cell">{row.report_downloads}</td>
                  <td className="px-4 py-2 text-gray-500 text-xs">{fmtDate(row.last_login)}</td>
                </tr>
              ))}
              {summary.length === 0 && (
                <tr><td colSpan={6} className="px-4 py-6 text-center text-gray-600">尚無使用紀錄</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Filter bar */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
        <div className="flex flex-wrap gap-3 items-end">
          <div className="flex flex-col gap-1">
            <label className="text-xs text-gray-500">客戶</label>
            <select
              value={filterOrg}
              onChange={e => setFilterOrg(e.target.value)}
              className="border border-gray-200 rounded px-2 py-1.5 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-400"
            >
              <option value="">所有客戶</option>
              {orgs.map(([id, name]) => <option key={id} value={id}>{name}</option>)}
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-xs text-gray-500">事件類型</label>
            <select
              value={filterType}
              onChange={e => setFilterType(e.target.value)}
              className="border border-gray-200 rounded px-2 py-1.5 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-400"
            >
              <option value="">所有事件</option>
              {allEventTypes.map(k => (
                <option key={k} value={k}>{EVENT_LABELS[k] || k}</option>
              ))}
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-xs text-gray-500">開始日期</label>
            <input type="date" value={dateFrom} onChange={e => setDateFrom(e.target.value)}
              className="border border-gray-200 rounded px-2 py-1.5 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-400" />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-xs text-gray-500">結束日期</label>
            <input type="date" value={dateTo} onChange={e => setDateTo(e.target.value)}
              className="border border-gray-200 rounded px-2 py-1.5 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-400" />
          </div>
          <button onClick={handleFilter} disabled={fetching}
            className="px-4 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded disabled:opacity-40">
            {fetching ? "查詢中..." : "套用篩選"}
          </button>
          <button onClick={handleReset} className="px-3 py-1.5 text-sm text-gray-500 hover:text-gray-700 underline">
            清除
          </button>
          <span className="ml-auto text-xs text-gray-600 self-end">共 {events.length} 筆</span>
        </div>
      </div>

      {/* Event feed */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-50 text-gray-500 text-xs border-b">
                <th className="px-4 py-2.5 text-left">時間</th>
                <th className="px-4 py-2.5 text-left">使用者</th>
                <th className="px-4 py-2.5 text-left hidden sm:table-cell">客戶</th>
                <th className="px-4 py-2.5 text-left">事件</th>
                <th className="px-4 py-2.5 text-left hidden md:table-cell">操作對象</th>
                <th className="px-4 py-2.5 text-left hidden lg:table-cell">IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {events.map(e => (
                <tr key={e.id} className="hover:bg-gray-50">
                  <td className="px-4 py-2 text-gray-500 text-xs whitespace-nowrap">{fmtDate(e.created_at)}</td>
                  <td className="px-4 py-2 text-gray-700 font-medium">{e.username}</td>
                  <td className="px-4 py-2 text-gray-500 hidden sm:table-cell">{e.org_name || "—"}</td>
                  <td className="px-4 py-2">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${AUDIT_EVENT_COLOR[e.event_type] || DEFAULT_BADGE}`}>
                      {EVENT_LABELS[e.event_type] || e.event_type}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-gray-600 text-xs hidden md:table-cell max-w-xs truncate">
                    {e.resource_label || "—"}
                  </td>
                  <td className="px-4 py-2 text-gray-600 text-xs hidden lg:table-cell font-mono">
                    {e.ip_address || "—"}
                  </td>
                </tr>
              ))}
              {events.length === 0 && (
                <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-600">無符合的紀錄</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
