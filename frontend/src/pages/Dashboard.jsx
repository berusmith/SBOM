import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/client";

const CRA_DEADLINE = new Date("2026-09-11T00:00:00Z");

function CRACountdown() {
  const [days, setDays] = useState(null);

  useEffect(() => {
    const calc = () => {
      const now = new Date();
      const diff = CRA_DEADLINE - now;
      setDays(Math.max(0, Math.ceil(diff / (1000 * 60 * 60 * 24))));
    };
    calc();
    const t = setInterval(calc, 60000);
    return () => clearInterval(t);
  }, []);

  if (days === null) return null;

  const urgent = days <= 30;
  const warning = days <= 90;
  const bg = urgent ? "bg-red-50 border-red-300" : warning ? "bg-orange-50 border-orange-300" : "bg-blue-50 border-blue-300";
  const textColor = urgent ? "text-red-700" : warning ? "text-orange-700" : "text-blue-700";
  const numColor = urgent ? "text-red-600" : warning ? "text-orange-600" : "text-blue-600";
  const label = urgent ? "緊急" : warning ? "注意" : "提醒";

  return (
    <div className={`border rounded-lg px-5 py-4 mb-6 flex items-center justify-between flex-wrap gap-3 ${bg}`}>
      <div className="flex items-center gap-3">
        <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${textColor} border-current`}>{label}</span>
        <span className={`text-sm font-medium ${textColor}`}>
          EU CRA Article 14 強制執行日：<span className="font-bold">2026 年 9 月 11 日</span>
        </span>
      </div>
      <div className="text-right">
        <span className={`text-3xl font-bold ${numColor}`}>{days}</span>
        <span className={`text-sm ml-1 ${textColor}`}>天</span>
      </div>
    </div>
  );
}

const SEVERITY = [
  { key: "critical", label: "Critical", color: "bg-red-500",    text: "text-red-700",    bg: "bg-red-50" },
  { key: "high",     label: "High",     color: "bg-orange-500", text: "text-orange-700", bg: "bg-orange-50" },
  { key: "medium",   label: "Medium",   color: "bg-yellow-500", text: "text-yellow-700", bg: "bg-yellow-50" },
  { key: "low",      label: "Low",      color: "bg-blue-500",   text: "text-blue-700",   bg: "bg-blue-50" },
  { key: "info",     label: "Info",     color: "bg-gray-400",   text: "text-gray-600",   bg: "bg-gray-50" },
];

const STATUS = [
  { key: "open",         label: "Open",         color: "bg-red-400" },
  { key: "in_triage",    label: "In Triage",    color: "bg-yellow-400" },
  { key: "affected",     label: "Affected",     color: "bg-orange-400" },
  { key: "not_affected", label: "Not Affected", color: "bg-green-400" },
  { key: "fixed",        label: "Fixed",        color: "bg-blue-400" },
];

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [riskOverview, setRiskOverview] = useState([]);
  const [topThreats, setTopThreats] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    Promise.all([
      api.get("/stats"),
      api.get("/stats/risk-overview"),
      api.get("/stats/top-threats"),
    ]).then(([s, r, t]) => {
      setStats(s.data);
      setRiskOverview(r.data);
      setTopThreats(t.data);
    }).catch(() => {}).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="text-gray-400 mt-8 text-center">載入中...</div>;
  if (!stats) return <div className="text-red-400 mt-8 text-center">無法取得統計資料</div>;

  const totalVulns = stats.vulnerabilities.total;
  const bySev = stats.vulnerabilities.by_severity;
  const byStatus = stats.vulnerabilities.by_status;
  const maxSev = Math.max(...Object.values(bySev), 1);
  const maxStatus = Math.max(...Object.values(byStatus), 1);

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-800 mb-6">儀表板</h1>

      <CRACountdown />

      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mb-6">
        {[
          { label: "客戶數",      value: stats.organizations,                     color: "bg-blue-500",   link: "/organizations" },
          { label: "產品數",      value: stats.products,                          color: "bg-indigo-500", link: "/organizations" },
          { label: "版本數",      value: stats.releases,                          color: "bg-purple-500", link: "/organizations" },
          { label: "元件數",      value: stats.components,                        color: "bg-teal-500",   link: null },
          { label: "CRA 進行中", value: stats.cra_incidents?.active ?? 0,        color: stats.cra_incidents?.active > 0 ? "bg-red-500" : "bg-gray-400", link: "/cra" },
        ].map((c) => (
          <div
            key={c.label}
            onClick={() => c.link && navigate(c.link)}
            className={`bg-white rounded-lg shadow p-5 flex items-center gap-4 ${c.link ? "cursor-pointer hover:shadow-md" : ""}`}
          >
            <div className={`${c.color} w-12 h-12 rounded-lg flex items-center justify-center text-white text-xl font-bold shrink-0`}>
              {c.value}
            </div>
            <span className="text-gray-600 font-medium text-sm">{c.label}</span>
          </div>
        ))}
      </div>

      {totalVulns === 0 ? (
        <div className="bg-white rounded-lg shadow p-8 text-center text-gray-400">
          尚未掃描任何漏洞。請上傳 SBOM 檔案以開始分析。
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

          {/* Severity breakdown */}
          <div className="bg-white rounded-lg shadow p-5">
            <h2 className="font-semibold text-gray-700 mb-4">漏洞嚴重度分布
              <span className="ml-2 text-sm font-normal text-gray-400">共 {totalVulns} 筆</span>
            </h2>
            <div className="space-y-3">
              {SEVERITY.map(({ key, label, color, text, bg }) => {
                const count = bySev[key] || 0;
                const pct = Math.round((count / totalVulns) * 100);
                return (
                  <div key={key}>
                    <div className="flex justify-between text-sm mb-1">
                      <span className={`font-medium ${text}`}>{label}</span>
                      <span className="text-gray-500">{count} ({pct}%)</span>
                    </div>
                    <div className="h-4 rounded-full bg-gray-100 overflow-hidden">
                      <div
                        className={`h-full rounded-full ${color} transition-all duration-500`}
                        style={{ width: `${(count / maxSev) * 100}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Status breakdown */}
          <div className="bg-white rounded-lg shadow p-5">
            <h2 className="font-semibold text-gray-700 mb-4">漏洞處理狀態</h2>
            <div className="space-y-3">
              {STATUS.map(({ key, label, color }) => {
                const count = byStatus[key] || 0;
                if (count === 0) return null;
                const pct = Math.round((count / totalVulns) * 100);
                return (
                  <div key={key}>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="text-gray-600 font-medium">{label}</span>
                      <span className="text-gray-500">{count} ({pct}%)</span>
                    </div>
                    <div className="h-4 rounded-full bg-gray-100 overflow-hidden">
                      <div
                        className={`h-full rounded-full ${color} transition-all duration-500`}
                        style={{ width: `${(count / maxStatus) * 100}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Quick summary badges */}
            <div className="mt-5 pt-4 border-t flex flex-wrap gap-2">
              {STATUS.map(({ key, label, color }) => {
                const count = byStatus[key] || 0;
                if (count === 0) return null;
                return (
                  <span key={key} className="flex items-center gap-1.5 text-xs text-gray-600 bg-gray-50 rounded-full px-3 py-1">
                    <span className={`w-2 h-2 rounded-full ${color}`} />
                    {label}: {count}
                  </span>
                );
              })}
            </div>
          </div>

        </div>
      )}

      {/* Patch tracking summary */}
      {stats.patch_tracking && (
        <div className="mt-4 bg-white rounded-lg shadow p-5">
          <h2 className="font-semibold text-gray-700 mb-4">修補追蹤</h2>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {/* Patch rate gauge */}
            <div className="flex flex-col items-center">
              <div className="relative w-24 h-24 mb-2">
                <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
                  <circle cx="18" cy="18" r="15.9" fill="none" stroke="#e5e7eb" strokeWidth="3" />
                  <circle
                    cx="18" cy="18" r="15.9" fill="none"
                    stroke={stats.patch_tracking.patch_rate >= 80 ? "#22c55e" : stats.patch_tracking.patch_rate >= 40 ? "#f59e0b" : "#ef4444"}
                    strokeWidth="3"
                    strokeDasharray={`${stats.patch_tracking.patch_rate} ${100 - stats.patch_tracking.patch_rate}`}
                    strokeLinecap="round"
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-lg font-bold text-gray-800">{stats.patch_tracking.patch_rate}%</span>
                </div>
              </div>
              <p className="text-sm text-gray-500">修補率</p>
            </div>
            {/* Fixed count */}
            <div className="flex flex-col items-center justify-center">
              <span className="text-3xl font-bold text-green-600">{stats.patch_tracking.fixed}</span>
              <p className="text-sm text-gray-500 mt-1">已修補漏洞</p>
            </div>
            {/* Avg days to fix */}
            <div className="flex flex-col items-center justify-center">
              <span className="text-3xl font-bold text-blue-600">
                {stats.patch_tracking.avg_days_to_fix != null ? stats.patch_tracking.avg_days_to_fix : "—"}
              </span>
              <p className="text-sm text-gray-500 mt-1">平均修補天數</p>
            </div>
          </div>
        </div>
      )}

      {/* Threat highlights */}
      {topThreats && (
        <div className="mt-4 bg-white rounded-lg shadow p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold text-gray-700">威脅速報</h2>
            {topThreats.active_kev_count > 0 && (
              <span className="flex items-center gap-1.5 bg-red-100 text-red-700 text-xs font-bold px-3 py-1 rounded-full">
                KEV {topThreats.active_kev_count} 筆未修補
              </span>
            )}
          </div>
          {topThreats.top_epss.length === 0 ? (
            <p className="text-sm text-gray-400">無高 EPSS 漏洞</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-gray-400 border-b">
                    <th className="pb-2 pr-4">CVE</th>
                    <th className="pb-2 pr-4">EPSS</th>
                    <th className="pb-2 pr-4">嚴重度</th>
                    <th className="pb-2 pr-4">元件</th>
                    <th className="pb-2">KEV</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {topThreats.top_epss.map((v) => {
                    const sevColor = { critical: "text-red-600 bg-red-50", high: "text-orange-600 bg-orange-50", medium: "text-yellow-600 bg-yellow-50", low: "text-blue-600 bg-blue-50" }[v.severity] || "text-gray-500 bg-gray-50";
                    return (
                      <tr key={v.cve_id} className="hover:bg-gray-50">
                        <td className="py-2 pr-4 font-mono text-xs text-gray-700">{v.cve_id}</td>
                        <td className="py-2 pr-4">
                          <span className={`font-semibold ${parseFloat(v.epss_score) >= 0.5 ? "text-red-600" : "text-orange-500"}`}>
                            {(v.epss_score * 100).toFixed(1)}%
                          </span>
                        </td>
                        <td className="py-2 pr-4">
                          <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${sevColor}`}>{v.severity}</span>
                        </td>
                        <td className="py-2 pr-4 text-gray-600 max-w-[160px] truncate">{v.component}</td>
                        <td className="py-2">
                          {v.is_kev && <span className="text-xs font-bold text-red-500 bg-red-50 px-2 py-0.5 rounded-full">KEV</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Risk overview table */}
      {riskOverview.length > 0 && (
        <div className="mt-4 bg-white rounded-lg shadow p-5">
          <h2 className="font-semibold text-gray-700 mb-4">客戶風險總覽</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-400 border-b">
                  <th className="pb-2 pr-4">客戶</th>
                  <th className="pb-2 pr-4 text-center">產品</th>
                  <th className="pb-2 pr-4 text-center">總漏洞</th>
                  <th className="pb-2 pr-4 text-center">未修 Critical</th>
                  <th className="pb-2 pr-4 text-center">未修 High</th>
                  <th className="pb-2 pr-4 text-center">修補率</th>
                  <th className="pb-2 text-center">風險評分</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {riskOverview.map((org) => {
                  const scoreColor = org.risk_score >= 50 ? "bg-red-100 text-red-700" : org.risk_score >= 20 ? "bg-orange-100 text-orange-700" : org.risk_score > 0 ? "bg-yellow-100 text-yellow-700" : "bg-green-100 text-green-700";
                  return (
                    <tr
                      key={org.org_id}
                      className="hover:bg-gray-50 cursor-pointer"
                      onClick={() => navigate("/organizations")}
                    >
                      <td className="py-2.5 pr-4 font-medium text-gray-800">{org.org_name}</td>
                      <td className="py-2.5 pr-4 text-center text-gray-500">{org.products}</td>
                      <td className="py-2.5 pr-4 text-center text-gray-600">{org.total_vulns}</td>
                      <td className="py-2.5 pr-4 text-center">
                        {org.unpatched_critical > 0
                          ? <span className="font-bold text-red-600">{org.unpatched_critical}</span>
                          : <span className="text-gray-300">—</span>}
                      </td>
                      <td className="py-2.5 pr-4 text-center">
                        {org.unpatched_high > 0
                          ? <span className="font-semibold text-orange-500">{org.unpatched_high}</span>
                          : <span className="text-gray-300">—</span>}
                      </td>
                      <td className="py-2.5 pr-4 text-center">
                        <span className={org.patch_rate >= 80 ? "text-green-600 font-semibold" : org.patch_rate >= 40 ? "text-yellow-600" : "text-red-500"}>
                          {org.patch_rate}%
                        </span>
                      </td>
                      <td className="py-2.5 text-center">
                        <span className={`text-xs font-bold px-2.5 py-1 rounded-full ${scoreColor}`}>{org.risk_score}</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
