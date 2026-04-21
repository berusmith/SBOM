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
    <div className={`border rounded-lg px-5 py-4 mb-6 flex items-center justify-between ${bg}`}>
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
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    api.get("/stats")
      .then((r) => setStats(r.data))
      .catch(() => {})
      .finally(() => setLoading(false));
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
    </div>
  );
}
