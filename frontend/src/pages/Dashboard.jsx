import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import api from "../api/client";
import { useToast } from "../components/Toast";
import { SEVERITY_COLOR, DEFAULT_BADGE } from "../constants/colors";
import { SkeletonStatCards, SkeletonTable } from "../components/Skeleton";

function TopVulns() {
  const [items, setItems] = useState(null);
  const { t } = useTranslation();

  useEffect(() => {
    api.get("/stats/top-vulns").then((r) => setItems(r.data)).catch(() => setItems([]));
  }, []);

  if (items === null) return null;
  if (items.length === 0) return null;

  return (
    <div className="mt-4 bg-white rounded-lg shadow p-5">
      <h2 className="font-semibold text-gray-700 mb-3">
        {t("dashboard.topThreats")}
      </h2>
      <div className="overflow-x-auto">
        <p className="sm:hidden text-xs text-gray-600 pb-1">{t("dashboard.scrollHint")}</p>
        <table className="w-full text-sm min-w-[320px]">
          <thead>
            <tr className="text-left text-xs text-gray-600 border-b">
              <th scope="col" className="pb-2 pr-4">CVE</th>
              <th scope="col" className="pb-2 pr-4">{t("releaseDetail.vulns.severity")}</th>
              <th scope="col" className="pb-2 pr-4 hidden md:table-cell">CVSS</th>
              <th scope="col" className="pb-2 pr-4">{t("dashboard.component")}</th>
              <th scope="col" className="pb-2 pr-4 hidden sm:table-cell">{t("dashboard.product")}</th>
              <th scope="col" className="pb-2 pr-4 hidden lg:table-cell">{t("dashboard.customer")}</th>
              <th scope="col" className="pb-2">{t("common.status")}</th>
            </tr>
          </thead>
          <tbody>
            {/*
              UX-007 — row navigation moved off <tr onClick> (which is
              keyboard-inaccessible) and onto a <Link> wrapping the CVE
              identifier.  Mouse users now click the CVE; the row still
              hover-highlights for visual continuity.  Keyboard users
              tab through the focusable CVE links.
            */}
            {items.map((v) => (
              <tr key={v.vuln_id} className="border-b last:border-0 hover:bg-gray-50">
                <td className="py-3 pr-4 font-mono text-xs">
                  <Link
                    to={`/releases/${v.release_id}`}
                    className="text-blue-700 hover:underline focus:outline-none focus:ring-2 focus:ring-blue-400 rounded"
                  >
                    {v.cve_id}
                  </Link>
                  {v.is_kev && (
                    <span className="ml-1 px-1 py-0.5 rounded text-white bg-red-600 font-bold text-xs">KEV</span>
                  )}
                </td>
                <td className="py-3 pr-4">
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_COLOR[v.severity] || DEFAULT_BADGE}`}>
                    {v.severity}
                  </span>
                </td>
                <td className="py-3 pr-4 text-gray-600 hidden md:table-cell">{v.cvss_score ?? "—"}</td>
                <td className="py-3 pr-4 text-gray-700">{v.component_name} <span className="text-gray-600">{v.component_version}</span></td>
                <td className="py-3 pr-4 text-gray-700 hidden sm:table-cell">{v.product_name} <span className="text-gray-600 text-xs">{v.release_version}</span></td>
                <td className="py-3 pr-4 text-gray-600 hidden lg:table-cell">{v.org_name}</td>
                <td className="py-3">
                  <span className="px-2 py-0.5 rounded text-xs bg-red-50 text-red-700">{v.status}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const CRA_DEADLINE = new Date("2026-09-11T00:00:00Z");

function CRACountdown() {
  const [days, setDays] = useState(null);
  const { t } = useTranslation();

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
  const label = urgent ? t("craCountdown.urgent") : warning ? t("craCountdown.warning") : t("craCountdown.reminder");

  return (
    <div className={`border rounded-lg px-5 py-4 mb-6 flex items-center justify-between flex-wrap gap-3 ${bg}`}>
      <div className="flex items-center gap-3">
        <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${textColor} border-current`}>{label}</span>
        <span className={`text-sm font-medium ${textColor}`}>
          {t("craCountdown.deadline")}<span className="font-bold">{t("craCountdown.deadlineDate")}</span>
        </span>
      </div>
      <div className="text-right">
        <span className={`text-3xl font-bold ${numColor}`}>{days}</span>
        <span className={`text-sm ml-1 ${textColor}`}>{t("craCountdown.days")}</span>
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

function ViewerOnboarding({ orgId }) {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const steps = [
    { num: 1, title: t("dashboard.onboarding.step1.title"), desc: t("dashboard.onboarding.step1.desc"), action: () => navigate(`/organizations/${orgId}/products`), actionLabel: t("dashboard.onboarding.step1.action") },
    { num: 2, title: t("dashboard.onboarding.step2.title"), desc: t("dashboard.onboarding.step2.desc"), action: null, actionLabel: null },
    { num: 3, title: t("dashboard.onboarding.step3.title"), desc: t("dashboard.onboarding.step3.desc"), action: null, actionLabel: null },
  ];

  return (
    <div className="bg-white rounded-xl border-2 border-dashed border-blue-200 p-6 mb-6">
      <div className="flex items-start gap-4">
        <div className="bg-blue-100 text-blue-600 rounded-full p-3 shrink-0">
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
        <div className="flex-1">
          <h2 className="font-semibold text-gray-800 mb-1">{t("dashboard.onboarding.title")}</h2>
          <p className="text-sm text-gray-500 mb-4">{t("dashboard.onboarding.hint")}</p>
          <div className="space-y-3">
            {steps.map((s) => (
              <div key={s.num} className="flex items-start gap-3">
                <div className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">{s.num}</div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-gray-700">{s.title}</span>
                    {s.action && (
                      <button onClick={s.action} className="text-xs text-blue-600 hover:underline">{s.actionLabel} →</button>
                    )}
                  </div>
                  <p className="text-xs text-gray-600 mt-0.5">{s.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [riskOverview, setRiskOverview] = useState([]);
  const [topThreats, setTopThreats] = useState(null);
  const [riskyComponents, setRiskyComponents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [qualitySummary, setQualitySummary] = useState(null);
  const [cveQuery, setCveQuery] = useState("");
  const [cveResult, setCveResult] = useState(null);
  const [cveLoading, setCveLoading] = useState(false);
  const role = localStorage.getItem("role") || "viewer";
  const orgId = localStorage.getItem("org_id") || "";
  const navigate = useNavigate();
  const { t } = useTranslation();
  const toast = useToast();

  useEffect(() => {
    const ac = new AbortController();
    const sig = { signal: ac.signal };
    Promise.all([
      api.get("/stats", sig),
      api.get("/stats/risk-overview", sig),
      api.get("/stats/top-threats", sig),
      api.get("/stats/top-risky-components", sig),
      api.get("/stats/sbom-quality-summary", sig),
    ]).then(([s, r, th, rc, q]) => {
      setStats(s.data);
      setRiskOverview(r.data);
      setTopThreats(th.data);
      setRiskyComponents(rc.data);
      setQualitySummary(q.data);
    }).catch((err) => {
      if (!ac.signal.aborted) toast.error(t("dashboard.loadError", "儀表板資料載入失敗，請重新整理頁面"));
    }).finally(() => { if (!ac.signal.aborted) setLoading(false); });
    return () => ac.abort();
  }, []);

  const handleCveSearch = async (e) => {
    e.preventDefault();
    if (!cveQuery.trim()) return;
    setCveLoading(true);
    setCveResult(null);
    try {
      const res = await api.get(`/stats/cve-impact?cve=${encodeURIComponent(cveQuery.trim())}`);
      setCveResult(res.data);
    } catch { setCveResult({ cve_id: cveQuery, affected_count: 0, affected: [] }); }
    finally { setCveLoading(false); }
  };

  if (loading) return (
    <div className="p-6 space-y-6">
      <SkeletonStatCards count={4} />
      <SkeletonTable rows={5} cols={5} />
    </div>
  );
  if (!stats) return <div className="text-red-400 mt-8 text-center">{t("dashboard.noStats")}</div>;

  const totalVulns = stats.vulnerabilities.total;
  const bySev = stats.vulnerabilities.by_severity;
  const byStatus = stats.vulnerabilities.by_status;
  const maxSev = Math.max(...Object.values(bySev), 1);
  const maxStatus = Math.max(...Object.values(byStatus), 1);

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-800 mb-6">{t("dashboard.title")}</h1>

      <CRACountdown />

      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-4 mb-6">
        {[
          { label: t("dashboard.customers"),   value: stats.organizations,              color: "bg-blue-500",   link: "/organizations" },
          { label: t("dashboard.products"),    value: stats.products,                   color: "bg-indigo-500", link: "/organizations" },
          { label: t("dashboard.releases"),    value: stats.releases,                   color: "bg-purple-500", link: "/organizations" },
          { label: t("dashboard.components"),  value: stats.components,                 color: "bg-teal-500",   link: null },
          { label: t("dashboard.craActive"),   value: stats.cra_incidents?.active ?? 0, color: stats.cra_incidents?.active > 0 ? "bg-red-500" : "bg-gray-400", link: "/cra" },
          { label: t("dashboard.slaOverdue"),  value: stats.overdue_vulns ?? 0,        color: (stats.overdue_vulns ?? 0) > 0 ? "bg-red-600" : "bg-gray-400", link: "/risk-overview" },
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

      {/* Viewer quick-access banner */}
      {role === "viewer" && orgId && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg px-5 py-3 mb-6 flex items-center justify-between gap-3">
          <p className="text-sm text-blue-700">{t("dashboard.viewerHint")}</p>
          <button
            onClick={() => navigate(`/organizations/${orgId}/products`)}
            className="text-sm font-medium text-blue-700 hover:text-blue-900 whitespace-nowrap shrink-0"
          >
            {t("dashboard.viewerGoToProducts")}
          </button>
        </div>
      )}

      {totalVulns === 0 ? (
        role === "viewer" && orgId ? (
          <ViewerOnboarding orgId={orgId} />
        ) : (
          <div className="bg-white rounded-lg shadow p-8 text-center text-gray-600">
            {t("dashboard.noVulns")}
          </div>
        )
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

          {/* Severity breakdown */}
          <div className="bg-white rounded-lg shadow p-5">
            <h2 className="font-semibold text-gray-700 mb-4">{t("dashboard.vulnSeverityDist")}
              <span className="ml-2 text-sm font-normal text-gray-600">{t("common.total", { count: totalVulns })}</span>
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
            <h2 className="font-semibold text-gray-700 mb-4">{t("dashboard.vulnStatus")}</h2>
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

      <TopVulns />

      {/* SBOM Quality Summary */}
      <div className="mt-4 bg-white rounded-lg shadow p-5">
        <h2 className="font-semibold text-gray-700 mb-4">{t("dashboard.sbomQuality")}</h2>
        {qualitySummary && qualitySummary.graded > 0 ? (
          <div className="flex flex-wrap gap-6 items-center">
            {/* Grade distribution */}
            <div className="flex gap-3">
              {["A","B","C","D"].map(g => (
                <div key={g} className="flex flex-col items-center">
                  <span className={`text-2xl font-bold ${g==="A"?"text-green-600":g==="B"?"text-blue-600":g==="C"?"text-yellow-600":"text-red-600"}`}>
                    {qualitySummary.grade_dist[g]}
                  </span>
                  <span className={`text-xs font-bold px-2 py-0.5 rounded-full mt-1 ${g==="A"?"bg-green-100 text-green-700":g==="B"?"bg-blue-100 text-blue-700":g==="C"?"bg-yellow-100 text-yellow-700":"bg-red-100 text-red-700"}`}>
                    {g}
                  </span>
                </div>
              ))}
            </div>
            <div className="flex gap-6 text-sm text-gray-600">
              <div><span className="font-semibold text-gray-800 text-lg">{qualitySummary.avg_score}</span><span className="ml-1 text-xs">分</span><br/><span className="text-xs">{t("dashboard.qualityAvg")}</span></div>
              {qualitySummary.low_quality_count > 0 && (
                <div><span className="font-semibold text-red-600 text-lg">{qualitySummary.low_quality_count}</span><br/><span className="text-xs text-red-600">{t("dashboard.qualityLow")}</span></div>
              )}
              <div><span className="text-xs text-gray-400">{t("dashboard.gradedOf", { graded: qualitySummary.graded, total: qualitySummary.total })}</span></div>
            </div>
          </div>
        ) : (
          <p className="text-sm text-gray-500">{t("dashboard.qualityNoData")}</p>
        )}
      </div>

      {/* CVE Impact Lookup */}
      <div className="mt-4 bg-white rounded-lg shadow p-5">
        <h2 className="font-semibold text-gray-700 mb-3">{t("dashboard.cveImpact")}</h2>
        <form onSubmit={handleCveSearch} className="flex gap-2 mb-3">
          <input
            value={cveQuery}
            onChange={e => setCveQuery(e.target.value)}
            placeholder={t("dashboard.cveInputHint")}
            className="border rounded px-3 py-1.5 text-sm flex-1 focus:outline-none focus:ring-2 focus:ring-blue-400"
          />
          <button
            type="submit"
            disabled={cveLoading}
            className="bg-blue-600 text-white px-4 py-1.5 rounded text-sm hover:bg-blue-700 disabled:opacity-50"
          >
            {cveLoading ? "..." : t("dashboard.cveSearch")}
          </button>
        </form>
        {cveResult && (
          cveResult.affected_count === 0 ? (
            <p className="text-sm text-gray-500">{t("dashboard.cveNoResult")}</p>
          ) : (
            <>
              <p className="text-sm font-medium text-red-700 mb-2">{t("dashboard.cveAffected", { n: cveResult.affected_count })}</p>
              <div className="overflow-x-auto">
                <table className="w-full text-xs min-w-[320px]">
                  <thead className="text-left text-gray-500 border-b">
                    <tr>
                      <th className="pb-2 pr-3">{t("organizations.name")}</th>
                      <th className="pb-2 pr-3">{t("products.name")}</th>
                      <th className="pb-2 pr-3">{t("releases.version")}</th>
                      <th className="pb-2 pr-3">{t("dashboard.component")}</th>
                      <th className="pb-2">{t("releaseDetail.vulns.severity")}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-50">
                    {cveResult.affected.map((r, i) => (
                      <tr key={i} className="hover:bg-gray-50 cursor-pointer" onClick={() => navigate(`/releases/${r.release_id}`)}>
                        <td className="py-2 pr-3 text-gray-700">{r.org_name}</td>
                        <td className="py-2 pr-3 text-gray-700">{r.product_name}</td>
                        <td className="py-2 pr-3 font-mono text-gray-600">{r.release_version}</td>
                        <td className="py-2 pr-3 text-gray-600">{r.component}</td>
                        <td className="py-2">
                          <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${r.severity==="critical"?"bg-red-100 text-red-700":r.severity==="high"?"bg-orange-100 text-orange-700":"bg-yellow-100 text-yellow-700"}`}>
                            {r.severity}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )
        )}
      </div>

      {/* Patch tracking summary */}
      {stats.patch_tracking && (
        <div className="mt-4 bg-white rounded-lg shadow p-5">
          <h2 className="font-semibold text-gray-700 mb-4">{t("dashboard.patchTracking")}</h2>
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
              <p className="text-sm text-gray-500">{t("dashboard.patchRate")}</p>
            </div>
            {/* Fixed count */}
            <div className="flex flex-col items-center justify-center">
              <span className="text-3xl font-bold text-green-600">{stats.patch_tracking.fixed}</span>
              <p className="text-sm text-gray-500 mt-1">{t("dashboard.fixedVulns")}</p>
            </div>
            {/* Avg days to fix */}
            <div className="flex flex-col items-center justify-center">
              <span className="text-3xl font-bold text-blue-600">
                {stats.patch_tracking.avg_days_to_fix != null ? stats.patch_tracking.avg_days_to_fix : "—"}
              </span>
              <p className="text-sm text-gray-500 mt-1">{t("dashboard.avgDaysToFix")}</p>
            </div>
          </div>
        </div>
      )}

      {/* Threat highlights */}
      {topThreats && (
        <div className="mt-4 bg-white rounded-lg shadow p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold text-gray-700">{t("dashboard.threatHighlights")}</h2>
            {topThreats.active_kev_count > 0 && (
              <span className="flex items-center gap-1.5 bg-red-100 text-red-700 text-xs font-bold px-3 py-1 rounded-full">
                {t("dashboard.kevUnresolved", { n: topThreats.active_kev_count })}
              </span>
            )}
          </div>
          {topThreats.top_epss.length === 0 ? (
            <p className="text-sm text-gray-600">{t("dashboard.noHighEpss")}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-gray-600 border-b">
                    <th className="pb-2 pr-4">CVE</th>
                    <th className="pb-2 pr-4">EPSS</th>
                    <th className="pb-2 pr-4">{t("releaseDetail.vulns.severity")}</th>
                    <th className="pb-2 pr-4">{t("dashboard.component")}</th>
                    <th className="pb-2">KEV</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {topThreats.top_epss.map((v) => {
                    const sevColor = { critical: "text-red-600 bg-red-50", high: "text-orange-600 bg-orange-50", medium: "text-yellow-600 bg-yellow-50", low: "text-blue-600 bg-blue-50" }[v.severity] || "text-gray-500 bg-gray-50";
                    return (
                      <tr key={v.cve_id} className="hover:bg-gray-50">
                        <td className="py-3 pr-4 font-mono text-xs text-gray-700">{v.cve_id}</td>
                        <td className="py-3 pr-4">
                          <span className={`font-semibold ${parseFloat(v.epss_score) >= 0.5 ? "text-red-600" : "text-orange-500"}`}>
                            {(v.epss_score * 100).toFixed(1)}%
                          </span>
                        </td>
                        <td className="py-3 pr-4">
                          <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${sevColor}`}>{v.severity}</span>
                        </td>
                        <td className="py-3 pr-4 text-gray-600 max-w-[160px] truncate">{v.component}</td>
                        <td className="py-3">
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

      {/* Top risky components */}
      {riskyComponents.length > 0 && (
        <div className="mt-4 bg-white rounded-lg shadow p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold text-gray-700">{t("dashboard.riskyComponents")}</h2>
            <span className="text-xs text-gray-600">{t("dashboard.riskySubtitle")}</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-600 border-b">
                  <th className="pb-2 pr-4">{t("dashboard.riskyCol")}</th>
                  <th className="pb-2 pr-4 text-center">{t("dashboard.riskyColVersions")}</th>
                  <th className="pb-2 pr-4 text-center">{t("dashboard.riskyColUnpatched")}</th>
                  <th className="pb-2 text-center">{t("dashboard.riskyColEpss")}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {riskyComponents.map((c, i) => (
                  <tr
                    key={i}
                    className="hover:bg-gray-50 cursor-pointer"
                    onClick={() => navigate(`/search?q=${encodeURIComponent(c.name)}`)}
                  >
                    <td className="py-3 pr-4">
                      <span className="font-medium text-gray-800">{c.name}</span>
                      {c.version && <span className="ml-1.5 text-xs text-gray-600">{c.version}</span>}
                    </td>
                    <td className="py-2.5 pr-4 text-center">
                      <span className="text-xs bg-blue-50 text-blue-700 px-2 py-0.5 rounded-full font-medium">
                        {t("dashboard.releaseCount", { n: c.release_count })}
                      </span>
                    </td>
                    <td className="py-2.5 pr-4 text-center">
                      <span className={`font-bold text-sm ${c.unpatched_ch >= 5 ? "text-red-600" : "text-orange-500"}`}>
                        {c.unpatched_ch}
                      </span>
                    </td>
                    <td className="py-2.5 text-center">
                      {c.max_epss != null ? (
                        <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                          c.max_epss >= 0.5 ? "bg-red-100 text-red-700" :
                          c.max_epss >= 0.1 ? "bg-orange-100 text-orange-700" :
                          "bg-gray-100 text-gray-500"
                        }`}>
                          {(c.max_epss * 100).toFixed(1)}%
                        </span>
                      ) : <span className="text-gray-300">—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-3 text-xs text-gray-600">{t("dashboard.riskyHint")}</p>
        </div>
      )}

      {/* Risk overview table */}
      {riskOverview.length > 0 && (
        <div className="mt-4 bg-white rounded-lg shadow p-5">
          <h2 className="font-semibold text-gray-700 mb-4">{t("dashboard.riskOverview")}</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-600 border-b">
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
                      onClick={() => navigate(`/organizations/${org.org_id}/products`)}
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
