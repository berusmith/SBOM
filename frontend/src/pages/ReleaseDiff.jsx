import { useEffect, useState } from "react";
import { useSearchParams, useNavigate, useLocation } from "react-router-dom";
import api from "../api/client";
import { SEVERITY_COLOR } from "../constants/colors";
import { SkeletonTable } from "../components/Skeleton";

const SEV_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

export default function ReleaseDiff() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const location = useLocation();
  const { orgId, orgName, productName } = location.state || {};
  const productId = searchParams.get("product");
  const fromId    = searchParams.get("from");
  const toId      = searchParams.get("to");

  const [diff, setDiff] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!productId || !fromId || !toId) { setError("參數不完整"); setLoading(false); return; }
    api.get(`/products/${productId}/diff`, { params: { from: fromId, to: toId } })
      .then((r) => setDiff(r.data))
      .catch((e) => setError(e.response?.data?.detail || "載入失敗"))
      .finally(() => setLoading(false));
  }, [productId, fromId, toId]);

  if (loading) return <div className="p-6"><SkeletonTable rows={6} cols={4} /></div>;
  if (error)   return <div className="p-8 text-center text-red-500">{error}</div>;
  if (!diff)   return null;

  const { components: c, vulnerabilities: v } = diff;

  // Severity breakdown of newly added vulns
  const newVulnBySev = v.added.reduce((acc, vv) => {
    const s = vv.severity || "info";
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});

  const hasChanges = c.added.length > 0 || c.removed.length > 0 || v.added.length > 0 || v.removed.length > 0;

  const exportCsv = () => {
    const rows = [
      ["類型", "項目", "版本/CVE", "嚴重度", "CVSS", "EPSS"],
      ...c.added.map(x => ["元件新增", x.name, x.version || "", "", "", ""]),
      ...c.removed.map(x => ["元件移除", x.name, x.version || "", "", "", ""]),
      ...v.added.map(x => ["漏洞新增", x.component, x.cve_id, x.severity || "", x.cvss_score ?? "", x.epss_score != null ? `${(x.epss_score * 100).toFixed(1)}%` : ""]),
      ...v.removed.map(x => ["漏洞消失", x.component, x.cve_id, x.severity || "", x.cvss_score ?? "", x.epss_score != null ? `${(x.epss_score * 100).toFixed(1)}%` : ""]),
    ];
    const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob(["﻿" + csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `diff_${diff.from_version}_${diff.to_version}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm mb-4 flex-wrap">
        <button onClick={() => navigate("/organizations")} className="text-blue-600 hover:underline">客戶管理</button>
        {orgId && orgName && (
          <><span className="text-gray-400">/</span>
          <button onClick={() => navigate(`/organizations/${orgId}/products`, { state: { orgId, orgName } })} className="text-blue-600 hover:underline">{orgName}</button></>
        )}
        {productId && (
          <><span className="text-gray-400">/</span>
          <button onClick={() => navigate(`/products/${productId}/releases`, { state: { orgId, orgName } })} className="text-blue-600 hover:underline">{productName || productId}</button></>
        )}
        <span className="text-gray-400">/</span>
        <span className="text-gray-600">版本比對</span>
      </div>

      {/* Title */}
      <div className="flex items-start justify-between gap-4 mb-6 flex-wrap">
        <div>
          <h2 className="text-xl font-bold text-gray-800 mb-1">{diff.product_name} — 版本比對</h2>
          <div className="flex items-center gap-2 text-sm">
            <span className="font-mono bg-gray-100 px-2 py-0.5 rounded text-gray-700">{diff.from_version}</span>
            <span className="text-gray-400">→</span>
            <span className="font-mono bg-blue-50 px-2 py-0.5 rounded text-blue-700 font-medium">{diff.to_version}</span>
          </div>
        </div>
        {hasChanges && (
          <button onClick={exportCsv}
            className="px-3 py-2 text-sm bg-emerald-600 hover:bg-emerald-700 text-white rounded shrink-0">
            匯出 CSV
          </button>
        )}
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
        {[
          { label: "元件新增", val: c.added.length,    color: "text-green-600", bg: "bg-green-50" },
          { label: "元件移除", val: c.removed.length,  color: "text-red-600",   bg: "bg-red-50" },
          { label: "元件不變", val: c.unchanged,       color: "text-gray-500",  bg: "bg-gray-50" },
          { label: "漏洞新增", val: v.added.length,    color: "text-red-600",   bg: "bg-red-50" },
          { label: "漏洞消失", val: v.removed.length,  color: "text-green-600", bg: "bg-green-50" },
          { label: "漏洞不變", val: v.unchanged,       color: "text-gray-500",  bg: "bg-gray-50" },
        ].map((s) => (
          <div key={s.label} className={`rounded-lg border p-4 text-center ${s.bg}`}>
            <div className={`text-2xl font-bold ${s.color}`}>{s.val}</div>
            <div className="text-xs text-gray-500 mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* New vuln severity breakdown */}
      {v.added.length > 0 && (
        <div className="bg-white rounded-lg border border-red-200 p-4 mb-5">
          <p className="text-sm font-medium text-gray-700 mb-2">新增漏洞嚴重度分布</p>
          <div className="flex gap-2 flex-wrap">
            {Object.entries(newVulnBySev).sort((a, b) => (SEV_ORDER[b[0]] || 0) - (SEV_ORDER[a[0]] || 0)).map(([sev, cnt]) => (
              <span key={sev} className={`px-3 py-1 rounded-full text-xs font-medium ${SEVERITY_COLOR[sev]}`}>
                {sev} × {cnt}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Sections */}
      {c.added.length > 0 && (
        <Section title={`新增元件 (${c.added.length})`} color="green">
          <SimpleCompTable items={c.added} />
        </Section>
      )}
      {c.removed.length > 0 && (
        <Section title={`移除元件 (${c.removed.length})`} color="red">
          <SimpleCompTable items={c.removed} />
        </Section>
      )}
      {v.added.length > 0 && (
        <Section title={`新增漏洞 (${v.added.length})`} color="red">
          <VulnTable items={v.added} />
        </Section>
      )}
      {v.removed.length > 0 && (
        <Section title={`消失漏洞 (${v.removed.length})`} color="green">
          <VulnTable items={v.removed} />
        </Section>
      )}

      {!hasChanges && (
        <div className="bg-white rounded-lg shadow p-8 text-center">
          <p className="text-2xl mb-2">✓</p>
          <p className="text-gray-700 font-medium">兩版本元件與漏洞完全相同</p>
          <p className="text-xs text-gray-500 mt-1">{c.unchanged} 個元件 · {v.unchanged} 個漏洞</p>
        </div>
      )}
    </div>
  );
}

function Section({ title, color, children }) {
  const border = color === "green" ? "border-green-200" : "border-red-200";
  const bg     = color === "green" ? "bg-green-50"      : "bg-red-50";
  const text   = color === "green" ? "text-green-700"   : "text-red-700";
  return (
    <div className={`mb-5 rounded-lg border ${border} overflow-hidden`}>
      <div className={`px-4 py-2 ${bg} ${text} font-medium text-sm`}>{title}</div>
      {children}
    </div>
  );
}

function SimpleCompTable({ items }) {
  return (
    <div className="overflow-x-auto">
    <table className="w-full text-sm bg-white min-w-[280px]">
      <thead className="bg-gray-50 text-gray-500 text-left">
        <tr>
          <th className="px-4 py-2">元件名稱</th>
          <th className="px-4 py-2">版本</th>
        </tr>
      </thead>
      <tbody>
        {items.map((c, i) => (
          <tr key={i} className="border-t">
            <td className="px-4 py-2 font-medium text-gray-800">{c.name}</td>
            <td className="px-4 py-2 text-gray-500 font-mono text-xs">{c.version || "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
    </div>
  );
}

function VulnTable({ items }) {
  return (
    <div className="overflow-x-auto">
    <table className="w-full text-sm bg-white min-w-[480px]">
      <thead className="bg-gray-50 text-gray-500 text-left">
        <tr>
          <th className="px-4 py-2">CVE ID</th>
          <th className="px-4 py-2">元件</th>
          <th className="px-4 py-2">嚴重度</th>
          <th className="px-4 py-2 hidden sm:table-cell">CVSS</th>
          <th className="px-4 py-2 hidden sm:table-cell">EPSS</th>
        </tr>
      </thead>
      <tbody>
        {items.map((v, i) => (
          <tr key={i} className="border-t hover:bg-gray-50">
            <td className="px-4 py-2 font-mono text-xs text-blue-700">
              {v.cve_id}
              {v.is_kev && <span className="ml-1.5 px-1.5 py-0.5 rounded text-white bg-red-600 font-bold text-xs">KEV</span>}
            </td>
            <td className="px-4 py-2 text-gray-600 text-xs">{v.component}</td>
            <td className="px-4 py-2">
              {v.severity && <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_COLOR[v.severity]}`}>{v.severity}</span>}
            </td>
            <td className="px-4 py-2 text-gray-600 hidden sm:table-cell">{v.cvss_score ?? "—"}</td>
            <td className="px-4 py-2 text-xs text-gray-500 hidden sm:table-cell">
              {v.epss_score != null ? `${(v.epss_score * 100).toFixed(1)}%` : "—"}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
    </div>
  );
}
