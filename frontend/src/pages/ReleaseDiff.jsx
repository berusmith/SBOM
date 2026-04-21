import { useEffect, useState } from "react";
import { useSearchParams, useNavigate, Link } from "react-router-dom";
import api from "../api/client";

const SEVERITY_COLOR = {
  critical: "bg-red-100 text-red-700",
  high:     "bg-orange-100 text-orange-700",
  medium:   "bg-yellow-100 text-yellow-700",
  low:      "bg-blue-100 text-blue-700",
  info:     "bg-gray-100 text-gray-500",
};

export default function ReleaseDiff() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const productId  = searchParams.get("product");
  const fromId     = searchParams.get("from");
  const toId       = searchParams.get("to");

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

  if (loading) return <div className="p-8 text-center text-gray-400">載入中...</div>;
  if (error)   return <div className="p-8 text-center text-red-500">{error}</div>;
  if (!diff)   return null;

  const { components: c, vulnerabilities: v } = diff;

  return (
    <div>
      <button onClick={() => navigate(-1)} className="text-blue-600 hover:underline text-sm mb-4 block">← 返回</button>

      <h2 className="text-xl font-bold text-gray-800 mb-1">{diff.product_name} — 版本比對</h2>
      <p className="text-sm text-gray-500 mb-6">
        <span className="font-mono bg-gray-100 px-2 py-0.5 rounded">{diff.from_version}</span>
        <span className="mx-2 text-gray-400">→</span>
        <span className="font-mono bg-gray-100 px-2 py-0.5 rounded">{diff.to_version}</span>
      </p>

      {/* Summary cards */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        {[
          { label: "元件新增", val: c.added.length,   color: "text-green-600" },
          { label: "元件移除", val: c.removed.length, color: "text-red-600" },
          { label: "漏洞新增", val: v.added.length,   color: "text-red-600" },
          { label: "漏洞修復/移除", val: v.removed.length, color: "text-green-600" },
        ].map((s) => (
          <div key={s.label} className="bg-white rounded-lg shadow p-4 text-center">
            <div className={`text-3xl font-bold ${s.color}`}>{s.val}</div>
            <div className="text-xs text-gray-500 mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Components added */}
      {c.added.length > 0 && (
        <Section title={`新增元件 (${c.added.length})`} color="green">
          <SimpleCompTable items={c.added} />
        </Section>
      )}

      {/* Components removed */}
      {c.removed.length > 0 && (
        <Section title={`移除元件 (${c.removed.length})`} color="red">
          <SimpleCompTable items={c.removed} />
        </Section>
      )}

      {/* Vulns added */}
      {v.added.length > 0 && (
        <Section title={`新增漏洞 (${v.added.length})`} color="red">
          <VulnTable items={v.added} />
        </Section>
      )}

      {/* Vulns removed */}
      {v.removed.length > 0 && (
        <Section title={`消失漏洞 (${v.removed.length})`} color="green">
          <VulnTable items={v.removed} />
        </Section>
      )}

      {c.added.length === 0 && c.removed.length === 0 && v.added.length === 0 && v.removed.length === 0 && (
        <div className="bg-white rounded-lg shadow p-8 text-center text-gray-400">兩版本元件與漏洞完全相同</div>
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
    <table className="w-full text-sm bg-white">
      <thead className="bg-gray-50 text-gray-500 text-left">
        <tr><th className="px-4 py-2">元件名稱</th><th className="px-4 py-2">版本</th></tr>
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
  );
}

function VulnTable({ items }) {
  return (
    <table className="w-full text-sm bg-white">
      <thead className="bg-gray-50 text-gray-500 text-left">
        <tr>
          <th className="px-4 py-2">CVE ID</th>
          <th className="px-4 py-2">元件</th>
          <th className="px-4 py-2">CVSS</th>
          <th className="px-4 py-2">嚴重度</th>
          <th className="px-4 py-2">EPSS</th>
        </tr>
      </thead>
      <tbody>
        {items.map((v, i) => (
          <tr key={i} className="border-t">
            <td className="px-4 py-2 font-mono text-xs text-blue-700">
              {v.cve_id}
              {v.is_kev && <span className="ml-1.5 px-1.5 py-0.5 rounded text-white bg-red-600 font-bold" style={{fontSize:"10px"}}>KEV</span>}
            </td>
            <td className="px-4 py-2 text-gray-600 text-xs">{v.component}</td>
            <td className="px-4 py-2 text-gray-600">{v.cvss_score ?? "—"}</td>
            <td className="px-4 py-2">
              {v.severity && <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_COLOR[v.severity]}`}>{v.severity}</span>}
            </td>
            <td className="px-4 py-2 text-xs text-gray-500">
              {v.epss_score != null ? `${(v.epss_score * 100).toFixed(1)}%` : "—"}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
