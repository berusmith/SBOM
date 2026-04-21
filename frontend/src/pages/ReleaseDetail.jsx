import React, { useEffect, useRef, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import api from "../api/client";

const SEVERITY_COLOR = {
  critical: "bg-red-100 text-red-700",
  high:     "bg-orange-100 text-orange-700",
  medium:   "bg-yellow-100 text-yellow-700",
  low:      "bg-blue-100 text-blue-700",
  info:     "bg-gray-100 text-gray-500",
};

const STATUS_OPTIONS = ["open", "in_triage", "not_affected", "affected", "fixed"];

const STATUS_LABEL = {
  open: "Open",
  in_triage: "In Triage",
  not_affected: "Not Affected",
  affected: "Affected",
  fixed: "Fixed",
};

const STATUS_COLOR = {
  open:         "bg-red-100 text-red-700",
  in_triage:    "bg-yellow-100 text-yellow-700",
  not_affected: "bg-green-100 text-green-700",
  affected:     "bg-orange-100 text-orange-700",
  fixed:        "bg-blue-100 text-blue-700",
};

const JUSTIFICATION_OPTIONS = [
  { value: "code_not_present",               label: "程式碼不存在 (code_not_present)" },
  { value: "code_not_reachable",             label: "程式碼不可達 (code_not_reachable)" },
  { value: "requires_configuration",         label: "需特殊設定才觸發 (requires_configuration)" },
  { value: "requires_dependency",            label: "需特殊相依才觸發 (requires_dependency)" },
  { value: "requires_environment",           label: "需特殊環境才觸發 (requires_environment)" },
  { value: "protected_by_compiler",          label: "編譯器保護 (protected_by_compiler)" },
  { value: "protected_at_runtime",           label: "執行期保護 (protected_at_runtime)" },
  { value: "protected_at_perimeter",         label: "邊界防護 (protected_at_perimeter)" },
  { value: "protected_by_mitigating_control", label: "緩解控制保護 (protected_by_mitigating_control)" },
];

const RESPONSE_OPTIONS = [
  { value: "can_not_fix",          label: "無法修復 (can_not_fix)" },
  { value: "will_not_fix",         label: "不予修復 (will_not_fix)" },
  { value: "update",               label: "升級版本 (update)" },
  { value: "rollback",             label: "回滾版本 (rollback)" },
  { value: "workaround_available", label: "有暫時解法 (workaround_available)" },
];

export default function ReleaseDetail() {
  const { releaseId } = useParams();
  const navigate = useNavigate();
  const fileRef = useRef();

  const [tab, setTab] = useState("components");
  const [components, setComponents] = useState([]);
  const [vulns, setVulns] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [downloading, setDownloading] = useState(false);
  const [downloadingCsaf, setDownloadingCsaf] = useState(false);
  const [downloadingEvidence, setDownloadingEvidence] = useState(false);
  const [downloadingIec, setDownloadingIec] = useState(false);
  const [loading, setLoading] = useState(false);
  const [rescanning, setRescanning] = useState(false);
  const [rescanResult, setRescanResult] = useState(null);
  const [enriching, setEnriching] = useState(false);
  const [exportingCsv, setExportingCsv] = useState(false);
  const [enrichingNvd, setEnrichingNvd] = useState(false);
  const [nvdMsg, setNvdMsg] = useState(null);
  const [expandedVuln, setExpandedVuln] = useState(null);
  const [vulnHistory, setVulnHistory] = useState({});
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [sortField, setSortField] = useState("cvss_score");
  const [sortAsc, setSortAsc] = useState(false);
  const [filterEpss, setFilterEpss] = useState(false);
  const [filterKev, setFilterKev] = useState(false);
  const [selected, setSelected] = useState(new Set());
  const [batchStatus, setBatchStatus] = useState("in_triage");
  const [batching, setBatching] = useState(false);
  const [violations, setViolations] = useState(null);
  const [locked, setLocked] = useState(false);
  const [integrity, setIntegrity] = useState(null);
  const [checkingIntegrity, setCheckingIntegrity] = useState(false);

  const fetchComponents = () => {
    api.get(`/releases/${releaseId}/components`).then((r) => setComponents(r.data)).catch(() => {});
  };
  const fetchVulns = () => {
    api.get(`/releases/${releaseId}/vulnerabilities`).then((r) => setVulns(r.data)).catch(() => {});
  };
  const fetchViolations = () => {
    api.get(`/policies/releases/${releaseId}/violations`).then((r) => setViolations(r.data)).catch(() => {});
  };
  const fetchRelease = () => {
    api.get(`/releases/${releaseId}`).then((r) => setLocked(r.data.locked ?? false)).catch(() => {});
  };

  useEffect(() => {
    fetchComponents();
    fetchVulns();
    fetchViolations();
    fetchRelease();
  }, [releaseId]);

  const handleLockToggle = async () => {
    const action = locked ? "unlock" : "lock";
    if (!locked && !window.confirm("鎖定後將無法上傳 SBOM、重新掃描或修改 VEX 狀態，確定鎖定？")) return;
    try {
      await api.post(`/releases/${releaseId}/${action}`);
      setLocked(!locked);
    } catch (e) { alert(e.response?.data?.detail || "操作失敗"); }
  };

  const handleCheckIntegrity = async () => {
    setCheckingIntegrity(true);
    setIntegrity(null);
    try {
      const r = await api.get(`/releases/${releaseId}/integrity`);
      setIntegrity(r.data);
    } catch { setIntegrity({ status: "error", message: "驗證失敗" }); }
    finally { setCheckingIntegrity(false); }
  };

  const handleUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setUploading(true);
    setUploadResult(null);
    const form = new FormData();
    form.append("file", file);
    try {
      const res = await api.post(`/releases/${releaseId}/sbom`, form, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setUploadResult({ ok: true, ...res.data });
      fetchComponents();
      fetchVulns();
    } catch (err) {
      setUploadResult({ ok: false, msg: err.response?.data?.detail || err.message });
    } finally {
      setUploading(false);
      fileRef.current.value = "";
    }
  };

  const handleDownloadReport = async () => {
    setDownloading(true);
    try {
      const resp = await api.get(`/releases/${releaseId}/report`, { responseType: "blob" });
      const url = URL.createObjectURL(new Blob([resp.data], { type: "application/pdf" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `SBOM_Report_${releaseId}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert("下載失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setDownloading(false);
    }
  };

  const handleDownloadIec = async () => {
    setDownloadingIec(true);
    try {
      const resp = await api.get(`/releases/${releaseId}/compliance/iec62443`, { responseType: "blob" });
      const url = URL.createObjectURL(new Blob([resp.data], { type: "application/pdf" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `IEC62443_${releaseId}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert("下載失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setDownloadingIec(false);
    }
  };

  const handleDownloadEvidence = async () => {
    setDownloadingEvidence(true);
    try {
      const resp = await api.get(`/releases/${releaseId}/evidence-package`, { responseType: "blob" });
      const url = URL.createObjectURL(new Blob([resp.data], { type: "application/zip" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `evidence_${releaseId}.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert("下載失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setDownloadingEvidence(false);
    }
  };

  const handleRescan = async () => {
    setRescanning(true);
    setRescanResult(null);
    try {
      const res = await api.post(`/releases/${releaseId}/rescan`);
      setRescanResult({ ok: true, ...res.data });
      fetchVulns();
      fetchComponents();
    } catch (err) {
      setRescanResult({ ok: false, msg: err.response?.data?.detail || err.message });
    } finally {
      setRescanning(false);
    }
  };

  const handleExportCsv = async () => {
    setExportingCsv(true);
    try {
      const resp = await api.get(`/releases/${releaseId}/vulnerabilities/export`, { responseType: "blob" });
      const url = URL.createObjectURL(new Blob([resp.data], { type: "text/csv" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `vulns_${releaseId}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert("匯出失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setExportingCsv(false);
    }
  };

  const handleEnrichNvd = async () => {
    setEnrichingNvd(true);
    setNvdMsg(null);
    try {
      const res = await api.post(`/releases/${releaseId}/enrich-nvd`);
      setNvdMsg(res.data.message);
    } catch (err) {
      setNvdMsg("NVD 補充失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setEnrichingNvd(false);
    }
  };

  const handleEnrichEpss = async () => {
    setEnriching(true);
    try {
      await api.post(`/releases/${releaseId}/enrich-epss`);
      fetchVulns();
    } catch (err) {
      alert("EPSS 更新失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setEnriching(false);
    }
  };

  const handleBatchVex = async () => {
    if (selected.size === 0) return;
    setBatching(true);
    try {
      await api.patch("/vulnerabilities/batch", {
        vuln_ids: [...selected],
        status: batchStatus,
      });
      setSelected(new Set());
      fetchVulns();
    } catch (err) {
      alert("批次更新失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setBatching(false);
    }
  };

  const handleDownloadCsaf = async () => {
    setDownloadingCsaf(true);
    try {
      const resp = await api.get(`/releases/${releaseId}/csaf`, { responseType: "blob" });
      const url = URL.createObjectURL(new Blob([resp.data], { type: "application/json" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `VEX_${releaseId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert("下載失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setDownloadingCsaf(false);
    }
  };

  const severityCounts = vulns.reduce((acc, v) => {
    acc[v.severity] = (acc[v.severity] || 0) + 1;
    return acc;
  }, {});

  const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const displayedVulns = [...vulns]
    .filter((v) =>
      (!filterSeverity || v.severity === filterSeverity) &&
      (!filterStatus || v.status === filterStatus) &&
      (!filterEpss || (v.epss_score != null && v.epss_score >= 0.1)) &&
      (!filterKev || v.is_kev)
    )
    .sort((a, b) => {
      let av, bv;
      if (sortField === "cvss_score") { av = a.cvss_score ?? -1; bv = b.cvss_score ?? -1; }
      else if (sortField === "severity") { av = SEVERITY_ORDER[a.severity] ?? -1; bv = SEVERITY_ORDER[b.severity] ?? -1; }
      else if (sortField === "epss_score") { av = a.epss_score ?? -1; bv = b.epss_score ?? -1; }
      else { av = a.cve_id; bv = b.cve_id; }
      if (av < bv) return sortAsc ? -1 : 1;
      if (av > bv) return sortAsc ? 1 : -1;
      return 0;
    });

  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <button onClick={() => navigate(-1)} className="text-blue-600 hover:underline text-sm">
          ← 返回
        </button>
        {violations && violations.total > 0 && (
          <span
            className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold cursor-pointer ${
              violations.violations.some((v) => v.action === "block")
                ? "bg-red-600 text-white"
                : "bg-orange-100 text-orange-700"
            }`}
            title="點擊查看 Policy 違規詳情"
            onClick={() => navigate("/policies")}
          >
            ⚠ {violations.total} 項 Policy 違規
          </span>
        )}
      </div>

      {/* Upload + Action area */}
      <div className="bg-white rounded-lg shadow p-4 mb-4 space-y-3">
        {/* Row 1: upload + status messages */}
        <div className="flex items-center gap-4 flex-wrap">
          <div>
            <p className="text-sm font-medium text-gray-700">上傳 SBOM 檔案</p>
            <p className="text-xs text-gray-400">支援 CycloneDX JSON、SPDX JSON</p>
          </div>
          <label className={`cursor-pointer px-4 py-2 rounded text-sm text-white ${uploading ? "bg-gray-400" : "bg-blue-600 hover:bg-blue-700"}`}>
            {uploading ? "上傳中..." : "選擇檔案"}
            <input ref={fileRef} type="file" accept=".json" className="hidden" onChange={handleUpload} disabled={uploading} />
          </label>
          {uploadResult && (
            <span className={`text-sm ${uploadResult.ok ? "text-green-600" : "text-red-500"}`}>
              {uploadResult.ok
                ? `完成：${uploadResult.components_found} 個元件，${uploadResult.vulnerabilities_found} 個漏洞`
                : `失敗：${uploadResult.msg}`}
            </span>
          )}
          {nvdMsg && <span className="text-sm text-blue-600">{nvdMsg}</span>}
          {rescanResult && (
            <span className={`text-sm ${rescanResult.ok ? "text-green-600" : "text-red-500"}`}>
              {rescanResult.ok
                ? `重新掃描完成：新增 ${rescanResult.new_vulnerabilities_found} 個漏洞`
                : `掃描失敗：${rescanResult.msg}`}
            </span>
          )}
        </div>

        {/* Row 2: grouped action buttons */}
        {components.length > 0 && (
          <div className="flex flex-wrap gap-x-4 gap-y-2 pt-2 border-t">

            {/* 掃描 group */}
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-gray-400 font-medium mr-1">掃描</span>
              <button onClick={handleRescan} disabled={rescanning}
                className={`px-3 py-1.5 rounded text-xs text-white ${rescanning ? "bg-gray-300" : "bg-orange-500 hover:bg-orange-600"}`}>
                {rescanning ? "掃描中..." : "重新掃描 CVE"}
              </button>
              <button onClick={handleEnrichNvd} disabled={enrichingNvd}
                className={`px-3 py-1.5 rounded text-xs text-white ${enrichingNvd ? "bg-gray-300" : "bg-cyan-600 hover:bg-cyan-700"}`}>
                {enrichingNvd ? "更新中..." : "更新 NVD"}
              </button>
              <button onClick={handleEnrichEpss} disabled={enriching}
                className={`px-3 py-1.5 rounded text-xs text-white ${enriching ? "bg-gray-300" : "bg-violet-600 hover:bg-violet-700"}`}>
                {enriching ? "更新中..." : "更新 EPSS"}
              </button>
            </div>

            <div className="border-l border-gray-200" />

            {/* 匯出 group */}
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-gray-400 font-medium mr-1">匯出</span>
              <button onClick={handleExportCsv} disabled={exportingCsv}
                className={`px-3 py-1.5 rounded text-xs text-white ${exportingCsv ? "bg-gray-300" : "bg-emerald-600 hover:bg-emerald-700"}`}>
                {exportingCsv ? "匯出中..." : "CSV"}
              </button>
              <button onClick={handleDownloadCsaf} disabled={downloadingCsaf}
                className={`px-3 py-1.5 rounded text-xs text-white ${downloadingCsaf ? "bg-gray-300" : "bg-purple-600 hover:bg-purple-700"}`}>
                {downloadingCsaf ? "產生中..." : "CSAF VEX"}
              </button>
              <button onClick={handleDownloadReport} disabled={downloading}
                className={`px-3 py-1.5 rounded text-xs text-white ${downloading ? "bg-gray-300" : "bg-green-600 hover:bg-green-700"}`}>
                {downloading ? "產生中..." : "PDF 報告"}
              </button>
              <button onClick={handleDownloadIec} disabled={downloadingIec}
                className={`px-3 py-1.5 rounded text-xs text-white ${downloadingIec ? "bg-gray-300" : "bg-teal-600 hover:bg-teal-700"}`}>
                {downloadingIec ? "產生中..." : "IEC 62443"}
              </button>
              <button onClick={handleDownloadEvidence} disabled={downloadingEvidence}
                className={`px-3 py-1.5 rounded text-xs text-white ${downloadingEvidence ? "bg-gray-300" : "bg-blue-600 hover:bg-blue-700"}`}>
                {downloadingEvidence ? "打包中..." : "證據包 ZIP"}
              </button>
            </div>

            <div className="border-l border-gray-200" />

            {/* 管理 group */}
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-gray-400 font-medium mr-1">管理</span>
              <button onClick={handleCheckIntegrity} disabled={checkingIntegrity}
                className="px-3 py-1.5 rounded text-xs border border-gray-300 text-gray-600 hover:bg-gray-50 disabled:opacity-40">
                {checkingIntegrity ? "驗證中..." : "完整性驗證"}
              </button>
              <button onClick={handleLockToggle}
                className={`px-3 py-1.5 rounded text-xs text-white ${locked ? "bg-gray-500 hover:bg-gray-600" : "bg-gray-700 hover:bg-gray-800"}`}>
                {locked ? "🔓 解鎖" : "🔒 鎖定"}
              </button>
            </div>

          </div>
        )}
      </div>

      {/* Integrity result */}
      {integrity && (
        <div className={`mb-3 px-4 py-3 rounded text-sm flex items-center gap-2 ${
          integrity.status === "ok" ? "bg-green-50 text-green-700" :
          integrity.status === "tampered" ? "bg-red-50 text-red-700" : "bg-yellow-50 text-yellow-700"
        }`}>
          <span>{integrity.status === "ok" ? "✓" : integrity.status === "tampered" ? "⚠" : "ℹ"}</span>
          <span>{integrity.message}</span>
          {integrity.stored_hash && (
            <span className="ml-2 font-mono text-xs opacity-60">SHA-256: {integrity.stored_hash.slice(0, 16)}…</span>
          )}
        </div>
      )}

      {/* Lock banner */}
      {locked && (
        <div className="mb-3 px-4 py-2 rounded bg-gray-100 border border-gray-300 text-sm text-gray-700 flex items-center gap-2">
          🔒 <span>此版本已鎖定，禁止上傳 SBOM、重新掃描及修改 VEX 狀態。</span>
        </div>
      )}

      {/* Severity summary */}
      {vulns.length > 0 && (
        <div className="flex gap-2 mb-4">
          {["critical","high","medium","low","info"].map((s) =>
            severityCounts[s] ? (
              <span key={s} className={`px-3 py-1 rounded-full text-xs font-medium ${SEVERITY_COLOR[s]}`}>
                {s} {severityCounts[s]}
              </span>
            ) : null
          )}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 mb-3">
        {["components", "vulnerabilities"].map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${
              tab === t ? "bg-blue-600 text-white" : "bg-white text-gray-600 hover:bg-gray-100"
            }`}
          >
            {t === "components" ? `元件 (${components.length})` : `漏洞 (${vulns.length})`}
          </button>
        ))}
      </div>

      {/* Components table */}
      {tab === "components" && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          {components.length === 0 ? (
            <div className="p-8 text-center text-gray-400">尚未上傳 SBOM 檔案</div>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-gray-50 text-gray-500 text-left">
                <tr>
                  <th className="px-4 py-3">元件名稱</th>
                  <th className="px-4 py-3">版本</th>
                  <th className="px-4 py-3">授權</th>
                  <th className="px-4 py-3">漏洞數</th>
                  <th className="px-4 py-3">最高風險</th>
                </tr>
              </thead>
              <tbody>
                {components.map((c) => (
                  <tr key={c.id} className="border-t hover:bg-gray-50">
                    <td className="px-4 py-2 font-medium text-gray-800 max-w-xs truncate">{c.name}</td>
                    <td className="px-4 py-2 text-gray-500">{c.version || "—"}</td>
                    <td className="px-4 py-2 text-gray-500 text-xs">{c.license || "—"}</td>
                    <td className="px-4 py-2">{c.vuln_count || "—"}</td>
                    <td className="px-4 py-2">
                      {c.highest_severity ? (
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_COLOR[c.highest_severity]}`}>
                          {c.highest_severity}
                        </span>
                      ) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Vulnerabilities table */}
      {tab === "vulnerabilities" && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          {vulns.length === 0 ? (
            <div className="p-8 text-center text-gray-400">
              {components.length === 0 ? "尚未上傳 SBOM 檔案" : "未發現漏洞"}
            </div>
          ) : (
            <>
              {/* Filter bar */}
              <div className="flex gap-3 items-center px-4 py-3 border-b bg-gray-50 flex-wrap">
                <select
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value)}
                  className="border rounded px-2 py-1 text-sm text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-400"
                >
                  <option value="">全部嚴重度</option>
                  {["critical","high","medium","low","info"].map((s) => (
                    <option key={s} value={s}>{s}{severityCounts[s] ? ` (${severityCounts[s]})` : ""}</option>
                  ))}
                </select>
                <select
                  value={filterStatus}
                  onChange={(e) => setFilterStatus(e.target.value)}
                  className="border rounded px-2 py-1 text-sm text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-400"
                >
                  <option value="">全部狀態</option>
                  {STATUS_OPTIONS.map((s) => (
                    <option key={s} value={s}>{STATUS_LABEL[s]}</option>
                  ))}
                </select>
                <label className="flex items-center gap-1.5 text-sm text-gray-600 cursor-pointer select-none">
                  <input type="checkbox" checked={filterEpss} onChange={(e) => setFilterEpss(e.target.checked)} />
                  僅顯示高 EPSS (&gt;10%)
                </label>
                <label className="flex items-center gap-1.5 text-sm text-red-600 cursor-pointer select-none font-medium">
                  <input type="checkbox" checked={filterKev} onChange={(e) => setFilterKev(e.target.checked)} />
                  僅顯示 CISA KEV
                </label>
                {(filterSeverity || filterStatus || filterEpss || filterKev) && (
                  <button
                    onClick={() => { setFilterSeverity(""); setFilterStatus(""); setFilterEpss(false); setFilterKev(false); }}
                    className="text-xs text-gray-400 hover:text-gray-600 underline"
                  >
                    清除篩選
                  </button>
                )}
                <span className="ml-auto text-xs text-gray-400">
                  顯示 {displayedVulns.length} / {vulns.length} 筆
                </span>
              </div>
            <table className="w-full text-sm">
              <thead className="bg-gray-50 text-gray-500 text-left">
                <tr>
                  <th className="px-3 py-3 w-8">
                    <input
                      type="checkbox"
                      checked={displayedVulns.length > 0 && displayedVulns.every((v) => selected.has(v.id))}
                      onChange={(e) => {
                        if (e.target.checked) setSelected(new Set(displayedVulns.map((v) => v.id)));
                        else setSelected(new Set());
                      }}
                    />
                  </th>
                  <th className="px-4 py-3 cursor-pointer select-none hover:text-gray-700" onClick={() => { setSortField("cve_id"); setSortAsc(sortField === "cve_id" ? !sortAsc : true); }}>
                    CVE ID {sortField === "cve_id" ? (sortAsc ? "↑" : "↓") : ""}
                  </th>
                  <th className="px-4 py-3">元件</th>
                  <th className="px-4 py-3 cursor-pointer select-none hover:text-gray-700" onClick={() => { setSortField("cvss_score"); setSortAsc(sortField === "cvss_score" ? !sortAsc : false); }}>
                    CVSS {sortField === "cvss_score" ? (sortAsc ? "↑" : "↓") : ""}
                  </th>
                  <th className="px-4 py-3 cursor-pointer select-none hover:text-gray-700" onClick={() => { setSortField("severity"); setSortAsc(sortField === "severity" ? !sortAsc : false); }}>
                    嚴重度 {sortField === "severity" ? (sortAsc ? "↑" : "↓") : ""}
                  </th>
                  <th className="px-4 py-3 cursor-pointer select-none hover:text-gray-700" onClick={() => { setSortField("epss_score"); setSortAsc(sortField === "epss_score" ? !sortAsc : false); }}>
                    EPSS {sortField === "epss_score" ? (sortAsc ? "↑" : "↓") : ""}
                  </th>
                  <th className="px-4 py-3">VEX 狀態</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {displayedVulns.map((v) => (
                  <React.Fragment key={v.id}>
                  <tr className={`border-t hover:bg-gray-50 ${selected.has(v.id) ? "bg-blue-50" : ""}`}>
                    <td className="px-3 py-2">
                      <input
                        type="checkbox"
                        checked={selected.has(v.id)}
                        onChange={(e) => {
                          const next = new Set(selected);
                          if (e.target.checked) next.add(v.id);
                          else next.delete(v.id);
                          setSelected(next);
                        }}
                      />
                    </td>
                    <td className="px-4 py-2 font-mono text-xs">
                      <button
                        onClick={() => {
                          const next = expandedVuln === v.id ? null : v.id;
                          setExpandedVuln(next);
                          if (next && !vulnHistory[next]) {
                            api.get(`/vulnerabilities/${next}/history`).then((r) =>
                              setVulnHistory((h) => ({ ...h, [next]: r.data }))
                            ).catch(() => {});
                          }
                        }}
                        className="text-blue-700 hover:underline text-left"
                      >
                        {v.cve_id}
                      </button>
                      {v.is_kev && (
                        <span className="ml-1.5 px-1.5 py-0.5 rounded text-white bg-red-600 font-bold tracking-wide" style={{fontSize:"10px"}}>KEV</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-gray-700">{v.component_name} {v.component_version}</td>
                    <td className="px-4 py-2 text-gray-600">{v.cvss_score ?? "—"}</td>
                    <td className="px-4 py-2">
                      {v.severity && (
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_COLOR[v.severity]}`}>
                          {v.severity}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-xs">
                      {v.epss_score != null ? (
                        <span className={`px-2 py-0.5 rounded font-medium ${
                          v.epss_score >= 0.5 ? "bg-red-100 text-red-700" :
                          v.epss_score >= 0.1 ? "bg-orange-100 text-orange-700" :
                          "bg-gray-100 text-gray-500"
                        }`}>
                          {(v.epss_score * 100).toFixed(1)}%
                        </span>
                      ) : <span className="text-gray-300">—</span>}
                    </td>
                    <td className="px-4 py-2">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${STATUS_COLOR[v.status] || "bg-gray-100 text-gray-600"}`}>
                        {STATUS_LABEL[v.status] || v.status}
                      </span>
                      {v.justification && (
                        <div className="text-xs text-gray-400 mt-0.5">{v.justification}</div>
                      )}
                      {v.detail && (
                        <div className="text-xs text-gray-400 mt-0.5 italic truncate max-w-xs">{v.detail}</div>
                      )}
                    </td>
                    <td className="px-4 py-2">
                      <VexEditButton vuln={v} onUpdate={fetchVulns} />
                    </td>
                  </tr>
                  {expandedVuln === v.id && (
                    <tr key={`${v.id}-detail`} className="bg-gray-50 border-t">
                      <td colSpan={9} className="px-6 py-3 text-sm text-gray-700 space-y-2">
                        {v.description && <p className="leading-relaxed">{v.description}</p>}
                        {!v.description && <p className="text-gray-400 italic">NVD 描述尚未補充，請點「更新 NVD」</p>}
                        <div className="flex gap-6 flex-wrap text-xs text-gray-500">
                          {v.cwe && <span><span className="font-medium text-gray-700">CWE：</span>{v.cwe}</span>}
                          {v.cvss_v3_score != null && <span><span className="font-medium text-gray-700">CVSS v3：</span>{v.cvss_v3_score}</span>}
                          {v.cvss_v4_score != null && <span><span className="font-medium text-gray-700">CVSS v4：</span>{v.cvss_v4_score}</span>}
                        </div>
                        {v.nvd_refs && v.nvd_refs.length > 0 && (
                          <div className="flex flex-wrap gap-2 text-xs">
                            <span className="font-medium text-gray-700">參考連結：</span>
                            {v.nvd_refs.map((url, i) => (
                              <a key={i} href={url} target="_blank" rel="noreferrer"
                                className="text-blue-600 hover:underline truncate max-w-xs">{url}</a>
                            ))}
                          </div>
                        )}
                        {/* VEX history timeline */}
                        {vulnHistory[v.id] && vulnHistory[v.id].length > 0 && (
                          <div className="mt-2">
                            <p className="text-xs font-medium text-gray-600 mb-1">狀態變更紀錄</p>
                            <ol className="space-y-1">
                              {vulnHistory[v.id].map((h) => (
                                <li key={h.id} className="flex items-start gap-2 text-xs text-gray-500">
                                  <span className="text-gray-300 mt-0.5">▸</span>
                                  <span className="font-mono text-gray-400 shrink-0">
                                    {h.changed_at ? new Date(h.changed_at).toLocaleString("zh-TW") : "—"}
                                  </span>
                                  <span>
                                    <span className="text-gray-500">{STATUS_LABEL[h.from_status] ?? h.from_status ?? "—"}</span>
                                    <span className="mx-1 text-gray-400">→</span>
                                    <span className="font-medium text-gray-700">{STATUS_LABEL[h.to_status] ?? h.to_status}</span>
                                    {h.note && <span className="ml-2 italic text-gray-400">{h.note}</span>}
                                  </span>
                                </li>
                              ))}
                            </ol>
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
            </>
          )}
        </div>
      )}
      {/* Floating batch action bar */}
      {selected.size > 0 && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 bg-gray-900 text-white rounded-xl shadow-2xl px-5 py-3 flex items-center gap-4 z-40">
          <span className="text-sm font-medium">已選 {selected.size} 筆</span>
          <select
            value={batchStatus}
            onChange={(e) => setBatchStatus(e.target.value)}
            className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm text-white focus:outline-none"
          >
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>{STATUS_LABEL[s]}</option>
            ))}
          </select>
          <button
            onClick={handleBatchVex}
            disabled={batching}
            className={`px-4 py-1.5 rounded text-sm font-medium ${batching ? "bg-gray-500" : "bg-blue-500 hover:bg-blue-400"}`}
          >
            {batching ? "更新中..." : "套用"}
          </button>
          <button
            onClick={() => setSelected(new Set())}
            className="text-gray-400 hover:text-white text-sm"
          >
            取消
          </button>
        </div>
      )}
    </div>
  );
}

function VexEditButton({ vuln, onUpdate }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="px-2 py-1 text-xs rounded border border-gray-300 text-gray-600 hover:bg-gray-50"
      >
        編輯
      </button>
      {open && <VexModal vuln={vuln} onClose={() => setOpen(false)} onUpdate={onUpdate} />}
    </>
  );
}

function VexModal({ vuln, onClose, onUpdate }) {
  const [status, setStatus] = useState(vuln.status);
  const [justification, setJustification] = useState(vuln.justification || "");
  const [response, setResponse] = useState(vuln.response || "");
  const [detail, setDetail] = useState(vuln.detail || "");
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.patch(`/vulnerabilities/${vuln.id}/status`, {
        status,
        justification: status === "not_affected" ? (justification || null) : null,
        response: status === "affected" ? (response || null) : null,
        detail: detail || null,
        note: note || null,
      });
      onUpdate();
      onClose();
    } catch {
      alert("更新失敗");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-md" onClick={(e) => e.stopPropagation()}>
        <h3 className="font-semibold text-gray-800 mb-1">VEX 狀態更新</h3>
        <p className="text-xs text-gray-400 mb-4 font-mono">{vuln.cve_id} — {vuln.component_name} {vuln.component_version}</p>

        <div className="space-y-4">
          {/* Status */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">狀態</label>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
            >
              {STATUS_OPTIONS.map((s) => (
                <option key={s} value={s}>{STATUS_LABEL[s]}</option>
              ))}
            </select>
          </div>

          {/* Justification — only for not_affected */}
          {status === "not_affected" && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Justification <span className="text-gray-400 font-normal">(不受影響的原因)</span>
              </label>
              <select
                value={justification}
                onChange={(e) => setJustification(e.target.value)}
                className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
              >
                <option value="">— 選擇原因 —</option>
                {JUSTIFICATION_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
          )}

          {/* Response — only for affected */}
          {status === "affected" && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Response <span className="text-gray-400 font-normal">(處置方式)</span>
              </label>
              <select
                value={response}
                onChange={(e) => setResponse(e.target.value)}
                className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
              >
                <option value="">— 選擇處置 —</option>
                {RESPONSE_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
          )}

          {/* Detail — always optional */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              說明 <span className="text-gray-400 font-normal">(自由文字，選填)</span>
            </label>
            <textarea
              value={detail}
              onChange={(e) => setDetail(e.target.value)}
              rows={3}
              placeholder="補充說明此漏洞的評估結果或處置方式..."
              className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400 resize-none"
            />
          </div>

          {/* Note — recorded in history */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              變更備註 <span className="text-gray-400 font-normal">(記入歷程，選填)</span>
            </label>
            <input
              type="text"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="例：已與開發確認此版本不影響"
              className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
            />
          </div>
        </div>

        <div className="flex justify-end gap-2 mt-5">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-600 border rounded hover:bg-gray-50">取消</button>
          <button
            onClick={handleSave}
            disabled={saving}
            className={`px-4 py-2 text-sm text-white rounded ${saving ? "bg-gray-400" : "bg-blue-600 hover:bg-blue-700"}`}
          >
            {saving ? "儲存中..." : "儲存"}
          </button>
        </div>
      </div>
    </div>
  );
}
