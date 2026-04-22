import React, { useEffect, useRef, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import api from "../api/client";
import { SEVERITY_COLOR, VEX_STATUS_COLOR, DEFAULT_BADGE } from "../constants/colors";
import { useToast } from "../components/Toast";
import { SkeletonInline } from "../components/Skeleton";

const STATUS_OPTIONS = ["open", "in_triage", "not_affected", "affected", "fixed"];

const STATUS_LABEL = {
  open: "Open",
  in_triage: "In Triage",
  not_affected: "Not Affected",
  affected: "Affected",
  fixed: "Fixed",
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
  const toast = useToast();
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
  const [downloadingIec42, setDownloadingIec42] = useState(false);
  const [downloadingIec33, setDownloadingIec33] = useState(false);
  const [loading, setLoading] = useState(false);
  const [rescanning, setRescanning] = useState(false);
  const [rescanResult, setRescanResult] = useState(null);
  const [enriching, setEnriching] = useState(false);
  const [exportingCsv, setExportingCsv] = useState(false);
  const [exportingCdx, setExportingCdx] = useState(false);
  const [exportingSpdx, setExportingSpdx] = useState(false);
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
  const [showSuppressed, setShowSuppressed] = useState(false);
  const [selected, setSelected] = useState(new Set());
  const [batchStatus, setBatchStatus] = useState("in_triage");
  const [batching, setBatching] = useState(false);
  const [violations, setViolations] = useState(null);
  const [licenseViolations, setLicenseViolations] = useState(null);
  const [locked, setLocked] = useState(false);
  const [integrity, setIntegrity] = useState(null);
  const [checkingIntegrity, setCheckingIntegrity] = useState(false);
  const [sbomQuality, setSbomQuality] = useState(null);
  const [gate, setGate] = useState(null);
  const [depGraph, setDepGraph] = useState(null);
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const [advancedMenuOpen, setAdvancedMenuOpen] = useState(false);
  const exportMenuRef = useRef();
  const advancedMenuRef = useRef();

  const fetchComponents = () => {
    api.get(`/releases/${releaseId}/components`).then((r) => setComponents(r.data)).catch(() => {});
  };
  const fetchQuality = () => {
    api.get(`/releases/${releaseId}/sbom-quality`).then((r) => setSbomQuality(r.data)).catch(() => setSbomQuality(null));
  };
  const fetchGate = () => {
    api.get(`/releases/${releaseId}/gate`).then((r) => setGate(r.data)).catch(() => setGate(null));
  };
  const fetchDepGraph = () => {
    api.get(`/releases/${releaseId}/dependency-graph`).then((r) => setDepGraph(r.data)).catch(() => setDepGraph(null));
  };
  const fetchVulns = () => {
    api.get(`/releases/${releaseId}/vulnerabilities`).then((r) => setVulns(r.data)).catch(() => {});
  };
  const fetchViolations = () => {
    api.get(`/policies/releases/${releaseId}/violations`).then((r) => setViolations(r.data)).catch(() => {});
    api.get(`/licenses/releases/${releaseId}/violations`).then((r) => setLicenseViolations(r.data)).catch(() => {});
  };
  const fetchRelease = () => {
    api.get(`/releases/${releaseId}`).then((r) => setLocked(r.data.locked ?? false)).catch(() => {});
  };

  useEffect(() => {
    fetchComponents();
    fetchVulns();
    fetchViolations();
    fetchRelease();
    fetchQuality();
    fetchGate();
    fetchDepGraph();
  }, [releaseId]);

  const handleLockToggle = async () => {
    const action = locked ? "unlock" : "lock";
    if (!locked && !window.confirm("鎖定後將無法上傳 SBOM、重新掃描或修改 VEX 狀態，確定鎖定？")) return;
    try {
      await api.post(`/releases/${releaseId}/${action}`);
      setLocked(!locked);
    } catch (e) { toast.error(e.response?.data?.detail || "操作失敗"); }
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

  // 點擊 dropdown 外部時關閉
  React.useEffect(() => {
    function handleClick(e) {
      if (exportMenuRef.current && !exportMenuRef.current.contains(e.target)) setExportMenuOpen(false);
      if (advancedMenuRef.current && !advancedMenuRef.current.contains(e.target)) setAdvancedMenuOpen(false);
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

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
      fetchQuality();
      fetchGate();
      fetchDepGraph();
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
      toast.error("下載失敗：" + (err.response?.data?.detail || err.message));
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
      toast.error("下載失敗：" + (err.response?.data?.detail || err.message));
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
      toast.error("下載失敗：" + (err.response?.data?.detail || err.message));
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
      toast.error("匯出失敗：" + (err.response?.data?.detail || err.message));
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
      toast.error("EPSS 更新失敗：" + (err.response?.data?.detail || err.message));
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
      toast.error("批次更新失敗：" + (err.response?.data?.detail || err.message));
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
      toast.error("下載失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setDownloadingCsaf(false);
    }
  };

  const severityCounts = vulns.filter(v => !v.suppressed).reduce((acc, v) => {
    acc[v.severity] = (acc[v.severity] || 0) + 1;
    return acc;
  }, {});
  const suppressedCount = vulns.filter(v => v.suppressed).length;

  const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const displayedVulns = [...vulns]
    .filter((v) =>
      (showSuppressed ? v.suppressed : !v.suppressed) &&
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
        {licenseViolations && licenseViolations.total > 0 && (
          <span
            className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold cursor-pointer ${
              licenseViolations.block_count > 0
                ? "bg-purple-700 text-white"
                : "bg-purple-100 text-purple-700"
            }`}
            title="點擊查看 License 違規詳情"
            onClick={() => navigate("/policies")}
          >
            ⚖ {licenseViolations.total} 個 License 違規
          </span>
        )}
      </div>

      {/* Upload + Download area */}
      <div className="bg-white rounded-lg shadow p-4 mb-4 flex items-center gap-4 flex-wrap">
        <div>
          <p className="text-sm font-medium text-gray-700 mb-1">上傳 SBOM 檔案</p>
          <p className="text-xs text-gray-400">支援 CycloneDX JSON、SPDX JSON</p>
        </div>
        <label className={`cursor-pointer px-4 py-2 rounded text-sm text-white ${uploading ? "bg-gray-400" : "bg-blue-600 hover:bg-blue-700"}`}>
          {uploading ? "上傳中..." : "選擇檔案"}
          <input ref={fileRef} type="file" accept=".json" className="hidden" onChange={handleUpload} disabled={uploading} />
        </label>
        {uploadResult && (
          <span className={`text-sm ${uploadResult.ok ? "text-green-600" : "text-red-500"}`}>
            {uploadResult.ok ? (
          <span>
            完成：{uploadResult.components_found} 個元件，{uploadResult.vulnerabilities_found} 個漏洞
            {uploadResult.diff && (
              <span className="ml-2 text-gray-500">
                ｜相較 <span className="font-medium text-gray-700">{uploadResult.diff.prev_version}</span>：
                {uploadResult.diff.components_added > 0 && <span className="text-orange-600"> +{uploadResult.diff.components_added} 元件</span>}
                {uploadResult.diff.components_removed > 0 && <span className="text-blue-600"> -{uploadResult.diff.components_removed} 元件</span>}
                {uploadResult.diff.vulns_added > 0 && <span className="text-red-600"> +{uploadResult.diff.vulns_added} 漏洞</span>}
                {uploadResult.diff.vulns_removed > 0 && <span className="text-green-600"> -{uploadResult.diff.vulns_removed} 漏洞</span>}
                {uploadResult.diff.components_added === 0 && uploadResult.diff.components_removed === 0 &&
                 uploadResult.diff.vulns_added === 0 && uploadResult.diff.vulns_removed === 0 &&
                  <span className="text-green-600"> 無差異</span>}
              </span>
            )}
          </span>
        ) : `失敗：${uploadResult.msg}`}
          </span>
        )}
        {nvdMsg && (
          <span className="text-sm text-blue-600">{nvdMsg}</span>
        )}
        {rescanResult && (
          <span className={`text-sm ${rescanResult.ok ? "text-green-600" : "text-red-500"}`}>
            {rescanResult.ok
              ? `重新掃描完成：新增 ${rescanResult.new_vulnerabilities_found} 個漏洞（掃描 ${rescanResult.components_scanned} 個元件）`
              : `掃描失敗：${rescanResult.msg}`}
          </span>
        )}
        {components.length > 0 && (
          <div className="mt-3 flex flex-wrap items-center gap-2">

            {/* 主要操作 */}
            <button
              onClick={handleRescan}
              disabled={rescanning}
              className={`px-4 py-2 rounded text-sm text-white font-medium ${rescanning ? "bg-gray-400" : "bg-orange-500 hover:bg-orange-600"} disabled:opacity-50`}
            >
              {rescanning ? "掃描中..." : "重新掃描 CVE"}
            </button>
            <button
              onClick={handleDownloadReport}
              disabled={downloading}
              className={`px-4 py-2 rounded text-sm text-white font-medium ${downloading ? "bg-gray-400" : "bg-blue-600 hover:bg-blue-700"} disabled:opacity-50`}
            >
              {downloading ? "產生中..." : "下載 PDF 報告"}
            </button>
            <button
              onClick={handleLockToggle}
              className={`px-4 py-2 rounded text-sm text-white font-medium ${locked ? "bg-gray-500 hover:bg-gray-600" : "bg-gray-700 hover:bg-gray-800"}`}
            >
              {locked ? "🔓 解鎖版本" : "🔒 鎖定版本"}
            </button>

            {/* 匯出 / 下載 dropdown */}
            <div className="relative" ref={exportMenuRef}>
              <button
                onClick={() => { setExportMenuOpen(o => !o); setAdvancedMenuOpen(false); }}
                className="px-4 py-2 rounded text-sm border border-gray-300 text-gray-700 hover:bg-gray-50 flex items-center gap-1"
              >
                匯出 / 下載 <span className="text-xs">▾</span>
              </button>
              {exportMenuOpen && (
                <div className="absolute left-0 top-full mt-1 bg-white rounded-lg shadow-lg border border-gray-200 z-20 min-w-[180px] py-1">
                  {[
                    { label: exportingCsv ? "匯出中..." : "匯出 CSV", disabled: exportingCsv, onClick: () => { handleExportCsv(); setExportMenuOpen(false); } },
                  ].map((item, i) => (
                    <button key={i} onClick={item.onClick} disabled={item.disabled}
                      className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50">
                      {item.label}
                    </button>
                  ))}
                  <button disabled={exportingCdx} onClick={async () => {
                    setExportMenuOpen(false); setExportingCdx(true);
                    try {
                      const resp = await api.get(`/releases/${releaseId}/export/cyclonedx-xml`, { responseType: "blob" });
                      const url = URL.createObjectURL(new Blob([resp.data], { type: "application/xml" }));
                      const a = document.createElement("a"); a.href = url; a.download = `cyclonedx_${releaseId.slice(0,8)}.xml`; a.click();
                      URL.revokeObjectURL(url);
                    } catch { toast.error("匯出失敗"); } finally { setExportingCdx(false); }
                  }} className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50">
                    {exportingCdx ? "匯出中..." : "CycloneDX XML"}
                  </button>
                  <button disabled={exportingSpdx} onClick={async () => {
                    setExportMenuOpen(false); setExportingSpdx(true);
                    try {
                      const resp = await api.get(`/releases/${releaseId}/export/spdx-json`, { responseType: "blob" });
                      const url = URL.createObjectURL(new Blob([resp.data], { type: "application/json" }));
                      const a = document.createElement("a"); a.href = url; a.download = `spdx_${releaseId.slice(0,8)}.json`; a.click();
                      URL.revokeObjectURL(url);
                    } catch { toast.error("匯出失敗"); } finally { setExportingSpdx(false); }
                  }} className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50">
                    {exportingSpdx ? "匯出中..." : "SPDX JSON"}
                  </button>
                  <div className="border-t border-gray-100 my-1" />
                  <button disabled={downloadingIec} onClick={() => { setExportMenuOpen(false); handleDownloadIec(); }}
                    className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50">
                    {downloadingIec ? "產生中..." : "IEC 62443-4-1 報告"}
                  </button>
                  <button disabled={downloadingIec42} onClick={async () => {
                    setExportMenuOpen(false); setDownloadingIec42(true);
                    try {
                      const resp = await api.get(`/releases/${releaseId}/compliance/iec62443-4-2`, { responseType: "blob" });
                      const url = URL.createObjectURL(new Blob([resp.data], { type: "application/pdf" }));
                      const a = document.createElement("a"); a.href = url; a.download = `IEC62443_4-2_${releaseId}.pdf`; a.click();
                      URL.revokeObjectURL(url);
                    } catch (err) { toast.error("下載失敗：" + (err.response?.data?.detail || err.message)); }
                    finally { setDownloadingIec42(false); }
                  }} className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50">
                    {downloadingIec42 ? "產生中..." : "IEC 62443-4-2 報告"}
                  </button>
                  <button disabled={downloadingIec33} onClick={async () => {
                    setExportMenuOpen(false); setDownloadingIec33(true);
                    try {
                      const resp = await api.get(`/releases/${releaseId}/compliance/iec62443-3-3`, { responseType: "blob" });
                      const url = URL.createObjectURL(new Blob([resp.data], { type: "application/pdf" }));
                      const a = document.createElement("a"); a.href = url; a.download = `IEC62443_3-3_${releaseId}.pdf`; a.click();
                      URL.revokeObjectURL(url);
                    } catch (err) { toast.error("下載失敗：" + (err.response?.data?.detail || err.message)); }
                    finally { setDownloadingIec33(false); }
                  }} className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50">
                    {downloadingIec33 ? "產生中..." : "IEC 62443-3-3 報告"}
                  </button>
                  <div className="border-t border-gray-100 my-1" />
                  <button disabled={downloadingEvidence} onClick={() => { setExportMenuOpen(false); handleDownloadEvidence(); }}
                    className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50">
                    {downloadingEvidence ? "打包中..." : "證據包 ZIP"}
                  </button>
                  <button disabled={downloadingCsaf} onClick={() => { setExportMenuOpen(false); handleDownloadCsaf(); }}
                    className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50">
                    {downloadingCsaf ? "產生中..." : "CSAF VEX"}
                  </button>
                </div>
              )}
            </div>

            {/* 進階操作 dropdown */}
            <div className="relative" ref={advancedMenuRef}>
              <button
                onClick={() => { setAdvancedMenuOpen(o => !o); setExportMenuOpen(false); }}
                className="px-4 py-2 rounded text-sm border border-gray-300 text-gray-700 hover:bg-gray-50 flex items-center gap-1"
              >
                進階操作 <span className="text-xs">▾</span>
              </button>
              {advancedMenuOpen && (
                <div className="absolute left-0 top-full mt-1 bg-white rounded-lg shadow-lg border border-gray-200 z-20 min-w-[160px] py-1">
                  <button disabled={enrichingNvd} onClick={() => { setAdvancedMenuOpen(false); handleEnrichNvd(); }}
                    className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50">
                    {enrichingNvd ? "啟動中..." : "更新 NVD 資料"}
                  </button>
                  <button disabled={enriching} onClick={() => { setAdvancedMenuOpen(false); handleEnrichEpss(); }}
                    className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50">
                    {enriching ? "更新中..." : "更新 EPSS 分數"}
                  </button>
                  <div className="border-t border-gray-100 my-1" />
                  <button disabled={checkingIntegrity} onClick={() => { setAdvancedMenuOpen(false); handleCheckIntegrity(); }}
                    className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50">
                    {checkingIntegrity ? "驗證中..." : "完整性驗證"}
                  </button>
                </div>
              )}
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

      {/* Release Policy Gate */}
      {gate && (
        <div className={`mb-4 rounded-lg border-2 p-4 ${gate.overall === "pass" ? "border-green-400 bg-green-50" : "border-red-400 bg-red-50"}`}>
          <div className="flex items-center justify-between mb-3">
            <div>
              <span className="text-sm font-semibold text-gray-700">發布品質閘門</span>
              <span className="ml-2 text-xs text-gray-400">Release Policy Gate</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs text-gray-500">{gate.passed}/{gate.total} 通過</span>
              <span className={`px-3 py-1 rounded-full text-sm font-bold tracking-wide ${gate.overall === "pass" ? "bg-green-500 text-white" : "bg-red-500 text-white"}`}>
                {gate.overall === "pass" ? "✓ PASS" : "✗ FAIL"}
              </span>
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {gate.checks.map((c) => (
              <div key={c.id} className={`flex items-start gap-2 px-3 py-2 rounded text-xs ${c.passed ? "bg-green-100" : "bg-red-100"}`}>
                <span className={`mt-0.5 shrink-0 font-bold text-sm ${c.passed ? "text-green-600" : "text-red-500"}`}>
                  {c.passed ? "✓" : "✗"}
                </span>
                <div>
                  <span className={`font-medium ${c.passed ? "text-green-800" : "text-red-800"}`}>{c.label}</span>
                  <div className="text-gray-500 mt-0.5">{c.detail}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SBOM Quality Score */}
      {sbomQuality && (() => {
        const gradeColor = {A:"text-green-600",B:"text-blue-600",C:"text-yellow-600",D:"text-red-600"}[sbomQuality.grade] || "text-gray-600";
        const gradeBg   = {A:"bg-green-50 border-green-200",B:"bg-blue-50 border-blue-200",C:"bg-yellow-50 border-yellow-200",D:"bg-red-50 border-red-200"}[sbomQuality.grade] || "bg-gray-50 border-gray-200";
        return (
          <div className={`mb-4 rounded-lg border p-4 ${gradeBg}`}>
            <div className="flex items-center justify-between mb-3">
              <div>
                <span className="text-sm font-semibold text-gray-700">SBOM 品質評分</span>
                <span className="ml-2 text-xs text-gray-400">NTIA 最低要求（7 項）</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-gray-500">{sbomQuality.passed}/{sbomQuality.total} 通過</span>
                <span className={`text-2xl font-bold ${gradeColor}`}>{sbomQuality.grade}</span>
                <span className={`text-lg font-bold ${gradeColor}`}>{sbomQuality.score}%</span>
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
              {sbomQuality.checks.map((c) => (
                <div key={c.id} className="flex items-start gap-2 text-xs">
                  <span className={`mt-0.5 shrink-0 font-bold ${c.passed ? "text-green-500" : "text-red-400"}`}>
                    {c.passed ? "✓" : "✗"}
                  </span>
                  <div>
                    <span className={`font-medium ${c.passed ? "text-gray-700" : "text-gray-500"}`}>{c.label}</span>
                    <span className="ml-1 text-gray-400">{c.detail}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })()}

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
        {[
          { key: "components",    label: `元件 (${components.length})` },
          { key: "vulnerabilities", label: `漏洞 (${vulns.length})` },
          { key: "dependency",    label: "依賴關係圖" },
        ].map(({ key, label }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${
              tab === key ? "bg-blue-600 text-white" : "bg-white text-gray-600 hover:bg-gray-100"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Components table */}
      {tab === "components" && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          {components.length === 0 ? (
            <div className="p-8 text-center text-gray-400">尚未上傳 SBOM 檔案</div>
          ) : (
            <div className="overflow-x-auto">
            <table className="w-full text-sm min-w-[480px]">
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
                    <td className="px-4 py-3 font-medium text-gray-800 max-w-[120px] sm:max-w-xs truncate">{c.name}</td>
                    <td className="px-4 py-3 text-gray-500">{c.version || "—"}</td>
                    <td className="px-4 py-3 text-gray-500 text-xs">{c.license || "—"}</td>
                    <td className="px-4 py-3">{c.vuln_count || "—"}</td>
                    <td className="px-4 py-3">
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
            </div>
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
                  className="w-full sm:w-auto border rounded px-2 py-1 text-sm text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-400"
                >
                  <option value="">全部嚴重度</option>
                  {["critical","high","medium","low","info"].map((s) => (
                    <option key={s} value={s}>{s}{severityCounts[s] ? ` (${severityCounts[s]})` : ""}</option>
                  ))}
                </select>
                <select
                  value={filterStatus}
                  onChange={(e) => setFilterStatus(e.target.value)}
                  className="w-full sm:w-auto border rounded px-2 py-1 text-sm text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-400"
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
                {suppressedCount > 0 && (
                  <label className="flex items-center gap-1.5 text-sm text-gray-500 cursor-pointer select-none">
                    <input type="checkbox" checked={showSuppressed} onChange={(e) => setShowSuppressed(e.target.checked)} />
                    顯示已抑制 ({suppressedCount})
                  </label>
                )}
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
            <div className="overflow-x-auto relative">
              <p className="sm:hidden text-xs text-gray-400 px-3 pb-1">← 左右滑動查看全部</p>
            <table className="w-full text-sm min-w-[700px]">
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
                  <th className="px-4 py-3 cursor-pointer select-none hover:text-gray-700 hidden md:table-cell" onClick={() => { setSortField("cvss_score"); setSortAsc(sortField === "cvss_score" ? !sortAsc : false); }}>
                    CVSS {sortField === "cvss_score" ? (sortAsc ? "↑" : "↓") : ""}
                  </th>
                  <th className="px-4 py-3 cursor-pointer select-none hover:text-gray-700" onClick={() => { setSortField("severity"); setSortAsc(sortField === "severity" ? !sortAsc : false); }}>
                    嚴重度 {sortField === "severity" ? (sortAsc ? "↑" : "↓") : ""}
                  </th>
                  <th className="px-4 py-3 cursor-pointer select-none hover:text-gray-700 hidden sm:table-cell" onClick={() => { setSortField("epss_score"); setSortAsc(sortField === "epss_score" ? !sortAsc : false); }}>
                    EPSS {sortField === "epss_score" ? (sortAsc ? "↑" : "↓") : ""}
                  </th>
                  <th className="px-4 py-3 hidden lg:table-cell">SLA</th>
                  <th className="px-4 py-3">VEX 狀態</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {displayedVulns.map((v) => (
                  <React.Fragment key={v.id}>
                  <tr className={`border-t hover:bg-gray-50 ${selected.has(v.id) ? "bg-blue-50" : ""} ${v.suppressed ? "opacity-50" : ""}`}>
                    <td className="px-3 py-3">
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
                    <td className="px-4 py-3 font-mono text-xs">
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
                    <td className="px-4 py-3 text-gray-700">{v.component_name} {v.component_version}</td>
                    <td className="px-4 py-3 text-xs hidden md:table-cell">
                      {v.cvss_v4_score != null ? (
                        <span className="flex items-center gap-1">
                          <span className="font-medium text-gray-700">{v.cvss_v4_score}</span>
                          <span className="px-1 rounded font-bold bg-purple-100 text-purple-700" style={{fontSize:"9px"}}>v4</span>
                        </span>
                      ) : v.cvss_v3_score != null ? (
                        <span className="flex items-center gap-1">
                          <span className="font-medium text-gray-700">{v.cvss_v3_score}</span>
                          <span className="px-1 rounded font-bold bg-blue-100 text-blue-700" style={{fontSize:"9px"}}>v3</span>
                        </span>
                      ) : (
                        <span className="text-gray-600">{v.cvss_score ?? "—"}</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {v.severity && (
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_COLOR[v.severity]}`}>
                          {v.severity}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs hidden sm:table-cell">
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
                    <td className="px-4 py-3 hidden lg:table-cell">
                      {v.sla_status === "overdue" ? (
                        <span className="text-xs font-bold text-white bg-red-500 px-2 py-0.5 rounded-full">
                          逾 {Math.abs(v.sla_days)} 天
                        </span>
                      ) : v.sla_status === "warning" ? (
                        <span className="text-xs font-semibold text-orange-700 bg-orange-100 px-2 py-0.5 rounded-full">
                          剩 {v.sla_days} 天
                        </span>
                      ) : v.sla_status === "ok" ? (
                        <span className="text-xs text-gray-400">{v.sla_days} 天</span>
                      ) : (
                        <span className="text-gray-200">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${VEX_STATUS_COLOR[v.status] || DEFAULT_BADGE}`}>
                        {STATUS_LABEL[v.status] || v.status}
                      </span>
                      {v.justification && (
                        <div className="text-xs text-gray-400 mt-0.5">{v.justification}</div>
                      )}
                      {v.detail && (
                        <div className="text-xs text-gray-400 mt-0.5 italic truncate max-w-xs">{v.detail}</div>
                      )}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="flex gap-1">
                        {!v.suppressed && <VexEditButton vuln={v} onUpdate={fetchVulns} />}
                        <SuppressButton vuln={v} onUpdate={fetchVulns} />
                      </div>
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
            </div>
            </>
          )}
        </div>
      )}
      {/* Dependency graph tab */}
      {tab === "dependency" && (
        <div className="bg-white rounded-lg shadow p-4">
          {!depGraph ? (
            <SkeletonInline rows={5} />
          ) : !depGraph.has_data ? (
            <div className="py-8 text-center text-gray-400">
              <p className="text-base mb-2">此 SBOM 不含依賴關係資料</p>
              <p className="text-sm text-gray-300">CycloneDX 需包含 <code>dependencies[]</code> 區塊，SPDX 需包含 <code>relationships[]</code></p>
            </div>
          ) : (
            <DependencyGraph nodes={depGraph.nodes} edges={depGraph.edges}
              totalNodes={depGraph.total_nodes} totalEdges={depGraph.total_edges} />
          )}
        </div>
      )}

      {/* Floating batch action bar */}
      {selected.size > 0 && (
        <div className="fixed bottom-4 sm:bottom-6 left-1/2 -translate-x-1/2 bg-gray-900 text-white rounded-xl shadow-2xl px-3 sm:px-6 py-3 flex items-center gap-4 z-40">
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

function DependencyGraph({ nodes, edges, totalNodes, totalEdges }) {
  const [selected, setSelected] = useState(null);

  // Build adjacency + compute levels via BFS
  const children = {}, inDegree = {}, nodeMap = {};
  nodes.forEach(n => { children[n.id] = []; inDegree[n.id] = 0; nodeMap[n.id] = n; });
  edges.forEach(e => {
    if (children[e.source]) children[e.source].push(e.target);
    if (e.target in inDegree) inDegree[e.target]++;
  });

  const roots = nodes.filter(n => n.is_root || inDegree[n.id] === 0).map(n => n.id);
  if (roots.length === 0 && nodes.length > 0) roots.push(nodes[0].id);

  const level = {};
  const queue = [...roots.map(r => ({ id: r, lvl: 0 }))];
  const visited = new Set();
  while (queue.length) {
    const { id, lvl } = queue.shift();
    if (visited.has(id)) continue;
    visited.add(id);
    level[id] = lvl;
    (children[id] || []).forEach(c => { if (!visited.has(c)) queue.push({ id: c, lvl: lvl + 1 }); });
  }
  nodes.forEach(n => { if (!(n.id in level)) level[n.id] = 0; });

  const byLevel = {};
  nodes.forEach(n => { const l = level[n.id]; if (!byLevel[l]) byLevel[l] = []; byLevel[l].push(n.id); });
  const maxLevel = Math.max(...Object.keys(byLevel).map(Number), 0);
  const maxPerLevel = Math.max(...Object.values(byLevel).map(a => a.length), 1);

  const NW = 130, NH = 28, HGAP = 60, VGAP = 12;
  const colW = NW + HGAP, rowH = NH + VGAP;
  const W = (maxLevel + 1) * colW + 20;
  const H = maxPerLevel * rowH + 20;

  const pos = {};
  Object.entries(byLevel).forEach(([lvl, ids]) => {
    const x = parseInt(lvl) * colW + 10;
    const totalH = ids.length * rowH - VGAP;
    const startY = (H - totalH) / 2;
    ids.forEach((id, i) => { pos[id] = { x, y: startY + i * rowH }; });
  });

  const selNode = selected ? nodeMap[selected] : null;

  return (
    <div>
      <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
        <div className="flex gap-4 text-xs text-gray-500">
          <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-red-400 inline-block"/><span>有 Critical/High 漏洞</span></span>
          <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-blue-500 inline-block"/><span>根節點</span></span>
          <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-gray-300 inline-block"/><span>一般元件</span></span>
        </div>
        <span className="text-xs text-gray-400">{totalNodes} 個節點 · {totalEdges} 條依賴{totalNodes > 200 ? "（顯示前 200）" : ""}</span>
      </div>
      {selNode && (
        <div className="mb-3 px-3 py-2 bg-blue-50 border border-blue-200 rounded text-sm flex items-center justify-between">
          <span><span className="font-semibold text-blue-800">{selNode.name}</span>{selNode.version && <span className="ml-1.5 text-xs text-gray-500">{selNode.version}</span>}
            {selNode.has_vuln && <span className="ml-2 text-xs text-red-600 font-medium">⚠ 有未解決漏洞</span>}</span>
          <button onClick={() => setSelected(null)} className="text-gray-400 hover:text-gray-600 text-xs">關閉</button>
        </div>
      )}
      <div className="overflow-auto border rounded bg-gray-50" style={{ maxHeight: "480px" }}>
        <svg width={W} height={Math.max(H, 200)} style={{ display: "block" }}>
          {/* Edges */}
          {edges.map((e, i) => {
            const s = pos[e.source], t = pos[e.target];
            if (!s || !t) return null;
            const x1 = s.x + NW, y1 = s.y + NH / 2, x2 = t.x, y2 = t.y + NH / 2;
            const mx = (x1 + x2) / 2;
            return <path key={i} d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`}
              fill="none" stroke="#d1d5db" strokeWidth="1" />;
          })}
          {/* Nodes */}
          {nodes.map(n => {
            const p = pos[n.id];
            if (!p) return null;
            const isRoot = n.is_root;
            const hasVuln = n.has_vuln;
            const isSel = selected === n.id;
            const fill = hasVuln ? "#fca5a5" : isRoot ? "#93c5fd" : "#e5e7eb";
            const stroke = isSel ? "#1d4ed8" : hasVuln ? "#ef4444" : isRoot ? "#3b82f6" : "#9ca3af";
            const label = n.name.length > 16 ? n.name.slice(0, 15) + "…" : n.name;
            return (
              <g key={n.id} onClick={() => setSelected(isSel ? null : n.id)} style={{ cursor: "pointer" }}>
                <rect x={p.x} y={p.y} width={NW} height={NH} rx={4}
                  fill={fill} stroke={stroke} strokeWidth={isSel ? 2 : 1} />
                <text x={p.x + NW / 2} y={p.y + NH / 2 + 1} textAnchor="middle" dominantBaseline="middle"
                  fontSize="9.5" fill={hasVuln ? "#7f1d1d" : isRoot ? "#1e3a8a" : "#374151"} fontWeight={isRoot ? "600" : "400"}>
                  {label}
                </text>
                {n.version && (
                  <text x={p.x + NW / 2} y={p.y + NH - 4} textAnchor="middle"
                    fontSize="7.5" fill="#9ca3af">{n.version.length > 12 ? n.version.slice(0,11)+"…" : n.version}</text>
                )}
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

function SuppressButton({ vuln, onUpdate }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className={`px-2 py-1 text-xs rounded border ${vuln.suppressed ? "border-amber-400 text-amber-700 bg-amber-50 hover:bg-amber-100" : "border-gray-300 text-gray-500 hover:bg-gray-50"}`}
        title={vuln.suppressed ? "管理抑制" : "抑制此漏洞（風險接受）"}
      >
        {vuln.suppressed ? "已抑制" : "抑制"}
      </button>
      {open && <SuppressModal vuln={vuln} onClose={() => setOpen(false)} onUpdate={onUpdate} />}
    </>
  );
}

function SuppressModal({ vuln, onClose, onUpdate }) {
  const [suppressing, setSuppressing] = useState(!vuln.suppressed);
  const [until, setUntil] = useState(vuln.suppressed_until ? vuln.suppressed_until.slice(0, 10) : "");
  const [reason, setReason] = useState(vuln.suppressed_reason || "");
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.patch(`/vulnerabilities/${vuln.id}/suppress`, {
        suppressed: suppressing,
        suppressed_until: suppressing && until ? until : null,
        suppressed_reason: suppressing && reason ? reason : null,
      });
      onUpdate();
      onClose();
    } catch (e) {
      toast.error(e.response?.data?.detail || "操作失敗");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-md mx-2 sm:mx-auto" onClick={(e) => e.stopPropagation()}>
        <h3 className="font-semibold text-gray-800 mb-1">漏洞抑制（風險接受）</h3>
        <p className="text-xs text-gray-400 mb-4 font-mono">{vuln.cve_id} — {vuln.component_name} {vuln.component_version}</p>

        <div className="space-y-4">
          <div className="flex gap-3">
            <button
              onClick={() => setSuppressing(true)}
              className={`flex-1 py-2 rounded text-sm font-medium border transition-colors ${suppressing ? "bg-amber-500 text-white border-amber-500" : "border-gray-300 text-gray-600 hover:bg-gray-50"}`}
            >
              抑制此漏洞
            </button>
            <button
              onClick={() => setSuppressing(false)}
              className={`flex-1 py-2 rounded text-sm font-medium border transition-colors ${!suppressing ? "bg-blue-600 text-white border-blue-600" : "border-gray-300 text-gray-600 hover:bg-gray-50"}`}
            >
              解除抑制
            </button>
          </div>

          {suppressing && (
            <>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  抑制原因 <span className="text-gray-400 font-normal">(選填)</span>
                </label>
                <textarea
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  rows={3}
                  placeholder="例：已通過風險評估，此環境不受影響，待下季修補計畫處理..."
                  className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-amber-400 resize-none"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  有效期限 <span className="text-gray-400 font-normal">(選填，到期後自動回復)</span>
                </label>
                <input
                  type="date"
                  value={until}
                  onChange={(e) => setUntil(e.target.value)}
                  className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-amber-400"
                />
              </div>
              <p className="text-xs text-amber-700 bg-amber-50 rounded px-3 py-2">
                抑制後此漏洞不計入嚴重度統計與 SLA，但仍記錄在案以供稽核。
              </p>
            </>
          )}
        </div>

        <div className="flex justify-end gap-2 mt-5">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-600 border rounded hover:bg-gray-50">取消</button>
          <button
            onClick={handleSave}
            disabled={saving}
            className={`px-4 py-2 text-sm text-white rounded ${saving ? "bg-gray-400" : suppressing ? "bg-amber-500 hover:bg-amber-600" : "bg-blue-600 hover:bg-blue-700"}`}
          >
            {saving ? "儲存中..." : suppressing ? "確認抑制" : "解除抑制"}
          </button>
        </div>
      </div>
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
      toast.error("更新失敗");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-md mx-2 sm:mx-auto" onClick={(e) => e.stopPropagation()}>
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
