import { useState, useEffect } from "react";
import { Upload, CheckCircle, AlertCircle, Clock } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import api from "../api/client";
import { useToast } from "../components/Toast";
import { Modal } from "../components/Modal";
import { formatApiError } from "../utils/errors";

export default function FirmwareUpload() {
  const { t } = useTranslation();
  const toast = useToast();
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [expandedScan, setExpandedScan] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [importModalOpen, setImportModalOpen] = useState(false);
  const [importingScan, setImportingScan] = useState(null);
  const [importData, setImportData] = useState({ org: "", product: "", version: "" });
  const [organizations, setOrganizations] = useState([]);
  const [products, setProducts] = useState([]);
  const [importLoading, setImportLoading] = useState(false);

  const fetchScans = async () => {
    try {
      const res = await api.get("/firmware/scans");
      setScans(res.data);
    } catch (err) {
      console.error("Failed to fetch scans:", err);
    }
  };

  // Auto-refresh scans every 3 seconds if there are running scans
  useEffect(() => {
    fetchScans();
    const hasRunning = scans.some(s => s.status === "running" || s.status === "pending");
    if (!hasRunning) setAutoRefresh(false);

    if (autoRefresh) {
      const interval = setInterval(fetchScans, 3000);
      return () => clearInterval(interval);
    }
  }, [autoRefresh, scans]);

  const handleDrop = (e) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file && (file.name.endsWith(".bin") || file.name.endsWith(".img") || file.name.endsWith(".zip"))) {
      setSelectedFile(file);
    } else {
      toast.error("請上傳 .bin, .img 或 .zip 檔案");
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;
    setUploading(true);
    try {
      const form = new FormData();
      form.append("file", selectedFile);
      const res = await api.post("/firmware/upload", form, {
        headers: { "Content-Type": "multipart/form-data" }
      });
      toast.success(`韌體上傳成功: ${res.data.scan_id.slice(0, 8)}`);
      setSelectedFile(null);
      setAutoRefresh(true);
      fetchScans();
    } catch (err) {
      toast.error(formatApiError(err, t("errors.uploadFailed")));
    } finally {
      setUploading(false);
    }
  };

  const handleImportAsRelease = async (scan) => {
    setImportingScan(scan);
    setImportData({
      org: "",
      product: "",
      version: scan.filename.replace(/\.[^/.]+$/, "") || "v1.0.0"
    });

    // Fetch organizations
    try {
      const orgs = await api.get("/organizations");
      setOrganizations(orgs.data || []);
    } catch (err) {
      toast.error(t("errors.cantLoad", { what: t("nav.customers") }));
    }

    setImportModalOpen(true);
  };

  const handleOrgChange = async (orgId) => {
    setImportData({ ...importData, org: orgId, product: "" });

    if (!orgId) {
      setProducts([]);
      return;
    }

    try {
      const prods = await api.get(`/organizations/${orgId}/products`);
      setProducts(prods.data || []);
    } catch (err) {
      toast.error(t("errors.cantLoad", { what: t("products.title") }));
    }
  };

  const handleImportConfirm = async () => {
    if (!importingScan || !importData.org || !importData.product || !importData.version) {
      toast.error("請填寫所有欄位");
      return;
    }

    setImportLoading(true);
    try {
      const result = await api.post(
        `/firmware/scans/${importingScan.id}/import-as-release`,
        {
          product_id: importData.product,
          version: importData.version,
          org_id: importData.org
        }
      );

      toast.success(`版本建立成功: ${result.data.version} (${result.data.component_count} 個元件)`);
      setImportModalOpen(false);

      // Navigate to new release
      const org = organizations.find(o => o.id === importData.org);
      const product = products.find(p => p.id === importData.product);

      navigate(`/releases/${result.data.release_id}`, {
        state: {
          orgId: importData.org,
          orgName: org?.name,
          productId: importData.product,
          productName: product?.name,
          version: importData.version
        }
      });
    } catch (err) {
      toast.error(formatApiError(err, t("errors.importFailed")));
    } finally {
      setImportLoading(false);
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case "completed":
        return <span className="px-2 py-1 rounded text-xs font-medium bg-green-100 text-green-700">✓ 完成</span>;
      case "running":
        return <span className="px-2 py-1 rounded text-xs font-medium bg-blue-100 text-blue-700">⟳ 掃描中</span>;
      case "failed":
        return <span className="px-2 py-1 rounded text-xs font-medium bg-red-100 text-red-700">✕ 失敗</span>;
      default:
        return <span className="px-2 py-1 rounded text-xs font-medium bg-gray-100 text-gray-700">⏳ 等待中</span>;
    }
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-800">韌體掃描</h1>
        <p className="text-sm text-gray-600 mt-1">上傳韌體映像檔，自動生成 SBOM 元件清單</p>
      </div>

      {/* Upload Area */}
      <div
        onDrop={handleDrop}
        onDragOver={(e) => e.preventDefault()}
        className="bg-white rounded-lg shadow p-8 mb-6 border-2 border-dashed border-gray-300 hover:border-blue-400 transition-colors text-center cursor-pointer"
      >
        <Upload size={32} className="mx-auto text-gray-400 mb-3" />
        <h2 className="text-lg font-medium text-gray-800 mb-1">拖放韌體檔案或點擊選擇</h2>
        <p className="text-xs text-gray-500 mb-4">支援: .bin, .img, .zip (最大 500MB)</p>
        {selectedFile && (
          <div className="bg-blue-50 border border-blue-200 rounded p-3 mb-4">
            <p className="text-sm text-blue-800">已選擇: <strong>{selectedFile.name}</strong></p>
            <p className="text-xs text-blue-600">{(selectedFile.size / 1024 / 1024).toFixed(2)} MB</p>
          </div>
        )}
        <div className="flex gap-3 justify-center">
          <label className="px-4 py-2 bg-blue-600 text-white rounded text-sm hover:bg-blue-700 cursor-pointer">
            選擇檔案
            <input
              type="file"
              accept=".bin,.img,.zip"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files[0];
                if (f && (f.name.endsWith(".bin") || f.name.endsWith(".img") || f.name.endsWith(".zip"))) {
                  setSelectedFile(f);
                } else if (f) {
                  toast.error("請上傳 .bin, .img 或 .zip 檔案");
                }
              }}
            />
          </label>
          <button
            onClick={handleUpload}
            disabled={!selectedFile || uploading}
            className="px-4 py-2 bg-green-600 text-white rounded text-sm hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed disabled:cursor-not-allowed"
          >
            {uploading ? "上傳中..." : "開始上傳"}
          </button>
        </div>
      </div>

      {/* Scans List */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-800">掃描歷史</h2>
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`px-3 py-1 text-xs rounded ${
              autoRefresh ? "bg-blue-100 text-blue-700" : "bg-gray-100 text-gray-700"
            }`}
          >
            {autoRefresh ? "⟳ 自動更新" : "暫停"}
          </button>
        </div>

        {scans.length === 0 ? (
          <div className="p-8 text-center text-gray-400">
            <p>尚無掃描記錄</p>
          </div>
        ) : (
          <div className="divide-y">
            {scans.map((scan) => (
              <div key={scan.id} className="p-4 hover:bg-gray-50">
                <div
                  className="flex items-center justify-between cursor-pointer"
                  onClick={() => setExpandedScan(expandedScan === scan.id ? null : scan.id)}
                >
                  <div className="flex-1">
                    <p className="font-medium text-gray-800">{scan.filename}</p>
                    <div className="flex items-center gap-3 mt-1 flex-wrap">
                      {getStatusBadge(scan.status)}
                      {scan.status === "running" && <span className="text-xs text-gray-500">進度: {scan.progress}%</span>}
                      {scan.components_count > 0 && (
                        <span className="text-xs text-gray-500">找到 {scan.components_count} 個元件</span>
                      )}
                      <span className="text-xs text-gray-400">
                        {new Date(scan.created_at).toLocaleString("zh-TW")}
                      </span>
                    </div>
                    {scan.status === "running" && (
                      <div className="mt-2 w-full bg-gray-200 rounded-full h-2">
                        <div
                          className="bg-blue-600 h-2 rounded-full transition-all"
                          style={{ width: `${scan.progress}%` }}
                        />
                      </div>
                    )}
                  </div>
                  <div className="ml-4 text-gray-400">
                    {expandedScan === scan.id ? "▲" : "▼"}
                  </div>
                </div>

                {/* Expanded Details */}
                {expandedScan === scan.id && (
                  <div className="mt-4 pt-4 border-t border-gray-200">
                    {scan.status === "failed" && (
                      <div className="bg-red-50 border border-red-200 rounded p-3 mb-3">
                        <p className="text-sm text-red-800">
                          <strong>錯誤:</strong> {scan.error_message}
                        </p>
                      </div>
                    )}

                    {scan.components && scan.components.length > 0 && (
                      <div className="mb-3">
                        <h4 className="font-medium text-gray-700 mb-2">檢測到的元件 ({scan.components.length})</h4>
                        <div className="max-h-48 overflow-y-auto border border-gray-200 rounded">
                          <table className="w-full text-xs">
                            <thead className="bg-gray-50">
                              <tr>
                                <th className="px-3 py-2 text-left">名稱</th>
                                <th className="px-3 py-2 text-left">版本</th>
                                <th className="px-3 py-2 text-left">類型</th>
                              </tr>
                            </thead>
                            <tbody>
                              {scan.components.map((comp, i) => (
                                <tr key={i} className="border-t hover:bg-gray-50">
                                  <td className="px-3 py-2">{comp.name}</td>
                                  <td className="px-3 py-2">{comp.version || "—"}</td>
                                  <td className="px-3 py-2 text-gray-500">{comp.type || "—"}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    {scan.status === "completed" && (
                      <button
                        onClick={() => handleImportAsRelease(scan)}
                        className="px-4 py-2 bg-indigo-600 text-white rounded text-sm hover:bg-indigo-700"
                      >
                        匯入為版本
                      </button>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Import Modal */}
      <Modal isOpen={importModalOpen} title="匯入為版本" onClose={() => !importLoading && setImportModalOpen(false)}>
        <div className="space-y-4">
          {/* Organization Select */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">組織</label>
            <select
              value={importData.org}
              onChange={(e) => handleOrgChange(e.target.value)}
              disabled={importLoading}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-base focus:outline-none focus:ring-2 focus:ring-blue-400"
            >
              <option value="">選擇組織...</option>
              {organizations.map((org) => (
                <option key={org.id} value={org.id}>
                  {org.name}
                </option>
              ))}
            </select>
          </div>

          {/* Product Select */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">產品</label>
            <select
              value={importData.product}
              onChange={(e) => setImportData({ ...importData, product: e.target.value })}
              disabled={importLoading || !importData.org}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-base focus:outline-none focus:ring-2 focus:ring-blue-400 disabled:bg-gray-50 disabled:text-gray-500"
            >
              <option value="">選擇產品...</option>
              {products.map((product) => (
                <option key={product.id} value={product.id}>
                  {product.name}
                </option>
              ))}
            </select>
          </div>

          {/* Version Input */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">版本號</label>
            <input
              type="text"
              value={importData.version}
              onChange={(e) => setImportData({ ...importData, version: e.target.value })}
              disabled={importLoading}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-base focus:outline-none focus:ring-2 focus:ring-blue-400"
              placeholder="e.g., v1.0.0"
            />
          </div>

          {/* Component Count Info */}
          {importingScan?.components_count > 0 && (
            <div className="bg-blue-50 border border-blue-200 rounded p-3">
              <p className="text-sm text-blue-800">
                將匯入 <strong>{importingScan.components_count}</strong> 個檢測到的元件
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex flex-col-reverse sm:flex-row gap-2 sm:gap-3 mt-5">
          <button
            type="button"
            onClick={() => setImportModalOpen(false)}
            disabled={importLoading}
            className="flex-1 px-4 py-2.5 border border-gray-300 text-gray-700 rounded-lg text-sm hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-blue-400 focus:ring-offset-1"
          >
            取消
          </button>
          <button
            type="button"
            onClick={handleImportConfirm}
            disabled={importLoading || !importData.org || !importData.product || !importData.version}
            className="flex-1 px-4 py-2.5 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:ring-offset-1"
          >
            {importLoading ? "匯入中..." : "確認匯入"}
          </button>
        </div>
      </Modal>
    </div>
  );
}
