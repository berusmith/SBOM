import { useState, useEffect } from "react";
import { Upload, CheckCircle, AlertCircle, Clock } from "lucide-react";
import api from "../api/client";
import { useToast } from "../components/Toast";

export default function FirmwareUpload() {
  const toast = useToast();
  const [scans, setScans] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [expandedScan, setExpandedScan] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchScans = async () => {
    try {
      const res = await api.get("/api/firmware/scans");
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
      const res = await api.post("/api/firmware/upload", form, {
        headers: { "Content-Type": "multipart/form-data" }
      });
      toast.success(`韌體上傳成功: ${res.data.scan_id.slice(0, 8)}`);
      setSelectedFile(null);
      setAutoRefresh(true);
      fetchScans();
    } catch (err) {
      toast.error("上傳失敗: " + (err.response?.data?.detail || err.message));
    } finally {
      setUploading(false);
    }
  };

  const handleImportAsRelease = (scan) => {
    // TODO: Implement import as release functionality
    toast.info("功能開發中：將掃描結果匯入為版本");
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
              onChange={(e) => e.target.files[0] && setSelectedFile(e.target.files[0])}
            />
          </label>
          <button
            onClick={handleUpload}
            disabled={!selectedFile || uploading}
            className="px-4 py-2 bg-green-600 text-white rounded text-sm hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
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
    </div>
  );
}
