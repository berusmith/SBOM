import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import api from "../api/client";

export default function Releases() {
  const { productId } = useParams();
  const navigate = useNavigate();
  const [releases, setReleases] = useState([]);
  const [productName, setProductName] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [version, setVersion] = useState("");
  const [loading, setLoading] = useState(false);
  const [showDiff, setShowDiff] = useState(false);
  const [diffFrom, setDiffFrom] = useState("");
  const [diffTo, setDiffTo] = useState("");

  const fetchData = () => {
    api.get(`/products/${productId}/releases`).then((res) => {
      setReleases(res.data.releases || []);
      setProductName(res.data.product_name || "");
    }).catch(() => {});
  };

  useEffect(() => { fetchData(); }, [productId]);

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!version.trim()) return;
    setLoading(true);
    try {
      await api.post(`/products/${productId}/releases`, { version });
      setVersion("");
      setShowForm(false);
      fetchData();
    } catch (err) {
      alert("建立失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (r) => {
    if (!window.confirm(`確定要刪除版本「${r.version}」？此操作將同時刪除 SBOM 檔案及所有漏洞資料，無法還原。`)) return;
    try {
      await api.delete(`/releases/${r.id}`);
      fetchData();
    } catch (err) {
      alert("刪除失敗：" + (err.response?.data?.detail || err.message));
    }
  };

  return (
    <div>
      <div className="flex items-center gap-2 mb-1">
        <button onClick={() => navigate("/organizations")} className="text-blue-600 hover:underline text-sm">
          客戶管理
        </button>
        <span className="text-gray-400">/</span>
        <span className="text-sm text-gray-600">{productName || productId}</span>
      </div>

      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-800">版本列表</h1>
        <div className="flex gap-2">
          {releases.length >= 2 && (
            <button
              onClick={() => setShowDiff(!showDiff)}
              className="bg-indigo-600 text-white px-4 py-2 rounded hover:bg-indigo-700 text-sm"
            >
              版本比對
            </button>
          )}
          <button
            onClick={() => setShowForm(!showForm)}
            className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 text-sm"
          >
            + 新增版本
          </button>
        </div>
      </div>

      {showForm && (
        <form onSubmit={handleCreate} className="bg-white rounded-lg shadow p-4 mb-4 flex gap-3">
          <input
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            placeholder="版本號（如：v1.0.1）"
            className="border rounded px-3 py-2 flex-1 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
          />
          <button type="submit" disabled={loading}
            className="bg-blue-600 text-white px-4 py-2 rounded text-sm hover:bg-blue-700 disabled:opacity-50">
            {loading ? "建立中..." : "確認"}
          </button>
          <button type="button" onClick={() => setShowForm(false)}
            className="text-gray-500 px-4 py-2 rounded text-sm hover:bg-gray-100">
            取消
          </button>
        </form>
      )}

      {showDiff && (
        <div className="bg-white rounded-lg shadow p-4 mb-4">
          <p className="text-sm font-medium text-gray-700 mb-3">選擇要比對的兩個版本</p>
          <div className="flex gap-3 items-center flex-wrap">
            <select value={diffFrom} onChange={(e) => setDiffFrom(e.target.value)}
              className="border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400">
              <option value="">— 舊版本 —</option>
              {releases.map((r) => <option key={r.id} value={r.id}>{r.version}</option>)}
            </select>
            <span className="text-gray-400">→</span>
            <select value={diffTo} onChange={(e) => setDiffTo(e.target.value)}
              className="border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400">
              <option value="">— 新版本 —</option>
              {releases.map((r) => <option key={r.id} value={r.id}>{r.version}</option>)}
            </select>
            <button
              disabled={!diffFrom || !diffTo || diffFrom === diffTo}
              onClick={() => navigate(`/releases/diff?product=${productId}&from=${diffFrom}&to=${diffTo}`)}
              className="px-4 py-2 bg-indigo-600 text-white rounded text-sm hover:bg-indigo-700 disabled:opacity-40"
            >
              開始比對
            </button>
            <button onClick={() => setShowDiff(false)} className="text-sm text-gray-400 hover:text-gray-600">取消</button>
          </div>
        </div>
      )}

      <div className="bg-white rounded-lg shadow overflow-hidden">
        {releases.length === 0 ? (
          <div className="p-8 text-center text-gray-400">尚無版本，點擊「新增版本」開始</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-gray-500 text-left">
              <tr>
                <th className="px-4 py-3">版本號</th>
                <th className="px-4 py-3">建立時間</th>
                <th className="px-4 py-3">SBOM</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {releases.map((r) => (
                <tr key={r.id} className="border-t hover:bg-gray-50">
                  <td className="px-4 py-3 font-medium text-gray-800">{r.version}</td>
                  <td className="px-4 py-3 text-gray-500">
                    {new Date(r.created_at).toLocaleDateString("zh-TW")}
                  </td>
                  <td className="px-4 py-3">
                    {r.sbom_file_path ? (
                      <span className="text-green-600 text-xs">已上傳</span>
                    ) : (
                      <span className="text-gray-400 text-xs">未上傳</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right flex justify-end gap-3">
                    <button
                      onClick={() => navigate(`/releases/${r.id}`)}
                      className="text-blue-600 hover:underline text-xs"
                    >
                      詳細
                    </button>
                    <button
                      onClick={() => handleDelete(r)}
                      className="text-red-500 hover:underline text-xs"
                    >
                      刪除
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
