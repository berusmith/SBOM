import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import api from "../api/client";

export default function Products() {
  const { orgId } = useParams();
  const navigate = useNavigate();
  const [products, setProducts] = useState([]);
  const [orgName, setOrgName] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: "", description: "" });
  const [loading, setLoading] = useState(false);

  const fetchData = () => {
    api.get("/organizations").then((res) => {
      const org = res.data.find((o) => o.id === orgId);
      if (org) setOrgName(org.name);
    });
    api.get(`/organizations/${orgId}/products`).then((res) => setProducts(res.data)).catch(() => {});
  };

  useEffect(() => { fetchData(); }, [orgId]);

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!form.name.trim()) return;
    setLoading(true);
    try {
      await api.post(`/organizations/${orgId}/products`, form);
      setForm({ name: "", description: "" });
      setShowForm(false);
      fetchData();
    } catch (err) {
      alert("建立失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (p) => {
    if (!window.confirm(`確定要刪除產品「${p.name}」？此操作將同時刪除所有版本及漏洞資料，無法還原。`)) return;
    try {
      await api.delete(`/products/${p.id}`);
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
        <span className="text-sm text-gray-600">{orgName}</span>
      </div>

      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-800">產品列表</h1>
        <button
          onClick={() => setShowForm(!showForm)}
          className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 text-sm"
        >
          + 新增產品
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleCreate} className="bg-white rounded-lg shadow p-4 mb-4 flex flex-col gap-3">
          <input
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            placeholder="產品名稱（如：工業閘道器 A1）"
            className="border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
          />
          <input
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            placeholder="產品描述（選填）"
            className="border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
          />
          <div className="flex gap-2">
            <button type="submit" disabled={loading}
              className="bg-blue-600 text-white px-4 py-2 rounded text-sm hover:bg-blue-700 disabled:opacity-50">
              {loading ? "建立中..." : "確認"}
            </button>
            <button type="button" onClick={() => setShowForm(false)}
              className="text-gray-500 px-4 py-2 rounded text-sm hover:bg-gray-100">
              取消
            </button>
          </div>
        </form>
      )}

      <div className="bg-white rounded-lg shadow overflow-hidden">
        {products.length === 0 ? (
          <div className="p-8 text-center text-gray-400">尚無產品，點擊「新增產品」開始</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-gray-500 text-left">
              <tr>
                <th className="px-4 py-3">產品名稱</th>
                <th className="px-4 py-3">描述</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {products.map((p) => (
                <tr key={p.id} className="border-t hover:bg-gray-50">
                  <td className="px-4 py-3 font-medium text-gray-800">{p.name}</td>
                  <td className="px-4 py-3 text-gray-500">{p.description || "—"}</td>
                  <td className="px-4 py-3 text-right flex justify-end gap-3">
                    <button
                      onClick={() => navigate(`/products/${p.id}/releases`)}
                      className="text-blue-600 hover:underline text-xs"
                    >
                      查看版本
                    </button>
                    <button
                      onClick={() => handleDelete(p)}
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
