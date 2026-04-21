import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/client";

export default function Organizations() {
  const [orgs, setOrgs] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [loading, setLoading] = useState(false);
  const [editOrg, setEditOrg] = useState(null);
  const [editName, setEditName] = useState("");
  const navigate = useNavigate();

  const fetchOrgs = () => {
    api.get("/organizations").then((res) => setOrgs(res.data)).catch(() => {});
  };

  useEffect(() => { fetchOrgs(); }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!name.trim()) return;
    setLoading(true);
    try {
      await api.post("/organizations", { name });
      setName("");
      setShowForm(false);
      fetchOrgs();
    } catch (err) {
      alert("建立失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = async (e) => {
    e.preventDefault();
    if (!editName.trim()) return;
    try {
      await api.patch(`/organizations/${editOrg.id}`, { name: editName });
      setEditOrg(null);
      fetchOrgs();
    } catch (err) {
      alert("更新失敗：" + (err.response?.data?.detail || err.message));
    }
  };

  const handleDelete = async (org) => {
    if (!window.confirm(`確定要刪除「${org.name}」？此操作將同時刪除所有產品、版本及漏洞資料，無法還原。`)) return;
    try {
      await api.delete(`/organizations/${org.id}`);
      fetchOrgs();
    } catch (err) {
      alert("刪除失敗：" + (err.response?.data?.detail || err.message));
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-800">客戶管理</h1>
        <button
          onClick={() => setShowForm(!showForm)}
          className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 text-sm"
        >
          + 新增客戶
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleCreate} className="bg-white rounded-lg shadow p-4 mb-4 flex flex-col sm:flex-row gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="客戶名稱（公司名）"
            className="border rounded px-3 py-2 flex-1 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
          />
          <div className="flex gap-2">
            <button
              type="submit"
              disabled={loading}
              className="flex-1 sm:flex-none bg-blue-600 text-white px-4 py-2 rounded text-sm hover:bg-blue-700 disabled:opacity-50"
            >
              {loading ? "建立中..." : "確認"}
            </button>
            <button
              type="button"
              onClick={() => setShowForm(false)}
              className="flex-1 sm:flex-none text-gray-500 px-4 py-2 rounded text-sm hover:bg-gray-100 border"
            >
              取消
            </button>
          </div>
        </form>
      )}

      {editOrg && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <form onSubmit={handleEdit} className="bg-white rounded-lg shadow-xl p-6 w-full max-w-sm mx-4">
            <h2 className="text-lg font-semibold mb-4">編輯客戶名稱</h2>
            <input
              value={editName}
              onChange={(e) => setEditName(e.target.value)}
              className="border rounded px-3 py-2 w-full text-sm focus:outline-none focus:ring-2 focus:ring-blue-400 mb-4"
              autoFocus
            />
            <div className="flex justify-end gap-2">
              <button type="button" onClick={() => setEditOrg(null)}
                className="text-gray-500 px-4 py-2 rounded text-sm hover:bg-gray-100">取消</button>
              <button type="submit"
                className="bg-blue-600 text-white px-4 py-2 rounded text-sm hover:bg-blue-700">儲存</button>
            </div>
          </form>
        </div>
      )}

      <div className="bg-white rounded-lg shadow overflow-hidden">
        {orgs.length === 0 ? (
          <div className="p-8 text-center text-gray-400">尚無客戶，點擊「新增客戶」開始</div>
        ) : (
          <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[400px]">
            <thead className="bg-gray-50 text-gray-500 text-left">
              <tr>
                <th className="px-4 py-3">客戶名稱</th>
                <th className="px-4 py-3">授權狀態</th>
                <th className="px-4 py-3">建立時間</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {orgs.map((org) => (
                <tr key={org.id} className="border-t hover:bg-gray-50">
                  <td className="px-4 py-3 font-medium text-gray-800">{org.name}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                      org.license_status === "active" ? "bg-green-100 text-green-700" :
                      org.license_status === "trial"  ? "bg-yellow-100 text-yellow-700" :
                      "bg-red-100 text-red-600"
                    }`}>
                      {org.license_status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-500">
                    {new Date(org.created_at).toLocaleDateString("zh-TW")}
                  </td>
                  <td className="px-4 py-3 text-right flex justify-end gap-3">
                    <button
                      onClick={() => navigate(`/organizations/${org.id}/products`)}
                      className="text-blue-600 hover:underline text-xs"
                    >
                      查看產品
                    </button>
                    <button
                      onClick={() => { setEditOrg(org); setEditName(org.name); }}
                      className="text-yellow-600 hover:underline text-xs"
                    >
                      編輯
                    </button>
                    <button
                      onClick={() => handleDelete(org)}
                      className="text-red-500 hover:underline text-xs"
                    >
                      刪除
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </div>
    </div>
  );
}
