import { useEffect, useState } from "react";
import api from "../api/client";
import { PasswordInput } from "../components/PasswordInput";
import { ConfirmModal } from "../components/ConfirmModal";
import { formatDate } from "../utils/date";
import { validate, validators } from "../utils/validate";

export default function Users() {
  const [users, setUsers] = useState([]);
  const [orgs, setOrgs] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [editUser, setEditUser] = useState(null);
  const [form, setForm] = useState({ username: "", password: "", role: "viewer", organization_id: "" });
  const [editForm, setEditForm] = useState({ password: "", role: "viewer", is_active: true, organization_id: "" });
  const [errors, setErrors] = useState({});
  const [editErrors, setEditErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState(null);
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);

  const flash = (type, text) => { setMsg({ type, text }); setTimeout(() => setMsg(null), 4000); };

  const fetchAll = () => {
    api.get("/users").then(r => setUsers(r.data)).catch(() => {});
    api.get("/organizations").then(r => setOrgs(r.data)).catch(() => {});
  };

  useEffect(() => { fetchAll(); }, []);

  const orgName = (id) => orgs.find(o => o.id === id)?.name || "—";

  const handleCreate = async (e) => {
    e.preventDefault();

    // Validate username and password
    const validationErrors = validate(
      { username: validators.username, password: validators.password, organization_id: form.role === "viewer" ? validators.required : () => null },
      { username: form.username, password: form.password, organization_id: form.organization_id }
    );
    if (Object.values(validationErrors).some(e => e)) {
      setErrors(validationErrors);
      return;
    }

    setErrors({});
    setLoading(true);
    try {
      await api.post("/users", form);
      setShowForm(false);
      setForm({ username: "", password: "", role: "viewer", organization_id: "" });
      flash("success", `帳號 ${form.username} 已建立`);
      fetchAll();
    } catch (err) {
      flash("error", err.response?.data?.detail || "建立失敗");
    } finally { setLoading(false); }
  };

  const handleEdit = async (e) => {
    e.preventDefault();

    // Validate password if provided
    if (editForm.password) {
      const validationErrors = validate(
        { password: validators.password },
        { password: editForm.password }
      );
      if (Object.values(validationErrors).some(e => e)) {
        setEditErrors(validationErrors);
        return;
      }
    }

    setEditErrors({});
    try {
      const payload = { role: editForm.role, is_active: editForm.is_active, organization_id: editForm.organization_id || null };
      if (editForm.password) payload.password = editForm.password;
      await api.patch(`/users/${editUser.id}`, payload);
      setEditUser(null);
      flash("success", "已更新");
      fetchAll();
    } catch (err) {
      flash("error", err.response?.data?.detail || "更新失敗");
    }
  };

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await api.delete(`/users/${confirmDelete.id}`);
      flash("success", `帳號 ${confirmDelete.username} 已刪除`);
      setConfirmDelete(null);
      fetchAll();
    } catch (err) {
      flash("error", err.response?.data?.detail || "刪除失敗");
    } finally {
      setDeleting(false);
    }
  };

  const openEdit = (u) => {
    setEditUser(u);
    setEditForm({ password: "", role: u.role, is_active: u.is_active, organization_id: u.organization_id || "" });
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-800">使用者管理</h1>
        <button onClick={() => setShowForm(!showForm)}
          className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 text-sm">
          + 新增帳號
        </button>
      </div>

      {msg && (
        <div className={`mb-4 px-4 py-3 rounded text-sm ${msg.type === "success" ? "bg-green-50 text-green-700 border border-green-200" : "bg-red-50 text-red-700 border border-red-200"}`}>
          {msg.text}
        </div>
      )}

      {showForm && (
        <form onSubmit={handleCreate} className="bg-white rounded-lg shadow p-5 mb-5 space-y-3">
          <h2 className="font-semibold text-gray-700">新增帳號</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-gray-500 block mb-1">帳號名稱</label>
              <div>
                <input
                  value={form.username}
                  onChange={e => {
                    setForm({ ...form, username: e.target.value });
                    if (errors.username) setErrors(prev => ({...prev, username: null}));
                  }}
                  className={`border rounded px-3 py-2 w-full text-sm focus:outline-none focus:ring-2 ${
                    errors.username ? "border-red-400 focus:ring-red-400" : "border-gray-300 focus:ring-blue-400"
                  }`}
                />
                {errors.username && <p className="text-xs text-red-500 mt-1">{errors.username}</p>}
              </div>
            </div>
            <div>
              <label className="text-xs text-gray-500 block mb-1">初始密碼</label>
              <PasswordInput
                value={form.password}
                onChange={e => {
                  setForm({ ...form, password: e.target.value });
                  if (errors.password) setErrors(prev => ({...prev, password: null}));
                }}
                error={errors.password}
              />
            </div>
            <div>
              <label className="text-xs text-gray-500 block mb-1">角色</label>
              <select value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}
                className="border rounded px-3 py-2 w-full text-sm">
                <option value="viewer">客戶（viewer）</option>
                <option value="admin">管理員（admin）</option>
              </select>
            </div>
            {form.role === "viewer" && (
              <div>
                <label className="text-xs text-gray-500 block mb-1">綁定組織 *</label>
                <select value={form.organization_id} onChange={e => setForm({ ...form, organization_id: e.target.value })}
                  required className="border rounded px-3 py-2 w-full text-sm">
                  <option value="">選擇組織</option>
                  {orgs.map(o => <option key={o.id} value={o.id}>{o.name}</option>)}
                </select>
              </div>
            )}
          </div>
          <div className="flex gap-2 justify-end">
            <button type="button" onClick={() => setShowForm(false)}
              className="text-gray-500 px-4 py-2 rounded text-sm hover:bg-gray-100 border">取消</button>
            <button type="submit" disabled={loading}
              className="bg-blue-600 text-white px-4 py-2 rounded text-sm hover:bg-blue-700 disabled:opacity-50">
              {loading ? "建立中..." : "確認建立"}
            </button>
          </div>
        </form>
      )}

      {editUser && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <form onSubmit={handleEdit} className="bg-white rounded-lg shadow-xl p-6 w-full max-w-sm mx-4 space-y-3">
            <h2 className="text-lg font-semibold">編輯帳號：{editUser.username}</h2>
            <div>
              <label className="text-xs text-gray-500 block mb-1">新密碼（留空則不修改，至少 6 字元）</label>
              <PasswordInput
                value={editForm.password}
                onChange={e => {
                  setEditForm({ ...editForm, password: e.target.value });
                  if (editErrors.password) setEditErrors(prev => ({...prev, password: null}));
                }}
                error={editErrors.password}
              />
            </div>
            <div>
              <label className="text-xs text-gray-500 block mb-1">角色</label>
              <select value={editForm.role} onChange={e => setEditForm({ ...editForm, role: e.target.value })}
                className="border rounded px-3 py-2 w-full text-sm">
                <option value="viewer">客戶（viewer）</option>
                <option value="admin">管理員（admin）</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-gray-500 block mb-1">綁定組織</label>
              <select value={editForm.organization_id} onChange={e => setEditForm({ ...editForm, organization_id: e.target.value })}
                className="border rounded px-3 py-2 w-full text-sm">
                <option value="">— 不綁定 —</option>
                {orgs.map(o => <option key={o.id} value={o.id}>{o.name}</option>)}
              </select>
            </div>
            <label className="flex items-center gap-2 text-sm text-gray-600 cursor-pointer">
              <input type="checkbox" checked={editForm.is_active} onChange={e => setEditForm({ ...editForm, is_active: e.target.checked })} />
              帳號啟用中
            </label>
            <div className="flex gap-2 justify-end pt-1">
              <button type="button" onClick={() => setEditUser(null)}
                className="text-gray-500 px-4 py-2 rounded text-sm hover:bg-gray-100">取消</button>
              <button type="submit"
                className="bg-blue-600 text-white px-4 py-2 rounded text-sm hover:bg-blue-700">儲存</button>
            </div>
          </form>
        </div>
      )}

      <div className="bg-white rounded-lg shadow overflow-hidden">
        {users.length === 0 ? (
          <div className="p-8 text-center text-gray-400">尚無帳號</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm min-w-[520px]">
              <thead className="bg-gray-50 text-gray-500 text-left">
                <tr>
                  <th className="px-4 py-3">帳號</th>
                  <th className="px-4 py-3">角色</th>
                  <th className="px-4 py-3">綁定組織</th>
                  <th className="px-4 py-3">狀態</th>
                  <th className="px-4 py-3">建立時間</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id} className="border-t hover:bg-gray-50">
                    <td className="px-4 py-3 font-medium text-gray-800">{u.username}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${u.role === "admin" ? "bg-purple-100 text-purple-700" : "bg-blue-100 text-blue-700"}`}>
                        {u.role === "admin" ? "管理員" : "客戶"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-500">{orgName(u.organization_id)}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${u.is_active ? "bg-green-100 text-green-700" : "bg-gray-100 text-gray-500"}`}>
                        {u.is_active ? "啟用" : "停用"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-xs">
                      {formatDate(u.created_at)}
                    </td>
                    <td className="px-4 py-3 text-right flex justify-end gap-2">
                      <button onClick={() => openEdit(u)}
                        className="text-yellow-600 px-2 py-1 rounded hover:bg-gray-100 text-xs">編輯</button>
                      <button onClick={() => setConfirmDelete(u)}
                        className="text-red-500 px-2 py-1 rounded hover:bg-gray-100 text-xs">刪除</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <ConfirmModal
        isOpen={!!confirmDelete}
        title="確認刪除帳號"
        message={`確定刪除帳號「${confirmDelete?.username}」？`}
        confirmText="刪除"
        cancelText="取消"
        isDangerous
        onConfirm={handleDelete}
        onCancel={() => setConfirmDelete(null)}
      />
    </div>
  );
}
