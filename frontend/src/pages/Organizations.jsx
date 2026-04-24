import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { Check } from "lucide-react";
import api from "../api/client";
import { useToast } from "../components/Toast";
import { PasswordInput } from "../components/PasswordInput";
import { ConfirmModal } from "../components/ConfirmModal";
import { formatDate } from "../utils/date";
import { validate, validators } from "../utils/validate";
import { SkeletonTable } from "../components/Skeleton";

export default function Organizations() {
  const { t } = useTranslation();
  const toast = useToast();
  const [orgs, setOrgs] = useState([]);
  const [orgsLoading, setOrgsLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [created, setCreated] = useState(null);
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [editOrg, setEditOrg] = useState(null);
  const [editName, setEditName] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const [confirmPlan, setConfirmPlan] = useState(null); // {org, newPlan}
  const navigate = useNavigate();
  const isAdmin = localStorage.getItem("role") === "admin";

  const fetchOrgs = () => {
    setOrgsLoading(true);
    api.get("/organizations")
      .then((res) => setOrgs(res.data))
      .catch(() => toast.error("客戶清單載入失敗，請重新整理"))
      .finally(() => setOrgsLoading(false));
  };

  useEffect(() => { fetchOrgs(); }, []);

  const handleCreate = async (e) => {
    e.preventDefault();

    // Validate required name, and optional username/password if provided
    const rules = { name: validators.required };
    if (username.trim()) {
      rules.username = validators.username;
    }
    if (password) {
      rules.password = validators.password;
    }

    const validationErrors = validate(rules, { name, username, password });
    if (Object.values(validationErrors).some(e => e)) {
      setErrors(validationErrors);
      return;
    }

    setErrors({});
    setLoading(true);
    try {
      const res = await api.post("/organizations", {
        name,
        username: username.trim() || undefined,
        password: password || undefined,
      });
      setName(""); setUsername(""); setPassword("");
      setShowForm(false);
      setCreated(res.data);
      fetchOrgs();
    } catch (err) {
      toast.error("建立失敗：" + (err.response?.data?.detail || err.message));
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
      toast.error("更新失敗：" + (err.response?.data?.detail || err.message));
    }
  };

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await api.delete(`/organizations/${confirmDelete.id}`);
      setConfirmDelete(null);
      fetchOrgs();
    } catch (err) {
      toast.error("刪除失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-800">{t("organizations.title")}</h1>
        {isAdmin && (
          <button
            onClick={() => setShowForm(!showForm)}
            className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 text-sm"
          >
            + {t("organizations.add")}
          </button>
        )}
      </div>

      {created && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-4 text-sm text-green-800">
          <div className="font-semibold mb-1 flex items-center gap-2"><Check size={16} /> 客戶「{created.name}」已建立</div>
          {created.account_created ? (
            <div>
              登入帳號已建立：<span className="font-mono font-medium">{created.username}</span>
              　請將初始密碼告知客戶，登入後建議立即修改。
            </div>
          ) : (
            <div className="text-gray-500">未建立登入帳號（可稍後在使用者管理中新增）</div>
          )}
          <button onClick={() => setCreated(null)} className="mt-2 text-xs text-green-600 underline">關閉</button>
        </div>
      )}

      {showForm && (
        <form onSubmit={handleCreate} className="bg-white rounded-lg shadow p-4 mb-4 space-y-3">
          <div className="font-medium text-sm text-gray-700">{t("organizations.add")}</div>
          <div>
            <input
              value={name}
              onChange={(e) => {
                setName(e.target.value);
                if (errors.name) setErrors(prev => ({...prev, name: null}));
              }}
              placeholder="客戶名稱（公司名）*"
              className={`border rounded px-3 py-2 w-full text-sm focus:outline-none focus:ring-2 ${
                errors.name ? "border-red-400 focus:ring-red-400" : "border-gray-300 focus:ring-blue-400"
              }`}
            />
            {errors.name && <p className="text-xs text-red-500 mt-1">{errors.name}</p>}
          </div>
          <div className="border-t pt-3">
            <div className="text-xs text-gray-500 mb-2">登入帳號（選填，留空則不建立）</div>
            <div className="flex flex-col sm:flex-row gap-2">
              <div className="flex-1">
                <input
                  value={username}
                  onChange={(e) => {
                    setUsername(e.target.value);
                    if (errors.username) setErrors(prev => ({...prev, username: null}));
                  }}
                  placeholder="帳號（至少 3 字元）"
                  className={`w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 ${
                    errors.username ? "border-red-400 focus:ring-red-400" : "border-gray-300 focus:ring-blue-400"
                  }`}
                />
                {errors.username && <p className="text-xs text-red-500 mt-1">{errors.username}</p>}
              </div>
              <div className="flex-1">
                <PasswordInput
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (errors.password) setErrors(prev => ({...prev, password: null}));
                  }}
                  placeholder="初始密碼（至少 6 字元）"
                  error={errors.password}
                />
              </div>
            </div>
          </div>
          <div className="flex gap-2 justify-end">
            <button
              type="button"
              onClick={() => { setShowForm(false); setUsername(""); setPassword(""); }}
              className="text-gray-500 px-4 py-2 rounded text-sm hover:bg-gray-100 border"
            >
              {t("common.cancel")}
            </button>
            <button
              type="submit"
              disabled={loading}
              className="bg-blue-600 text-white px-4 py-2 rounded text-sm hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? t("common.creating") : t("common.confirmCreate")}
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

      {orgsLoading ? <SkeletonTable rows={4} cols={4} /> : null}
      <div className="bg-white rounded-lg shadow overflow-hidden" style={{ display: orgsLoading ? "none" : "" }}>
        {orgs.length === 0 ? (
          <div className="p-8 text-center text-gray-600">{t("organizations.noData")}</div>
        ) : (
          <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[280px]">
            <thead className="bg-gray-50 text-gray-500 text-left">
              <tr>
                <th className="px-4 py-3">{t("organizations.name")}</th>
                <th className="px-4 py-3 hidden sm:table-cell">授權狀態</th>
                <th className="px-4 py-3">方案</th>
                <th className="px-4 py-3 hidden md:table-cell">建立時間</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {orgs.map((org) => (
                <tr key={org.id} className="border-t hover:bg-gray-50">
                  <td className="px-4 py-3 font-medium text-gray-800">{org.name}</td>
                  <td className="px-4 py-3 hidden sm:table-cell">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                      org.license_status === "active" ? "bg-green-100 text-green-700" :
                      org.license_status === "trial"  ? "bg-yellow-100 text-yellow-700" :
                      "bg-red-100 text-red-600"
                    }`}>
                      {org.license_status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {isAdmin ? (
                      <select
                        value={org.plan || "starter"}
                        onChange={(e) => setConfirmPlan({ org, newPlan: e.target.value })}
                        className="border rounded px-2 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-blue-400"
                      >
                        <option value="starter">Starter</option>
                        <option value="standard">Standard</option>
                        <option value="professional">Professional</option>
                      </select>
                    ) : (
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        org.plan === "professional" ? "bg-purple-100 text-purple-700" :
                        org.plan === "standard"     ? "bg-blue-100 text-blue-700" :
                        "bg-gray-100 text-gray-600"
                      }`}>
                        {org.plan || "Starter"}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-gray-500 hidden md:table-cell">
                    {formatDate(org.created_at)}
                  </td>
                  <td className="px-4 py-3 text-right flex justify-end gap-3">
                    <button
                      onClick={() => navigate(`/organizations/${org.id}/products`)}
                      className="text-blue-600 px-3 py-2 rounded hover:bg-gray-100 text-xs"
                    >
                      {t("organizations.viewProducts")}
                    </button>
                    {isAdmin && (
                      <>
                        <button
                          onClick={() => { setEditOrg(org); setEditName(org.name); }}
                          className="text-yellow-600 px-3 py-2 rounded hover:bg-gray-100 text-xs"
                        >
                          {t("common.edit")}
                        </button>
                        <button
                          onClick={() => setConfirmDelete(org)}
                          className="text-red-500 px-3 py-2 rounded hover:bg-gray-100 text-xs"
                        >
                          {t("common.delete")}
                        </button>
                      </>
                    )}
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
        title={t("organizations.deleteTitle")}
        message={t("organizations.deleteMessage", { name: confirmDelete?.name })}
        confirmText={t("common.confirmDelete")}
        cancelText={t("common.cancel")}
        isDangerous
        requireTypeName={confirmDelete?.name}
        onConfirm={handleDelete}
        onCancel={() => setConfirmDelete(null)}
      />

      <ConfirmModal
        isOpen={!!confirmPlan}
        title="確認變更方案"
        message={`確定要將「${confirmPlan?.org?.name}」的方案從 ${confirmPlan?.org?.plan || 'starter'} 變更為 ${confirmPlan?.newPlan}？\n降級可能導致客戶無法存取部分功能。`}
        confirmText="確認變更"
        cancelText={t("common.cancel")}
        onConfirm={async () => {
          await api.patch(`/organizations/${confirmPlan.org.id}/plan`, { plan: confirmPlan.newPlan });
          setConfirmPlan(null);
          fetchOrgs();
        }}
        onCancel={() => setConfirmPlan(null)}
      />
    </div>
  );
}
