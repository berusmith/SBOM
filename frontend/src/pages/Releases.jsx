import { lazy, Suspense, useEffect, useState } from "react";
import { useParams, useNavigate, useLocation } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { Lock } from "lucide-react";
import api from "../api/client";
import { useToast } from "../components/Toast";
import { ConfirmModal } from "../components/ConfirmModal";
import { formatDate } from "../utils/date";
import { SkeletonInline } from "../components/Skeleton";

const TrendChart = lazy(() => import("../components/TrendChart"));

export default function Releases() {
  const { t } = useTranslation();
  const toast = useToast();
  const { productId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const { orgId, orgName } = location.state || {};
  const [releases, setReleases] = useState([]);
  const [productName, setProductName] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [version, setVersion] = useState("");
  const [loading, setLoading] = useState(false);
  const [showDiff, setShowDiff] = useState(false);
  const [diffFrom, setDiffFrom] = useState("");
  const [diffTo, setDiffTo] = useState("");
  const [trendData, setTrendData] = useState([]);
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const [showTrend, setShowTrend] = useState(false);
  const [editRelease, setEditRelease] = useState(null);
  const [editVersion, setEditVersion] = useState("");
  const [editSaving, setEditSaving] = useState(false);

  const fetchData = () => {
    api.get(`/products/${productId}/releases`).then((res) => {
      setReleases(res.data.releases || []);
      setProductName(res.data.product_name || "");
    }).catch(() => {});
    api.get(`/products/${productId}/vuln-trend`).then((res) => setTrendData(res.data)).catch(() => {});
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
      toast.error("建立失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await api.delete(`/releases/${confirmDelete.id}`);
      setConfirmDelete(null);
      fetchData();
    } catch (err) {
      toast.error("刪除失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setDeleting(false);
    }
  };

  const handleEditVersion = async (e) => {
    e.preventDefault();
    if (!editVersion.trim()) return;
    setEditSaving(true);
    try {
      await api.patch(`/releases/${editRelease.id}/version`, { version: editVersion.trim() });
      setEditRelease(null);
      toast.success("版本號已更新");
      fetchData();
    } catch (err) {
      toast.error("更新失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setEditSaving(false);
    }
  };

  return (
    <div>
      <div className="flex items-center gap-2 mb-1 flex-wrap">
        <button onClick={() => navigate("/organizations")} className="text-blue-600 hover:underline text-sm">
          客戶管理
        </button>
        {orgId && orgName && (
          <>
            <span className="text-gray-600">/</span>
            <button onClick={() => navigate(`/organizations/${orgId}/products`, { state: { orgId, orgName } })} className="text-blue-600 hover:underline text-sm">
              {orgName}
            </button>
          </>
        )}
        <span className="text-gray-600">/</span>
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
              {t("common.releaseDiff")}
            </button>
          )}
          <button
            onClick={() => setShowForm(!showForm)}
            className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 text-sm"
          >
            + {t("releases.add")}
          </button>
        </div>
      </div>

      {showForm && (
        <form onSubmit={handleCreate} className="bg-white rounded-lg shadow p-4 mb-4 flex flex-col sm:flex-row gap-2">
          <input
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            placeholder="版本號（如：v1.0.1）"
            className="border rounded px-3 py-2 flex-1 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
          />
          <div className="flex gap-2">
            <button type="submit" disabled={loading}
              className="flex-1 sm:flex-none bg-blue-600 text-white px-4 py-2 rounded text-sm hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed">
              {loading ? t("common.creating") : t("common.confirm")}
            </button>
            <button type="button" onClick={() => setShowForm(false)}
              className="flex-1 sm:flex-none text-gray-500 px-4 py-2 rounded text-sm hover:bg-gray-100 border">
              {t("common.cancel")}
            </button>
          </div>
        </form>
      )}

      {trendData.filter(d => d.total > 0).length >= 2 && (
        <>
          {!showTrend ? (
            <button
              onClick={() => setShowTrend(true)}
              className="bg-white border border-gray-200 rounded-lg px-4 py-3 text-sm text-blue-600 hover:bg-blue-50 mb-4"
            >
              {t("common.showTrend")}
            </button>
          ) : (
            <Suspense fallback={<SkeletonInline rows={5} />}>
              <TrendChart data={trendData} />
            </Suspense>
          )}
        </>
      )}

      {showDiff && (
        <div className="bg-white rounded-lg shadow p-4 mb-4">
          <p className="text-sm font-medium text-gray-700 mb-3">選擇要比對的兩個版本</p>
          <div className="flex gap-3 items-center flex-wrap">
            <select value={diffFrom} onChange={(e) => setDiffFrom(e.target.value)}
              className="border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400">
              <option value="">— 舊版本 —</option>
              {releases.map((r) => <option key={r.id} value={r.id}>{r.version}</option>)}
            </select>
            <span className="text-gray-600">→</span>
            <select value={diffTo} onChange={(e) => setDiffTo(e.target.value)}
              className="border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400">
              <option value="">— 新版本 —</option>
              {releases.map((r) => <option key={r.id} value={r.id}>{r.version}</option>)}
            </select>
            <button
              disabled={!diffFrom || !diffTo || diffFrom === diffTo}
              onClick={() => navigate(`/releases/diff?product=${productId}&from=${diffFrom}&to=${diffTo}`, { state: { orgId, orgName, productId, productName } })}
              className="px-4 py-2 bg-indigo-600 text-white rounded text-sm hover:bg-indigo-700 disabled:opacity-40"
            >
              開始比對
            </button>
            <button onClick={() => setShowDiff(false)} className="text-sm text-gray-600 hover:text-gray-600">取消</button>
          </div>
        </div>
      )}

      <div className="bg-white rounded-lg shadow overflow-hidden">
        {releases.length === 0 ? (
          <div className="p-8 text-center text-gray-600">{t("releases.noData")}</div>
        ) : (
          <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[280px]" role="table">
            <caption className="sr-only">版本列表</caption>
            <thead className="bg-gray-50 text-gray-500 text-left">
              <tr>
                <th className="px-4 py-3" scope="col">{t("releases.version")}</th>
                <th className="px-4 py-3 hidden sm:table-cell" scope="col">{t("common.createdAt")}</th>
                <th className="px-4 py-3 hidden sm:table-cell" scope="col">SBOM</th>
                <th className="px-4 py-3" scope="col">漏洞</th>
                <th className="px-4 py-3" scope="col">操作</th>
              </tr>
            </thead>
            <tbody>
              {releases.map((r) => (
                <tr key={r.id} className="border-t hover:bg-gray-50">
                  <td className="px-4 py-3 font-medium text-gray-800">
                    {r.version}
                    {r.locked && <Lock size={14} className="inline ml-1.5 text-gray-600" />}
                  </td>
                  <td className="px-4 py-3 text-gray-500 hidden sm:table-cell">
                    {formatDate(r.created_at)}
                  </td>
                  <td className="px-4 py-3 hidden sm:table-cell">
                    {r.has_sbom ? (
                      <span className="text-green-600 text-xs">已上傳</span>
                    ) : (
                      <span className="text-gray-600 text-xs">未上傳</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {r.vuln_total > 0 ? (
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {r.vuln_critical > 0 && (
                          <span className="px-1.5 py-0.5 rounded text-xs font-bold bg-red-100 text-red-700">C:{r.vuln_critical}</span>
                        )}
                        {r.vuln_high > 0 && (
                          <span className="px-1.5 py-0.5 rounded text-xs font-bold bg-orange-100 text-orange-700">H:{r.vuln_high}</span>
                        )}
                        <span className="text-xs text-gray-600">共{r.vuln_total}</span>
                      </div>
                    ) : (
                      <span className="text-xs text-gray-300">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right flex justify-end gap-2">
                    <button
                      onClick={() => navigate(`/releases/${r.id}`, { state: { orgId, orgName, productId, productName, version: r.version } })}
                      className="text-blue-600 px-3 py-2 rounded hover:bg-gray-100 text-xs"
                    >
                      {t("common.detail")}
                    </button>
                    {!r.locked && (
                      <button
                        onClick={() => { setEditRelease(r); setEditVersion(r.version); }}
                        className="text-yellow-600 px-3 py-2 rounded hover:bg-gray-100 text-xs"
                      >
                        {t("common.edit")}
                      </button>
                    )}
                    <button
                      onClick={() => setConfirmDelete(r)}
                      className="text-red-500 px-3 py-2 rounded hover:bg-gray-100 text-xs"
                    >
                      {t("common.delete")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </div>

      {/* Edit version modal */}
      {editRelease && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 px-4">
          <form onSubmit={handleEditVersion} className="bg-white rounded-xl shadow-xl p-6 w-full max-w-sm space-y-4">
            <h3 className="font-semibold text-gray-800">修改版本號</h3>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">版本號</label>
              <input value={editVersion} onChange={(e) => setEditVersion(e.target.value)} required autoFocus
                className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400" />
            </div>
            <div className="flex gap-2 justify-end">
              <button type="button" onClick={() => setEditRelease(null)}
                className="px-4 py-2 text-sm border rounded text-gray-600 hover:bg-gray-100">{t("common.cancel")}</button>
              <button type="submit" disabled={editSaving}
                className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50">
                {editSaving ? "儲存中..." : "儲存"}
              </button>
            </div>
          </form>
        </div>
      )}

      <ConfirmModal
        isOpen={!!confirmDelete}
        title={t("releases.deleteTitle")}
        message={t("releases.deleteMessage", { version: confirmDelete?.version })}
        confirmText={t("common.confirmDelete")}
        cancelText={t("common.cancel")}
        isDangerous
        onConfirm={handleDelete}
        onCancel={() => setConfirmDelete(null)}
      />
    </div>
  );
}
