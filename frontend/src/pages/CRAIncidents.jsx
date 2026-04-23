import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import api from "../api/client";
import { CRA_STATUS_COLOR, DEFAULT_BADGE } from "../constants/colors";
import { useToast } from "../components/Toast";
import { SkeletonTable } from "../components/Skeleton";
import { ConfirmModal } from "../components/ConfirmModal";
import { formatDateTime } from "../utils/date";

function Countdown({ seconds, label }) {
  if (seconds === null || seconds === undefined) return null;
  if (seconds === 0) return <span className="text-xs text-red-600 font-bold flex items-center gap-1"><AlertTriangle size={12} /> {label} 已逾時</span>;

  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const urgent = seconds < 6 * 3600;
  return (
    <span className={`text-xs font-mono ${urgent ? "text-red-600 font-bold" : "text-gray-500"}`}>
      {label} 剩 {h}h {m}m
    </span>
  );
}

export default function CRAIncidents() {
  const toast = useToast();
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const navigate = useNavigate();

  const fetchIncidents = () => {
    api.get("/cra/incidents")
      .then((r) => setIncidents(r.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await api.delete(`/cra/incidents/${confirmDelete.id}`);
      setConfirmDelete(null);
      fetchIncidents();
    } catch (err) {
      toast.error("刪除失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setDeleting(false);
    }
  };

  useEffect(() => { fetchIncidents(); }, []);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-800">CRA 事件管理</h1>
        <button
          onClick={() => setShowForm(true)}
          className="px-4 py-2 bg-red-600 text-white text-sm rounded hover:bg-red-700"
        >
          + 新增事件
        </button>
      </div>

      {showForm && (
        <CreateForm
          onClose={() => setShowForm(false)}
          onCreated={() => { setShowForm(false); fetchIncidents(); }}
        />
      )}

      {loading ? (
        <SkeletonTable rows={5} cols={5} />
      ) : incidents.length === 0 ? (
        <div className="bg-white rounded-lg shadow p-10 text-center text-gray-600">
          <p className="text-lg mb-1">尚無 CRA 事件</p>
          <p className="text-sm">偵測到主動被利用漏洞時，在此建立事件並追蹤 24/72/14 通報時限。</p>
        </div>
      ) : (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[600px]">
            <thead className="bg-gray-50 text-gray-500 text-left">
              <tr>
                <th className="px-4 py-3">事件標題</th>
                <th className="px-4 py-3 hidden sm:table-cell">觸發 CVE</th>
                <th className="px-4 py-3">狀態</th>
                <th className="px-4 py-3">時限</th>
                <th className="px-4 py-3">建立時間</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((inc) => (
                <tr
                  key={inc.id}
                  className="border-t hover:bg-gray-50 cursor-pointer"
                  onClick={() => navigate(`/cra/${inc.id}`)}
                >
                  <td className="px-4 py-3 font-medium text-gray-800 max-w-[150px] sm:max-w-xs truncate">{inc.title}</td>
                  <td className="px-4 py-3 font-mono text-xs text-blue-700 hidden sm:table-cell">
                    {inc.trigger_cve_ids || "—"}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${CRA_STATUS_COLOR[inc.status] || DEFAULT_BADGE}`}>
                      {inc.status_label}
                    </span>
                  </td>
                  <td className="px-4 py-3 space-y-0.5">
                    {inc.status === "clock_running" && (
                      <Countdown seconds={inc.t24_remaining_seconds} label="T+24h" />
                    )}
                    {["t24_submitted", "investigating"].includes(inc.status) && (
                      <Countdown seconds={inc.t72_remaining_seconds} label="T+72h" />
                    )}
                    {["t72_submitted", "remediating"].includes(inc.status) && (
                      <Countdown seconds={inc.t14d_remaining_seconds} label="T+14d" />
                    )}
                    {!["clock_running","t24_submitted","investigating","t72_submitted","remediating"].includes(inc.status) && (
                      <span className="text-xs text-gray-600">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-gray-600 text-xs">
                    {formatDateTime(inc.created_at)}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={(e) => { e.stopPropagation(); setConfirmDelete(inc); }}
                      className="text-red-500 px-2 py-1 rounded hover:bg-gray-100 text-xs"
                    >
                      刪除
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </div>
      )}
    </div>
  );
}

function CreateForm({ onClose, onCreated }) {
  const [title, setTitle] = useState("");
  const [cveIds, setCveIds] = useState("");
  const [description, setDescription] = useState("");
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!title.trim()) return;
    setSaving(true);
    try {
      await api.post("/cra/incidents", {
        title: title.trim(),
        trigger_cve_ids: cveIds.trim() || null,
        description: description.trim() || null,
        trigger_source: "manual",
      });
      onCreated();
    } catch (err) {
      toast.error("建立失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-md" onClick={(e) => e.stopPropagation()}>
        <h2 className="font-semibold text-gray-800 mb-4">新增 CRA 事件</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">事件標題 <span className="text-red-500">*</span></label>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="例：Log4Shell 影響評估"
              className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">觸發 CVE <span className="text-gray-600 font-normal">(逗號分隔)</span></label>
            <input
              value={cveIds}
              onChange={(e) => setCveIds(e.target.value)}
              placeholder="CVE-2021-44228,CVE-2021-45046"
              className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">說明 <span className="text-gray-600 font-normal">(選填)</span></label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400 resize-none"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button type="button" onClick={onClose} className="px-4 py-2 text-sm text-gray-600 border rounded hover:bg-gray-50">取消</button>
            <button
              type="submit"
              disabled={saving || !title.trim()}
              className={`px-4 py-2 text-sm text-white rounded ${saving || !title.trim() ? "bg-gray-400" : "bg-red-600 hover:bg-red-700"}`}
            >
              {saving ? "建立中..." : "建立"}
            </button>
          </div>
        </form>
      </div>

      <ConfirmModal
        isOpen={!!confirmDelete}
        title="確認刪除事件"
        message={`確定要刪除事件「${confirmDelete?.title}」？此操作無法還原。`}
        confirmText="刪除"
        cancelText="取消"
        isDangerous
        onConfirm={handleDelete}
        onCancel={() => setConfirmDelete(null)}
      />
    </div>
  );
}
