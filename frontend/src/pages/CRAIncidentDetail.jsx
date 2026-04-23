import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Check, AlertTriangle, Clock } from "lucide-react";
import api from "../api/client";
import { CRA_STATUS_COLOR, DEFAULT_BADGE } from "../constants/colors";
import { useToast } from "../components/Toast";
import { SkeletonDetail } from "../components/Skeleton";
import { ConfirmModal } from "../components/ConfirmModal";

const STATES = [
  "detected", "pending_triage", "clock_running", "t24_submitted",
  "investigating", "t72_submitted", "remediating", "final_submitted", "closed",
];

const STATE_LABEL = {
  detected:        "已偵測",
  pending_triage:  "等待分析",
  clock_running:   "時鐘進行中",
  t24_submitted:   "T+24h 已提交",
  investigating:   "調查中",
  t72_submitted:   "T+72h 已提交",
  remediating:     "修補中",
  final_submitted: "最終報告已提交",
  closed:          "已結案",
};

function useCountdown(seconds) {
  const [secs, setSecs] = useState(seconds);
  useEffect(() => {
    setSecs(seconds);
    if (!seconds || seconds <= 0) return;
    const t = setInterval(() => setSecs((s) => Math.max(0, s - 1)), 1000);
    return () => clearInterval(t);
  }, [seconds]);
  return secs;
}

function DeadlineBar({ label, seconds, submitted }) {
  const remaining = useCountdown(seconds);

  if (submitted) {
    return (
      <div className="flex items-center gap-3 py-3 border-b last:border-0">
        <div className="w-24 text-xs font-bold text-green-600">{label}</div>
        <div className="flex-1">
          <div className="h-2 rounded-full bg-green-200 overflow-hidden">
            <div className="h-full bg-green-500 w-full" />
          </div>
        </div>
        <div className="w-32 text-xs text-green-600 text-right font-medium flex items-center justify-end gap-1">
          <Check size={14} /> 已提交
        </div>
      </div>
    );
  }

  if (seconds === null || seconds === undefined) {
    return (
      <div className="flex items-center gap-3 py-3 border-b last:border-0 opacity-40">
        <div className="w-24 text-xs font-medium text-gray-500">{label}</div>
        <div className="flex-1">
          <div className="h-2 rounded-full bg-gray-100" />
        </div>
        <div className="w-32 text-xs text-gray-600 text-right">尚未開始</div>
      </div>
    );
  }

  const totalSecs = label === "T+24h" ? 86400 : label === "T+72h" ? 259200 : 1209600;
  const pct = Math.max(0, Math.min(100, (remaining / totalSecs) * 100));
  const urgent = remaining < 6 * 3600;
  const overdue = remaining === 0;
  const h = Math.floor(remaining / 3600);
  const m = Math.floor((remaining % 3600) / 60);
  const s = remaining % 60;

  return (
    <div className="flex items-center gap-3 py-3 border-b last:border-0">
      <div className={`w-24 text-xs font-bold ${urgent ? "text-red-600" : "text-gray-700"}`}>{label}</div>
      <div className="flex-1">
        <div className="h-2 rounded-full bg-gray-100 overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${overdue ? "bg-red-600 w-full" : urgent ? "bg-red-500" : "bg-blue-500"}`}
            style={{ width: `${100 - pct}%` }}
          />
        </div>
      </div>
      <div className={`w-32 text-xs font-mono text-right ${overdue ? "text-red-600 font-bold" : urgent ? "text-red-500 font-bold" : "text-gray-600"}`}>
        {overdue ? <span className="flex items-center justify-end gap-1"><AlertTriangle size={12} /> 已逾時</span> : `${h}h ${String(m).padStart(2,"0")}m ${String(s).padStart(2,"0")}s`}
      </div>
    </div>
  );
}

export default function CRAIncidentDetail() {
  const toast = useToast();
  const { incidentId } = useParams();
  const navigate = useNavigate();
  const [inc, setInc] = useState(null);
  const [loading, setLoading] = useState(true);
  const [confirmClose, setConfirmClose] = useState(false);
  const [closing, setClosing] = useState(false);

  const fetch = () => {
    api.get(`/cra/incidents/${incidentId}`)
      .then((r) => setInc(r.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetch(); }, [incidentId]);

  if (loading) return <div className="p-6"><SkeletonDetail sections={3} /></div>;
  if (!inc) return <div className="text-red-400 text-center mt-8">事件不存在</div>;

  const currentIdx = STATES.indexOf(inc.status);

  return (
    <div>
      <button onClick={() => navigate("/cra")} className="text-blue-600 hover:underline text-sm mb-4 block">
        ← 返回 CRA 事件列表
      </button>

      {/* Header */}
      <div className="bg-white rounded-lg shadow p-5 mb-4">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-gray-800 mb-1">{inc.title}</h1>
            {inc.trigger_cve_ids && (
              <div className="flex flex-wrap gap-1 mb-2">
                {inc.trigger_cve_ids.split(",").map((c) => (
                  <span key={c} className="font-mono text-xs bg-blue-50 text-blue-700 px-2 py-0.5 rounded">{c.trim()}</span>
                ))}
              </div>
            )}
            {inc.description && <p className="text-sm text-gray-500">{inc.description}</p>}
          </div>
          <span className={`px-3 py-1 rounded-full text-sm font-medium shrink-0 ${CRA_STATUS_COLOR[inc.status] || DEFAULT_BADGE}`}>
            {inc.status_label}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-4">

        {/* Timeline */}
        <div className="lg:col-span-2 bg-white rounded-lg shadow p-5">
          <h2 className="font-semibold text-gray-700 mb-4">CRA 時限追蹤</h2>
          <DeadlineBar
            label="T+24h"
            seconds={inc.t24_remaining_seconds}
            submitted={["t24_submitted","investigating","t72_submitted","remediating","final_submitted","closed"].includes(inc.status)}
          />
          <DeadlineBar
            label="T+72h"
            seconds={inc.t72_remaining_seconds}
            submitted={["t72_submitted","remediating","final_submitted","closed"].includes(inc.status)}
          />
          <DeadlineBar
            label="T+14d"
            seconds={inc.t14d_remaining_seconds}
            submitted={["final_submitted","closed"].includes(inc.status)}
          />

          {inc.enisa_ref_t24 && (
            <div className="mt-3 text-xs text-gray-500">ENISA T+24h Ref: <span className="font-mono">{inc.enisa_ref_t24}</span></div>
          )}
          {inc.enisa_ref_t72 && (
            <div className="text-xs text-gray-500">ENISA T+72h Ref: <span className="font-mono">{inc.enisa_ref_t72}</span></div>
          )}
          {inc.enisa_ref_final && (
            <div className="text-xs text-gray-500">ENISA Final Ref: <span className="font-mono">{inc.enisa_ref_final}</span></div>
          )}
        </div>

        {/* State progress */}
        <div className="bg-white rounded-lg shadow p-5">
          <h2 className="font-semibold text-gray-700 mb-4">處理進度</h2>
          <div className="space-y-1">
            {STATES.map((s, idx) => {
              const done = idx < currentIdx;
              const active = idx === currentIdx;
              return (
                <div key={s} className={`flex items-center gap-2 text-xs py-1 ${active ? "font-bold text-gray-800" : done ? "text-green-600" : "text-gray-300"}`}>
                  <span className={`w-4 h-4 rounded-full flex items-center justify-center shrink-0 text-white text-xs
                    ${active ? "bg-blue-500" : done ? "bg-green-500" : "bg-gray-200"}`}>
                    {done ? <Check size={12} className="text-white" /> : idx + 1}
                  </span>
                  {STATE_LABEL[s]}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Actions */}
      {inc.status !== "closed" && (
        <ActionPanel inc={inc} onUpdate={fetch} />
      )}

      {/* Audit log */}
      <div className="bg-white rounded-lg shadow p-5 mt-4">
        <h2 className="font-semibold text-gray-700 mb-3">稽核記錄</h2>
        {inc.audit_log.length === 0 ? (
          <p className="text-sm text-gray-600">尚無記錄</p>
        ) : (
          <div className="space-y-1">
            {inc.audit_log.map((entry, i) => (
              <div key={i} className="text-xs font-mono text-gray-600 bg-gray-50 rounded px-3 py-1.5">{entry}</div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ActionPanel({ inc, onUpdate }) {
  const toast = useToast();
  const [confirmClose, setConfirmClose] = useState(false);
  const [closing, setClosing] = useState(false);
  const [note, setNote] = useState("");
  const [enisaRef, setEnisaRef] = useState("");
  const [remDate, setRemDate] = useState("");
  const [saving, setSaving] = useState(false);

  const handleStartClock = async () => {
    setSaving(true);
    try {
      await api.post(`/cra/incidents/${inc.id}/start-clock`, { note: note || null });
      onUpdate();
      setNote("");
    } catch (err) {
      toast.error("操作失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setSaving(false);
    }
  };

  const handleCloseNotAffected = async () => {
    setClosing(true);
    try {
      await api.post(`/cra/incidents/${inc.id}/close-not-affected`, { note: note || null });
      setConfirmClose(false);
      onUpdate();
    } catch (err) {
      toast.error("操作失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setClosing(false);
    }
  };

  const handleAdvance = async () => {
    setSaving(true);
    try {
      await api.post(`/cra/incidents/${inc.id}/advance`, {
        note: note || null,
        enisa_ref: enisaRef || null,
        remediation_available_at: remDate || null,
      });
      onUpdate();
      setNote("");
      setEnisaRef("");
      setRemDate("");
    } catch (err) {
      toast.error("操作失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setSaving(false);
    }
  };

  const needsEnisaRef = ["clock_running", "investigating", "remediating"].includes(inc.status);
  const needsRemDate = inc.status === "t72_submitted";

  return (
    <div className="bg-white rounded-lg shadow p-5">
      <h2 className="font-semibold text-gray-700 mb-4">操作</h2>
      <div className="space-y-3">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">備註 <span className="text-gray-600 font-normal">(選填，會記入稽核記錄)</span></label>
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            rows={2}
            className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400 resize-none"
          />
        </div>

        {needsEnisaRef && (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">ENISA Reference ID <span className="text-gray-600 font-normal">(提交後填入)</span></label>
            <input
              value={enisaRef}
              onChange={(e) => setEnisaRef(e.target.value)}
              placeholder="ENISA-2026-XXXX"
              className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
            />
          </div>
        )}

        {needsRemDate && (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">修補發布時間 <span className="text-gray-600 font-normal">(T+14d 從此時算起)</span></label>
            <input
              type="datetime-local"
              value={remDate}
              onChange={(e) => setRemDate(e.target.value)}
              className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
            />
          </div>
        )}

        <div className="flex flex-wrap gap-2 pt-1">
          {inc.status === "pending_triage" && (
            <>
              <button
                onClick={handleStartClock}
                disabled={saving}
                className={`px-4 py-2 text-sm text-white rounded flex items-center gap-2 ${saving ? "bg-gray-400" : "bg-red-600 hover:bg-red-700"}`}
              >
                <Clock size={16} /> 確認受影響，啟動時鐘
              </button>
              <button
                onClick={() => setConfirmClose(true)}
                disabled={closing}
                className={`px-4 py-2 text-sm text-white rounded flex items-center gap-2 ${closing ? "bg-gray-400" : "bg-green-600 hover:bg-green-700"}`}
              >
                <Check size={16} /> 不受影響，關閉
              </button>
            </>
          )}
          {inc.can_advance && inc.status !== "pending_triage" && (
            <button
              onClick={handleAdvance}
              disabled={saving}
              className={`px-4 py-2 text-sm text-white rounded ${saving ? "bg-gray-400" : "bg-blue-600 hover:bg-blue-700"}`}
            >
              {inc.next_action_label} →
            </button>
          )}
          {inc.status === "detected" && (
            <button
              onClick={handleAdvance}
              disabled={saving}
              className={`px-4 py-2 text-sm text-white rounded ${saving ? "bg-gray-400" : "bg-yellow-600 hover:bg-yellow-700"}`}
            >
              開始分析 →
            </button>
          )}
        </div>
      </div>

      <ConfirmModal
        isOpen={confirmClose}
        title="確認關閉事件"
        message="確認此事件不受影響並關閉？"
        confirmText="關閉"
        cancelText="取消"
        isDangerous
        onConfirm={handleCloseNotAffected}
        onCancel={() => setConfirmClose(false)}
      />
    </div>
  );
}
