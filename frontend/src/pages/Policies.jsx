import { useEffect, useState } from "react";
import api from "../api/client";

const SEVERITY_OPTIONS = [
  { value: "any",      label: "任何嚴重度" },
  { value: "critical", label: "Critical" },
  { value: "high",     label: "High" },
  { value: "medium",   label: "Medium" },
  { value: "low",      label: "Low" },
];

const SEV_COLOR = {
  critical: "text-red-600 bg-red-50",
  high:     "text-orange-600 bg-orange-50",
  medium:   "text-yellow-700 bg-yellow-50",
  low:      "text-blue-600 bg-blue-50",
  any:      "text-gray-600 bg-gray-100",
};

const DEFAULT_FORM = {
  name: "", description: "", severity: "any", require_kev: false,
  statuses: "open,in_triage,affected", min_days_open: 30, action: "warn", enabled: true,
};

export default function Policies() {
  const [rules, setRules] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editRule, setEditRule] = useState(null);
  const [form, setForm] = useState(DEFAULT_FORM);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState(null);

  const flash = (type, text) => { setMsg({ type, text }); setTimeout(() => setMsg(null), 4000); };

  const fetchAll = () => {
    Promise.all([
      api.get("/policies"),
      api.get("/policies/violations/summary"),
    ]).then(([r1, r2]) => {
      setRules(r1.data);
      setSummary(r2.data);
    }).catch(() => {}).finally(() => setLoading(false));
  };

  useEffect(() => { fetchAll(); }, []);

  const openCreate = () => { setEditRule(null); setForm(DEFAULT_FORM); setShowForm(true); };
  const openEdit = (r) => {
    setEditRule(r);
    setForm({
      name: r.name, description: r.description, severity: r.severity,
      require_kev: r.require_kev, statuses: r.statuses,
      min_days_open: r.min_days_open, action: r.action, enabled: r.enabled,
    });
    setShowForm(true);
  };

  const handleSave = async () => {
    if (!form.name.trim()) { flash("err", "請填寫規則名稱"); return; }
    setSaving(true);
    try {
      if (editRule) {
        await api.patch(`/policies/${editRule.id}`, form);
        flash("ok", "規則已更新");
      } else {
        await api.post("/policies", form);
        flash("ok", "規則已建立");
      }
      setShowForm(false);
      fetchAll();
    } catch (e) {
      flash("err", e.response?.data?.detail || "儲存失敗");
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (rule) => {
    try {
      await api.patch(`/policies/${rule.id}`, { enabled: !rule.enabled });
      fetchAll();
    } catch { flash("err", "更新失敗"); }
  };

  const handleDelete = async (rule) => {
    if (!window.confirm(`確定要刪除「${rule.name}」？`)) return;
    try {
      await api.delete(`/policies/${rule.id}`);
      flash("ok", "規則已刪除");
      fetchAll();
    } catch { flash("err", "刪除失敗"); }
  };

  const violationCount = (ruleId) =>
    summary?.by_rule?.find((x) => x.rule_id === ruleId)?.violation_count ?? 0;

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-800">Policy 引擎</h1>
        <button
          onClick={openCreate}
          className="px-4 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700"
        >
          + 新增規則
        </button>
      </div>

      {msg && (
        <div className={`mb-4 px-4 py-3 rounded text-sm ${msg.type === "ok" ? "bg-green-50 text-green-700" : "bg-red-50 text-red-600"}`}>
          {msg.text}
        </div>
      )}

      {/* Summary bar */}
      {summary && (
        <div className={`mb-5 rounded-lg px-5 py-3 flex items-center gap-4 ${summary.total_violations > 0 ? "bg-red-50 border border-red-200" : "bg-green-50 border border-green-200"}`}>
          <span className={`text-2xl font-bold ${summary.total_violations > 0 ? "text-red-600" : "text-green-600"}`}>
            {summary.total_violations}
          </span>
          <div>
            <p className={`font-semibold text-sm ${summary.total_violations > 0 ? "text-red-700" : "text-green-700"}`}>
              {summary.total_violations > 0 ? "項全平台違規" : "目前無違規"}
            </p>
            <p className="text-xs text-gray-500">已啟用 {rules.filter((r) => r.enabled).length} 條規則</p>
          </div>
        </div>
      )}

      {loading ? (
        <div className="text-gray-400 text-center mt-8">載入中...</div>
      ) : rules.length === 0 ? (
        <div className="bg-white rounded-lg shadow p-8 text-center text-gray-400">尚無規則</div>
      ) : (
        <div className="space-y-3">
          {rules.map((rule) => {
            const vc = violationCount(rule.id);
            return (
              <div key={rule.id} className={`bg-white rounded-lg shadow p-4 flex items-start gap-4 ${!rule.enabled ? "opacity-50" : ""}`}>
                {/* Toggle */}
                <button
                  onClick={() => handleToggle(rule)}
                  className={`mt-0.5 w-10 h-6 rounded-full transition-colors shrink-0 ${rule.enabled ? "bg-blue-500" : "bg-gray-300"}`}
                  title={rule.enabled ? "停用" : "啟用"}
                >
                  <div className={`w-4 h-4 bg-white rounded-full mx-auto transition-transform ${rule.enabled ? "translate-x-2" : "-translate-x-2"}`} />
                </button>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-semibold text-gray-800">{rule.name}</span>
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${SEV_COLOR[rule.severity]}`}>
                      {SEVERITY_OPTIONS.find((o) => o.value === rule.severity)?.label}
                    </span>
                    {rule.require_kev && (
                      <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-red-600 text-white">KEV</span>
                    )}
                    {rule.action === "block" && (
                      <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-gray-800 text-white">阻擋</span>
                    )}
                  </div>
                  {rule.description && (
                    <p className="text-xs text-gray-500 mt-0.5">{rule.description}</p>
                  )}
                  <div className="flex gap-4 mt-1.5 text-xs text-gray-500">
                    <span>超過 <span className="font-semibold text-gray-700">{rule.min_days_open}</span> 天</span>
                    <span>狀態：{rule.statuses}</span>
                  </div>
                </div>

                {/* Violation badge */}
                <div className="shrink-0 text-center">
                  {vc > 0 ? (
                    <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-red-100 text-red-700 font-bold text-sm">{vc}</span>
                  ) : (
                    <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-green-100 text-green-600 text-lg">✓</span>
                  )}
                  <p className="text-xs text-gray-400 mt-0.5">違規</p>
                </div>

                {/* Actions */}
                <div className="shrink-0 flex gap-2">
                  <button onClick={() => openEdit(rule)} className="text-xs text-blue-600 hover:underline">編輯</button>
                  <button onClick={() => handleDelete(rule)} className="text-xs text-red-500 hover:underline">刪除</button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Rule form modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setShowForm(false)}>
          <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-lg mx-2 sm:mx-4" onClick={(e) => e.stopPropagation()}>
            <h3 className="font-semibold text-gray-800 mb-4">{editRule ? "編輯規則" : "新增規則"}</h3>

            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">規則名稱 <span className="text-red-400">*</span></label>
                <input
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">說明</label>
                <input
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">嚴重度條件</label>
                  <select
                    value={form.severity}
                    onChange={(e) => setForm({ ...form, severity: e.target.value })}
                    className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
                  >
                    {SEVERITY_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">超過天數才違規</label>
                  <input
                    type="number" min={0}
                    value={form.min_days_open}
                    onChange={(e) => setForm({ ...form, min_days_open: parseInt(e.target.value) || 0 })}
                    className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">適用狀態（逗號分隔）</label>
                <input
                  value={form.statuses}
                  onChange={(e) => setForm({ ...form, statuses: e.target.value })}
                  placeholder="open,in_triage,affected"
                  className="w-full border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-blue-400"
                />
                <p className="text-xs text-gray-400 mt-0.5">可用值：open / in_triage / affected / not_affected / fixed</p>
              </div>

              <div className="flex gap-6">
                <label className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.require_kev}
                    onChange={(e) => setForm({ ...form, require_kev: e.target.checked })}
                    className="rounded"
                  />
                  僅適用 KEV 漏洞
                </label>
                <label className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.enabled}
                    onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                    className="rounded"
                  />
                  啟用此規則
                </label>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">動作</label>
                <div className="flex gap-4">
                  {[{ v: "warn", l: "警告（顯示徽章）" }, { v: "block", l: "阻擋（標記嚴重）" }].map((o) => (
                    <label key={o.v} className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                      <input type="radio" value={o.v} checked={form.action === o.v}
                        onChange={() => setForm({ ...form, action: o.v })} />
                      {o.l}
                    </label>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-2 mt-5">
              <button onClick={() => setShowForm(false)} className="px-4 py-2 text-sm text-gray-600 border rounded hover:bg-gray-50">取消</button>
              <button
                onClick={handleSave}
                disabled={saving}
                className={`px-4 py-2 text-sm text-white rounded ${saving ? "bg-gray-400" : "bg-blue-600 hover:bg-blue-700"}`}
              >
                {saving ? "儲存中..." : "儲存"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
