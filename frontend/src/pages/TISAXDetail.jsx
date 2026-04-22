import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import api from "../api/client";

const STATUS_CONFIG = {
  compliant:  { label: "達標",  cls: "bg-green-100 text-green-700" },
  near:       { label: "接近",  cls: "bg-yellow-100 text-yellow-700" },
  gap:        { label: "缺口",  cls: "bg-red-100 text-red-700" },
  unassessed: { label: "未評",  cls: "bg-gray-100 text-gray-500" },
};

const MATURITY_LABELS = {
  0: "0 — 未執行",
  1: "1 — 臨時措施",
  2: "2 — 已執行",
  3: "3 — 可預測",
  4: "4 — 可測量",
  5: "5 — 最佳化",
};

function StatusBadge({ status }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.unassessed;
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${cfg.cls}`}>{cfg.label}</span>
  );
}

function ControlRow({ ctrl, onSave }) {
  const [expanded, setExpanded] = useState(false);
  const [editing, setEditing]   = useState(false);
  const [form, setForm] = useState({
    current_maturity: ctrl.current_maturity,
    target_maturity:  ctrl.target_maturity,
    evidence_note:    ctrl.evidence_note || "",
    owner:            ctrl.owner || "",
    due_date:         ctrl.due_date || "",
    remarks:          ctrl.remarks || "",
  });
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    try {
      await onSave(ctrl.id, {
        current_maturity: parseInt(form.current_maturity),
        target_maturity:  parseInt(form.target_maturity),
        evidence_note:    form.evidence_note || null,
        owner:            form.owner || null,
        due_date:         form.due_date || null,
        remarks:          form.remarks || null,
      });
      setEditing(false);
    } catch (err) {
      alert("儲存失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setSaving(false);
    }
  };

  const gap = ctrl.target_maturity - ctrl.current_maturity;

  return (
    <div className="border-b border-gray-100 last:border-0">
      <div
        className="flex items-center gap-3 px-4 py-3 hover:bg-gray-50 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <span className="text-xs font-mono text-gray-400 w-16 shrink-0">{ctrl.control_number}</span>
        <span className="flex-1 text-sm text-gray-800">{ctrl.name}</span>
        <div className="flex items-center gap-2 shrink-0">
          {gap > 0 && (
            <span className="text-xs text-red-400">差距 {gap}</span>
          )}
          <span className="text-xs text-gray-500">{ctrl.current_maturity}/{ctrl.target_maturity}</span>
          <StatusBadge status={ctrl.status} />
          <span className="text-gray-300 text-xs">{expanded ? "▲" : "▼"}</span>
        </div>
      </div>

      {expanded && (
        <div className="px-4 pb-4 bg-gray-50/50">
          <p className="text-xs text-gray-500 mb-3 leading-relaxed">{ctrl.requirement_summary}</p>

          {!editing ? (
            <div className="space-y-2">
              {ctrl.evidence_note && (
                <div className="text-xs"><span className="text-gray-400">證據說明：</span>{ctrl.evidence_note}</div>
              )}
              {ctrl.owner && (
                <div className="text-xs"><span className="text-gray-400">負責人：</span>{ctrl.owner}</div>
              )}
              {ctrl.due_date && (
                <div className="text-xs"><span className="text-gray-400">預計完成：</span>{ctrl.due_date}</div>
              )}
              {ctrl.remarks && (
                <div className="text-xs"><span className="text-gray-400">備註：</span>{ctrl.remarks}</div>
              )}
              <button onClick={(e) => { e.stopPropagation(); setEditing(true); }}
                className="mt-2 text-xs text-blue-600 hover:underline">編輯評估結果</button>
            </div>
          ) : (
            <div className="space-y-3" onClick={e => e.stopPropagation()}>
              <div className="flex gap-4">
                <div className="flex-1">
                  <label className="text-xs text-gray-500 block mb-1">當前成熟度</label>
                  <select value={form.current_maturity}
                    onChange={e => setForm({ ...form, current_maturity: e.target.value })}
                    className="border rounded px-2 py-1 text-sm w-full">
                    {[0,1,2,3,4,5].map(n => (
                      <option key={n} value={n}>{MATURITY_LABELS[n]}</option>
                    ))}
                  </select>
                </div>
                <div className="flex-1">
                  <label className="text-xs text-gray-500 block mb-1">目標成熟度</label>
                  <select value={form.target_maturity}
                    onChange={e => setForm({ ...form, target_maturity: e.target.value })}
                    className="border rounded px-2 py-1 text-sm w-full">
                    {[0,1,2,3,4,5].map(n => (
                      <option key={n} value={n}>{MATURITY_LABELS[n]}</option>
                    ))}
                  </select>
                </div>
              </div>
              <div>
                <label className="text-xs text-gray-500 block mb-1">證據說明</label>
                <textarea value={form.evidence_note}
                  onChange={e => setForm({ ...form, evidence_note: e.target.value })}
                  rows={2} placeholder="描述現有的控制措施與佐證..."
                  className="border rounded px-2 py-1 text-sm w-full resize-none" />
              </div>
              <div className="flex gap-3">
                <div className="flex-1">
                  <label className="text-xs text-gray-500 block mb-1">負責人</label>
                  <input value={form.owner} onChange={e => setForm({ ...form, owner: e.target.value })}
                    className="border rounded px-2 py-1 text-sm w-full" />
                </div>
                <div className="flex-1">
                  <label className="text-xs text-gray-500 block mb-1">預計完成日</label>
                  <input type="date" value={form.due_date}
                    onChange={e => setForm({ ...form, due_date: e.target.value })}
                    className="border rounded px-2 py-1 text-sm w-full" />
                </div>
              </div>
              <div>
                <label className="text-xs text-gray-500 block mb-1">備註</label>
                <input value={form.remarks} onChange={e => setForm({ ...form, remarks: e.target.value })}
                  className="border rounded px-2 py-1 text-sm w-full" />
              </div>
              <div className="flex gap-2">
                <button onClick={handleSave} disabled={saving}
                  className="bg-blue-600 text-white px-3 py-1.5 rounded text-xs hover:bg-blue-700 disabled:opacity-50">
                  {saving ? "儲存中..." : "儲存"}
                </button>
                <button onClick={() => setEditing(false)}
                  className="text-gray-500 px-3 py-1.5 rounded text-xs hover:bg-gray-200 border">取消</button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function TISAXDetail() {
  const { assessmentId } = useParams();
  const navigate = useNavigate();
  const [data, setData]       = useState(null);
  const [gap, setGap]         = useState(null);
  const [tab, setTab]         = useState("controls"); // controls | gap
  const [filterStatus, setFilterStatus] = useState("");
  const [exporting, setExporting]       = useState(false);
  const [exportingPdf, setExportingPdf] = useState(false);

  const fetchData = () => {
    api.get(`/tisax/assessments/${assessmentId}`).then(r => setData(r.data));
    api.get(`/tisax/assessments/${assessmentId}/gap-report`).then(r => setGap(r.data));
  };

  useEffect(() => { fetchData(); }, [assessmentId]);

  const handleSaveControl = async (controlId, payload) => {
    await api.patch(`/tisax/assessments/${assessmentId}/controls/${controlId}`, payload);
    fetchData();
  };

  const handleExportCsv = async () => {
    setExporting(true);
    try {
      const resp = await api.get(`/tisax/assessments/${assessmentId}/export-csv`, { responseType: "blob" });
      const url = URL.createObjectURL(new Blob([resp.data], { type: "text/csv" }));
      const a = document.createElement("a");
      a.href = url; a.download = `tisax_${assessmentId.slice(0,8)}.csv`; a.click();
      URL.revokeObjectURL(url);
    } catch { alert("匯出失敗"); } finally { setExporting(false); }
  };

  const handleExportPdf = async () => {
    setExportingPdf(true);
    try {
      const resp = await api.get(`/tisax/assessments/${assessmentId}/export-pdf`, { responseType: "blob" });
      const url = URL.createObjectURL(new Blob([resp.data], { type: "application/pdf" }));
      const a = document.createElement("a");
      a.href = url; a.download = `tisax_${assessmentId.slice(0,8)}.pdf`; a.click();
      URL.revokeObjectURL(url);
    } catch { alert("PDF 匯出失敗"); } finally { setExportingPdf(false); }
  };

  if (!data) return <div className="text-gray-400 p-6">載入中...</div>;

  const { compliant = 0, near = 0, gap: gapCount = 0, unassessed = 0 } = data.by_status;
  const total = data.total_controls;
  const readiness = gap ? gap.readiness : 0;

  const allControls = (data.chapters || []).flatMap(ch => ch.controls);
  const filtered = filterStatus
    ? allControls.filter(c => c.status === filterStatus)
    : allControls;
  const filteredByChapter = {};
  filtered.forEach(c => {
    const ch = c.chapter;
    if (!filteredByChapter[ch]) filteredByChapter[ch] = [];
    filteredByChapter[ch].push(c);
  });

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center gap-2">
        <button onClick={() => navigate("/tisax")} className="text-blue-600 hover:underline text-sm">
          TISAX 自評管理
        </button>
        <span className="text-gray-400">/</span>
        <span className="text-sm text-gray-600">
          {data.module === "infosec" ? "資訊安全" : "原型保護"} — {data.assessment_level}
        </span>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "達標", value: compliant, cls: "text-green-600" },
          { label: "接近", value: near,      cls: "text-yellow-500" },
          { label: "缺口", value: gapCount,  cls: "text-red-500" },
          { label: "未評", value: unassessed, cls: "text-gray-400" },
        ].map(({ label, value, cls }) => (
          <div key={label} className="bg-white rounded-xl border border-gray-200 p-4 text-center">
            <div className={`text-2xl font-bold ${cls}`}>{value}</div>
            <div className="text-xs text-gray-500 mt-1">{label}</div>
          </div>
        ))}
      </div>

      {/* Readiness bar */}
      {gap && (
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-700">
              {data.assessment_level} 達標率
            </span>
            <div className="flex items-center gap-3">
              <span className="text-sm font-bold text-gray-800">{(readiness * 100).toFixed(1)}%</span>
              <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                gap.go_nogo === "GO"
                  ? "bg-green-100 text-green-700"
                  : "bg-red-100 text-red-700"
              }`}>{gap.go_nogo}</span>
              <span className="text-xs text-gray-400">門檻 {(gap.al_threshold * 100).toFixed(0)}%</span>
            </div>
          </div>
          <div className="bg-gray-100 rounded-full h-3">
            <div
              className={`h-3 rounded-full transition-all ${readiness >= gap.al_threshold ? "bg-green-500" : "bg-red-400"}`}
              style={{ width: `${Math.min(readiness * 100, 100)}%` }}
            />
          </div>
        </div>
      )}

      {/* Tabs + export */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
        <div className="flex border border-gray-200 rounded-lg overflow-hidden text-sm">
          {["controls", "gap"].map(t => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-4 py-2 ${tab === t ? "bg-blue-600 text-white" : "bg-white text-gray-600 hover:bg-gray-50"}`}>
              {t === "controls" ? "控制項自評" : "差距分析"}
            </button>
          ))}
        </div>
        {tab === "controls" && (
          <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
            className="border border-gray-200 rounded px-2 py-1.5 text-xs text-gray-600">
            <option value="">所有狀態</option>
            <option value="unassessed">未評</option>
            <option value="gap">缺口</option>
            <option value="near">接近</option>
            <option value="compliant">達標</option>
          </select>
        )}
        <div className="sm:ml-auto flex gap-2">
          <button onClick={handleExportPdf} disabled={exportingPdf}
            className="w-full sm:w-auto px-3 py-1.5 text-xs bg-red-600 text-white rounded hover:bg-red-700 disabled:opacity-50">
            {exportingPdf ? "產生中..." : "匯出 PDF"}
          </button>
          <button onClick={handleExportCsv} disabled={exporting}
            className="w-full sm:w-auto px-3 py-1.5 text-xs bg-emerald-600 text-white rounded hover:bg-emerald-700 disabled:opacity-50">
            {exporting ? "匯出中..." : "匯出 CSV"}
          </button>
        </div>
      </div>

      {/* Controls tab */}
      {tab === "controls" && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
          {Object.entries(filteredByChapter).length === 0 ? (
            <div className="p-8 text-center text-gray-400">無符合條件的控制項</div>
          ) : (
            Object.entries(filteredByChapter).map(([chapter, controls]) => (
              <div key={chapter}>
                <div className="px-4 py-2 bg-gray-50 border-b border-gray-100">
                  <span className="text-xs font-semibold text-gray-600">{chapter}</span>
                  <span className="ml-2 text-xs text-gray-400">{controls.length} 項</span>
                </div>
                {controls.map(ctrl => (
                  <ControlRow key={ctrl.id} ctrl={ctrl} onSave={handleSaveControl} />
                ))}
              </div>
            ))
          )}
        </div>
      )}

      {/* Gap tab */}
      {tab === "gap" && gap && (
        <div className="space-y-4">
          {gap.gaps.length === 0 && gap.near.length === 0 ? (
            <div className="bg-white rounded-xl border border-gray-200 p-8 text-center text-gray-400">
              尚無差距項目（可能尚未開始自評）
            </div>
          ) : (
            <>
              {gap.gaps.length > 0 && (
                <div className="bg-white rounded-xl border border-red-200 overflow-hidden">
                  <div className="px-4 py-3 bg-red-50 border-b border-red-100">
                    <span className="text-sm font-semibold text-red-700">缺口項目（{gap.gaps.length} 項）— 需優先改善</span>
                  </div>
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="bg-gray-50 text-xs text-gray-500">
                        <th className="px-4 py-2 text-left">編號</th>
                        <th className="px-4 py-2 text-left">控制項</th>
                        <th className="px-4 py-2 text-center">當前</th>
                        <th className="px-4 py-2 text-center">目標</th>
                        <th className="px-4 py-2 text-center">差距</th>
                        <th className="px-4 py-2 text-left hidden sm:table-cell">負責人</th>
                        <th className="px-4 py-2 text-left hidden sm:table-cell">預計完成</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                      {gap.gaps.map(c => (
                        <tr key={c.id} className="hover:bg-red-50/30">
                          <td className="px-4 py-2 font-mono text-xs text-gray-400">{c.control_number}</td>
                          <td className="px-4 py-2 text-gray-800">{c.name}</td>
                          <td className="px-4 py-2 text-center font-bold text-red-500">{c.current_maturity}</td>
                          <td className="px-4 py-2 text-center text-gray-500">{c.target_maturity}</td>
                          <td className="px-4 py-2 text-center font-bold text-red-600">
                            -{c.target_maturity - c.current_maturity}
                          </td>
                          <td className="px-4 py-2 text-gray-500 text-xs hidden sm:table-cell">{c.owner || "—"}</td>
                          <td className="px-4 py-2 text-gray-500 text-xs hidden sm:table-cell">{c.due_date || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {gap.near.length > 0 && (
                <div className="bg-white rounded-xl border border-yellow-200 overflow-hidden">
                  <div className="px-4 py-3 bg-yellow-50 border-b border-yellow-100">
                    <span className="text-sm font-semibold text-yellow-700">接近項目（{gap.near.length} 項）— 再努力 1 級即達標</span>
                  </div>
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="bg-gray-50 text-xs text-gray-500">
                        <th className="px-4 py-2 text-left">編號</th>
                        <th className="px-4 py-2 text-left">控制項</th>
                        <th className="px-4 py-2 text-center">當前</th>
                        <th className="px-4 py-2 text-center">目標</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                      {gap.near.map(c => (
                        <tr key={c.id} className="hover:bg-yellow-50/30">
                          <td className="px-4 py-2 font-mono text-xs text-gray-400">{c.control_number}</td>
                          <td className="px-4 py-2 text-gray-800">{c.name}</td>
                          <td className="px-4 py-2 text-center font-bold text-yellow-600">{c.current_maturity}</td>
                          <td className="px-4 py-2 text-center text-gray-500">{c.target_maturity}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
