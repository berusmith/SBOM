import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/client";
import { TISAX_LEVEL_COLOR, DEFAULT_BADGE } from "../constants/colors";

const MODULE_LABELS = { infosec: "資訊安全", prototype: "原型保護" };

function MaturityBar({ value, max = 5 }) {
  const pct = (value / max) * 100;
  const color = value >= 4 ? "bg-green-500" : value >= 2 ? "bg-yellow-400" : "bg-red-400";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 bg-gray-100 rounded-full h-2">
        <div className={`${color} h-2 rounded-full transition-all`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-gray-500 w-6">{value.toFixed(1)}</span>
    </div>
  );
}

export default function TISAXAssessments() {
  const navigate = useNavigate();
  const [assessments, setAssessments] = useState([]);
  const [orgs, setOrgs] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ organization_id: "", module: "infosec", assessment_level: "AL2" });
  const [loading, setLoading] = useState(false);
  const isAdmin = localStorage.getItem("role") === "admin";
  const orgId   = localStorage.getItem("org_id");

  const fetchAll = () => {
    api.get("/tisax/assessments").then(r => setAssessments(r.data));
    if (isAdmin) api.get("/organizations").then(r => setOrgs(r.data));
  };

  useEffect(() => { fetchAll(); }, []);

  useEffect(() => {
    if (!isAdmin && orgId) setForm(f => ({ ...f, organization_id: orgId }));
  }, [isAdmin, orgId]);

  const handleCreate = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await api.post("/tisax/assessments", form);
      setShowForm(false);
      navigate(`/tisax/${res.data.id}`);
    } catch (err) {
      alert("建立失敗：" + (err.response?.data?.detail || err.message));
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm("確定要刪除此評估？所有自評資料將一併刪除。")) return;
    try {
      await api.delete(`/tisax/assessments/${id}`);
      fetchAll();
    } catch (err) {
      alert("刪除失敗：" + (err.response?.data?.detail || err.message));
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
        <h1 className="text-xl font-bold text-gray-800">TISAX 自評管理</h1>
        <button onClick={() => setShowForm(!showForm)}
          className="w-full sm:w-auto sm:ml-auto bg-blue-600 text-white px-4 py-2 rounded text-sm hover:bg-blue-700">
          + 新增評估
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleCreate}
          className="bg-white rounded-xl shadow-sm border border-gray-200 p-5 space-y-4">
          <h2 className="font-semibold text-gray-700">新增 TISAX 評估</h2>
          {isAdmin && (
            <div>
              <label className="text-xs text-gray-500 block mb-1">客戶組織</label>
              <select value={form.organization_id}
                onChange={e => setForm({ ...form, organization_id: e.target.value })}
                className="border rounded px-3 py-2 text-sm w-full" required>
                <option value="">選擇客戶</option>
                {orgs.map(o => <option key={o.id} value={o.id}>{o.name}</option>)}
              </select>
            </div>
          )}
          <div className="flex gap-4">
            <div className="flex-1">
              <label className="text-xs text-gray-500 block mb-1">評估模組</label>
              <select value={form.module} onChange={e => setForm({ ...form, module: e.target.value })}
                className="border rounded px-3 py-2 text-sm w-full">
                <option value="infosec">資訊安全（41 項）</option>
                <option value="prototype">原型保護（22 項）</option>
              </select>
            </div>
            <div className="flex-1">
              <label className="text-xs text-gray-500 block mb-1">評估等級</label>
              <select value={form.assessment_level}
                onChange={e => setForm({ ...form, assessment_level: e.target.value })}
                className="border rounded px-3 py-2 text-sm w-full">
                <option value="AL1">AL1（自評）</option>
                <option value="AL2">AL2（遠端稽核）</option>
                <option value="AL3">AL3（現場稽核）</option>
              </select>
            </div>
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

      {assessments.length === 0 ? (
        <div className="bg-white rounded-xl border border-gray-200 p-12 text-center text-gray-400">
          尚無評估，點擊「新增評估」開始 TISAX 自評
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {assessments.map(a => {
            const { compliant = 0, near = 0, gap = 0, unassessed = 0 } = a.by_status;
            const total = a.total_controls;
            const progress = total ? Math.round(((compliant + near + gap) / total) * 100) : 0;
            return (
              <div key={a.id}
                className="bg-white rounded-xl shadow-sm border border-gray-200 p-5 hover:shadow-md transition-shadow">
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <span className="text-xs font-medium text-gray-500">
                      {MODULE_LABELS[a.module] || a.module}
                    </span>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${TISAX_LEVEL_COLOR[a.assessment_level] || DEFAULT_BADGE}`}>
                        {a.assessment_level}
                      </span>
                      <span className="text-xs text-gray-400">{total} 項控制項</span>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => navigate(`/tisax/${a.id}`)}
                      className="text-blue-600 hover:underline text-xs">開始自評</button>
                    <button onClick={() => handleDelete(a.id)}
                      className="text-red-400 hover:underline text-xs">刪除</button>
                  </div>
                </div>

                <div className="mb-3">
                  <div className="flex justify-between text-xs text-gray-500 mb-1">
                    <span>整體進度</span><span>{progress}%</span>
                  </div>
                  <div className="bg-gray-100 rounded-full h-2">
                    <div className="bg-blue-500 h-2 rounded-full" style={{ width: `${progress}%` }} />
                  </div>
                </div>

                <div className="flex gap-3 text-xs">
                  <span className="text-green-600">✓ 達標 {compliant}</span>
                  <span className="text-yellow-500">≈ 接近 {near}</span>
                  <span className="text-red-500">✗ 缺口 {gap}</span>
                  <span className="text-gray-400">— 未評 {unassessed}</span>
                </div>
                <div className="mt-3">
                  <div className="text-xs text-gray-500 mb-1">平均成熟度</div>
                  <MaturityBar value={a.avg_maturity} />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
