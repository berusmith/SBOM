import { useEffect, useRef, useState } from "react";
import api from "../api/client";
import { ConfirmModal } from "../components/ConfirmModal";
import { formatDate, formatDateTime } from "../utils/date";

export default function Settings() {
  // Current user role
  const [currentRole, setCurrentRole] = useState(null);

  // Alert settings
  const [cfg, setCfg] = useState(null);
  const [webhook, setWebhook] = useState("");
  const [email, setEmail] = useState("");
  const [intervalHours, setIntervalHours] = useState(24);
  const [saving, setSaving] = useState(false);
  const [testingWh, setTestingWh] = useState(false);
  const [testingEmail, setTestingEmail] = useState(false);

  // Monitor status
  const [monitorStatus, setMonitorStatus] = useState(null);
  const [triggering, setTriggering] = useState(false);

  // Brand settings
  const [brand, setBrand] = useState(null);
  const [companyName, setCompanyName] = useState("");
  const [tagline, setTagline] = useState("");
  const [primaryColor, setPrimaryColor] = useState("#1e3a8a");
  const [reportFooter, setReportFooter] = useState("");
  const [savingBrand, setSavingBrand] = useState(false);
  const [uploadingLogo, setUploadingLogo] = useState(false);
  const [logoUrl, setLogoUrl] = useState(null);
  const logoInputRef = useRef(null);

  const [msg, setMsg] = useState(null);
  const flash = (type, text) => { setMsg({ type, text }); setTimeout(() => setMsg(null), 4000); };

  const fetchCfg = () => {
    api.get("/settings/alerts").then((r) => {
      setCfg(r.data);
      setWebhook(r.data.webhook_url || "");
      setEmail(r.data.alert_email_to || "");
      setIntervalHours(r.data.monitor_interval_hours ?? 24);
    }).catch(() => {});
  };

  const fetchMonitorStatus = () => {
    api.get("/settings/monitor").then((r) => setMonitorStatus(r.data)).catch(() => {});
  };

  const fetchBrand = () => {
    api.get("/settings/brand").then((r) => {
      setBrand(r.data);
      setCompanyName(r.data.company_name || "");
      setTagline(r.data.tagline || "");
      setPrimaryColor(r.data.primary_color || "#1e3a8a");
      setReportFooter(r.data.report_footer || "");
      if (r.data.has_logo) {
        api.get("/settings/brand/logo", { responseType: "blob" }).then((res) => {
          setLogoUrl(URL.createObjectURL(res.data));
        }).catch(() => setLogoUrl(null));
      } else {
        setLogoUrl(null);
      }
    }).catch(() => {});
  };

  useEffect(() => {
    fetchCfg();
    fetchBrand();
    fetchMonitorStatus();
    api.get("/auth/me").then((r) => setCurrentRole(r.data.role)).catch(() => {});
  }, []);

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.patch("/settings/alerts", {
        webhook_url: webhook,
        alert_email_to: email,
        monitor_interval_hours: intervalHours,
      });
      flash("ok", "通知設定已儲存");
      fetchCfg();
      fetchMonitorStatus();
    } catch (e) {
      flash("err", e.response?.data?.detail || "儲存失敗");
    } finally {
      setSaving(false);
    }
  };

  const handleTriggerScan = async () => {
    setTriggering(true);
    try {
      const r = await api.post("/settings/monitor/trigger");
      if (r.data.status === "already_running") {
        flash("ok", "掃描已在執行中");
      } else {
        flash("ok", "已啟動全域掃描，完成後若有新漏洞將發送通知");
        setTimeout(fetchMonitorStatus, 3000);
      }
    } catch (e) {
      flash("err", e.response?.data?.detail || "啟動失敗");
    } finally {
      setTriggering(false);
    }
  };

  const handleTestWebhook = async () => {
    setTestingWh(true);
    try {
      await api.post("/settings/alerts/test-webhook");
      flash("ok", "Webhook 測試發送成功");
    } catch (e) {
      flash("err", e.response?.data?.detail || "Webhook 測試失敗");
    } finally {
      setTestingWh(false);
    }
  };

  const handleTestEmail = async () => {
    setTestingEmail(true);
    try {
      await api.post("/settings/alerts/test-email");
      flash("ok", "測試 Email 已發送，請檢查收件匣");
    } catch (e) {
      flash("err", e.response?.data?.detail || "Email 測試失敗");
    } finally {
      setTestingEmail(false);
    }
  };

  const handleSaveBrand = async () => {
    setSavingBrand(true);
    try {
      await api.patch("/settings/brand", {
        company_name: companyName,
        tagline,
        primary_color: primaryColor,
        report_footer: reportFooter,
      });
      flash("ok", "品牌設定已儲存");
      fetchBrand();
    } catch (e) {
      flash("err", e.response?.data?.detail || "儲存失敗");
    } finally {
      setSavingBrand(false);
    }
  };

  const handleLogoUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadingLogo(true);
    const fd = new FormData();
    fd.append("file", file);
    try {
      await api.post("/settings/brand/logo", fd, { headers: { "Content-Type": "multipart/form-data" } });
      flash("ok", "Logo 上傳成功");
      fetchBrand();
    } catch (err) {
      flash("err", err.response?.data?.detail || "Logo 上傳失敗");
    } finally {
      setUploadingLogo(false);
      if (logoInputRef.current) logoInputRef.current.value = "";
    }
  };

  const handleDeleteLogo = async () => {
    try {
      await api.delete("/settings/brand/logo");
      flash("ok", "Logo 已移除");
      fetchBrand();
    } catch {
      flash("err", "移除失敗");
    }
  };

  return (
    <div className="max-w-2xl">
      <h2 className="text-xl font-bold text-gray-800 mb-6">系統設定</h2>

      {msg && (
        <div className={`mb-4 px-4 py-3 rounded text-sm ${msg.type === "ok" ? "bg-green-50 text-green-700" : "bg-red-50 text-red-600"}`}>
          {msg.text}
        </div>
      )}

      {/* ── User management (admin only) ── */}
      {currentRole === "admin" && <UserManagement flash={flash} />}

      {/* ── API tokens (admin only) ── */}
      {currentRole === "admin" && <ApiTokens flash={flash} />}

      {/* ── Brand settings ── */}
      <div className="bg-white rounded-lg shadow p-5 mb-4">
        <h3 className="font-semibold text-gray-700 mb-1">報告品牌設定</h3>
        <p className="text-xs text-gray-600 mb-4">設定後，PDF 報告將顯示貴公司 Logo、名稱與主色調</p>

        {/* Logo upload */}
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 mb-1">公司 Logo</label>
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
            {brand?.has_logo && logoUrl ? (
              <>
                <img
                  src={logoUrl}
                  alt="logo"
                  className="h-12 object-contain border rounded px-2 bg-gray-50"
                />
                <button
                  onClick={handleDeleteLogo}
                  className="text-xs text-red-500 hover:underline"
                >
                  移除
                </button>
              </>
            ) : (
              <span className="text-xs text-gray-600">尚未上傳</span>
            )}
            <button
              onClick={() => logoInputRef.current?.click()}
              disabled={uploadingLogo}
              className="px-3 py-1.5 text-sm border rounded text-gray-600 hover:bg-gray-50 disabled:opacity-40"
            >
              {uploadingLogo ? "上傳中..." : brand?.has_logo ? "更換 Logo" : "上傳 Logo"}
            </button>
            <input
              ref={logoInputRef}
              type="file"
              accept="image/*"
              className="hidden"
              onChange={handleLogoUpload}
            />
            <span className="text-xs text-gray-600">PNG / JPG，最大 2MB</span>
          </div>
        </div>

        {/* Company name */}
        <div className="mb-3">
          <label className="block text-sm font-medium text-gray-700 mb-1">公司名稱</label>
          <input
            value={companyName}
            onChange={(e) => setCompanyName(e.target.value)}
            placeholder="例：台灣資安顧問股份有限公司"
            className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
          />
        </div>

        {/* Tagline */}
        <div className="mb-3">
          <label className="block text-sm font-medium text-gray-700 mb-1">副標語 <span className="text-gray-600 font-normal">(選填)</span></label>
          <input
            value={tagline}
            onChange={(e) => setTagline(e.target.value)}
            placeholder="例：Securing the Supply Chain"
            className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
          />
        </div>

        {/* Primary color */}
        <div className="mb-3">
          <label className="block text-sm font-medium text-gray-700 mb-1">主題色（報告標題/表頭）</label>
          <div className="flex items-center gap-3 flex-wrap">
            <input
              type="color"
              value={primaryColor}
              onChange={(e) => setPrimaryColor(e.target.value)}
              className="h-9 w-14 cursor-pointer border rounded"
            />
            <input
              value={primaryColor}
              onChange={(e) => setPrimaryColor(e.target.value)}
              placeholder="#1e3a8a"
              className="w-28 border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-blue-400"
            />
            {/* Preview swatch */}
            <div
              className="flex-1 h-9 rounded flex items-center px-3 text-white text-xs font-semibold"
              style={{ backgroundColor: primaryColor }}
            >
              預覽色彩
            </div>
          </div>
        </div>

        {/* Report footer */}
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 mb-1">報告頁尾文字 <span className="text-gray-600 font-normal">(選填)</span></label>
          <input
            value={reportFooter}
            onChange={(e) => setReportFooter(e.target.value)}
            placeholder="例：機密文件，僅供客戶參閱。Copyright © 2025"
            className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
          />
        </div>

        <button
          onClick={handleSaveBrand}
          disabled={savingBrand}
          className={`px-5 py-2 rounded text-sm text-white font-medium ${savingBrand ? "bg-gray-400" : "bg-blue-600 hover:bg-blue-700"}`}
        >
          {savingBrand ? "儲存中..." : "儲存品牌設定"}
        </button>
      </div>

      {/* ── Continuous monitoring ── */}
      <div className="bg-white rounded-lg shadow p-5 mb-4">
        <h3 className="font-semibold text-gray-700 mb-1">持續漏洞監控</h3>
        <p className="text-xs text-gray-600 mb-4">系統定期對所有版本重新掃描 OSV.dev，發現新 CVE 時自動發送通知</p>

        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 mb-4">
          <div>
            <label className="block text-xs text-gray-500 mb-1">掃描頻率</label>
            <select
              value={intervalHours}
              onChange={(e) => setIntervalHours(Number(e.target.value))}
              className="border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
            >
              <option value={0}>停用</option>
              <option value={6}>每 6 小時</option>
              <option value={12}>每 12 小時</option>
              <option value={24}>每 24 小時</option>
              <option value={48}>每 48 小時</option>
              <option value={72}>每 72 小時</option>
            </select>
          </div>

          <button
            onClick={handleTriggerScan}
            disabled={triggering}
            className="sm:mt-5 px-4 py-2 text-sm border rounded text-gray-600 hover:bg-gray-50 disabled:opacity-40"
          >
            {triggering ? "啟動中..." : "立即掃描一次"}
          </button>
        </div>

        {monitorStatus && (
          <div className="bg-gray-50 rounded p-3 text-xs text-gray-500 space-y-1">
            <div className="flex gap-4 flex-wrap">
              <span>
                狀態：
                <span className={monitorStatus.is_scanning ? "text-blue-600 font-medium" : "text-gray-600"}>
                  {monitorStatus.is_scanning ? "掃描中..." : "閒置"}
                </span>
              </span>
              {monitorStatus.last_run && (
                <span>
                  上次執行：{formatDateTime(monitorStatus.last_run)}
                  {monitorStatus.last_run_new_count > 0 && (
                    <span className="ml-1 text-orange-500 font-medium">（+{monitorStatus.last_run_new_count} 新漏洞）</span>
                  )}
                </span>
              )}
              {!monitorStatus.last_run && <span className="text-gray-600">尚未執行過</span>}
              {monitorStatus.next_run && (
                <span>下次排程：{formatDateTime(monitorStatus.next_run)}</span>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ── Webhook ── */}
      <div className="bg-white rounded-lg shadow p-5 mb-4">
        <h3 className="font-semibold text-gray-700 mb-1">Webhook 通知</h3>
        <p className="text-xs text-gray-600 mb-3">重新掃描發現新漏洞時，POST JSON 到此 URL（支援 Slack / Teams / 自定義）</p>
        <div className="flex gap-2">
          <input
            value={webhook}
            onChange={(e) => setWebhook(e.target.value)}
            placeholder="https://hooks.slack.com/services/..."
            className="flex-1 border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
          />
          <button
            onClick={handleTestWebhook}
            disabled={testingWh || !webhook.trim()}
            className="px-3 py-2 text-sm border rounded text-gray-600 hover:bg-gray-50 disabled:opacity-40"
          >
            {testingWh ? "測試中..." : "測試"}
          </button>
        </div>
      </div>

      {/* ── Email ── */}
      <div className="bg-white rounded-lg shadow p-5 mb-4">
        <h3 className="font-semibold text-gray-700 mb-1">Email 通知</h3>
        <p className="text-xs text-gray-600 mb-3">重新掃描發現新漏洞時寄送 Email 通知</p>
        <div className="flex gap-2 mb-3">
          <input
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            type="email"
            className="flex-1 border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
          />
          <button
            onClick={handleTestEmail}
            disabled={testingEmail || !email.trim()}
            className="px-3 py-2 text-sm border rounded text-gray-600 hover:bg-gray-50 disabled:opacity-40"
          >
            {testingEmail ? "測試中..." : "測試"}
          </button>
        </div>

        {cfg && (
          <div className={`text-xs px-3 py-2 rounded ${cfg.smtp_configured ? "bg-green-50 text-green-700" : "bg-yellow-50 text-yellow-700"}`}>
            {cfg.smtp_configured
              ? `SMTP 已設定：${cfg.smtp_host}:${cfg.smtp_port}（寄件人：${cfg.smtp_from}）`
              : "SMTP 未設定 — 請在 .env 設定 SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASSWORD / SMTP_FROM"}
          </div>
        )}
      </div>

      <button
        onClick={handleSave}
        disabled={saving}
        className={`px-6 py-2 rounded text-sm text-white font-medium ${saving ? "bg-gray-400" : "bg-blue-600 hover:bg-blue-700"}`}
      >
        {saving ? "儲存中..." : "儲存通知設定"}
      </button>
    </div>
  );
}

function ApiTokens({ flash }) {
  const [tokens, setTokens] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [scope, setScope] = useState("admin");
  const [saving, setSaving] = useState(false);
  const [newToken, setNewToken] = useState(null);
  const [confirmRevoke, setConfirmRevoke] = useState(null);
  const [copied, setCopied] = useState(false);

  const fetchTokens = () => api.get("/tokens").then((r) => setTokens(r.data)).catch(() => {});
  useEffect(() => { fetchTokens(); }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!name.trim()) return;
    setSaving(true);
    try {
      const r = await api.post("/tokens", { name: name.trim(), scope });
      setNewToken(r.data);
      setName("");
      setScope("admin");
      setShowForm(false);
      fetchTokens();
    } catch (err) {
      flash("err", err.response?.data?.detail || "建立失敗");
    } finally {
      setSaving(false);
    }
  };

  const handleRevoke = async () => {
    try {
      await api.delete(`/tokens/${confirmRevoke.id}`);
      flash("ok", "Token 已撤銷");
      setConfirmRevoke(null);
      fetchTokens();
    } catch (err) {
      flash("err", err.response?.data?.detail || "撤銷失敗");
    }
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(newToken.token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { /* ignore */ }
  };

  return (
    <div className="bg-white rounded-lg shadow p-5 mb-4">
      <div className="flex items-center justify-between mb-1">
        <h3 className="font-semibold text-gray-700">API 金鑰</h3>
        <button
          onClick={() => setShowForm(!showForm)}
          className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
        >
          + 新增 Token
        </button>
      </div>
      <p className="text-xs text-gray-600 mb-4">
        供 CI/CD pipeline 長期存取使用。Header：<code className="bg-gray-100 px-1 rounded">Authorization: Bearer sbom_xxx</code>
      </p>

      {showForm && (
        <form onSubmit={handleCreate} className="bg-gray-50 rounded p-4 mb-4 flex gap-2 items-end flex-wrap">
          <div className="flex-1 min-w-[200px]">
            <label className="block text-xs font-medium text-gray-600 mb-1">Token 名稱（供辨識用途）</label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="例：GitLab CI / Jenkins build"
              maxLength={100}
              className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">權限範圍</label>
            <select
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              className="border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
            >
              <option value="read">唯讀（僅 GET）</option>
              <option value="write">讀寫（不可刪除）</option>
              <option value="admin">管理員（完整權限）</option>
            </select>
          </div>
          <div className="flex gap-2">
            <button type="submit" disabled={saving}
              className={`px-4 py-2 text-sm text-white rounded ${saving ? "bg-gray-400" : "bg-blue-600 hover:bg-blue-700"}`}>
              {saving ? "建立中..." : "建立"}
            </button>
            <button type="button" onClick={() => { setShowForm(false); setName(""); setScope("admin"); }}
              className="px-4 py-2 text-sm text-gray-600 border rounded hover:bg-gray-50">
              取消
            </button>
          </div>
        </form>
      )}

      {newToken && (
        <div className="bg-yellow-50 border border-yellow-300 rounded p-4 mb-4">
          <p className="text-sm font-semibold text-yellow-800 mb-2">Token 建立成功，僅顯示此一次，請立即複製保存</p>
          <div className="flex gap-2 items-center mb-2">
            <code className="flex-1 bg-white border rounded px-3 py-2 text-xs font-mono break-all">{newToken.token}</code>
            <button
              onClick={handleCopy}
              className="px-3 py-2 text-sm border rounded bg-white hover:bg-gray-50 whitespace-nowrap"
            >
              {copied ? "已複製" : "複製"}
            </button>
          </div>
          <button
            onClick={() => { setNewToken(null); setCopied(false); }}
            className="text-xs text-gray-600 hover:underline"
          >
            我已保存，關閉
          </button>
        </div>
      )}

      <div className="space-y-2">
        {tokens.map((t) => (
          <div key={t.id} className="flex items-center justify-between py-2 border-b last:border-0">
            <div className="min-w-0 flex-1">
              <p className={`text-sm font-medium ${t.revoked ? "text-gray-600 line-through" : "text-gray-800"}`}>
                {t.name}
                <span className={`ml-2 text-xs px-1.5 py-0.5 rounded font-normal ${
                  t.scope === "admin" ? "bg-red-100 text-red-700" :
                  t.scope === "write" ? "bg-blue-100 text-blue-700" :
                  "bg-gray-100 text-gray-600"
                }`}>
                  {t.scope === "admin" ? "Admin" : t.scope === "write" ? "Write" : "Read"}
                </span>
              </p>
              <p className="text-xs text-gray-600 font-mono">{t.prefix}...</p>
              <p className="text-xs text-gray-500">
                建立：{t.created_at ? formatDateTime(t.created_at) : "—"}
                {" · "}
                上次使用：{t.last_used_at ? formatDateTime(t.last_used_at) : "尚未使用"}
              </p>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              {t.revoked ? (
                <span className="text-xs text-gray-600 bg-gray-100 px-2 py-0.5 rounded">已撤銷</span>
              ) : (
                <button
                  onClick={() => setConfirmRevoke(t)}
                  className="text-xs text-red-500 hover:underline"
                >
                  撤銷
                </button>
              )}
            </div>
          </div>
        ))}
        {tokens.length === 0 && (
          <p className="text-sm text-gray-600 text-center py-3">尚未建立 API Token</p>
        )}
      </div>

      <ConfirmModal
        isOpen={!!confirmRevoke}
        title="確認撤銷 API Token"
        message={`撤銷後「${confirmRevoke?.name}」將立即失效，且無法復原。`}
        confirmText="撤銷"
        cancelText="取消"
        isDangerous
        onConfirm={handleRevoke}
        onCancel={() => setConfirmRevoke(null)}
      />
    </div>
  );
}

function UserManagement({ flash }) {
  const [users, setUsers] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ username: "", password: "", role: "viewer" });
  const [saving, setSaving] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);

  const fetchUsers = () => api.get("/users").then((r) => setUsers(r.data)).catch(() => {});
  useEffect(() => { fetchUsers(); }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!form.username.trim() || !form.password.trim()) return;
    setSaving(true);
    try {
      await api.post("/users", form);
      flash("ok", "使用者已建立");
      setForm({ username: "", password: "", role: "viewer" });
      setShowForm(false);
      fetchUsers();
    } catch (err) {
      flash("err", err.response?.data?.detail || "建立失敗");
    } finally {
      setSaving(false);
    }
  };

  const handleToggleRole = async (u) => {
    const newRole = u.role === "admin" ? "viewer" : "admin";
    try {
      await api.patch(`/users/${u.id}`, { role: newRole });
      fetchUsers();
    } catch (err) {
      flash("err", err.response?.data?.detail || "更新失敗");
    }
  };

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await api.delete(`/users/${confirmDelete.id}`);
      flash("ok", "使用者已刪除");
      setConfirmDelete(null);
      fetchUsers();
    } catch (err) {
      flash("err", err.response?.data?.detail || "刪除失敗");
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="bg-white rounded-lg shadow p-5 mb-4">
      <div className="flex items-center justify-between mb-1">
        <h3 className="font-semibold text-gray-700">使用者管理</h3>
        <button
          onClick={() => setShowForm(!showForm)}
          className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
        >
          + 新增使用者
        </button>
      </div>
      <p className="text-xs text-gray-600 mb-4">管理可登入此平台的帳號，僅 admin 可見此設定</p>

      {showForm && (
        <form onSubmit={handleCreate} className="bg-gray-50 rounded p-4 mb-4 flex flex-col sm:flex-row gap-2 items-end flex-wrap">
          <div className="flex-1 min-w-[140px]">
            <label className="block text-xs font-medium text-gray-600 mb-1">帳號</label>
            <input
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              placeholder="username"
              className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
            />
          </div>
          <div className="flex-1 min-w-[140px]">
            <label className="block text-xs font-medium text-gray-600 mb-1">密碼（至少 6 字元）</label>
            <input
              type="password"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              className="w-full border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">角色</label>
            <select
              value={form.role}
              onChange={(e) => setForm({ ...form, role: e.target.value })}
              className="border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
            >
              <option value="viewer">Viewer（唯讀）</option>
              <option value="admin">Admin（管理員）</option>
            </select>
          </div>
          <div className="flex gap-2">
            <button type="submit" disabled={saving}
              className={`px-4 py-2 text-sm text-white rounded ${saving ? "bg-gray-400" : "bg-blue-600 hover:bg-blue-700"}`}>
              {saving ? "建立中..." : "建立"}
            </button>
            <button type="button" onClick={() => setShowForm(false)}
              className="px-4 py-2 text-sm text-gray-600 border rounded hover:bg-gray-50">
              取消
            </button>
          </div>
        </form>
      )}

      <div className="space-y-2">
        {users.map((u) => (
          <div key={u.id} className="flex items-center justify-between py-2 border-b last:border-0">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center text-sm font-bold">
                {u.username[0].toUpperCase()}
              </div>
              <div>
                <p className="text-sm font-medium text-gray-800">{u.username}</p>
                <p className="text-xs text-gray-600">{u.created_at ? formatDate(u.created_at) : ""}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {!u.is_active && (
                <span className="text-xs text-gray-600 bg-gray-100 px-2 py-0.5 rounded">已停用</span>
              )}
              <button
                onClick={() => handleToggleRole(u)}
                className={`px-2.5 py-0.5 rounded text-xs font-semibold cursor-pointer transition-colors ${
                  u.role === "admin"
                    ? "bg-blue-100 text-blue-700 hover:bg-blue-200"
                    : "bg-gray-100 text-gray-600 hover:bg-gray-200"
                }`}
                title="點擊切換角色"
              >
                {u.role === "admin" ? "Admin" : "Viewer"}
              </button>
              <button
                onClick={() => setConfirmDelete(u)}
                className="text-xs text-red-500 hover:underline"
              >
                刪除
              </button>
            </div>
          </div>
        ))}
        {users.length === 0 && (
          <p className="text-sm text-gray-600 text-center py-3">尚無使用者</p>
        )}

      <ConfirmModal
        isOpen={!!confirmDelete}
        title="確認刪除使用者"
        message={`確定要刪除使用者「${confirmDelete?.username}」？`}
        confirmText="刪除"
        cancelText="取消"
        isDangerous
        onConfirm={handleDelete}
        onCancel={() => setConfirmDelete(null)}
      />
      </div>
    </div>
  );
}
