import { useEffect, useRef, useState } from "react";
import api from "../api/client";

export default function Settings() {
  // Alert settings
  const [cfg, setCfg] = useState(null);
  const [webhook, setWebhook] = useState("");
  const [email, setEmail] = useState("");
  const [saving, setSaving] = useState(false);
  const [testingWh, setTestingWh] = useState(false);
  const [testingEmail, setTestingEmail] = useState(false);

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
    }).catch(() => {});
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

  useEffect(() => { fetchCfg(); fetchBrand(); }, []);

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.patch("/settings/alerts", { webhook_url: webhook, alert_email_to: email });
      flash("ok", "通知設定已儲存");
      fetchCfg();
    } catch (e) {
      flash("err", e.response?.data?.detail || "儲存失敗");
    } finally {
      setSaving(false);
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

      {/* ── Brand settings ── */}
      <div className="bg-white rounded-lg shadow p-5 mb-4">
        <h3 className="font-semibold text-gray-700 mb-1">報告品牌設定</h3>
        <p className="text-xs text-gray-400 mb-4">設定後，PDF 報告將顯示貴公司 Logo、名稱與主色調</p>

        {/* Logo upload */}
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 mb-1">公司 Logo</label>
          <div className="flex items-center gap-3">
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
              <span className="text-xs text-gray-400">尚未上傳</span>
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
            <span className="text-xs text-gray-400">PNG / JPG，最大 2MB</span>
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
          <label className="block text-sm font-medium text-gray-700 mb-1">副標語 <span className="text-gray-400 font-normal">(選填)</span></label>
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
          <div className="flex items-center gap-3">
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
          <label className="block text-sm font-medium text-gray-700 mb-1">報告頁尾文字 <span className="text-gray-400 font-normal">(選填)</span></label>
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

      {/* ── Webhook ── */}
      <div className="bg-white rounded-lg shadow p-5 mb-4">
        <h3 className="font-semibold text-gray-700 mb-1">Webhook 通知</h3>
        <p className="text-xs text-gray-400 mb-3">重新掃描發現新漏洞時，POST JSON 到此 URL（支援 Slack / Teams / 自定義）</p>
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
        <p className="text-xs text-gray-400 mb-3">重新掃描發現新漏洞時寄送 Email 通知</p>
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
