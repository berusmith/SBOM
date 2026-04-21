import { useEffect, useState } from "react";
import api from "../api/client";

export default function Settings() {
  const [cfg, setCfg] = useState(null);
  const [webhook, setWebhook] = useState("");
  const [email, setEmail] = useState("");
  const [saving, setSaving] = useState(false);
  const [testingWh, setTestingWh] = useState(false);
  const [testingEmail, setTestingEmail] = useState(false);
  const [msg, setMsg] = useState(null); // {type: 'ok'|'err', text}

  const flash = (type, text) => { setMsg({ type, text }); setTimeout(() => setMsg(null), 4000); };

  const fetchCfg = () => {
    api.get("/settings/alerts").then((r) => {
      setCfg(r.data);
      setWebhook(r.data.webhook_url || "");
      setEmail(r.data.alert_email_to || "");
    }).catch(() => {});
  };

  useEffect(() => { fetchCfg(); }, []);

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.patch("/settings/alerts", { webhook_url: webhook, alert_email_to: email });
      flash("ok", "設定已儲存");
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

  return (
    <div className="max-w-2xl">
      <h2 className="text-xl font-bold text-gray-800 mb-6">通知設定</h2>

      {msg && (
        <div className={`mb-4 px-4 py-3 rounded text-sm ${msg.type === "ok" ? "bg-green-50 text-green-700" : "bg-red-50 text-red-600"}`}>
          {msg.text}
        </div>
      )}

      {/* Webhook */}
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

      {/* Email */}
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

        {/* SMTP status */}
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
        {saving ? "儲存中..." : "儲存設定"}
      </button>
    </div>
  );
}
