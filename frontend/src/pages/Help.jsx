export default function Help() {
  const sections = [
    {
      title: "快速開始",
      color: "blue",
      items: [
        {
          step: "1",
          heading: "建立客戶",
          body: "點選「客戶管理」→「新增客戶」，填入客戶名稱與聯絡 Email。一個客戶可以有多個產品。",
        },
        {
          step: "2",
          heading: "新增產品與版本",
          body: "進入客戶後點「新增產品」，再進入產品頁新增版本（Release）。每個版本對應一份 SBOM 檔案。",
        },
        {
          step: "3",
          heading: "上傳 SBOM",
          body: "進入版本詳情頁，點「選擇檔案」上傳 SBOM（支援 CycloneDX JSON、SPDX JSON）。上傳後系統自動解析元件並透過 OSV.dev 掃描 CVE。",
        },
        {
          step: "4",
          heading: "處理漏洞 (VEX)",
          body: "在版本詳情的「漏洞」頁籤，點每筆漏洞右側「編輯」按鈕更新 VEX 狀態：Open → In Triage → Affected / Not Affected / Fixed。",
        },
      ],
    },
    {
      title: "漏洞情資",
      color: "orange",
      items: [
        {
          heading: "EPSS 分數",
          body: "更新 EPSS 後，顯示 FIRST.org 的實際被利用機率（0–100%）。≥10% 標橙色，≥50% 標紅色。可用「僅顯示高 EPSS」快速篩選。",
        },
        {
          heading: "CISA KEV 標記",
          body: "標有「KEV」紅色徽章的漏洞代表已知被實際利用（Known Exploited Vulnerabilities），需優先處理。",
        },
        {
          heading: "NVD 豐富化",
          body: "點「更新 NVD」後，系統從 NVD API 補充 CVE 描述、CWE 分類、CVSS v3/v4 分數與參考連結。點 CVE ID 展開可查看。",
        },
      ],
    },
    {
      title: "報告與匯出",
      color: "green",
      items: [
        {
          heading: "PDF 報告",
          body: "產生包含品牌 Logo、漏洞清單、VEX 狀態的完整 PDF 報告。可在「通知設定 → 品牌設定」自訂 Logo、公司名稱與主題色。",
        },
        {
          heading: "IEC 62443 合規報告",
          body: "針對 11 項 IEC 62443-4-1 要求（SM-9、DM-1~5、SUM-1~5）自動評估並產生 PDF 報告。",
        },
        {
          heading: "CSAF VEX 文件",
          body: "依 CSAF 2.0 標準匯出 VEX 文件，可提交給客戶或監管機構作為漏洞處置証明。",
        },
        {
          heading: "證據包 ZIP",
          body: "打包 PDF 報告 + CSAF VEX + 原始 SBOM 檔案 + 清單為一個 ZIP，方便整包存檔或提交稽核。",
        },
        {
          heading: "CSV 匯出",
          body: "將漏洞清單（含 CVSS、EPSS、VEX 狀態）匯出為 CSV，方便在 Excel 中進一步分析。",
        },
      ],
    },
    {
      title: "合規管理",
      color: "red",
      items: [
        {
          heading: "CRA 事件管理",
          body: "EU CRA Article 14 要求在 24 小時內通報重大漏洞事件。在「CRA 事件」頁建立事件後，啟動時鐘會自動追蹤 T+24h / T+72h / T+14d 各項法規期限。",
        },
        {
          heading: "Policy 引擎",
          body: "在「Policy」頁自訂規則，例如「Critical 漏洞超過 7 天未修補則警告」。系統自動比對所有版本並在版本詳情頁顯示違規警示。",
        },
        {
          heading: "SBOM 完整性驗證",
          body: "點「完整性驗證」按鈕，系統以 SHA-256 確認 SBOM 檔案未被竄改，保護已核准版本的可信度。",
        },
        {
          heading: "版本鎖定",
          body: "鎖定版本後，禁止上傳新 SBOM、重新掃描或修改 VEX 狀態，保護已稽核通過的版本記錄。",
        },
      ],
    },
    {
      title: "分析與總覽",
      color: "purple",
      items: [
        {
          heading: "儀表板",
          body: "顯示全平台的漏洞嚴重度分布、VEX 處理狀態、修補率，以及「需處理的高風險漏洞 Top 10」清單，可直接點擊跳到對應版本。",
        },
        {
          heading: "跨客戶風險總覽",
          body: "依風險分數（Critical×10 + High×3 + 進行中 CRA×5）排列所有客戶，快速識別最需關注的組織。",
        },
        {
          heading: "版本比對 Diff",
          body: "在版本列表頁點「版本比對」，選兩個版本後可看到新增 / 移除 / 變更的漏洞差異，適合評估升級影響。",
        },
        {
          heading: "全域元件搜尋",
          body: "頂端導覽列的搜尋框可跨所有客戶搜尋元件名稱，快速找出哪些產品使用了特定元件（如 Log4j）。",
        },
      ],
    },
    {
      title: "通知與設定",
      color: "gray",
      items: [
        {
          heading: "Webhook 通知",
          body: "在「通知設定」設定 Webhook URL（支援 Slack / Teams），每當發現新漏洞時自動推送通知。",
        },
        {
          heading: "Email 通知",
          body: "設定 SMTP 後，新漏洞發現時自動寄送 Email 通知。需在後端 .env 設定 SMTP 參數。",
        },
        {
          heading: "品牌設定",
          body: "上傳公司 Logo、設定公司名稱、主題色與頁尾文字，所有 PDF 報告都會套用品牌樣式。",
        },
      ],
    },
  ];

  const colorMap = {
    blue:   { header: "bg-blue-600",   badge: "bg-blue-100 text-blue-700",   step: "bg-blue-600 text-white" },
    orange: { header: "bg-orange-500", badge: "bg-orange-100 text-orange-700", step: "bg-orange-500 text-white" },
    green:  { header: "bg-emerald-600",badge: "bg-emerald-100 text-emerald-700", step: "bg-emerald-600 text-white" },
    red:    { header: "bg-red-600",    badge: "bg-red-100 text-red-700",     step: "bg-red-600 text-white" },
    purple: { header: "bg-violet-600", badge: "bg-violet-100 text-violet-700", step: "bg-violet-600 text-white" },
    gray:   { header: "bg-gray-600",   badge: "bg-gray-100 text-gray-700",   step: "bg-gray-600 text-white" },
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-800">使用說明</h1>
        <p className="text-gray-500 mt-1 text-sm">SBOM Management Platform — ICS/OT 製造商合規管理平台</p>
      </div>

      {/* CRA countdown banner */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg px-5 py-4 mb-6 flex items-center justify-between">
        <div>
          <p className="font-semibold text-blue-800 text-sm">EU CRA Article 14 強制執行日：2026 年 9 月 11 日</p>
          <p className="text-blue-600 text-xs mt-0.5">製造商需在發現漏洞後 24 小時內通報 ENISA；72 小時內提交早期預警；14 天內提交完整報告。</p>
        </div>
        <span className="text-xs text-blue-500 bg-blue-100 px-3 py-1 rounded-full font-medium whitespace-nowrap ml-4">Article 14</span>
      </div>

      <div className="space-y-6">
        {sections.map((sec) => {
          const c = colorMap[sec.color];
          return (
            <div key={sec.title} className="bg-white rounded-lg shadow overflow-hidden">
              <div className={`${c.header} px-5 py-3`}>
                <h2 className="text-white font-semibold">{sec.title}</h2>
              </div>
              <div className="p-5 grid grid-cols-1 md:grid-cols-2 gap-4">
                {sec.items.map((item, i) => (
                  <div key={i} className="flex gap-3">
                    {item.step ? (
                      <span className={`w-7 h-7 rounded-full flex items-center justify-center text-sm font-bold shrink-0 mt-0.5 ${c.step}`}>
                        {item.step}
                      </span>
                    ) : (
                      <span className={`px-2 py-0.5 rounded text-xs font-medium h-fit shrink-0 mt-0.5 ${c.badge}`}>
                        功能
                      </span>
                    )}
                    <div>
                      <p className="font-medium text-gray-800 text-sm">{item.heading}</p>
                      <p className="text-gray-500 text-sm mt-0.5 leading-relaxed">{item.body}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>

      {/* Keyboard shortcuts */}
      <div className="mt-6 bg-white rounded-lg shadow p-5">
        <h2 className="font-semibold text-gray-700 mb-3">常見操作提示</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm text-gray-600">
          <div className="flex gap-2"><span className="text-gray-400">→</span> 點擊 CVE ID 可展開查看 NVD 描述、CWE、CVSS 詳情與參考連結</div>
          <div className="flex gap-2"><span className="text-gray-400">→</span> 勾選多筆漏洞後，底部浮出批次更新列可一次更改 VEX 狀態</div>
          <div className="flex gap-2"><span className="text-gray-400">→</span> 儀表板「高風險漏洞」清單可直接點擊跳至對應版本頁面</div>
          <div className="flex gap-2"><span className="text-gray-400">→</span> 版本鎖定前請先完成所有 VEX 評估，鎖定後無法再修改</div>
          <div className="flex gap-2"><span className="text-gray-400">→</span> Policy 違規會在版本詳情頁頂端顯示紅色/橙色警示徽章</div>
          <div className="flex gap-2"><span className="text-gray-400">→</span> 頂端搜尋框可跨客戶搜尋元件名稱（例如搜尋 log4j）</div>
        </div>
      </div>

      <p className="text-center text-xs text-gray-400 mt-6">
        API 文件：<a href="http://localhost:9100/docs" target="_blank" rel="noreferrer" className="text-blue-500 hover:underline">http://localhost:9100/docs</a>
      </p>
    </div>
  );
}
