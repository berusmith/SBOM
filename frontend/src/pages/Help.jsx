import { useState, useMemo, useEffect, useRef } from "react";

// ──────────────────────────────────────────────
// Help content data
// ──────────────────────────────────────────────
const SECTIONS = [
  {
    id: "quickstart",
    title: "快速入門",
    icon: "🚀",
    articles: [
      {
        id: "flow",
        title: "完整作業流程（8 步驟）",
        content: [
          {
            type: "steps",
            items: [
              { step: "Step 1", title: "建立客戶組織", body: "左側選單 → 客戶管理 → 新增組織。填入客戶公司名稱，授權狀態選 trial（正式收費後改 active）。所有資料以組織為隔離單位，不同客戶資料不互見。" },
              { step: "Step 2", title: "建立產品", body: "點進組織 → 新增產品。填入設備型號名稱（如：工業閘道器 GA-200）。一個組織可有多個產品。" },
              { step: "Step 3", title: "建立版本 & 上傳 SBOM", body: "點進產品 → 新增版本 → 填入版本號（如：v2.1.0）。進入版本詳情 → 上傳 SBOM（.json 格式）。支援 CycloneDX JSON 與 SPDX JSON。上傳後系統自動解析元件清單。" },
              { step: "Step 4", title: "掃描 CVE + 豐富化情資", body: "在版本頁面依序點擊：① 開始掃描（OSV.dev，對每個元件 PURL 查詢 CVE）→ ② 豐富化 EPSS（FIRST.org 利用可能性分數）→ ③ 豐富化 NVD（補充描述、CWE、CVSS v3/v4）。未設定 NVD API Key 時每筆約 7 秒，申請免費 Key 後速度提升 10 倍。" },
              { step: "Step 5", title: "VEX 標注（排除假陽性）", body: "SBOM 掃描常出現大量假陽性（元件有漏洞但產品未用到該功能）。在漏洞清單逐筆或批次標注 VEX 狀態。這是顧問最核心的加值服務。" },
              { step: "Step 6", title: "合規評估", body: "版本頁面 → 報告區塊。可產出 IEC 62443-4-1、4-2、3-3 三份評估報告，以及 CRA 合規摘要。" },
              { step: "Step 7", title: "產出報告與證據包", body: "下載 PDF 報告、CSV 匯出、CSAF VEX 文件，或一鍵下載合規證據包 ZIP（PDF + CSAF + SBOM 原始檔 + manifest）。客戶確認後鎖定版本。" },
              { step: "Step 8", title: "（視需要）建立 CRA 事件", body: "當發現已被積極利用的漏洞（CISA KEV 標記或確認 affected）時，依 EU CRA Article 14 需在規定時限內通報 ENISA。前往 CRA 事件頁面建立事件並啟動 SLA 時鐘。" },
            ],
          },
        ],
      },
      {
        id: "scenarios",
        title: "常見作業情境",
        content: [
          {
            type: "scenario",
            title: "情境 A：新版本上市前審查",
            body: "建立版本 → 上傳客戶提供的 SBOM → 掃描 + 豐富化 → VEX 標注排除假陽性 → 產出 IEC 62443 報告 + 合規證據包 → 鎖定版本。",
          },
          {
            type: "scenario",
            title: "情境 B：CVE 緊急事件回應（如 Log4Shell）",
            body: "① 全域搜尋欄輸入 log4j，找出所有受影響產品版本。② CRA 事件頁面建立事件，填入 CVE-2021-44228。③ 各版本進行 VEX 評估（哪些真正受影響？）。④ 啟動 SLA 時鐘，依時限提交 ENISA 報告。⑤ 修補後更新 VEX 為 fixed，下載最新報告。",
          },
          {
            type: "scenario",
            title: "情境 C：跨客戶週報",
            body: "左側選單 → 風險總覽，查看各組織未修補 Critical/High 數量排行，點進排名最高的組織優先處理。",
          },
        ],
      },
    ],
  },
  {
    id: "sbom",
    title: "SBOM 上傳與掃描",
    icon: "📦",
    articles: [
      {
        id: "upload",
        title: "支援的 SBOM 格式",
        content: [
          {
            type: "table",
            headers: ["格式", "版本", "PURL 支援", "授權欄位"],
            rows: [
              ["CycloneDX JSON", "1.4 / 1.5 / 1.6", "components[].purl", "components[].licenses"],
              ["SPDX JSON", "2.2 / 2.3", "packages[].externalRefs（PURL type）", "packages[].licenseConcluded"],
            ],
          },
          { type: "note", text: "有 PURL 的元件 CVE 掃描準確度最高。無 PURL 時系統以 name + version 模糊比對，可能有漏報。" },
        ],
      },
      {
        id: "scan",
        title: "CVE 掃描說明",
        content: [
          {
            type: "list",
            items: [
              "掃描引擎：OSV.dev API（Google 維護，涵蓋 NVD、GitHub Advisory、GHSA 等多來源）",
              "查詢方式：每個元件的 PURL 發送 POST /v1/query，結果以 (component_id, cve_id) 去重",
              "EPSS：FIRST.org API，提供 0–100% 利用可能性分數，數字越高代表越常被真實攻擊利用",
              "CISA KEV：CISA 已知被利用漏洞清單，KEV 標記的 CVE 必須優先處理",
              "NVD 豐富化：補充 CVE 描述、CWE 分類、CVSS v3/v4 向量、參考連結",
            ],
          },
          { type: "note", text: "NVD API Key 免費申請：https://nvd.nist.gov/developers/request-an-api-key。無 Key 時限速 1 req/7s；有 Key 可達 50 req/30s。" },
        ],
      },
      {
        id: "integrity",
        title: "SBOM 完整性驗證",
        content: [
          { type: "para", text: "上傳 SBOM 時系統自動計算 SHA-256 Hash 並儲存。之後可隨時點選「完整性驗證」確認檔案是否被竄改。這是 CRA Article 13 要求「SBOM 完整性」的技術佐證之一。" },
          { type: "para", text: "鎖定版本後，所有元件與漏洞資料均禁止修改，確保報告與 DB 狀態一致。" },
        ],
      },
    ],
  },
  {
    id: "vex",
    title: "VEX 標注指南",
    icon: "🏷️",
    articles: [
      {
        id: "vex-what",
        title: "什麼是 VEX？",
        content: [
          { type: "para", text: "VEX（Vulnerability Exploitability eXchange）是 CISA 制定的標準，用來聲明某個產品對某個 CVE 的實際可利用性。SBOM 掃描只能告訴你「元件有漏洞」，VEX 則告訴你「這個漏洞在我的產品中是否真的有風險」。" },
          { type: "para", text: "正確的 VEX 標注可大幅降低假陽性，讓報告更精準，也讓客戶更容易理解真正需要處理的項目。EU CRA 要求製造商發布 SBOM 時同時維護漏洞處置狀態，VEX 正是這項要求的技術實現。" },
        ],
      },
      {
        id: "vex-status",
        title: "VEX 狀態說明",
        content: [
          {
            type: "table",
            headers: ["狀態", "意義", "何時使用"],
            rows: [
              ["open", "尚未評估（預設）", "剛掃描完，還沒開始看"],
              ["in_triage", "評估中", "顧問正在分析是否受影響"],
              ["not_affected", "不受影響", "元件有漏洞但產品不會被利用"],
              ["affected", "確認受影響", "漏洞在此產品中可被利用，需要處置"],
              ["fixed", "已修補", "已升級元件或套用修補"],
            ],
          },
        ],
      },
      {
        id: "vex-justification",
        title: "not_affected 理由（justification）",
        content: [
          { type: "para", text: "標注 not_affected 時必須選擇理由，這是 CycloneDX VEX 規格的要求，也是合規報告的重要依據。" },
          {
            type: "table",
            headers: ["理由", "適用情境"],
            rows: [
              ["code_not_present", "漏洞元件根本未被打包進韌體（間接相依但未使用）"],
              ["code_not_reachable", "程式碼存在但執行路徑不可到達（如僅用於測試的程式碼路徑）"],
              ["requires_configuration", "需要特定非預設設定才能觸發（預設設定安全）"],
              ["requires_dependency", "需要搭配另一個未部署的相依才能利用"],
              ["requires_environment", "需要特定執行環境（如攻擊者需本機存取）"],
              ["protected_by_compiler", "編譯器保護（如 Stack Canary、ASLR）已緩解"],
              ["protected_at_runtime", "執行時期保護機制緩解（如 SELinux、容器隔離）"],
              ["protected_at_perimeter", "網路邊界保護（如防火牆、VPN 限制）"],
              ["protected_by_mitigating_control", "其他緩解控制（需在 detail 欄位說明）"],
            ],
          },
        ],
      },
      {
        id: "vex-affected",
        title: "affected 回應方式（response）",
        content: [
          {
            type: "table",
            headers: ["回應", "意義"],
            rows: [
              ["update", "計畫升級到修補版本"],
              ["workaround_available", "提供 workaround（需在 detail 說明）"],
              ["will_not_fix", "已知但決定不修補（需說明原因）"],
              ["can_not_fix", "技術上無法修補（如已停止維護的元件）"],
              ["rollback", "回滾到前一個安全版本"],
            ],
          },
        ],
      },
      {
        id: "vex-batch",
        title: "批次更新技巧",
        content: [
          { type: "para", text: "同一個元件（如 openssl 1.1.1）通常有多個 CVE，且處置方式相同。勾選全部相關 CVE，使用批次更新功能一次套用相同狀態與理由，可大幅縮短標注時間。" },
          { type: "para", text: "批次更新後仍可對個別 CVE 覆寫設定。所有狀態變更均自動記錄於 VEX 歷程，可供稽核查詢。" },
        ],
      },
    ],
  },
  {
    id: "cra",
    title: "CRA 事件管理",
    icon: "🚨",
    articles: [
      {
        id: "cra-overview",
        title: "EU CRA Article 14 說明",
        content: [
          { type: "para", text: "EU Cyber Resilience Act（CRA）Article 14 要求製造商在「知悉（awareness）」產品存在被積極利用的漏洞後，必須在規定時限內通報 ENISA（歐盟網路安全局）。" },
          {
            type: "table",
            headers: ["通報類型", "截止時限", "說明"],
            rows: [
              ["Early Warning", "知悉後 24 小時", "初步通知，告知事件存在"],
              ["Vulnerability Notification", "知悉後 72 小時", "詳細技術報告"],
              ["Final Report", "修補可用後 14 天內", "完整根因分析與修補說明"],
            ],
          },
          { type: "note", text: "強制執行日：2026 年 9 月 11 日。不合規罰款最高為全球年營收 2.5%。" },
        ],
      },
      {
        id: "cra-statemachine",
        title: "事件狀態機",
        content: [
          {
            type: "flow",
            steps: [
              { state: "detected", label: "偵測到漏洞", desc: "建立事件，尚未確認是否需要通報" },
              { state: "pending_triage", label: "等待分類", desc: "評估漏洞是否符合 CRA 通報條件" },
              { state: "clock_running", label: "時鐘啟動（T+0）", desc: "按下 start-clock = 法律意義上的知悉時間點，24h/72h 倒數開始" },
              { state: "t24_submitted", label: "Early Warning 已提交", desc: "T+24h 通報完成，記錄 ENISA 參考編號" },
              { state: "investigating", label: "調查中", desc: "技術分析與影響範圍確認" },
              { state: "t72_submitted", label: "Notification 已提交", desc: "T+72h 詳細通報完成" },
              { state: "remediating", label: "修補中", desc: "修補方案開發/部署中" },
              { state: "final_submitted", label: "Final Report 已提交", desc: "修補後 14 天內完成最終報告" },
              { state: "closed", label: "關閉", desc: "事件完成，所有稽核紀錄保留" },
            ],
          },
          { type: "note", text: "pending_triage 也可直接 → closed（close-not-affected），用於確認漏洞不符合通報條件的情況。" },
        ],
      },
      {
        id: "cra-clock",
        title: "SLA 時鐘操作注意事項",
        content: [
          { type: "para", text: "start-clock 按鈕代表法律意義上的「知悉時間點（awareness timestamp）」，按下後 T+24h 與 T+72h 倒數計時即刻開始。這個時間點在後續稽核中具有法律效力，確認要通報前再按，無法撤回。" },
          { type: "para", text: "系統設計上刻意將「建立事件」與「啟動時鐘」分開：允許先建立事件進行內部評估，確認屬於 CRA 通報範圍後再按 start-clock，保留緩衝空間。" },
        ],
      },
    ],
  },
  {
    id: "reports",
    title: "報告與匯出",
    icon: "📄",
    articles: [
      {
        id: "report-types",
        title: "可匯出的報告類型",
        content: [
          {
            type: "table",
            headers: ["報告", "格式", "說明"],
            rows: [
              ["主報告", "PDF", "含 Logo、客戶名、嚴重度分布圖、漏洞明細"],
              ["IEC 62443-4-1", "PDF", "11 項 SDL 要求評估（SM-9、DM-1~5、SUM-1~5）"],
              ["IEC 62443-4-2", "PDF", "元件層級 4 大類 12 項技術要求評估"],
              ["IEC 62443-3-3", "PDF", "系統層級 7 大 FR 安全要求評估"],
              ["漏洞清單", "CSV", "可交給客戶或匯入其他系統"],
              ["CSAF VEX", "JSON", "CSAF 2.0 格式，符合 EU CRA 要求的機器可讀 VEX 文件"],
              ["合規證據包", "ZIP", "PDF + CSAF + SBOM 原始檔 + manifest.json"],
            ],
          },
        ],
      },
      {
        id: "report-brand",
        title: "品牌化設定",
        content: [
          { type: "para", text: "設定 → 品牌設定：上傳公司 Logo（建議 PNG 背景透明，最大 2MB）、填入公司名稱與報告頁尾文字、設定主題色（HEX，影響 PDF 報告頁首顏色）。所有後續產出的 PDF 自動套用。" },
        ],
      },
      {
        id: "evidence",
        title: "合規證據包內容",
        content: [
          {
            type: "list",
            items: [
              "vulnerability_report.pdf — 完整漏洞分析 PDF 報告",
              "vex_statement.json — CSAF 2.0 格式 VEX 聲明",
              "sbom_original.json — 上傳時的原始 SBOM 檔案",
              "manifest.json — 清單（含各檔案 SHA-256、產生時間、版本資訊）",
            ],
          },
          { type: "para", text: "manifest.json 中的 Hash 可用於向稽核人員證明報告未被事後竄改。建議在版本鎖定後下載並存檔。" },
        ],
      },
    ],
  },
  {
    id: "compliance",
    title: "合規標準說明",
    icon: "✅",
    articles: [
      {
        id: "cra-art13",
        title: "EU CRA Article 13（安全要求）",
        content: [
          { type: "para", text: "CRA Article 13 要求製造商在產品生命週期內維護 SBOM、持續追蹤已知漏洞、在合理時間內提供安全更新。本平台的 VEX 管理、版本鎖定、完整性驗證均直接對應此要求。" },
          {
            type: "table",
            headers: ["CRA 要求", "平台對應功能"],
            rows: [
              ["維護 SBOM", "SBOM 上傳、版本管理、SHA-256 完整性驗證"],
              ["追蹤已知漏洞", "CVE 掃描、EPSS、KEV 標記"],
              ["漏洞處置狀態", "VEX 標注（open/affected/fixed/not_affected）"],
              ["安全更新記錄", "VEX 歷程、fixed_at 時間戳"],
            ],
          },
        ],
      },
      {
        id: "iec62443",
        title: "IEC 62443 對應說明",
        content: [
          { type: "para", text: "IEC 62443 是 ICS/OT 工業控制系統的主要國際資安標準，與 CRA 高度互補。取得 IEC 62443 認證是台灣 OT 製造商證明 CRA 合規的主要技術路徑。" },
          {
            type: "table",
            headers: ["子標準", "範疇", "本平台評估項目"],
            rows: [
              ["IEC 62443-4-1", "安全開發生命週期（SDL）", "SM-9 安全更新管理、DM-1~5 缺陷管理、SUM-1~5 安全更新程序"],
              ["IEC 62443-4-2", "元件技術安全要求", "CR-1 識別與認證、CR-2 使用控制、CR-3 系統完整性、CR-4 資料保密性"],
              ["IEC 62443-3-3", "系統安全要求", "FR-1~7 七大 Foundational Requirement"],
            ],
          },
        ],
      },
    ],
  },
  {
    id: "settings",
    title: "通知與設定",
    icon: "⚙️",
    articles: [
      {
        id: "notifications",
        title: "Webhook 與 Email 通知",
        content: [
          { type: "para", text: "設定 → 通知設定。設定後，系統在發現新漏洞或新 KEV 漏洞時自動發送通知。" },
          {
            type: "table",
            headers: ["通知類型", "說明"],
            rows: [
              ["Webhook", "POST JSON 至指定 URL。相容 Slack Incoming Webhook、Microsoft Teams Webhook。"],
              ["Email", "透過 SMTP 寄送。需在 backend/.env 設定 SMTP_HOST / SMTP_USER / SMTP_PASSWORD。"],
            ],
          },
        ],
      },
      {
        id: "env",
        title: "環境變數說明（backend/.env）",
        content: [
          {
            type: "table",
            headers: ["變數", "預設值", "說明"],
            rows: [
              ["SECRET_KEY", "change-me-in-production", "JWT 簽名金鑰，正式環境請修改"],
              ["ADMIN_USERNAME", "admin", "管理員帳號"],
              ["ADMIN_PASSWORD", "sbom@2024", "管理員密碼，正式環境請修改"],
              ["JWT_EXPIRE_HOURS", "8", "Token 有效時間（小時）"],
              ["NVD_API_KEY", "（空）", "NVD API Key，免費申請可大幅提升豐富化速度"],
              ["SMTP_HOST", "（空）", "Email 通知 SMTP 伺服器"],
              ["SMTP_PORT", "587", "SMTP 連接埠"],
              ["SMTP_USER", "（空）", "SMTP 帳號"],
              ["SMTP_PASSWORD", "（空）", "SMTP 密碼"],
              ["SMTP_FROM", "（空）", "寄件人 Email"],
            ],
          },
        ],
      },
      {
        id: "policies",
        title: "Policy 引擎",
        content: [
          { type: "para", text: "左側選單 → Policy。可設定自訂規則，系統自動偵測違規並在儀表板標記。" },
          {
            type: "list",
            items: [
              "範例：Critical 漏洞超過 7 天未修補 → 自動標記警告",
              "範例：High 漏洞 KEV 標記但狀態仍為 open → 立即告警",
              "所有違規記錄可匯出供稽核使用",
            ],
          },
        ],
      },
    ],
  },
  {
    id: "faq",
    title: "常見問題 FAQ",
    icon: "❓",
    articles: [
      {
        id: "faq-general",
        title: "一般問題",
        content: [
          {
            type: "faq",
            items: [
              {
                q: "後端啟動後 port 9100 被占用怎麼辦？",
                a: "執行：netstat -ano | findstr :9100 找出 PID，再執行 taskkill /PID <PID號碼> /F 終止程序，然後重新啟動後端。",
              },
              {
                q: "bcrypt 出現警告訊息「(trapped) error reading bcrypt version」？",
                a: "這是 passlib 與新版 bcrypt 的相容性警告，不影響任何功能，可安全忽略。",
              },
              {
                q: "NVD 豐富化很慢，要等很久？",
                a: "未設定 NVD API Key 時限速約 7 秒/筆。請至 https://nvd.nist.gov/developers/request-an-api-key 免費申請 API Key，填入 backend/.env 的 NVD_API_KEY，速度可提升約 10 倍。",
              },
              {
                q: "換電腦後資料怎麼辦？",
                a: "資料儲存在 backend/sbom.db（SQLite 資料庫）和 backend/uploads/（上傳的 SBOM 檔案）。這兩個目錄不進 git。換機器時需手動複製這兩個目錄，或重新建立資料。",
              },
              {
                q: "如何重設管理員密碼？",
                a: "修改 backend/.env 的 ADMIN_PASSWORD，刪除 backend/sbom.db，重新啟動後端（資料庫會重建並使用新密碼）。注意：這會清空所有資料。",
              },
            ],
          },
        ],
      },
      {
        id: "faq-sbom",
        title: "SBOM 相關",
        content: [
          {
            type: "faq",
            items: [
              {
                q: "上傳 SBOM 後元件數量比預期少？",
                a: "請確認 SBOM 格式正確：CycloneDX 需有 components[] 陣列，SPDX 需有 packages[] 陣列。部分工具產生的 SBOM 格式不完全符合規格，可用 CycloneDX CLI 或 syft 重新產生。",
              },
              {
                q: "掃描後大量 CVE 都是假陽性怎麼辦？",
                a: "這是正常現象，尤其是有許多間接相依元件時。使用批次 VEX 更新，對同一元件的所有 CVE 批次標注 not_affected + code_not_present，可快速清除假陽性。之後設定 Policy 規則讓系統自動偵測真正需要關注的漏洞。",
              },
              {
                q: "CSAF VEX 文件是什麼？有什麼用？",
                a: "CSAF（Common Security Advisory Framework）2.0 是 OASIS 標準，也是 EU CRA 指定的機器可讀漏洞通報格式。製造商發布安全公告或向 ENISA 通報時，CSAF 格式讓資訊可以被自動化工具解析與處理。",
              },
              {
                q: "版本鎖定後還可以解鎖嗎？",
                a: "可以。有管理員權限的帳號可以解鎖。解鎖有稽核紀錄。建議在有正當理由（如發現資料錯誤）時才解鎖，解鎖後修改完畢再重新鎖定。",
              },
            ],
          },
        ],
      },
      {
        id: "faq-cra",
        title: "CRA 法規相關",
        content: [
          {
            type: "faq",
            items: [
              {
                q: "什麼情況下需要啟動 CRA 事件通報流程？",
                a: "當產品的漏洞被「積極利用（actively exploited）」時需要通報。判斷依據：(1) 漏洞在 CISA KEV 清單上，(2) 有公開的 exploit PoC 且確認影響此產品，(3) 已有客戶回報遭攻擊。純理論漏洞不需通報。",
              },
              {
                q: "T+24h 的「知悉」時間點怎麼計算？",
                a: "按下 start-clock 按鈕的時間即為法律意義上的知悉時間點。建議在確認事件屬於 CRA 通報範圍後再按，因為這個時間點無法修改且具法律效力。",
              },
              {
                q: "如果趕不上 T+24h 怎麼辦？",
                a: "應盡快提交，並在 Early Warning 內容中說明知悉到提交之間的延遲原因。CRA 允許在「有合理理由」時稍微延遲，但需要文件佐證。延遲比不提交好。",
              },
            ],
          },
        ],
      },
    ],
  },
  {
    id: "tisax",
    title: "TISAX 自評",
    icon: "🏭",
    articles: [
      {
        id: "tisax-what",
        title: "什麼是 TISAX？",
        content: [
          {
            type: "text",
            body: "TISAX（Trusted Information Security Assessment Exchange）是德國汽車工業協會（VDA）制定的資訊安全評估機制，基於 VDA ISA 6.0 標準。德系 OEM（BMW、Mercedes-Benz、Volkswagen Group 等）要求供應商通過 TISAX 評估才能參與敏感專案。",
          },
          {
            type: "table",
            headers: ["評估等級", "稽核方式", "適用情境"],
            rows: [
              ["AL1", "自評（無外部驗證）", "一般資訊交換"],
              ["AL2", "遠端稽核（ENX 認可機構）", "機密資訊、原型相關專案"],
              ["AL3", "現場稽核", "高度敏感原型、測試車"],
            ],
          },
          {
            type: "note",
            text: "本平台支援 AL1 自評準備與 AL2/AL3 差距分析，但實際 TISAX 認證需透過 ENX Portal 申請正式稽核。",
          },
        ],
      },
      {
        id: "tisax-modules",
        title: "評估模組說明",
        content: [
          {
            type: "table",
            headers: ["模組", "控制項數", "適用情境"],
            rows: [
              ["資訊安全（IS）", "41 項（7 章）", "所有申請者必評"],
              ["原型保護（PP）", "22 項（8 子類）", "接觸研發樣品、測試車、未公開零件"],
            ],
          },
          {
            type: "list",
            items: [
              "資訊安全模組涵蓋：政策與組織、人資安全、實體安全、存取控制、IT 安全、供應商管理、合規共 7 章",
              "原型保護模組涵蓋：安全分類、合約管理、實體安全、人員管理、訪客管理、原型車輛、測試試駕、活動展示",
              "兩個模組可同時建立，分別評估",
            ],
          },
        ],
      },
      {
        id: "tisax-create",
        title: "新增評估與填寫自評",
        content: [
          {
            type: "steps",
            items: [
              { step: "Step 1", title: "新增評估", body: "左側選單 → TISAX → 點擊「新增評估」。Admin 需選擇客戶組織；Viewer 自動綁定自己的組織。選擇模組（資訊安全 / 原型保護）與評估等級（AL1/AL2/AL3）。系統自動建立對應的控制項清單。" },
              { step: "Step 2", title: "展開控制項", body: "在評估頁面點擊任一控制項列可展開詳情。顯示：控制項名稱、要求重點描述、目前狀態。" },
              { step: "Step 3", title: "填寫成熟度", body: "點擊「編輯評估結果」，設定「當前成熟度」（0–5）和「目標成熟度」。建議目標設為 3（可預測）以上才能通過 AL2 稽核。" },
              { step: "Step 4", title: "填寫證據說明", body: "在「證據說明」欄描述現有的控制措施（如：已建立 MFA、定期進行備份測試等）。填寫負責人與預計完成日，便於追蹤改善進度。" },
              { step: "Step 5", title: "確認狀態自動計算", body: "系統根據「當前成熟度 vs 目標成熟度」自動計算狀態：達標（current ≥ target）、接近（差 1 級）、缺口（差 2 級以上）、未評（current = 0）。" },
            ],
          },
        ],
      },
      {
        id: "tisax-maturity",
        title: "成熟度等級定義（0–5）",
        content: [
          {
            type: "table",
            headers: ["等級", "名稱", "說明"],
            rows: [
              ["0", "未執行", "完全未實施此控制措施"],
              ["1", "臨時措施", "有些對應行為，但非正式化，依賴個人"],
              ["2", "已執行", "措施已正式實施並文件化"],
              ["3", "可預測", "流程已標準化、可重複，並定期審查"],
              ["4", "可測量", "有 KPI 衡量效果，持續監控"],
              ["5", "最佳化", "持續改善，對應業界最佳實踐"],
            ],
          },
          {
            type: "note",
            text: "AL2 稽核通常要求核心控制項達到成熟度 3（可預測）。建議將目標成熟度設為 3，差距分析報告即顯示需要改善的項目。",
          },
        ],
      },
      {
        id: "tisax-gap",
        title: "差距分析與報告匯出",
        content: [
          {
            type: "list",
            items: [
              "點擊「差距分析」頁籤，查看所有缺口項目（按差距大小排序）與接近項目",
              "GO/NO-GO 判定：AL1 門檻 80%、AL2 門檻 90%、AL3 門檻 95% 控制項達標",
              "「匯出 PDF」：產出完整自評報告，包含摘要計分卡、達標率進度條、缺口清單、完整控制項清單。適合提交給客戶或 ENX 稽核員參考",
              "「匯出 CSV」：所有控制項含成熟度、證據說明、負責人、完成日的 Excel 相容格式，適合內部追蹤改善進度",
            ],
          },
          {
            type: "note",
            text: "TISAX 正式認證需在 ENX Portal（portal.enx.com）申請，由 ENX 認可機構執行稽核。本平台的自評結果是稽核準備的內部工具，不能直接作為認證文件。",
          },
        ],
      },
    ],
  },
];

// ──────────────────────────────────────────────
// Utilities
// ──────────────────────────────────────────────
function flattenText(content) {
  return content
    .map((block) => {
      if (block.type === "para" || block.type === "note") return block.text;
      if (block.type === "list") return block.items.join(" ");
      if (block.type === "table") return block.rows.flat().join(" ");
      if (block.type === "steps") return block.items.map((i) => i.title + " " + i.body).join(" ");
      if (block.type === "scenario") return block.title + " " + block.body;
      if (block.type === "faq") return block.items.map((i) => i.q + " " + i.a).join(" ");
      if (block.type === "flow") return block.steps.map((s) => s.label + " " + s.desc).join(" ");
      return "";
    })
    .join(" ");
}

function highlight(text, query) {
  if (!query) return text;
  const parts = text.split(new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "gi"));
  return parts.map((part, i) =>
    part.toLowerCase() === query.toLowerCase() ? (
      <mark key={i} className="bg-yellow-200 rounded px-0.5">{part}</mark>
    ) : part
  );
}

// ──────────────────────────────────────────────
// Content renderers
// ──────────────────────────────────────────────
function renderBlock(block, idx, query) {
  const hl = (t) => highlight(t, query);

  if (block.type === "para") {
    return <p key={idx} className="text-gray-700 leading-relaxed mb-3">{hl(block.text)}</p>;
  }

  if (block.type === "note") {
    return (
      <div key={idx} className="bg-blue-50 border-l-4 border-blue-400 rounded-r px-4 py-3 mb-4 text-sm text-blue-800">
        <span className="font-semibold">注意：</span> {hl(block.text)}
      </div>
    );
  }

  if (block.type === "list") {
    return (
      <ul key={idx} className="list-disc list-inside space-y-1.5 mb-4 text-gray-700">
        {block.items.map((item, i) => <li key={i} className="leading-relaxed">{hl(item)}</li>)}
      </ul>
    );
  }

  if (block.type === "table") {
    return (
      <div key={idx} className="overflow-x-auto mb-4">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="bg-gray-100">
              {block.headers.map((h, i) => (
                <th key={i} className="text-left px-3 py-2 border border-gray-200 font-semibold text-gray-700">{hl(h)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {block.rows.map((row, ri) => (
              <tr key={ri} className={ri % 2 === 0 ? "bg-white" : "bg-gray-50"}>
                {row.map((cell, ci) => (
                  <td key={ci} className="px-3 py-2 border border-gray-200 text-gray-700 align-top">{hl(cell)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (block.type === "steps") {
    return (
      <ol key={idx} className="space-y-4 mb-4">
        {block.items.map((item, i) => (
          <li key={i} className="flex gap-4">
            <span className="shrink-0 w-20 text-xs font-bold text-blue-600 bg-blue-50 rounded px-2 py-1 h-fit mt-0.5 text-center">{item.step}</span>
            <div>
              <div className="font-semibold text-gray-800 mb-1">{hl(item.title)}</div>
              <div className="text-gray-600 text-sm leading-relaxed">{hl(item.body)}</div>
            </div>
          </li>
        ))}
      </ol>
    );
  }

  if (block.type === "scenario") {
    return (
      <div key={idx} className="bg-green-50 border border-green-200 rounded-lg px-4 py-3 mb-3">
        <div className="font-semibold text-green-800 mb-1">{hl(block.title)}</div>
        <div className="text-sm text-green-700 leading-relaxed">{hl(block.body)}</div>
      </div>
    );
  }

  if (block.type === "flow") {
    return (
      <ol key={idx} className="space-y-2 mb-4">
        {block.steps.map((s, i) => (
          <li key={i} className="flex items-start gap-3">
            <div className="shrink-0 flex flex-col items-center">
              <span className="w-7 h-7 rounded-full bg-blue-600 text-white text-xs flex items-center justify-center font-bold">{i + 1}</span>
              {i < block.steps.length - 1 && <div className="w-0.5 h-5 bg-gray-300 mt-1" />}
            </div>
            <div className="pb-2">
              <span className="font-semibold text-gray-800">{hl(s.label)}</span>
              <span className="text-xs text-gray-400 ml-2 font-mono">{s.state}</span>
              <div className="text-sm text-gray-600 mt-0.5">{hl(s.desc)}</div>
            </div>
          </li>
        ))}
      </ol>
    );
  }

  if (block.type === "faq") {
    return (
      <div key={idx} className="space-y-3 mb-4">
        {block.items.map((item, i) => (
          <details key={i} className="border border-gray-200 rounded-lg group">
            <summary className="px-4 py-3 cursor-pointer font-medium text-gray-800 hover:bg-gray-50 rounded-lg select-none flex justify-between items-center">
              <span>{hl(item.q)}</span>
              <span className="text-gray-400 group-open:rotate-180 transition-transform ml-2 shrink-0">▾</span>
            </summary>
            <div className="px-4 pb-3 pt-1 text-sm text-gray-700 leading-relaxed border-t border-gray-100">
              {hl(item.a)}
            </div>
          </details>
        ))}
      </div>
    );
  }

  return null;
}

// ──────────────────────────────────────────────
// Search results view
// ──────────────────────────────────────────────
function SearchResults({ query, onSelect }) {
  const results = useMemo(() => {
    const q = query.toLowerCase();
    const found = [];
    for (const section of SECTIONS) {
      for (const article of section.articles) {
        const text = article.title + " " + flattenText(article.content);
        if (text.toLowerCase().includes(q)) {
          found.push({ section, article });
        }
      }
    }
    return found;
  }, [query]);

  if (results.length === 0) {
    return (
      <div className="text-center py-16 text-gray-400">
        <div className="text-4xl mb-3">🔍</div>
        <div>找不到「{query}」相關內容</div>
      </div>
    );
  }

  return (
    <div>
      <div className="text-sm text-gray-500 mb-4">找到 {results.length} 筆結果</div>
      <div className="space-y-4">
        {results.map(({ section, article }) => (
          <div
            key={article.id}
            onClick={() => onSelect(section.id, article.id)}
            className="border border-gray-200 rounded-lg px-4 py-3 hover:border-blue-400 hover:bg-blue-50 cursor-pointer transition-colors"
          >
            <div className="text-xs text-gray-400 mb-1">{section.icon} {section.title}</div>
            <div className="font-semibold text-blue-700">{highlight(article.title, query)}</div>
            <div className="text-sm text-gray-500 mt-1 line-clamp-2">
              {highlight(flattenText(article.content).slice(0, 150), query)}…
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────
// Article view
// ──────────────────────────────────────────────
function ArticleView({ section, article, query }) {
  const ref = useRef(null);
  useEffect(() => {
    ref.current?.scrollTo({ top: 0 });
  }, [article.id]);

  return (
    <div ref={ref} className="h-full overflow-y-auto">
      <div className="text-xs text-gray-400 mb-1">{section.icon} {section.title}</div>
      <h2 className="text-xl font-bold text-gray-900 mb-5 pb-3 border-b border-gray-200">
        {highlight(article.title, query)}
      </h2>
      {article.content.map((block, idx) => renderBlock(block, idx, query))}
    </div>
  );
}

// ──────────────────────────────────────────────
// Main component
// ──────────────────────────────────────────────
export default function Help() {
  const [query, setQuery] = useState("");
  const [activeSectionId, setActiveSectionId] = useState(SECTIONS[0].id);
  const [activeArticleId, setActiveArticleId] = useState(SECTIONS[0].articles[0].id);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const activeSection = SECTIONS.find((s) => s.id === activeSectionId);
  const activeArticle = activeSection?.articles.find((a) => a.id === activeArticleId);

  const handleSelect = (sectionId, articleId) => {
    setActiveSectionId(sectionId);
    setActiveArticleId(articleId);
    setQuery("");
    setSidebarOpen(false);
  };

  const isSearching = query.trim().length > 0;

  return (
    <div className="flex flex-col h-[calc(100vh-7rem)]">
      {/* Header */}
      <div className="flex items-center gap-3 mb-4 flex-wrap">
        <h1 className="text-xl font-bold text-gray-900">說明中心</h1>
        <div className="flex-1 min-w-48 max-w-md relative">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="搜尋說明內容..."
            className="w-full border border-gray-300 rounded-lg px-4 py-2 pl-9 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
          />
          <span className="absolute left-3 top-2.5 text-gray-400 text-sm">🔍</span>
          {query && (
            <button onClick={() => setQuery("")} className="absolute right-3 top-2.5 text-gray-400 hover:text-gray-600 text-xs">✕</button>
          )}
        </div>
        {/* Mobile sidebar toggle */}
        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className="md:hidden px-3 py-2 border border-gray-300 rounded-lg text-sm text-gray-600"
        >
          目錄
        </button>
      </div>

      <div className="flex flex-1 gap-4 min-h-0">
        {/* Sidebar */}
        <aside className={`
          ${sidebarOpen ? "block fixed left-4 right-4 top-32 bottom-4 md:static z-40 bg-white shadow-lg rounded-lg p-3 w-auto overflow-y-auto" : "hidden"}
          md:block md:relative md:z-auto md:bg-transparent md:shadow-none md:rounded-none md:p-0 md:w-52 lg:w-60 shrink-0 md:bottom-auto
        `}>
          <nav className="space-y-1">
            {SECTIONS.map((section) => (
              <div key={section.id}>
                <div className="text-xs font-semibold text-gray-500 uppercase tracking-wider px-2 pt-3 pb-1">
                  {section.icon} {section.title}
                </div>
                {section.articles.map((article) => (
                  <button
                    key={article.id}
                    onClick={() => handleSelect(section.id, article.id)}
                    className={`w-full text-left px-3 py-1.5 rounded text-sm transition-colors ${
                      !isSearching && activeSectionId === section.id && activeArticleId === article.id
                        ? "bg-blue-600 text-white"
                        : "text-gray-600 hover:bg-gray-100 hover:text-gray-900"
                    }`}
                  >
                    {article.title}
                  </button>
                ))}
              </div>
            ))}
          </nav>
        </aside>

        {/* Content */}
        <main className="flex-1 bg-white border border-gray-200 rounded-lg p-5 sm:p-6 overflow-y-auto min-h-0">
          {isSearching ? (
            <SearchResults query={query.trim()} onSelect={handleSelect} />
          ) : activeSection && activeArticle ? (
            <ArticleView section={activeSection} article={activeArticle} query="" />
          ) : null}
        </main>
      </div>
    </div>
  );
}
