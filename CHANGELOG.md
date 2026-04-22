# Changelog

所有版本的重要異動記錄。格式依照 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.0.0/)。

---

## [Unreleased] — Phase 2 進行中

### 計畫新增
- CSAF 2.0 完整匯入/匯出
- 供應商 VEX 鏈繼承（上游 VEX 自動帶入）
- 韌體掃描（EMBA 整合）
- CRA Article 14 合規證據包（完整版）

---

## [1.5.0] — 2026-03

### 新增
- IEC 62443-3-3 系統層級報告（11 項 SR 要求評估）
- IEC 62443-4-2 元件層級報告（4 大類 12 項 CR 要求）
- Policy 引擎：自訂規則自動偵測違規（e.g. Critical > 7 天未修補）
- 跨客戶風險總覽頁（各 Org 未修補 Critical/High 排行）
- CRA 事件管理（Article 14 狀態機 + 24h/72h/14d SLA 時鐘）
- 版本鎖定/解鎖（保護已核准版本）
- 版本 Diff 比對（兩版本間漏洞差異分析）
- 品牌化報告（Logo 上傳、主題色、頁尾）
- Webhook 通知（Slack/Teams 相容）
- Email 通知（SMTP 設定）

### 改善
- 儀表板新增修補追蹤區塊（修補率圓環圖、平均修補天數）
- VEX 歷程查詢（每次狀態變更完整記錄）

---

## [1.0.0] — 2025-12

### 新增（Phase 1 完成）
- 多租戶組織/產品/版本/元件 CRUD
- SBOM 上傳解析（CycloneDX JSON + SPDX JSON）
- CVE 掃描（OSV.dev API，依 PURL 批次查詢）
- VEX 狀態管理（open / in_triage / not_affected / affected / fixed）
- 批次 VEX 更新
- EPSS 整合（FIRST.org，利用可能性分數）
- CISA KEV 標記（已知被利用漏洞）
- NVD 豐富化（描述、CWE、CVSS v3/v4、參考連結）
- PDF 報告匯出（fpdf2）
- CSV 漏洞匯出
- CSAF VEX 文件產出
- 合規證據包 ZIP（PDF + CSAF + SBOM + 清單）
- SBOM 完整性驗證（SHA-256）
- 全域元件搜尋
- JWT 登入認證（Token 有效期 8 小時）
- 儀表板統計（嚴重度分布、處理狀態）
- 25/25 測試通過
