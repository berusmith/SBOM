# Changelog

所有版本的重要異動記錄。格式依照 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.0.0/)。

---

## [Unreleased]

### 計畫中
- 部署 Oracle Cloud 生產環境（所有功能已完成）
- Binary SBOM 生成（Syft，等客戶需求）
- FDA Pre-market 合規報告（等醫材客戶）

---

## [2.0.0] — 2026-04

### 安全性修正（P1）
- **DELETE /releases 權限修正**：加入 `require_admin` 守衛，viewer 無法刪除 release
- **SBOM 品質評分 DB 快取**：上傳時計算 score/grade 寫入 `releases` 表，`/stats/sbom-quality-summary` 不再每次讀全部 SBOM 檔案
- **top-risky-components SQL 聚合**：改用 SQL `GROUP BY` + `SUM(CASE)`，不再載入全部 Component 到 Python
- **CRA incident 多租戶隔離**：合規報告（IEC 62443-4-1/3-3、NIS2）的 CRA incident 查詢加入 `org_id` 過濾
- **SSO 帳號需審批**：OIDC 自動建立的帳號預設 `is_active=False`，需管理員啟用

### 效能與 UX 改善（P2）
- **ReleaseDetail re-render 優化**：~15 個下載/匯出 useState 合併為 `busy` 物件
- **useMemo 優化**：`displayedVulns`、`severityCounts` 加 `useMemo`，只在篩選條件變更時重算
- **Dashboard AbortController**：5 個 API 請求加 AbortController，離開頁面自動取消
- **合規報告去重複查詢**：移除 4 處重複的 Product/Org 查詢，直接使用 `_assert_release_org` 回傳值
- **Dashboard i18n 補齊**：高風險元件表格 6 處硬編碼中文改用 `t()`

### 其他改善
- **使用者管理強化**：編輯帳號支援修改登入帳號（username）；新增帳號表單加入 Email 欄位；列表新增 Email 欄
- **測試修正**：viewer 建立測試加 `organization_id`；測試數從 39 → 55 項
- **移除重複 /health 端點**（死碼）
- **React Router v7 future flag 警告消除**

### 修正（TISAX 功能補強）
- **個資保護模組（Data Protection）**：新增 4 項 GDPR 相關控制項（DP-9.1 個資保護政策、DP-9.2 個資識別與分類、DP-9.3 資料主體權利管理、DP-9.4 個資洩漏事件 72h 通報）；建立評估時可選「個資保護（4 項，GDPR）」；VDA ISA 6.0 控制項從 65 → 69 項
- **Plan 檢查補齊**：`GET /assessments/{id}`、`PATCH /controls/{id}`、`DELETE /assessments/{id}` 補加 `require_plan("tisax")`，所有端點一致要求 Professional plan
- **TISAX 稽核紀錄整合**：建立 / 控制項更新 / 刪除評估寫入 `audit_events`（`tisax_create / tisax_control_update / tisax_delete`）；AdminActivity 頁加入對應事件標籤

### 改善（通知與搜尋）
- **漏洞文字搜尋**：ReleaseDetail 漏洞篩選列新增文字輸入框，支援 CVE ID 和元件名稱模糊搜尋（不分大小寫），納入「清除篩選」重置
- **通知規則（Alert Rules）**：`AlertConfig` 新增 `alert_min_severity / alert_kev_always / alert_epss_threshold` 三欄；`_passes_alert_rule()` 過濾函式；Settings 頁新增「通知規則」卡片（嚴重度下拉 / EPSS 滑桿 / KEV 一律通知 checkbox）；規則全不通過時靜默跳過
- **多收件人 Email**：`alert_email_to` 改支援逗號分隔多地址；`send_email()` 拆分 recipients 清單；測試信同樣寄送所有收件人
- **抑制到期通知**：`monitor.py` 每次掃描後查詢 `suppressed_until < now`，自動清除到期抑制並觸發通知（受通知規則篩選）

### 新增（競品落差補強）
- **NIS2 Directive Article 21 合規報告**：`nis2_report.py` 評估 5 個 SBOM 可量化控制項（21.2(b) 事件處理、(d) 供應鏈安全、(e) 漏洞管理、(h) 加密政策 CWE-326/327/310、(i) 資產管理 NTIA）；`GET /api/releases/{id}/compliance/nis2` → PDF；繼承 CjkPDF 支援中文；ReleaseDetail 匯出選單加入
- **Slack / Teams 格式化通知**：`send_webhook()` 自動偵測 URL 類型；`hooks.slack.com` → Block Kit（fields + 顏色 attachment）；`webhook.office.com` → MessageCard（Adaptive Cards 格式）；其他 URL → 原有通用 JSON，不影響現有設定
- **GitLab CI 範本**（`tools/sbom-gitlab-ci/`）：`sbom-upload` + `sbom-gate` 兩個 job；純 stdlib 無外部依賴；支援 `SBOM_FILE / SBOM_API_URL / FAIL_ON_GATE` 變數；rules: main + merge_request；附 README 含 Syft SBOM 生成範例

### 改善
- **組織刪除二次確認**：`ConfirmModal` 新增 `requireTypeName` 屬性；刪除組織時必須輸入組織名稱才能啟用確認按鈕，防止誤刪
- **JWT 登出即失效**：`revoked_tokens` 資料表（jti, expires_at）；JWT 加 `jti` claim；`get_current_user` 查黑名單；`POST /auth/logout`；啟動時自動清除過期 token；Layout/Profile 登出前先呼叫 API
- **Release 版本號編輯**：`PATCH /api/releases/{id}/version`（鎖定版本不可改）；Releases 頁加「編輯」按鈕 + modal
- **Webhook 失敗重試**：`send_webhook()` 指數退避最多 3 次（1s、2s 間隔）
- **SBOM 上傳進度條**：Axios `onUploadProgress` → 藍色進度條；傳輸中顯示百分比；傳輸完成顯示「解析中...」
- **User email 欄位**：`users.email`（nullable）；Profile 頁顯示/編輯；Users 頁表格帳號下方顯示；忘記密碼支援以 email 查詢；`PATCH /auth/profile` 自助更新
- **Product 編輯**：`PATCH /api/products/{id}`；Products 頁加「編輯」按鈕 + modal
- **稽核紀錄 CSV 匯出**：`GET /api/admin/activity/export`（後端 CSV，max 5000 筆）；AdminActivity 頁改呼叫後端，自動帶入篩選條件
- **ReleaseDiff UI 改善**：補「不變」數量卡片；新增漏洞嚴重度分布 badge；匯出 CSV；空狀態改善
- **忘記密碼流程**：`PasswordResetToken` 資料表；`POST /forgot-password`（always 204）+ `/reset-password`；SMTP 寄 30 分鐘時效連結；Login 頁加連結；ForgotPassword / ResetPassword 頁面
- **SQLite 自動備份**：`deploy/backup.sh`（sqlite3 .backup，保留 14 天）
- **Share link 上限**：同一 release 最多 20 條，超過回 400
- **Monitor 跳過通知**：`_last_skip_dt` 記錄、`get_status()` 回傳、Settings 頁橘色警示
- **Release 備註欄位**：`releases.notes`；`PATCH /releases/{id}/notes`；ReleaseDetail 可編輯區塊
- **Health Check endpoint**：`GET /health`（無需登入、不計 rate limit）；回傳 `status/version/db/monitor/timestamp`；DB 掛掉時回 `degraded`；供 UptimeRobot / load balancer / cron 監控
- **Async I/O 修正**：`upload_source`（Python AST call graph）與 `scan_iac_archive`（Trivy subprocess）改用 `asyncio.to_thread`，長時間掃描不再阻塞 event loop，其他使用者請求不受影響
- **Rate Limiting**：`core/rate_limit.py` 滑動視窗（純 stdlib，無外部依賴）；登入端點 10 次/5 分鐘/IP（成功後重置）；全域 API middleware 300 次/分鐘/IP；支援 nginx `X-Forwarded-For`；超限回 429 + Retry-After
- **列表端點分頁保護**：`GET /releases/{id}/components` 新增 `skip/limit`（預設 2000，硬上限 5000），回傳 `{total, skip, limit, items}`；`list_vulnerabilities` 早有 max=1000 ✅
- **稽核紀錄覆蓋率補齊**：`audit_events` 表從 8 種事件擴展至 21 種，新增 `org_create/update/plan_change/delete`、`product_create`、`vex_update`、`vex_batch_update`、`vuln_suppress/unsuppress`、`token_create/revoke`、`share_link_create/revoke`、`release_lock/unlock`、`signature_deleted`、`password_change`；VEX 變更記錄 CVE ID 與狀態轉換，Plan 變更記錄新舊方案名稱

### 修正（安全 / 效能 / 併發）
- **OIDC CSRF 修補**：`/oidc/callback` 加入 state cookie 驗證，防止 authorization code 注入攻擊
- **Migration SQL Injection 防護**：`_list_columns` / `_add_column` 加入 `_ALLOWED_TABLES` 白名單，table 名稱不在清單時 raise ValueError
- **IDOR 修補**：`/rescan` endpoint 補加 `_assert_release_org()` org scope 檢查
- **併發安全**：`_active_enrichments` 的 check-then-add 改以 `threading.Lock` 保護原子性，防止雙重執行
- **資料完整性**：`vulnerabilities` 加 `UniqueConstraint("component_id","cve_id")`，migration 同步建立 `UNIQUE INDEX`，防止並發 rescan 產生重複 CVE
- **N+1 查詢消除**：`list_components`、PDF report、CSV export、compliance report 共 6 處 component 查詢加 `selectinload(vulnerabilities)`，多元件 release 從 N+1 次降為 2 次 SQL
- **啟動安全警告**：`SECRET_KEY` 使用預設值或短於 32 bytes 時記錄 WARNING

### 新增
- **IEC 62443 PDF CJK 字型支援**：`font_manager.py` 自動偵測字型（Windows `msyh.ttc`、Linux NotoSansSC、自動下載 fallback）；`CjkPDF` 基礎類別供三份報告（4-1/4-2/3-3）繼承；組織名稱、產品名稱等中文欄位可正確渲染至 PDF
- **SBOM 脫敏分享連結**：Professional plan；`POST /api/releases/{id}/share-link` 建立時效 token；`GET /api/share/{token}` 無需登入公開下載；`mask_internal` 過濾 `internal://` / `private://` 元件；記錄下載次數；ReleaseDetail 面板含複製、撤銷
- **UI/UX 全面修正（19 項）**：Plan 降級確認 modal、批次 VEX 操作回饋、Dashboard 錯誤提示、Plan 鎖定功能灰色圖示、麵包屑補抓、骨架屏、SBOM 上傳引導 toast、TISAX/CRA 空白頁說明、角色切換確認、簽章鎖定提示、分享連結 toast、i18n 補完、clipboard 錯誤、Token 只顯示一次警告加強
- **Plan 分層系統**：Starter / Standard / Professional 三層；後端 `require_plan()` FastAPI dependency（非 admin 回 402）；前端 `utils/plan.js` + Layout badge + 按鈕/頁面自動隱藏；Organizations 頁 admin 可即時切換 plan
- **SSO / OIDC 整合**：`OIDC_ISSUER` / `CLIENT_ID` / `CLIENT_SECRET` 設定後自動啟用；`/oidc/login` redirect + `/oidc/callback` JWT 回傳；支援 Azure AD / Google / Keycloak；`oidc_sub` 欄位；Login 頁 SSO 按鈕
- **Postgres 後端選項**：`_is_sqlite` 分支 + `_add_column_safe()` migration helper；切換只需改 `DATABASE_URL`
- **持續監控**：`monitor.py` 背景排程（6/12/24/48/72h 可選）+ 手動觸發；Settings UI 顯示上次執行時間和下次排程
- **SBOM 格式互轉**（`POST /api/convert`）：CycloneDX JSON ↔ SPDX JSON、CycloneDX ↔ XML
- **SBOM 品質評分 Dashboard**：`/stats/sbom-quality-summary` A/B/C/D 分布卡片
- **CVE 影響查詢**：`/stats/cve-impact?cve=CVE-xxx` + Dashboard 即時查詢框
- **Reachability 分析（三階段）**：上傳原始碼 zip → Phase 1 import 掃描、Phase 2 測試目錄過濾、Phase 3 Python AST call graph（alias 追蹤、route decorator 進入點、1-hop call graph）；`function_reachable` / `reachable` / `test_only` / `not_found`
- **GHSA 漏洞情資補強**：GitHub Security Advisories REST API，支援 npm/pypi/maven/nuget/cargo/gem/go；ghsa_id 欄位；上傳自動觸發 + 手動補充端點
- **Container / IaC 掃描（Trivy）**：`POST /scan-image`（Container Image）、`POST /scan-iac`（Terraform/K8s zip，回傳 misconfiguration 列表）
- **SBOM 簽章驗證（Sigstore/cosign）**：ECDSA / RSA-PSS / RSA-PKCS1；自動偵測演算法；Policy Gate 第 6 項
- **TISAX 模組**：VDA ISA 6.0，63 個控制項，maturity 0–5，AL2/AL3 gap 分析，PDF/CSV 匯出
- **GitHub Action + CLI**：`tools/sbom-action/`（composite action）、`tools/sbom-cli/sbom.py`（upload/gate/diff）
- **API Token 最小權限**：read / write / admin scope，`require_admin_scope` 守衛
- **首屏性能優化**：路由 lazy load、DependencyGraph/TrendChart 獨立 chunk、依賴圖延後 fetch

### 改善
- License 風險分類（Permissive / Copyleft / Commercial）+ 違規通知
- 韌體掃描支援 EMBA demo mode（Windows 開發環境）
- 競品落差文件（`docs/competitor-gap.md`）持續更新

---

## [1.5.0] — 2026-03

### 新增
- IEC 62443-3-3 系統層級報告（11 項 SR 要求評估）
- IEC 62443-4-2 元件層級報告（4 大類 12 項 CR 要求）
- Policy 引擎：自訂規則自動偵測違規
- 跨客戶風險總覽頁
- CRA 事件管理（Article 14 狀態機 + 24h/72h/14d SLA 時鐘）
- 版本鎖定/解鎖、版本 Diff 比對
- 品牌化報告、Webhook + Email 通知
- 漏洞抑制（Suppression / Risk Acceptance）

---

## [1.0.0] — 2025-12

### 新增（Phase 1 完成）
- 多租戶組織/產品/版本/元件 CRUD
- SBOM 上傳解析（CycloneDX JSON + SPDX JSON）
- CVE 掃描（OSV.dev API，依 PURL 批次查詢）
- VEX 狀態管理（open / in_triage / not_affected / affected / fixed）
- EPSS 整合（FIRST.org）、CISA KEV 標記、NVD 豐富化
- PDF 報告、CSV 匯出、CSAF VEX、合規證據包 ZIP
- SBOM 完整性驗證（SHA-256）
- JWT 登入認證
