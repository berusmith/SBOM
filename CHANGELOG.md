# Changelog

所有版本的重要異動記錄。格式依照 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.0.0/)。

---

## [Unreleased]

### 計畫中
- Postgres 後端選項

---

## [2.0.0] — 2026-04

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
