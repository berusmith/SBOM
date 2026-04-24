# 下一項工作詳細計畫

## 已完成功能清單（截至 2026-04-24）

| 功能 | Commit |
|------|--------|
| API Token 最小權限（read/write/admin scope） | `eac0231` |
| 首屏性能優化（路由 lazy + 依賴圖延後 fetch） | `b0e6231` |
| License 風險分類 + 通知測試按鈕 | — |
| GitHub Action + CLI（`tools/sbom-action/` + `tools/sbom-cli/`） | `1650499` |
| SBOM Sigstore 簽章驗證（ECDSA/RSA，Policy Gate 第 6 項） | `6b755ad` |
| TISAX 模組（VDA ISA 6.0，63 控制項，AL2/AL3 gap 分析） | — |
| Container/IaC 掃描（Trivy，`POST /scan-image` + `/scan-iac`） | `9e0df10` |
| GHSA 漏洞情資補強（GitHub Advisory Database，ghsa_id 欄位） | `5c6538b` |
| Reachability Phase 1（import 層級，Python/Node） | `e3c6521` |
| Reachability Phase 2（模組層級，test/scripts 過濾） | `b842aeb` |
| Reachability Phase 3（Python AST call graph，function_reachable） | `7016ca0` |
| i18n 國際化（EN/中切換，react-i18next，297 key） | `665a50e` |
| SBOM 格式互轉（`POST /api/convert`，CycloneDX ↔ SPDX ↔ XML） | `bbc786c` |
| SBOM 品質評分 Dashboard 卡片（`/stats/sbom-quality-summary`） | `bbc786c` |
| CVE 影響查詢（`/stats/cve-impact`，Dashboard 查詢框） | `bbc786c` |
| Postgres 後端選項（`_is_sqlite` + `_add_column_safe` helper） | `d3a1cbd` |
| SSO / OIDC 整合（`/oidc/login` `/oidc/callback`，Azure AD/Google/Keycloak） | `45cd27f` |
| Plan 分層系統（Starter/Standard/Professional，後端 guard + 前端 UI gating） | `bcbd8cf` |
| SBOM 脫敏分享連結（時效 token / 內部元件過濾 / 無需登入下載） | `a251c68` |
| UI/UX 全面修正（19 項：High×3 / Medium×8 / Low×4） | `4de512b` |
| IEC 62443 PDF CJK 字型支援（font_manager + CjkPDF，Windows/Linux/下載） | `ec33a75` |
| 行動版 UI/UX 全面優化（漏洞卡片、觸控目標、表格欄位隱藏、下拉定位） | `c94b022` |
| 安全/效能/併發修正（OIDC CSRF、IDOR、N+1、UniqueConstraint、Lock） | `17a12b3` |
| 稽核紀錄補齊（audit_events 從 8 → 21 種事件，含 VEX/Token/Lock/Plan） | `ad502c5` |
| Rate Limiting（登入 10/5min + 全域 300/min/IP，滑動視窗 middleware） | `cbc681e` |
| 列表端點分頁保護（components skip/limit，硬上限 5000） | `cbc681e` |
| Health Check endpoint（GET /health，DB 連通性 + monitor 狀態） | `d0ed38f` |
| Async I/O 修正（upload_source + scan_iac 改 asyncio.to_thread） | `d0ed38f` |
| 忘記密碼流程（PasswordResetToken / SMTP 寄信 / 30 分鐘時效） | `4723feb` |
| SQLite 自動備份腳本（deploy/backup.sh，保留 14 天，sqlite3 .backup） | `4723feb` |
| Share link 上限（同一 release 最多 20 條） | `4723feb` |
| Monitor 跳過通知（_last_skip_dt，Settings 頁橘色警示） | `4723feb` |
| Release 備註欄位（releases.notes，PATCH /notes，ReleaseDetail 編輯區） | `4723feb` |
| User email 欄位（users.email，Profile/Users UI，forgot-password 支援） | `20d0a5c` |
| Product 編輯（PATCH /products/{id}，名稱/描述 modal） | `20d0a5c` |
| 稽核紀錄 CSV 匯出（GET /admin/activity/export，帶入篩選條件） | `20d0a5c` |
| ReleaseDiff UI 改善（不變數卡片、嚴重度分布、匯出 CSV、KEV badge 修正） | `20d0a5c` |
| JWT 登出即失效（RevokedToken 黑名單，jti claim，啟動清除過期） | `d6c9c63` |
| Release 版本號編輯（PATCH /releases/{id}/version，Releases 頁 modal） | `d6c9c63` |
| Webhook 失敗重試（指數退避 3 次，1s / 2s 間隔） | `d6c9c63` |
| SBOM 上傳進度條（Axios onUploadProgress，百分比顯示） | `d6c9c63` |
| 組織刪除二次確認（ConfirmModal requireTypeName，必須輸入名稱才能確認） | `8650bcd` |
| 漏洞文字搜尋（CVE ID / 元件名稱模糊搜尋，ReleaseDetail 篩選列）| `14e3d1f` |
| 通知規則（min_severity / epss_threshold / kev_always，Settings UI）| `14e3d1f` |
| 多收件人 Email（逗號分隔，send_email 支援 recipients 清單）| `14e3d1f` |
| 抑制到期通知（monitor 掃描後自動清除過期抑制並發通知）| `14e3d1f` |
| NIS2 Art.21 合規報告（5 控制項評估，GET /compliance/nis2，PDF）| `3fd8d8b` |
| Slack / Teams 格式化通知（Block Kit / MessageCard 自動偵測）| `3fd8d8b` |
| GitLab CI 範本（tools/sbom-gitlab-ci/，sbom-upload + sbom-gate）| `3fd8d8b` |

---

## 待做（依優先順序）

| # | 項目 | 預估 | 理由 |
|---|------|------|------|
| 1 | ~~**Postgres 後端選項**~~ | ✅ 完成 | |
| 2 | ~~**持續監控**~~（新 CVE 自動重評全組合） | ✅ 完成 | monitor.py + scheduler + Settings UI 均已存在 |
| 3 | ~~**SSO / LDAP 整合**~~ | ✅ 完成 | OIDC（Azure AD/Google/Keycloak），`oidc_sub` 欄位，Login SSO 按鈕 |
| 4 | ~~**SBOM 脫敏與供應鏈分享**~~ | ✅ 完成 | 分享連結 + 脫敏過濾 + 下載計數，`a251c68` |
| 5 | ~~**Binary/PDF 盤點引導**~~ | ❌ 不做 | NLP 替代方案也確認不做 |

### 持續監控說明
- 現況：漏洞資料需手動觸發 rescan / enrich-nvd
- 目標：新 CVE 進 NVD/GHSA 後，背景自動重評所有受影響元件，有新漏洞時發通知
- 實作方向：排程任務（APScheduler）每日跑 OSV batch query，比對現有元件 PURL

### Plan 分層說明
- Starter：1 org / 3 products / 10 releases，基礎漏洞掃描，無 CRA/IEC/TISAX
- Standard：無限量，加 CRA / IEC 62443-4-1 / EPSS / GHSA / 持續監控 / SSO
- Professional：全功能，加 IEC 62443-4-2/3-3 / TISAX / Reachability / Trivy / 簽章
- 切換：Organizations 頁 admin 直接下拉，後端 `PATCH /organizations/{id}/plan`，`402` 守衛

---

## 已知問題

- CRA `start-clock` 狀態機在已 `clock_running` 時回 409（設計如此，非 bug）

## 低優先待改（已記錄，暫不修）

| 項目 | 說明 |
|------|------|
| API token timing attack | SQL hash 比對可改 `hmac.compare_digest`；實際風險極低 |
| OIDC 自動建立新使用者 | 可加 email domain 白名單；需 OIDC 設定者授權才能觸發 |
| ~~無限 share link 建立~~ | ✅ 已修：每 release 上限 20 條 |
| ~~monitor.py 靜默跳過~~ | ✅ 已修：last_skip_dt + Settings 頁警示 |
| ~~非同步 endpoint 阻塞 I/O~~ | ✅ 已修：upload_source + scan_iac 改 asyncio.to_thread |
