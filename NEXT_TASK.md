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
| 無限 share link 建立 | 可加每 release 上限；屬資料 bloat，非安全漏洞 |
| monitor.py 靜默跳過 | 與手動 rescan 衝突時回傳 0 但無使用者通知；可加狀態端點 |
| 非同步 endpoint 阻塞 I/O | Trivy / AST 掃描在 async route 中同步執行；可改 `asyncio.to_thread` |
