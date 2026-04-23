# API 參考文件

Base URL: `http://localhost:9100`  
互動式文件: `http://localhost:9100/docs`  
所有端點（`/api/auth/login` 除外）需要 `Authorization: Bearer <token>` 標頭。

Token 支援兩種格式：
- **JWT**（由 `/api/auth/login` 取得，24 小時有效）— 給 UI 使用者
- **API Token**（以 `sbom_` 開頭的長效金鑰）— 給 CI/CD pipeline 使用，需由 admin 於 Settings 頁建立

---

## 認證

### POST /api/auth/login
取得 JWT Token。

**Request Body**
```json
{ "username": "admin", "password": "sbom@2024" }
```

**Response 200**
```json
{ "access_token": "<jwt>", "token_type": "bearer" }
```

### GET /api/auth/me
取得目前登入使用者資訊。

---

## 組織 Organizations

| 方法 | 路徑 | 說明 |
|------|------|------|
| GET | `/api/organizations` | 列出所有組織 |
| POST | `/api/organizations` | 建立組織 |
| PATCH | `/api/organizations/{org_id}` | 更新組織名稱/授權狀態 |
| DELETE | `/api/organizations/{org_id}` | 刪除組織（cascade） |

**Organization 物件**
```json
{
  "id": "uuid",
  "name": "台灣工控股份有限公司",
  "license_status": "active",  // active | trial | expired
  "created_at": "2025-01-01T00:00:00Z"
}
```

---

## 產品 Products

| 方法 | 路徑 | 說明 |
|------|------|------|
| GET | `/api/organizations/{org_id}/products` | 列出該組織所有產品 |
| POST | `/api/organizations/{org_id}/products` | 建立產品 |
| DELETE | `/api/products/{product_id}` | 刪除產品（cascade） |
| GET | `/api/products/{product_id}/releases` | 列出該產品所有版本 |
| GET | `/api/products/{product_id}/vuln-trend` | 漏洞趨勢（各版本嚴重度數量）；`total` 僅計算未解決，`total_all` 含所有 |
| GET | `/api/products/{product_id}/diff?v1={id}&v2={id}` | 兩版本漏洞差異 |

---

## 版本 Releases

| 方法 | 路徑 | 說明 |
|------|------|------|
| POST | `/api/products/{product_id}/releases` | 建立版本 |
| GET | `/api/releases/{release_id}` | 取得版本詳情 |
| DELETE | `/api/releases/{release_id}` | 刪除版本（cascade） |
| POST | `/api/releases/{release_id}/sbom` | 上傳 SBOM 檔案（multipart/form-data, field: `file`） |
| POST | `/api/releases/{release_id}/rescan` | 重新掃描所有元件 CVE |
| POST | `/api/releases/{release_id}/enrich-epss` | 更新 EPSS 分數 |
| POST | `/api/releases/{release_id}/enrich-nvd` | 從 NVD 補充 CVE 詳情 |
| GET | `/api/releases/{release_id}/components` | 列出所有元件 |
| GET | `/api/releases/{release_id}/vulnerabilities` | 列出所有漏洞（含 VEX 狀態、SLA、抑制狀態） |
| GET | `/api/releases/{release_id}/vulnerabilities/export` | 下載漏洞 CSV |
| GET | `/api/releases/{release_id}/compliance` | 合規摘要 |
| GET | `/api/releases/{release_id}/report` | 下載 PDF 報告 |
| GET | `/api/releases/{release_id}/compliance/iec62443` | IEC 62443-4-1 報告 PDF |
| GET | `/api/releases/{release_id}/compliance/iec62443-4-2` | IEC 62443-4-2 元件報告 PDF |
| GET | `/api/releases/{release_id}/compliance/iec62443-3-3` | IEC 62443-3-3 系統報告 PDF |
| GET | `/api/releases/{release_id}/evidence-package` | 下載合規證據包 ZIP |
| GET | `/api/releases/{release_id}/csaf` | 下載 CSAF 2.0 VEX JSON |
| GET | `/api/releases/{release_id}/integrity` | 驗證 SBOM SHA-256 完整性 |
| POST | `/api/releases/{release_id}/lock` | 鎖定版本（禁止修改） |
| POST | `/api/releases/{release_id}/unlock` | 解鎖版本 |
| GET | `/api/releases/{release_id}/patch-stats` | 修補統計（修補率、平均天數） |
| GET | `/api/releases/{release_id}/gate` | 發布品質閘門（5 項 PASS/FAIL 檢查） |
| GET | `/api/releases/{release_id}/dependency-graph` | 依賴關係圖（節點 + 邊，適用 CycloneDX/SPDX） |
| GET | `/api/releases/{release_id}/export/cyclonedx-xml` | 匯出 CycloneDX XML |
| GET | `/api/releases/{release_id}/export/spdx-json` | 匯出 SPDX JSON |

### POST /api/releases/{release_id}/sbom — 上傳回應

```json
{
  "components_found": 42,
  "vulnerabilities_found": 17,
  "diff": {
    "prev_version": "v1.0.0",
    "components_added": 3,
    "components_removed": 1,
    "vulns_added": 5,
    "vulns_removed": 2
  }
}
```
`diff` 欄位：若此 release 所屬 product 有前一個版本，自動計算差異；無前版本則為 `null`。

### GET /api/releases/{release_id}/vulnerabilities — 漏洞項目欄位

```json
{
  "id": "uuid",
  "cve_id": "CVE-2021-44228",
  "component_name": "log4j-core",
  "component_version": "2.14.1",
  "cvss_score": 10.0,
  "cvss_v3_score": 10.0,
  "cvss_v4_score": null,
  "severity": "critical",
  "status": "open",
  "justification": null,
  "response": null,
  "detail": null,
  "epss_score": 0.975,
  "epss_percentile": 0.999,
  "is_kev": true,
  "description": "Apache Log4j2 遠端程式碼執行...",
  "cwe": "CWE-917",
  "nvd_refs": ["https://nvd.nist.gov/..."],
  "sla_days": -3,
  "sla_status": "overdue",
  "suppressed": false,
  "suppressed_until": null,
  "suppressed_reason": null
}
```

**sla_status 值：**
- `overdue` — 已逾期（`sla_days` 為負，表示超過天數）
- `warning` — 剩餘 ≤ 25% SLA 天數（即將到期）
- `ok` — 正常
- `na` — 不適用（已 fixed / not_affected，或無 scanned_at）

**SLA 基準（Critical 已豁免列入抑制）：**

| 嚴重度 | SLA 天數 |
|--------|---------|
| critical | 7 天 |
| high | 30 天 |
| medium | 90 天 |
| low | 180 天 |

已抑制（`suppressed=true`）的漏洞：`sla_status` 回傳 `na`，不計入逾期統計。

### GET /api/releases/{release_id}/gate — 發布品質閘門

```json
{
  "overall": "fail",
  "passed": 3,
  "total": 5,
  "checks": [
    { "id": "no_critical_open",   "label": "無 Critical 未修補",    "passed": false, "detail": "2 個 Critical open 漏洞" },
    { "id": "untriaged_ratio",    "label": "未分類率 < 20%",         "passed": true,  "detail": "未分類 3 / 共 17 (17.6%)" },
    { "id": "kev_resolved",       "label": "所有 KEV 已處置",        "passed": true,  "detail": "0 個 KEV 仍 open" },
    { "id": "sbom_quality",       "label": "SBOM 品質 ≥ 70%",        "passed": true,  "detail": "品質分數 85%" },
    { "id": "no_policy_block",    "label": "無 Policy Block 違規",   "passed": false, "detail": "1 個 block 等級違規" }
  ]
}
```

抑制的漏洞不計入 `no_critical_open` 與 `untriaged_ratio` 檢查。

---

## 漏洞 Vulnerabilities

| 方法 | 路徑 | 說明 |
|------|------|------|
| PATCH | `/api/vulnerabilities/{vuln_id}/status` | 更新 VEX 狀態 |
| PATCH | `/api/vulnerabilities/batch` | 批次更新 VEX 狀態 |
| GET | `/api/vulnerabilities/{vuln_id}/history` | 查詢 VEX 變更歷程 |
| PATCH | `/api/vulnerabilities/{vuln_id}/suppress` | 設定/解除抑制（風險接受） |

**VEX 狀態更新 Request Body**
```json
{
  "status": "not_affected",
  "justification": "code_not_present",
  "response": null,
  "detail": "此元件在產品中未啟用相關功能",
  "note": "已與開發確認"
}
```

**suppressed 更新 Request Body**
```json
{
  "suppressed": true,
  "suppressed_until": "2026-12-31",
  "suppressed_reason": "已通過風險評估，待下季修補計畫處理"
}
```
- `suppressed_until`：ISO 日期字串 `YYYY-MM-DD`（選填，不填表示永久抑制）
- 到期後 `_is_suppressed()` 自動失效，不需排程工作

**justification 有效值**（`status = not_affected` 時）
- `code_not_present` — 程式碼不存在
- `code_not_reachable` — 程式碼不可達
- `requires_configuration` — 需特定設定才能觸發
- `requires_dependency` — 需特定相依才能觸發
- `requires_environment` — 需特定環境才能觸發
- `protected_by_compiler` — 編譯器保護
- `protected_at_runtime` — 執行期保護
- `protected_at_perimeter` — 邊界防護
- `protected_by_mitigating_control` — 已有緩解控制

**response 有效值**（`status = affected` 時）
- `update` — 計畫升級
- `rollback` — 回滾版本
- `workaround_available` — 提供 workaround
- `will_not_fix` — 不修補
- `can_not_fix` — 無法修補

---

## CRA 事件 Incidents

| 方法 | 路徑 | 說明 |
|------|------|------|
| GET | `/api/cra/incidents` | 列出所有 CRA 事件 |
| POST | `/api/cra/incidents` | 建立新事件 |
| GET | `/api/cra/incidents/{incident_id}` | 取得事件詳情（含稽核紀錄） |
| POST | `/api/cra/incidents/{incident_id}/start-clock` | 啟動 SLA 時鐘（T+0） |
| POST | `/api/cra/incidents/{incident_id}/advance` | 推進狀態（見狀態機） |
| POST | `/api/cra/incidents/{incident_id}/close-not-affected` | 關閉（確認不受影響） |
| DELETE | `/api/cra/incidents/{incident_id}` | 刪除事件 |

**CRA 事件狀態機**
```
detected → pending_triage
pending_triage → clock_running  (via start-clock)
pending_triage → closed         (via close-not-affected)
clock_running → t24_submitted   (T+24h Early Warning 提交後)
t24_submitted → investigating
investigating → t72_submitted   (T+72h Notification 提交後)
t72_submitted → remediating
remediating → final_submitted   (修補完成後 14 天內提交 Final Report)
final_submitted → closed
```

---

## 統計 Stats

| 方法 | 路徑 | 說明 |
|------|------|------|
| GET | `/api/stats` | 全平台摘要統計 |
| GET | `/api/stats/risk-overview` | 各組織風險排行 |
| GET | `/api/stats/top-threats` | 最高風險漏洞清單 |
| GET | `/api/stats/top-risky-components` | 高風險元件排行（依累積 CVSS 分數） |

**GET /api/stats 回應（含新增欄位）**
```json
{
  "total_organizations": 5,
  "total_products": 12,
  "total_releases": 28,
  "total_vulnerabilities": 340,
  "open_critical": 7,
  "open_high": 23,
  "overdue_vulns": 4
}
```
`overdue_vulns`：已逾 SLA 且未抑制的漏洞數。

**GET /api/stats/top-risky-components 回應**
```json
[
  {
    "name": "log4j-core",
    "version": "2.14.1",
    "purl": "pkg:maven/...",
    "vuln_count": 3,
    "max_severity": "critical",
    "total_cvss": 27.5,
    "product_name": "工業閘道器 GA-200",
    "release_version": "v2.1.0"
  }
]
```

---

## 搜尋 Search

| 方法 | 路徑 | 說明 |
|------|------|------|
| GET | `/api/search/components?q={keyword}` | 跨組織搜尋元件名稱 |

---

## 設定 Settings

| 方法 | 路徑 | 說明 |
|------|------|------|
| GET | `/api/settings/brand` | 取得品牌設定 |
| POST | `/api/settings/brand` | 更新品牌設定（公司名、主題色、頁尾） |
| POST | `/api/settings/brand/logo` | 上傳 Logo（multipart/form-data） |
| GET | `/api/settings/alerts` | 取得通知設定 |
| POST | `/api/settings/alerts` | 更新通知設定（Webhook URL / Email） |

---

## API 金鑰 API Tokens

長效金鑰供 CI/CD pipeline 整合使用。僅 admin 可建立/列表/撤銷。建立時明文只回傳一次，資料庫僅存 SHA-256 hash。

| 方法 | 路徑 | 說明 |
|------|------|------|
| GET | `/api/tokens` | 列出所有 API tokens（不含明文） |
| POST | `/api/tokens` | 建立新 token，body：`{"name": "GitLab CI"}`，回傳 `token` 欄位即明文 |
| DELETE | `/api/tokens/{id}` | 撤銷 token（立即失效，不可復原） |

**使用範例**
```bash
curl -H "Authorization: Bearer sbom_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
     http://localhost:9100/api/organizations
```

API Token 認證身份固定為 admin role，每次呼叫會更新 `last_used_at`。

---

## 管理 Admin

| 方法 | 路徑 | 說明 |
|------|------|------|
| GET | `/api/admin/activity` | 查詢稽核日誌（支援日期篩選） |

**查詢參數**
- `date_from`：起始日期（`YYYY-MM-DD`，選填）
- `date_to`：結束日期（`YYYY-MM-DD`，選填）

---

## 錯誤代碼

| HTTP | 情境 |
|------|------|
| 400 | 請求格式錯誤或業務規則違反 |
| 401 | 未提供或過期的 JWT / 已撤銷的 API Token |
| 404 | 資源不存在 |
| 409 | 衝突（如：組織名稱重複；或版本已鎖定） |
| 422 | Pydantic 驗證失敗 |
| 500 | 伺服器內部錯誤 |

錯誤 Response 格式：
```json
{ "detail": "錯誤說明（中文）" }
```
