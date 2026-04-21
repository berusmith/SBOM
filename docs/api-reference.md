# API 參考文件

Base URL: `http://localhost:9100`  
互動式文件: `http://localhost:9100/docs`  
所有端點（`/api/auth/login` 除外）需要 `Authorization: Bearer <token>` 標頭。

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
| GET | `/api/products/{product_id}/vuln-trend` | 漏洞趨勢（各版本嚴重度數量） |
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
| GET | `/api/releases/{release_id}/vulnerabilities` | 列出所有漏洞（含 VEX 狀態） |
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

---

## 漏洞 Vulnerabilities

| 方法 | 路徑 | 說明 |
|------|------|------|
| PATCH | `/api/vulnerabilities/{vuln_id}/status` | 更新 VEX 狀態 |
| PATCH | `/api/vulnerabilities/batch` | 批次更新 VEX 狀態 |
| GET | `/api/vulnerabilities/{vuln_id}/history` | 查詢 VEX 變更歷程 |

**VEX 狀態更新 Request Body**
```json
{
  "status": "not_affected",  // open | in_triage | not_affected | affected | fixed
  "justification": "code_not_present",  // 僅 not_affected 時有效
  "response": null,                     // 僅 affected 時有效
  "detail": "此元件在產品中未啟用相關功能"
}
```

**justification 有效值**（`status = not_affected` 時）
- `code_not_present` — 程式碼不存在
- `code_not_reachable` — 程式碼不可達
- `requires_configuration` — 需特定設定才能觸發
- `requires_dependency` — 需特定相依才能觸發
- `protected_by_mitigating_control` — 已有緩解控制

**response 有效值**（`status = affected` 時）
- `update` — 計畫升級
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

## 錯誤代碼

| HTTP | 情境 |
|------|------|
| 400 | 請求格式錯誤或業務規則違反 |
| 401 | 未提供或過期的 JWT Token |
| 404 | 資源不存在 |
| 409 | 衝突（如：組織名稱重複） |
| 422 | Pydantic 驗證失敗 |
| 500 | 伺服器內部錯誤 |

錯誤 Response 格式：
```json
{ "detail": "錯誤說明（中文）" }
```
