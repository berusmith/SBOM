# 業務邏輯文件

## 核心流程概覽

```
組織 → 產品 → 版本
               ↓
          上傳 SBOM
               ↓
        解析元件清單
               ↓
       OSV.dev 漏洞掃描
               ↓
    豐富化（EPSS / KEV / NVD）
               ↓
        VEX 漏洞分類
               ↓
      合規報告 / 證據包
```

---

## 1. SBOM 上傳與初始掃描

**端點：** `POST /api/releases/{release_id}/sbom`

1. 接收上傳檔案（最大 50 MB）
2. 驗證 JSON 格式（CycloneDX 或 SPDX）
3. 解析元件 → `[{name, version, purl, license}]`
4. 儲存檔案，計算 SHA-256 雜湊（完整性驗證用）
5. 刪除既有元件（支援重複上傳覆蓋）
6. 寫入新元件到 DB
7. 對每個 PURL 查詢 OSV.dev，依 `(component_id, cve_id)` 去重
8. 批量查詢 EPSS 分數、比對 CISA KEV 清單
9. 回傳 `{components_found, vulnerabilities_found}`

---

## 2. 漏洞豐富化管線

### 2a. 重新掃描（Rescan）
**端點：** `POST /api/releases/{release_id}/rescan`

- 對現有元件重新查詢 OSV.dev
- 只新增尚未存在的 CVE（不覆蓋已有紀錄）
- 更新所有漏洞的 EPSS 分數與 KEV 標記
- 若有新漏洞，觸發告警（Webhook / Email）

### 2b. EPSS 豐富化
**端點：** `POST /api/releases/{release_id}/enrich-epss`

- 批量查詢 FIRST.org（500 CVE/次）
- 更新 `epss_score`（0–1）、`epss_percentile`
- 同步更新 KEV 標記

### 2c. NVD 豐富化（背景任務）
**端點：** `POST /api/releases/{release_id}/enrich-nvd`

- 立即回傳預估時間（秒）
- 後台執行：每個唯一 CVE 查詢 NVD API 2.0
- 限速：無 API Key 7s/次，有 Key 0.7s/次
- 429 錯誤自動退讓 35 秒
- 更新：`description`、`cwe`、`cvss_v3_score/vector`、`cvss_v4_score/vector`、`nvd_refs`

---

## 3. VEX 漏洞分類

### 狀態

| 狀態 | 說明 |
|------|------|
| `open` | 新發現，待分類 |
| `in_triage` | 分析中 |
| `not_affected` | 確認不受影響（需填 justification） |
| `affected` | 確認受影響（需填 response） |
| `fixed` | 已修補（自動記錄 `fixed_at`） |

### Justification（`not_affected` 專用）

| 值 | 說明 |
|----|------|
| `code_not_present` | 漏洞程式碼未包含在產品中 |
| `code_not_reachable` | 程式碼存在但執行路徑不可達 |
| `requires_configuration` | 需特定設定才能觸發 |
| `requires_dependency` | 需要缺少的傳遞依賴 |
| `requires_environment` | 環境特定（如僅 Windows） |
| `protected_by_compiler` | 編譯器緩解措施保護 |
| `protected_at_runtime` | 執行時保護機制 |
| `protected_at_perimeter` | 邊界防護（如 WAF） |
| `protected_by_mitigating_control` | 補償性控制措施 |

### Response（`affected` 專用）

| 值 | 說明 |
|----|------|
| `can_not_fix` | 廠商無法修復 |
| `will_not_fix` | 廠商不打算修復 |
| `update` | 升級可解決 |
| `rollback` | 回滾至舊版本 |
| `workaround_available` | 暫時緩解措施 |

### 狀態轉換邏輯

**端點：** `PATCH /api/vulnerabilities/{vuln_id}/status`

1. 驗證 status、justification、response 組合合法
2. 確認 Release 未鎖定（鎖定回傳 409）
3. 建立 VexHistory 紀錄（`from_status → to_status`，附時間與備註）
4. 更新漏洞欄位
   - 轉為非 `not_affected` → 清除 `justification`
   - 轉為非 `affected` → 清除 `response`
   - 轉為 `fixed` → 自動設定 `fixed_at = now()`
   - 離開 `fixed` → 清除 `fixed_at`

---

## 4. Release 鎖定與完整性驗證

### 鎖定
**端點：** `POST /api/releases/{release_id}/lock`

- 鎖定後禁止：SBOM 重新上傳、漏洞狀態修改
- 用於正式稽核或合規提交後

### 完整性驗證
**端點：** `GET /api/releases/{release_id}/integrity`

重新計算 SBOM 檔案 SHA-256 並與 DB 紀錄比對：

| 結果 | 說明 |
|------|------|
| `ok` | 檔案完整，未被竄改 |
| `tampered` | 雜湊不符，檔案已被修改 |
| `no_file` | SBOM 尚未上傳 |
| `no_hash` | 舊版本未記錄雜湊 |

---

## 5. CRA 事件狀態機

**目的：** 追蹤符合 ENISA 框架的法規事件回應時程

**重要：** CRA 事件為全局實體，不綁定特定組織或產品。

### 狀態流程

```
detected
  └→ pending_triage
        ├→ closed（close-not-affected：確認不在範圍內）
        └→ clock_running（start-clock：設定 T+0，開始計時）
              └→ t24_submitted（T+24h Early Warning 提交）
                    └→ investigating（開始調查）
                          └→ t72_submitted（T+72h Notification 提交）
                                └→ remediating（補丁就緒，開始 T+14d 計時）
                                      └→ final_submitted（Final Report 提交）
                                            └→ closed
```

### 時程截止點

| 里程碑 | 截止時間 |
|--------|----------|
| Early Warning | T+0 起 24 小時 |
| Full Notification | T+0 起 72 小時 |
| Final Report | 補丁發布後 14 天 |

### 關鍵端點

- `POST /api/cra/incidents` — 建立事件（狀態：`detected`）
- `POST /api/cra/incidents/{id}/start-clock` — 開始計時（需 `pending_triage`）
- `POST /api/cra/incidents/{id}/advance` — 推進至下一狀態
- `POST /api/cra/incidents/{id}/close-not-affected` — 關閉（確認不受影響，需 `pending_triage`）

---

## 6. 合規政策規則引擎

### 規則結構

| 欄位 | 說明 |
|------|------|
| `severity` | `critical / high / medium / low / any` |
| `require_kev` | 僅標記 KEV 漏洞 |
| `statuses` | 觸發的漏洞狀態（如 `open,in_triage`） |
| `min_days_open` | 最少開放天數才觸發 |
| `action` | `warn`（警告）或 `block`（阻擋） |
| `enabled` | 啟用/停用 |

### 評估邏輯

```python
def evaluate(rule, vuln):
    if not rule.enabled: return False
    if rule.severity != "any" and vuln.severity != rule.severity: return False
    if rule.require_kev and not vuln.is_kev: return False
    if vuln.status not in rule.statuses: return False
    days_open = (now - vuln.scanned_at).days
    return days_open >= rule.min_days_open
```

### 預設規則

| 規則 | 條件 |
|------|------|
| Critical 7d | Critical + open/in_triage，開放 ≥ 7 天 |
| KEV 3d | KEV + open/in_triage，開放 ≥ 3 天 |
| High 30d | High + open/in_triage，開放 ≥ 30 天 |

---

## 7. 合規報告

### 基本漏洞報告
**端點：** `GET /api/releases/{release_id}/report`

- PDF 格式，含品牌客製化（Logo、公司名、主色、頁尾）
- 元件與漏洞摘要表格，按 CVSS 降序排列

### IEC 62443-4-1（SDL 安全開發生命週期）
**端點：** `GET /api/releases/{release_id}/compliance/iec62443`

評估控制項：SM-9（安全設計）、DM-1~5（缺陷管理）、SUM-1~5（供應鏈管理）

### IEC 62443-4-2（元件安全）
**端點：** `GET /api/releases/{release_id}/compliance/iec62443-4-2`

評估控制項：CR-1（存取控制）、CR-2（軟體限制）、CR-3（設定管理）、CR-4（安全更新）

### IEC 62443-3-3（系統安全）
**端點：** `GET /api/releases/{release_id}/compliance/iec62443-3-3`

評估 FR-1~7 功能需求：識別、保護、偵測、回應、復原

---

## 8. 證據包（Evidence Package）

**端點：** `GET /api/releases/{release_id}/evidence-package`

下載 ZIP 檔，包含：

| 檔案 | 內容 |
|------|------|
| `manifest.json` | 元資料、檔案雜湊、時間戳記 |
| `vex_summary.json` | 漏洞清單與 VEX 狀態/理由 |
| `csaf_vex.json` | CSAF 2.0 格式（行業標準） |
| `vulnerability_report.pdf` | 品牌化 PDF 報告 |
| `sbom.json` | 原始 SBOM 檔案 |

**用途：** 稽核追蹤、法規提交、第三方驗證

---

## 9. CSAF 匯出

**端點：** `GET /api/releases/{release_id}/csaf`

輸出 CSAF 2.0 JSON 文件：
- 文件元資料（ID、版本、追蹤資訊）
- 產品樹（產品名稱與 ID）
- 每個 CVE 對應產品的 VEX 狀態（`known_affected / known_not_affected / fixed / under_investigation`）
- Threat 敘述（含 justification）
- Remediation 說明（含 response）

---

## 10. 告警通知

**觸發條件：** Rescan 後有新漏洞

**Webhook Payload：**
```json
{
  "event": "new_vulnerabilities",
  "product": "產品名稱",
  "org": "組織名稱",
  "version": "1.0.0",
  "release_id": "uuid",
  "new_vuln_count": 5,
  "kev_count": 1,
  "critical_count": 2,
  "vulnerabilities": [/* 最多 50 筆 */]
}
```

**Email：** 含組織/產品/版本、各嚴重度數量、KEV 數量、前 20 筆漏洞清單

---

## 11. 統計與風險分析

### 全平台統計
**端點：** `GET /api/stats`

- 組織/產品/版本/元件總數
- 各嚴重度與狀態的漏洞數
- 修補率、平均修補天數
- 活躍 CRA 事件數

### 跨組織風險總覽
**端點：** `GET /api/stats/risk-overview`

每個組織計算：
- `unpatched_critical`、`unpatched_high` 數量
- 風險分數 = `critical * 10 + high * 3`
- 修補率

依風險分數降序排列。

### Top Threats
**端點：** `GET /api/stats/top-threats`

- 活躍 KEV 漏洞數（未解決）
- 前 5 筆最高 EPSS 分數漏洞（未解決）

---

## 12. 版本差異比對

**端點：** `GET /api/products/{product_id}/diff?from=v1_id&to=v2_id`

比對兩個 Release：
- 元件：新增 / 移除 / 不變 數量
- 漏洞：新增 / 移除 / 不變 數量
- 結果按 CVSS 降序排列

---

## 13. 使用者與權限

| 角色 | 權限 |
|------|------|
| `admin` | 完整存取，包含建立/修改/刪除所有資源 |
| `viewer` | 唯讀（目前端點層級尚未全面強制執行） |

JWT Bearer Token，8 小時到期，儲存於瀏覽器 `localStorage`。

---

## 14. CSV 匯出

**端點：** `GET /api/releases/{release_id}/vulnerabilities/export`

欄位：CVE ID、元件名稱/版本、CVSS v3/v4、嚴重度、EPSS 分數/百分位、KEV 標記、CWE、VEX 狀態/理由/回應/備註/描述

編碼：UTF-8 BOM（相容 Excel 直接開啟）

---

## 15. 品牌客製化

**端點：** `GET/PATCH /api/settings/brand`、`POST /api/settings/brand/logo`

| 欄位 | 說明 |
|------|------|
| `company_name` | 公司名稱（顯示於報告） |
| `tagline` | 副標題 |
| `primary_color` | 主色（`#RRGGBB`） |
| `report_footer` | PDF 頁尾文字（法律/合規聲明） |
| `logo_path` | 上傳的 Logo 路徑（PNG/JPG，最大 2 MB） |
