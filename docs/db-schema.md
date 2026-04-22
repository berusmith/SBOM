# 資料庫 Schema 文件

資料庫：SQLite，檔案位置 `backend/sbom.db`  
主鍵：全部使用 UUID（String）  
Cascade：所有子表均設定 `cascade="all, delete-orphan"`

---

## 資料關聯圖

```
organizations
    └── products
            └── releases
                    ├── components
                    │       └── vulnerabilities
                    │               └── vex_history
                    ├── vex_statements
                    └── compliance_maps

cra_incidents        (org 層級，獨立)
users                (全域)
policy_rules         (全域)
brand_config         (全域，單筆)
alert_config         (全域，單筆)
audit_events         (全域，append-only)
```

---

## 資料表詳細欄位

### organizations

| 欄位 | 類型 | 說明 |
|------|------|------|
| id | String PK | UUID |
| name | String UNIQUE | 組織名稱（客戶公司名） |
| license_status | String | `active` / `trial` / `expired`，預設 `trial` |
| created_at | DateTime | 建立時間（UTC） |

---

### products

| 欄位 | 類型 | 說明 |
|------|------|------|
| id | String PK | UUID |
| organization_id | String FK → organizations.id | |
| name | String | 產品名稱（如：工業閘道器 A1） |
| description | Text nullable | 產品說明 |

---

### releases

| 欄位 | 類型 | 說明 |
|------|------|------|
| id | String PK | UUID |
| product_id | String FK → products.id | |
| version | String | 版本號（如：v1.2.3） |
| sbom_file_path | String nullable | 上傳檔案路徑（`uploads/<uuid>_<filename>`） |
| dtrack_project_uuid | String nullable | 保留欄位（未來整合用） |
| created_at | DateTime | 建立時間 |
| sbom_hash | String nullable | 上傳 SBOM 的 SHA-256，用於完整性驗證 |
| locked | Boolean | `true` 表示版本已鎖定，禁止修改，預設 `false` |

---

### components

| 欄位 | 類型 | 說明 |
|------|------|------|
| id | String PK | UUID |
| release_id | String FK → releases.id | |
| name | String | 元件名稱（如：`log4j-core`） |
| version | String nullable | 版本號 |
| purl | String nullable | Package URL（如：`pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`） |
| license | String nullable | 授權類型（如：`Apache-2.0`） |

---

### vulnerabilities

| 欄位 | 類型 | 說明 |
|------|------|------|
| id | String PK | UUID |
| component_id | String FK → components.id | |
| cve_id | String | CVE 編號（如：`CVE-2021-44228`） |
| cvss_score | Float nullable | CVSS 分數（舊版，保留相容性） |
| severity | String nullable | `critical` / `high` / `medium` / `low` / `info` |
| status | String | VEX 狀態，預設 `open`（見下方 VEX 狀態） |
| justification | String nullable | VEX not_affected 理由（見 API 文件） |
| response | String nullable | VEX affected 回應方式（見 API 文件） |
| detail | Text nullable | 自由文字補充說明 |
| epss_score | Float nullable | EPSS 利用可能性分數（0–1） |
| epss_percentile | Float nullable | EPSS 百分位排名（0–1） |
| is_kev | Boolean | 是否在 CISA KEV 清單，預設 `false` |
| description | String nullable | NVD CVE 描述 |
| cwe | String nullable | CWE 編號（如：`CWE-20,CWE-917`） |
| nvd_refs | String nullable | NVD 參考連結（JSON 陣列序列化） |
| cvss_v3_score | Float nullable | CVSS v3 分數 |
| cvss_v3_vector | String nullable | CVSS v3 向量字串 |
| cvss_v4_score | Float nullable | CVSS v4 分數 |
| cvss_v4_vector | String nullable | CVSS v4 向量字串 |
| scanned_at | DateTime | 最後掃描時間（SLA 起算點） |
| fixed_at | DateTime nullable | 標記為 fixed 的時間（計算修補天數用） |
| suppressed | Boolean | 是否已抑制（風險接受），預設 `false` |
| suppressed_until | DateTime nullable | 抑制有效期限；`null` 表示永久；到期後自動失效 |
| suppressed_reason | String nullable | 抑制原因（自由文字，稽核紀錄用） |

**VEX 狀態（status）：** `open` / `in_triage` / `not_affected` / `affected` / `fixed`

**SLA 基準（基於 scanned_at）：**

| severity | SLA 天數 |
|----------|---------|
| critical | 7 |
| high | 30 |
| medium | 90 |
| low | 180 |

抑制中的漏洞不計入 SLA 逾期統計。

---

### vex_history

VEX 狀態變更的 append-only 稽核紀錄。

| 欄位 | 類型 | 說明 |
|------|------|------|
| id | String PK | UUID |
| vulnerability_id | String FK → vulnerabilities.id | |
| from_status | String nullable | 變更前狀態 |
| to_status | String | 變更後狀態 |
| note | Text nullable | 備註（由操作者填入） |
| changed_at | DateTime | 變更時間（UTC） |

---

### vex_statements

Release 層級的 VEX 聲明（CSAF 匯出用）。

| 欄位 | 類型 | 說明 |
|------|------|------|
| id | String PK | UUID |
| release_id | String FK → releases.id | |
| cve_id | String | CVE 編號 |
| status | String | `not_affected` / `in_triage` / `affected` / `fixed` |
| justification | Text nullable | 聲明理由 |
| created_at | DateTime | 建立時間 |
| updated_at | DateTime | 最後更新時間 |

---

### cra_incidents

CRA Article 14 事件管理，掛在 organization 層級（透過 org_id 欄位隔離）。

| 欄位 | 類型 | 說明 |
|------|------|------|
| id | String PK | UUID |
| title | String | 事件標題 |
| description | String nullable | 事件說明 |
| trigger_cve_ids | String nullable | 觸發 CVE（逗號分隔，如：`CVE-2021-44228`） |
| trigger_source | String nullable | `manual` / `kev` / `osv` |
| status | String | 狀態機狀態，預設 `detected` |
| awareness_timestamp | DateTime nullable | T+0：SLA 時鐘啟動時間 |
| t24_deadline | DateTime nullable | T+24h Early Warning 截止 |
| t72_deadline | DateTime nullable | T+72h Notification 截止 |
| remediation_available_at | DateTime nullable | 修補可用時間 |
| t14d_deadline | DateTime nullable | 最終報告截止（修補後 14 天） |
| enisa_ref_t24 | String nullable | ENISA T+24h 參考編號 |
| enisa_ref_t72 | String nullable | ENISA T+72h 參考編號 |
| enisa_ref_final | String nullable | ENISA Final Report 參考編號 |
| org_id | String nullable FK → organizations.id | 所屬組織 |
| audit_log | String nullable | Append-only 稽核紀錄（換行分隔，格式：`ISO_TS\|USER\|ACTION\|NOTE`） |
| created_at | DateTime | 建立時間 |
| updated_at | DateTime | 最後更新時間 |

---

### users

| 欄位 | 類型 | 說明 |
|------|------|------|
| id | String PK | UUID |
| username | String UNIQUE | 使用者名稱 |
| hashed_password | String | bcrypt hash |
| role | String | `admin`（完整權限）/ `viewer`（唯讀） |
| organization_id | String nullable FK → organizations.id | 限定使用者只能看到特定組織 |

---

### policy_rules

自訂合規政策規則。

| 欄位 | 類型 | 說明 |
|------|------|------|
| id | String PK | UUID |
| name | String | 規則名稱 |
| condition | String | 觸發條件（如：`severity=critical AND days_open>7`） |
| action | String | `warn` / `block` |
| enabled | Boolean | 是否啟用 |
| created_at | DateTime | 建立時間 |

---

### brand_config（單筆）

| 欄位 | 類型 | 說明 |
|------|------|------|
| id | String PK | UUID |
| company_name | String nullable | 公司名稱（顯示於報告） |
| primary_color | String nullable | 主題色（HEX，如：`#1a56db`） |
| footer_text | String nullable | 報告頁尾文字 |
| logo_path | String nullable | Logo 檔案路徑 |

---

### alert_config（單筆）

| 欄位 | 類型 | 說明 |
|------|------|------|
| id | String PK | UUID |
| webhook_url | String nullable | Webhook 端點（Slack/Teams incoming webhook） |
| email_to | String nullable | 通知收件人 Email |
| notify_new_vuln | Boolean | 發現新漏洞時通知，預設 `false` |
| notify_kev | Boolean | 新 KEV 漏洞時通知，預設 `false` |
| monitor_interval_hours | Integer | 背景監控間隔小時數，預設 24 |
| monitor_last_run | DateTime nullable | 上次監控執行時間 |

---

## Schema 遷移說明

本專案**不使用 Alembic**。新欄位透過 `backend/app/main.py` 啟動時的 `ALTER TABLE ADD COLUMN` 區塊處理（若欄位已存在則跳過）。  
新增欄位時，請在 `main.py` 的 migration 區塊加入對應的 `ALTER TABLE` 陳述式。

SQLite 不支援 `DROP COLUMN` / `RENAME COLUMN`（需建新表搬移）。
