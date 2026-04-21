# Phase 2 功能規格書

**目標里程碑：** 2026-Q3（CRA Article 14 強制執行前）  
**優先邏輯：** 直接支援 CRA 合規 > IEC 62443 深化 > 技術基礎設施

---

## 功能清單

| # | 功能 | 優先度 | 狀態 |
|---|------|--------|------|
| 2.1 | CSAF 2.0 完整匯入 | 高 | 計畫中 |
| 2.2 | CRA Article 14 強化（證據包 v2） | 高 | 計畫中 |
| 2.3 | VEX 鏈繼承（供應商上游） | 中 | 計畫中 |
| 2.4 | 韌體掃描（EMBA 整合） | 中 | 計畫中 |
| 2.5 | 資料庫遷移系統（Alembic） | 低 | 計畫中 |

---

## 2.1 CSAF 2.0 完整匯入

**現況：** 已可匯出 CSAF VEX JSON。缺少匯入（從廠商 advisory 導入）。

**目標：** 可將廠商發布的 CSAF 2.0 advisory 匯入平台，自動對應至受影響元件並批次更新 VEX 狀態。

### 功能需求

- 上傳 CSAF 2.0 JSON 檔案（`csaf_version: "2.0"`）
- 解析 `product_tree` 與 `vulnerabilities[].remediations`
- 比對平台內元件的 PURL / 產品名稱
- 對比對成功的漏洞批次套用 VEX 狀態（`fixed` / `not_affected`）
- 匯入結果摘要：成功對應 N 筆、未對應 M 筆

### 新增端點

```
POST /api/csaf/import          上傳 CSAF JSON 並解析
GET  /api/csaf/advisories      列出已匯入的 advisories
GET  /api/csaf/advisories/{id} 取得 advisory 詳情
```

### 新增檔案

```
backend/app/api/csaf.py
backend/app/models/csaf_advisory.py
backend/app/services/csaf_service.py
frontend/src/pages/CSAFAdvisories.jsx
```

### 資料欄位（csaf_advisories 表）

| 欄位 | 類型 | 說明 |
|------|------|------|
| id | String PK | UUID |
| document_title | String | CSAF `document.title` |
| document_id | String | CSAF `document.tracking.id` |
| publisher | String | 發布廠商名稱 |
| severity | String | 最高嚴重度 |
| raw_json | Text | 原始 CSAF JSON |
| matched_count | Integer | 成功對應漏洞數 |
| imported_at | DateTime | 匯入時間 |

---

## 2.2 CRA Article 14 強化

**現況：** SLA 時鐘 + 狀態機已完成。缺少正式的通報草稿產生器與 ENISA 格式輸出。

**目標：** 從事件資料自動產生三份通報草稿（Early Warning / Notification / Final Report），格式符合 ENISA EUVDB 模板。

### 功能需求

- Early Warning 草稿（T+24h）：事件概述、受影響產品、CVE 編號、初步評估
- Vulnerability Notification 草稿（T+72h）：詳細技術分析、影響範圍、暫時緩解措施
- Final Report 草稿（修補後 14 天內）：完整根因分析、修補措施、預防措施
- 草稿以 PDF 或 Markdown 匯出
- 每份草稿可在平台上編輯後下載（非直接提交 ENISA，需人工審核）

### 新增端點

```
GET  /api/cra/incidents/{id}/draft-t24     產生 T+24h 草稿
GET  /api/cra/incidents/{id}/draft-t72     產生 T+72h 草稿
GET  /api/cra/incidents/{id}/draft-final   產生最終報告草稿
```

---

## 2.3 VEX 鏈繼承

**現況：** VEX 狀態為各版本獨立管理。

**目標：** 當上游供應商提供 VEX 聲明時，可自動繼承至平台內使用相同元件的所有版本。

### 功能需求

- 建立「供應商（Supplier）」記錄，關聯到 Organization
- 供應商可上傳其 CSAF VEX 或手動設定 VEX 聲明
- 當供應商的 VEX 更新時，繼承至所有引用相同 PURL 的 release
- 繼承的 VEX 標記來源為「供應商繼承」，與手動設定區分
- 顧問可覆寫繼承的 VEX（覆寫後不再自動更新）

### 新增表

```
suppliers              供應商記錄
supplier_vex_cache     供應商 VEX 聲明快取
```

### 繼承規則

```
元件 PURL 完全匹配 → 自動繼承
PURL 前綴匹配（忽略版本） → 標記為「供應商建議」，需人工確認
無匹配 → 不動
```

---

## 2.4 韌體掃描（EMBA 整合）

**現況：** 平台只處理 SBOM 文件，不直接分析韌體二進位。

**目標：** 整合 EMBA 開源框架，對上傳的韌體映像進行靜態分析，自動產生 SBOM 並掃描漏洞。

### 前置條件

- EMBA 需安裝於同一台機器或可連接的 Linux 伺服器（EMBA 僅支援 Linux）
- Windows 開發環境需透過 WSL2 或另一台 Linux 機器呼叫

### 分階段實作

**Phase 2.4a — 基礎（先做）**
- 上傳韌體映像（`.bin` / `.img` / `.zip`）
- 呼叫 EMBA 執行分析（非同步，可能需要數分鐘到數小時）
- 解析 EMBA 輸出，提取元件清單 → 自動轉為平台 SBOM
- 在掃描結果頁面顯示分析進度與結果

**Phase 2.4b — 深化**
- 硬編碼密碼/金鑰掃描結果整合
- 已知惡意韌體 hash 比對
- 網路服務暴露清單

### 新增端點

```
POST /api/firmware/upload        上傳韌體（multipart）
GET  /api/firmware/scans         列出掃描任務
GET  /api/firmware/scans/{id}    取得掃描進度與結果
POST /api/firmware/scans/{id}/import-sbom  將掃描結果建立為 release SBOM
```

---

## 2.5 資料庫遷移系統（Alembic）

**現況：** Schema 變更透過 `main.py` 啟動時的 `ALTER TABLE ADD COLUMN` 處理。此方式無法：刪除/重命名欄位、處理資料遷移、記錄 schema 版本歷史。

**目標：** 引入 Alembic，建立標準化 migration 流程。

### 實作步驟

1. 安裝：`pip install alembic`，在 `backend/` 執行 `alembic init alembic`
2. 設定 `alembic/env.py` 指向 SQLite 資料庫
3. 建立初始 baseline migration（代表目前 schema 狀態）
4. 未來 schema 變更：`alembic revision --autogenerate -m "add_xxx_table"`
5. 從 `main.py` 移除現有 `ALTER TABLE` 區塊（由 Alembic 接管）

### 注意事項

- SQLite 的 Alembic 支援有限（不支援 DROP COLUMN、RENAME COLUMN 的原生 ALTER）
- 需使用 `batch_alter_table` 方法繞過 SQLite 限制
- 生產環境升級前務必備份 `sbom.db`

---

## 時程建議

```
2026-05  2.1 CSAF 匯入 + 2.2 CRA 草稿產生器
2026-06  2.3 VEX 鏈繼承
2026-07  2.4a 韌體掃描基礎
2026-08  完整測試 + 客戶驗收
2026-09  CRA Article 14 強制執行日（2026-09-11）
```
