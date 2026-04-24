# TISAX 合規模組 — 規劃筆記

> **狀態：✅ 已完成（2026-04）**  
> 實作：`backend/app/api/tisax.py`、`backend/app/models/tisax.py`、`frontend/src/pages/TISAXAssessments.jsx`、`TISAXDetail.jsx`  
> 參考來源：aa.txt（車用資安標準整理，4月17–18日對話記錄）

---

## 背景

現有 SBOM 平台已有 IEC 62443 合規模組。  
用戶詢問是否可加入 **TISAX（VDA ISA 6.0）** 自評模組，供 ICS/OT 製造商接觸德系 OEM 客戶時使用。

---

## 什麼是 TISAX

| 項目 | 說明 |
|------|------|
| 全名 | Trusted Information Security Assessment Exchange |
| 制定 | VDA（德國汽車工業協會）+ ENX Association |
| 性質 | 供應鏈資安評估機制（非法規，但德系 OEM 實質強制） |
| 標準版本 | VDA ISA 6.0（2024 年 4 月生效） |
| 評估等級 | AL1（自評）/ AL2（遠端）/ AL3（現場） |
| 有效期 | 3 年 |

### 三大評估模組

| 模組 | 控制項數 | 適用情境 |
|------|---------|---------|
| 資訊安全（Information Security） | 41 項 | 所有申請者必考 |
| 原型保護（Prototype Protection） | 22 項 | 接觸研發樣品、測試車、未公開零件 |
| 個資保護（Data Protection） | 4 項 | 處理車主／員工個資 |

### VDA ISA 6.0 控制項結構

**資訊安全 41 項（7 章）**
- 1.x 政策與組織
- 2.x 人資安全
- 3.x 實體安全
- 4.x 存取控制（IAM）
- 5.x IT 安全
- 6.x 供應商管理
- 7.x 合規

**原型保護 22 項（8 子類）**
- 8.1 安全分類與管理
- 8.2 合約管理
- 8.3 實體與環境安全
- 8.4 組織與人員
- 8.5 訪客管理
- 8.6 原型車輛與零件處理
- 8.7 測試與試駕
- 8.8 活動與展示

---

## 可參考的現有系統

| 來源 | 類型 | 用途 |
|------|------|------|
| **ENX Portal** (portal.enx.com) | 官方 | 下載 VDA ISA 6.0 官方 Excel 問卷（最權威） |
| **verinice** (verinice.com) | 開源 Java/Web | 看控制項與組織/產品綁定的架構設計 |
| **Drata** | 商業 SaaS | 參考：自動對應控制項、證據收集、OEM 報告格式 |
| **OneTrust** | 商業 SaaS | 參考：問卷管理、供應商評估流程 |

---

## 功能規劃草案（待細化）

### 核心頁面

1. **TISAX 自評儀表板**
   - 兩個模組（資訊安全 / 原型保護）進度環形圖
   - 整體成熟度分數（0–5 級）
   - 缺口項目數、達標項目數

2. **控制項自評表**
   - 依章節展開（折疊式）
   - 每項：控制項名稱、要求重點、當前成熟度（下拉 0–5）、目標成熟度、差距
   - 狀態標籤：達標（綠）/ 接近（黃）/ 缺口（紅）/ 未評（灰）
   - 欄位：證據文件描述、負責人、預計完成日、備註

3. **差距分析報告**
   - 依風險排序的缺口清單
   - 可匯出 PDF / Excel

4. **稽核準備度**
   - AL2 / AL3 達標率試算
   - Go/No-Go 判準（建議 ≥ 95% 控制項達目標成熟度）

### 資料模型（草案）

```
TISAXAssessment
  id, organization_id, module (infosec|prototype|privacy)
  assessment_level (AL1|AL2|AL3), status, created_at

TISAXControlItem
  id, assessment_id, control_number (e.g. "8.3.2")
  category, name, requirement_summary
  current_maturity (0-5), target_maturity (0-5)
  status (compliant|near|gap|unassessed)
  evidence_note, owner, due_date, remarks
```

### API 端點（草案）

```
POST   /api/tisax/assessments
GET    /api/tisax/assessments/{id}
PUT    /api/tisax/assessments/{id}/controls/{control_id}
GET    /api/tisax/assessments/{id}/gap-report
GET    /api/tisax/assessments/{id}/export-pdf
GET    /api/tisax/assessments/{id}/export-excel
```

---

## 實作優先順序建議

1. **Phase 1（最小可用）**：後端資料模型 + 63 個控制項種子資料 + 基本自評 CRUD
2. **Phase 2（可用）**：前端自評表頁面 + 儀表板 + 差距分析
3. **Phase 3（完整）**：PDF/Excel 匯出 + 多組織共用控制項基礎資料庫

---

## 參考文件

- `D:\projects\SBOM\aa.txt` — 車用資安標準整理完整對話（含 VDA ISA 6.0 控制項翻譯、稽核 Q&A、18 份 SOP 清單）
- ENX 官方：https://portal.enx.com/en-us/TISAX/downloads/
- VDA ISA Berater：https://vda-isa-berater.com/en/vda-isa-catalog-6/
