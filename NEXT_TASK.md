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
| Reachability Phase 1（import 層級，Python/Node，reachability 欄位） | `e3c6521` |

---

## 待做（依優先順序）

| # | 項目 | 預估 | 理由 |
|---|------|------|------|
| 1 | ~~**Reachability Phase 1**~~（import 層級，Python/Node） | ✅ 完成 | |
| 2 | **Reachability Phase 2**（模組層級，過濾 test/scripts） | 2–3 週 | Phase 1 完成後接續 |
| 3 | **Reachability Phase 3**（函式層級 call graph） | 1–2 月 | 真正的 Endor Labs 等級 |
| 4 | **Postgres 後端選項** | ~1 週 | 進企業客戶前必過關 |

### Reachability 各期說明

**Phase 1 — 依賴是否實際被 import（1–2 週）**
- 使用者上傳原始碼 zip，後端掃描 import 語句
- 支援 Python（`import X` / `from X import`）、Node（`require` / `import from`）
- 每個漏洞新增欄位 `reachability: "imported" | "not_found" | "unknown"`
- 純文字比對，不需 AST，不需新套件
- 預估噪音削減 20–40%

**Phase 2 — 模組層級追蹤（2–3 週）**
- 追蹤哪些檔案 import 了問題套件
- 過濾僅出現在 `tests/`、`test_*`、`scripts/` 的使用
- 結果：`reachability: "reachable" | "test_only" | "not_imported"`
- 額外削減 10–20% 噪音

**Phase 3 — 函式層級 Call Graph（1–2 月）**
- 真正的 AST 靜態分析，建 call graph
- 確認漏洞函式是否在呼叫鏈上
- 對標 Endor Labs / Snyk 等級

---

## 已知問題

- IEC 62443-4-2 / 3-3 PDF 在 Windows 有 CJK 字型問題（fpdf2 Helvetica 限制）
- CRA `start-clock` 狀態機在已 `clock_running` 時回 409（設計如此，非 bug）
