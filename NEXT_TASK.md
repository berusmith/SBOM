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

---

## 待做（依優先順序）

| # | 項目 | 預估 | 理由 |
|---|------|------|------|
| 1 | **Postgres 後端選項** | ~1 週 | 進企業客戶前必過關；脫敏分享的前提 |
| 2 | **SBOM 脫敏與供應鏈分享** | ~2 週 | 需 Postgres 先完成 |
| 3 | **Binary/PDF 盤點引導** | 待評估 | OT 舊設備無原始碼場景，對標 Keysight |

---

## 已知問題

- IEC 62443-4-2 / 3-3 PDF 在 Windows 有 CJK 字型問題（fpdf2 Helvetica 限制）
- CRA `start-clock` 狀態機在已 `clock_running` 時回 409（設計如此，非 bug）
