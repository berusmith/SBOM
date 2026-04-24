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

---

## 待做（依優先順序）

| # | 項目 | 預估 | 理由 |
|---|------|------|------|
| 1 | **漏洞情資補強**（GHSA + Debian/RHEL advisory） | 3–5 天 | 縮短比 NVD 早 47 天的情資落差；顧問話術直接加分 |
| 2 | **Reachability 分析**（Python/Node 先行） | ~2 月 | 2026 SCA 最熱賣點；Endor 號稱噪音砍 90% |
| 3 | **Postgres 後端選項** | ~1 週 | 進企業客戶前必過關 |

---

## 已知問題

- IEC 62443-4-2 / 3-3 PDF 在 Windows 有 CJK 字型問題（fpdf2 Helvetica 限制）
- CRA `start-clock` 狀態機在已 `clock_running` 時回 409（設計如此，非 bug）
