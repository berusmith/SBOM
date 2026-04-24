# Changelog

所有版本的重要異動記錄。格式依照 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.0.0/)。

---

## [Unreleased]

### 計畫中
- Postgres 後端選項

---

## [2.0.0] — 2026-04

### 新增
- **Reachability 分析（三階段）**：上傳原始碼 zip → Phase 1 import 掃描、Phase 2 測試目錄過濾、Phase 3 Python AST call graph（alias 追蹤、route decorator 進入點、1-hop call graph）；`function_reachable` / `reachable` / `test_only` / `not_found`
- **GHSA 漏洞情資補強**：GitHub Security Advisories REST API，支援 npm/pypi/maven/nuget/cargo/gem/go；ghsa_id 欄位；上傳自動觸發 + 手動補充端點
- **Container / IaC 掃描（Trivy）**：`POST /scan-image`（Container Image）、`POST /scan-iac`（Terraform/K8s zip，回傳 misconfiguration 列表）
- **SBOM 簽章驗證（Sigstore/cosign）**：ECDSA / RSA-PSS / RSA-PKCS1；自動偵測演算法；Policy Gate 第 6 項
- **TISAX 模組**：VDA ISA 6.0，63 個控制項，maturity 0–5，AL2/AL3 gap 分析，PDF/CSV 匯出
- **GitHub Action + CLI**：`tools/sbom-action/`（composite action）、`tools/sbom-cli/sbom.py`（upload/gate/diff）
- **API Token 最小權限**：read / write / admin scope，`require_admin_scope` 守衛
- **首屏性能優化**：路由 lazy load、DependencyGraph/TrendChart 獨立 chunk、依賴圖延後 fetch

### 改善
- License 風險分類（Permissive / Copyleft / Commercial）+ 違規通知
- 韌體掃描支援 EMBA demo mode（Windows 開發環境）
- 競品落差文件（`docs/competitor-gap.md`）持續更新

---

## [1.5.0] — 2026-03

### 新增
- IEC 62443-3-3 系統層級報告（11 項 SR 要求評估）
- IEC 62443-4-2 元件層級報告（4 大類 12 項 CR 要求）
- Policy 引擎：自訂規則自動偵測違規
- 跨客戶風險總覽頁
- CRA 事件管理（Article 14 狀態機 + 24h/72h/14d SLA 時鐘）
- 版本鎖定/解鎖、版本 Diff 比對
- 品牌化報告、Webhook + Email 通知
- 漏洞抑制（Suppression / Risk Acceptance）

---

## [1.0.0] — 2025-12

### 新增（Phase 1 完成）
- 多租戶組織/產品/版本/元件 CRUD
- SBOM 上傳解析（CycloneDX JSON + SPDX JSON）
- CVE 掃描（OSV.dev API，依 PURL 批次查詢）
- VEX 狀態管理（open / in_triage / not_affected / affected / fixed）
- EPSS 整合（FIRST.org）、CISA KEV 標記、NVD 豐富化
- PDF 報告、CSV 匯出、CSAF VEX、合規證據包 ZIP
- SBOM 完整性驗證（SHA-256）
- JWT 登入認證
