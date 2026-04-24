# 競品落差分析

**日期**：2026-04-24（更新）
**對照競品**：Anchore、Snyk、Dependency-Track (OWASP)、Black Duck、FOSSA、Cybellum、Finite State、NetRise、Endor Labs、Socket、Phylum

---

## 1. 掃描深度與覆蓋率

| 面向 | 現況 | 競品標竿 | 落差 |
|------|------|---------|------|
| 韌體/二進位分析 | EMBA 包一層 | Cybellum / Finite State / NetRise 有 binary SCA、加密金鑰偵測、韌體 diff、Yocto/Buildroot 解析 | 大 |
| 漏洞資料來源 | OSV.dev 單一來源 | Snyk / Black Duck 自有 DB + 私有 advisory（比 NVD 早 2–4 週）| 中 |
| 容器 / IaC 掃描 | 無 | Snyk、Anchore、Trivy 標配 | 大 |
| 惡意套件偵測 | 無 | Snyk / Socket / Phylum 有行為分析 | 中 |

## 2. 資料與情資

- ✅ 已有：EPSS、KEV、NVD enrichment
- ✅ 已有：SBOM 來源真實性（Sigstore/cosign ECDSA、RSA-PSS 簽章驗證）
- ❌ 缺：exploit maturity、commercial threat intel（Snyk 私有 DB 比 NVD 早 47 天）
- ❌ 缺：reachability analysis（呼叫鏈是否真的會碰到漏洞函式）——Snyk / Endor Labs 的主打，Endor 號稱噪音砍 90%

## 3. DevSecOps 整合

- ✅ 已有：API Token（read/write/admin scope）、GitHub Action（`tools/sbom-action/`）、CLI（`tools/sbom-cli/sbom.py`）
- ✅ 已有：Container Image 掃描（`POST /scan-image`，Trivy 後端）、IaC/Terraform/K8s misconfiguration 掃描（`POST /scan-iac`）
- ❌ 缺：GitLab CI 原生範本、Jenkins plugin、IDE 外掛、OPA/Rego policy as code、Splunk/Elastic/Slack 原生整合

## 4. 規模與多租戶

| 面向 | 現況 | 競品 |
|------|------|------|
| DB | SQLite 單機 | Postgres + k8s |
| RBAC | admin / viewer + 單層 org scope | 細粒度 RBAC + SSO/SAML/SCIM |
| 稽核不可竄改 | AuditEvent append-only（同 DB） | hash chain / WORM storage |

## 5. 合規輸出

### 強項（競品反而弱）
- **IEC 62443-4-1 / 4-2 / 3-3** 三份子標準自動化報告
- **CRA T+24 / 72 / 14d 時程鐘 + 事故生命週期**——幾乎沒競品做到這麼貼歐盟諮詢實務
- CSAF 匯出

### 缺
- TISAX（汽車供應鏈，計畫中見 `docs/TISAX_MODULE_PLAN.md`）
- ISO/SAE 21434（汽車）
- UNECE R155 / R156
- FDA Pre-market Cybersecurity（醫材）
- NIS2 報表

---

## 相對突出的地方

1. CRA 時程鐘 + 事故生命週期
2. IEC 62443 三份子標準自動化報告
3. 中文化 + 本地顧問 SOP
4. 離線部署（Oracle Cloud 1GB RAM 可跑）
5. 價格差距 10–100 倍

---

## 建議補強優先順序

| # | 項目 | 工時 | 理由 |
|---|------|------|------|
| 1 | ~~**GitHub Action + CLI**~~ | ✅ 完成 | |
| 2 | ~~**SBOM Sigstore 簽章驗證**~~ | ✅ 完成 | |
| 3 | ~~**Container / IaC 掃描（Trivy）**~~ | ✅ 完成 | |
| 4 | **Reachability**（Python/Node 先行） | 2 月 | 2026 年 SCA 最熱賣點；Endor 號稱噪音砍 90% |
| 5 | **TISAX 模組** | 2 週 | 補汽車供應鏈 |
| 6 | **Postgres 後端選項** | 1 週 | 進企業客戶必過關 |
