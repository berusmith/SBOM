# 競品落差分析

**日期**：2026-04-23
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
- ❌ 缺：exploit maturity、commercial threat intel
- ❌ 缺：reachability analysis（呼叫鏈是否真的會碰到漏洞函式）——Snyk / Endor Labs 的主打
- ❌ 缺：SBOM 來源真實性（Sigstore / in-toto attestation）

## 3. DevSecOps 整合

- 現況：只有 API Token（read/write/admin scope）
- 競品：現成 GitHub Action、GitLab CI、Jenkins plugin、IDE 外掛、OPA/Rego policy as code、Splunk/Elastic/Slack 原生整合
- **這塊是最大落差，但也最便宜補上** ← 下一項工作

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
| 1 | **GitHub Action + CLI** | 2–3 天 | 立刻打開 CI/CD 客戶；已有 API Token 基礎 |
| 2 | **Reachability**（Python/Node 先行） | 2 月 | 差異化關鍵 |
| 3 | **SBOM Sigstore 簽章驗證** | 1 週 | CRA 稽核會被問 |
| 4 | **TISAX 模組** | 2 週 | 補汽車供應鏈 |
| 5 | **Postgres 後端選項** | 1 週 | 進企業客戶必過關 |
