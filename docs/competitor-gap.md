# 競品落差分析

**日期**：2026-04-24（更新）
**對照競品**：Anchore Enterprise、Snyk、Dependency-Track (OWASP)、Black Duck、FOSSA、Cybellum、Finite State、NetRise、Endor Labs、Socket、Phylum、**Cybeats SBOM Studio**、**Keysight SBOM Manager**、**FOSSLight**、**Microsoft SBOM Tool**

---

## 競品快速定位表

| 競品 | 分類 | 主要客群 | 對你的威脅程度 |
|------|------|---------|--------------|
| **Dependency-Track** | SBOM 管理（免費開源） | 一般軟體廠商、DevSecOps | **中高**（免費 + SSO + 持續監控，功能差距縮小中）|
| **Anchore Enterprise** | SBOM 管理 + 容器 + 政府合規 | 美國聯邦政府、DoD、Fortune 500 | 低（客群不重疊；無 CRA/IEC/TISAX）|
| Snyk | SCA + 漏洞管理 | 開發者 | 低（不做 ICS/OT 合規） |
| Black Duck | SCA + License | 大企業 | 低（昂貴，無 CRA） |
| Cybellum | 韌體/Binary SCA | 汽車 OEM | 中（汽車市場重疊） |
| Finite State / NetRise | 韌體分析 | IoT/OT | 中（技術層面） |
| Endor Labs | Reachability SCA | 開發者 | 低（無合規） |
| **Cybeats SBOM Studio** | SBOM 管理 + 合規 | **ICS/OT + 醫材** | **高（客群完全重疊）** |
| **Keysight SBOM Manager** | SBOM 管理 + Binary | **OT + 製造業** | **高（2026-03 新上市）** |
| FOSSLight | SBOM 管理 + 授權合規 | 一般軟體廠商 | 低（無 CRA/IEC 合規） |
| Microsoft SBOM Tool | SBOM 生成工具 | CI/CD 使用者 | 無（上游工具，互補）|

---

## 1. 掃描深度與覆蓋率

| 面向 | 現況 | 競品標竿 | 落差 |
|------|------|---------|------|
| 韌體/二進位分析 | EMBA 包一層 | Cybellum / Finite State / NetRise / **Keysight**（binary-only，不需原始碼）| 大 |
| 漏洞資料來源 | OSV.dev + GHSA | Snyk / Black Duck 自有 DB（比 NVD 早 47 天）| 中 |
| 容器 / IaC 掃描 | ✅ Trivy 整合 | Snyk、Anchore 標配 | 補平 |
| 惡意套件偵測 | 無 | Snyk / Socket / Phylum 行為分析 | 中 |
| SBOM 生成 | 無（靠上游工具） | Keysight / Cybeats / FOSSLight 有 | 中（刻意不做，互補策略）|

## 2. 資料與情資

- ✅ 已有：EPSS、KEV、NVD enrichment、GHSA
- ✅ 已有：SBOM 來源真實性（Sigstore/cosign ECDSA、RSA-PSS 簽章驗證）
- ✅ 已有：Reachability 三階段（import → 模組 → Python AST call graph）`function_reachable` / `reachable` / `test_only` / `not_found`
- ❌ 缺：exploit maturity、commercial threat intel

## 3. DevSecOps 整合

- ✅ 已有：API Token（read/write/admin scope）、GitHub Action、CLI
- ✅ 已有：Container Image 掃描（Trivy）、IaC/Terraform/K8s misconfiguration 掃描
- ❌ 缺：GitLab CI 原生範本、Jenkins plugin、IDE 外掛、Splunk/Elastic/Slack 原生整合

## 4. 規模與多租戶

| 面向 | 現況 | 競品 |
|------|------|------|
| DB | ✅ SQLite / Postgres 可選 | Postgres + k8s |
| RBAC | admin / viewer + 單層 org scope | 細粒度 RBAC + SSO/SAML/SCIM |
| SSO / LDAP | ❌ 僅帳密 JWT | DT：OIDC + LDAP + AD；Anchore：SAML |
| 持續監控 | ❌ 需手動 rescan | DT：新 CVE 自動重評全組合 |
| 稽核不可竄改 | AuditEvent append-only（同 DB） | hash chain / WORM storage |

## 5. 合規輸出

### 強項（主要競品都沒有）
- **IEC 62443-4-1 / 4-2 / 3-3** 三份子標準自動化報告
- **CRA T+24 / 72 / 14d 時程鐘 + 事故生命週期**（Keysight 提到 CRA 但無時程鐘）
- **TISAX VDA ISA 6.0**（63 控制項、AL2/AL3 gap）
- CSAF 匯出

### 缺
- FDA Pre-market Cybersecurity（醫材）— Cybeats、Keysight 有
- ISO/SAE 21434（汽車）
- UNECE R155 / R156
- NIS2 報表

---

## 重點競品深度比較

### Cybeats SBOM Studio（最直接競品）
- 加拿大上市公司（Toronto，CYBTS），企業報價
- 客群：**ICS/OT + 醫療設備**，與你完全重疊
- 有 FDA、有 GitHub Action
- **你的優勢**：CRA 時程鐘更深、IEC 62443 三份報告、TISAX、Reachability、離線部署、價格

### Keysight SBOM Manager（2026-03 新上市，警戒）
- 測試儀器大廠跨入，品牌認知度高
- 三模組：Generator（Binary-only）+ Studio + Consumer
- 有 CRA + FDA 合規聲稱，有 VEX
- **你的優勢**：IEC 62443 三份子標準（Keysight 未提）、TISAX、CRA 時程鐘深度、Reachability、離線 + 低成本
- **你的缺口**：Binary-only SBOM 生成（不需原始碼），這對無原始碼的舊 OT 設備很關鍵

### Dependency-Track（最直接的開源競品，威脅程度中高）
- 免費、Apache 2.0、社群成熟、Docker 部署、Postgres 原生
- 漏洞來源：NVD + GHSA + OSS Index + Snyk + OSV + **VulnDB（商業）**
- **DT 有但你沒有**：
  1. 持續監控（新 CVE 公布後自動重評全組合，不需手動 rescan）
  2. SSO：OIDC + LDAP + Active Directory
  3. Slack / Teams / WebEx 原生通知
  4. CPE 誤配問題（你的優勢：PURL-first 更精確）
- **你有但 DT 沒有**：CRA 時程鐘、IEC 62443、TISAX、Reachability、格式互轉、品質評分、中文化、離線低成本
- **你的差異化說詞**：「DT 是找漏洞的工具，我是管合規的平台；DT 告訴你有漏洞，我告訴你 CRA 還剩幾天、IEC 62443 哪裡沒過。」

### Anchore Enterprise（客群不重疊，參考用）
- 開源 Syft + Grype 的商業版，主打美國聯邦政府、DoD、Fortune 500
- 強項：Malware/Secret 偵測、Policy-as-code（JSON）、Air-gapped（IL4-6）、K8s 原生（EKS/ECS/GKE）
- 合規標準：NIST / FedRAMP / DISA —— **完全沒有 CRA / IEC 62443 / TISAX**
- **你的差異化說詞**：「Anchore 是美國政府合規工具，你是歐盟製造業合規，客戶重疊機率很低；若同場競爭，強調三份 IEC 62443 報告和 CRA 時程鐘。」

### FOSSLight（非直接競品）
- LG 開源，免費
- 強項是 OSS 授權合規（授權義務追蹤）
- 無 CRA / IEC 62443 / TISAX
- 客群是一般軟體廠商，不是 ICS/OT

### Microsoft SBOM Tool（上游工具，不是競品）
- 純 SBOM 生成，輸出 SPDX 2.2/3.0
- CI pipeline 用，產出後就結束
- **互補關係**：客戶用 Microsoft SBOM Tool 生成 → 上傳你的平台管理

---

## 相對突出的地方

1. CRA T+24/72/14d 時程鐘 + 事故生命週期（幾乎無競品做到此深度）
2. IEC 62443 三份子標準自動化報告（4-1 / 4-2 / 3-3）
3. TISAX VDA ISA 6.0 自評（63 個控制項、AL2/AL3 gap 分析）
4. Reachability 三階段 AST call graph（連 Keysight/Cybeats 都沒有）
5. 中文化 + 本地顧問 SOP
6. 離線部署（Oracle Cloud 1GB RAM 可跑）
7. 價格差距 10–100 倍

---

## 建議補強優先順序

| # | 項目 | 工時 | 理由 |
|---|------|------|------|
| 1 | ~~**GitHub Action + CLI**~~ | ✅ 完成 | |
| 2 | ~~**SBOM Sigstore 簽章驗證**~~ | ✅ 完成 | |
| 3 | ~~**Container / IaC 掃描（Trivy）**~~ | ✅ 完成 | |
| 4 | ~~**TISAX 模組**~~ | ✅ 完成 | |
| 5 | ~~**漏洞情資補強（GHSA）**~~ | ✅ 完成 | |
| 6 | ~~**Reachability（Python AST 三階段）**~~ | ✅ 完成 | |
| 7 | ~~**Postgres 後端選項**~~ | ✅ 完成 | |
| 8 | **持續監控**（新 CVE 自動重評） | 1 週 | DT 的核心優勢；客戶問最多 |
| 9 | **SSO / LDAP 整合** | 1–2 週 | DT 有 OIDC+LDAP+AD；企業 IT 必問 |
| 10 | **FDA Pre-market Cybersecurity 報告** | 2 週 | 有醫材客戶詢問時再做 |
| 11 | **Binary SBOM 生成（無原始碼）** | 待評估 | Keysight 的核心賣點；對舊 OT 設備客戶有吸引力 |
