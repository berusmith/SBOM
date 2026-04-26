# SBOM Management Platform

適用於 ICS/OT 製造商的 SBOM 管理平台，符合 EU CRA、IEC 62443、NIS2、TISAX 法規要求。

## 重點能力一眼看完

- **SBOM 拆解（生成）** — 內建呼叫 [Trivy](https://github.com/aquasecurity/trivy) 拆解容器映像 / IaC，內建呼叫 [Syft](https://github.com/anchore/syft) 從原始碼 zip 與 binary（`.exe` / `.so` / `.dll` / `.jar` / `.whl` / firmware image）產出 SBOM；支援上傳既有 CycloneDX / SPDX SBOM
- **漏洞情資** — OSV.dev 自動掃描 + EPSS 利用可能性 + CISA KEV 已知被利用 + NVD CVE 詳情 + GitHub Security Advisories
- **VEX 與抑制** — open / in_triage / not_affected / affected / fixed 五狀態，可批次更新；獨立 suppression 機制（含到期時間）
- **多重合規報告** — EU CRA 事件管理、IEC 62443-4-1 / 4-2 / 3-3、TISAX 自評、NIS2 Article 21；全部 PDF + CSAF VEX
- **多租戶** — 每個 organization 獨立隔離；3 階方案（Starter / Standard / Professional）
- **企業就緒** — JWT + OIDC SSO、API Token（read/write/admin scope）、稽核日誌、Webhook（Slack / Teams 自動格式化）、Email 通知、Sigstore 簽章驗證、SBOM 脫敏分享連結、持續監控背景掃描
- **部署** — 開發機（Windows / macOS / Linux）+ 生產 Mac Mini（launchd + Homebrew，無需 sudo / Docker）

---

## 系統需求

| 項目 | 開發機 | 生產（Mac Mini） |
|------|-------|------------------|
| Python | 3.11+ | 3.11+（`brew install python@3.11`） |
| Node.js | 18+ | 不需要（前端在開發機 build） |
| 資料庫 | SQLite（內建） | PostgreSQL 16（推薦）/ SQLite |
| 反向代理 | 不需要 | nginx（必裝 — backend 綁 127.0.0.1） |
| 作業系統 | Windows 10/11、macOS、Linux | macOS（已驗證 Mac Mini） |
| Docker | 不需要 | 不需要（純 launchd + venv） |

---

## 首次安裝（新機器）

### 1. 拉取程式碼

```bash
git clone https://github.com/berusmith/SBOM.git
cd SBOM/sbom-platform
```

### 2. 安裝後端套件

```bash
cd backend
pip install -r requirements.txt
```

### 3. 建立環境設定檔

```bash
# Windows
copy .env.example .env

# 基本功能不需修改 .env 即可運作
# 如需 Email 通知或更快的 NVD 查詢，請編輯 .env 填入對應值
```

### 4. 安裝前端套件

```bash
cd ../frontend
npm install
```

### 5.（可選）啟用 SBOM 拆解能力

平台本體只負責「消費 SBOM 與管理漏洞」，實際的拆解動作由外部工具承擔。三條路自由組合：

| 拆解對象 | 工具 | License | 啟用 |
|---------|------|---------|------|
| 容器映像 / IaC | Trivy | Apache-2.0 ✅ | `brew install trivy`（macOS）/ apt|dnf |
| 原始碼 zip → SBOM | Syft | Apache-2.0 ✅ | `brew install syft` |
| Binary / firmware → SBOM | Syft | Apache-2.0 ✅ | `brew install syft` |
| 韌體深度解包（需要時） | EMBA | **GPL-3.0** ⚠️ | 自行 `git clone` 或 `docker pull embeddedanalyzer/emba`；本產品**不打包**，詳見 [`NOTICE.md`](NOTICE.md) §3 |

裝好後對應端點直接可用 — `POST /api/releases/{id}/sbom-from-source` 等。沒裝時 503 + 安裝指引。

---

## 啟動平台

雙擊以下腳本（位於 `sbom-platform/` 目錄下）：

| 腳本 | 說明 |
|------|------|
| `start_backend.bat` | 啟動後端 API（port 9100） |
| `start_frontend.bat` | 啟動前端介面（port 3000） |

或手動執行：

```bash
# 後端（在 backend/ 目錄下）
python -m uvicorn app.main:app --port 9100 --reload

# 前端（在 frontend/ 目錄下）
npm run dev
```

啟動後開啟瀏覽器：**http://localhost:3000**

---

## 部署到生產（Mac Mini）

開發機與生產分離 — 開發機跑 Vite dev server，生產 Mac Mini 跑 launchd + nginx。一鍵部署：

```bash
# 一次裝齊：Postgres + nginx + Trivy + Syft（其餘 EMBA 因為 GPL-3.0 預設不裝，需要時加 INSTALL_EMBA=1 看安裝指南）
INSTALL_POSTGRES=1 INSTALL_NGINX=1 INSTALL_TRIVY=1 INSTALL_SYFT=1 \
SBOM_DEPLOY_HOST=mac-mini.local \
bash deploy/first-deploy.sh
```

詳細流程、SSL 設定、Tailscale 等：[`deploy/MACMINI_SETUP.md`](deploy/MACMINI_SETUP.md)

---

## 預設帳號

| 帳號 | 密碼 |
|------|------|
| `admin` | `sbom@2024` |

> **⚠️ 生產環境必改**：自 v2.x 起，當 `DEBUG=false` 時若 `SECRET_KEY` 或 `ADMIN_PASSWORD` 仍是預設值，後端會**拒絕啟動並 `sys.exit(1)`**。請務必在 `backend/.env` 設定強隨機值（`python -c 'import secrets; print(secrets.token_hex(32))'`）。

---

## 環境變數說明（`backend/.env`）

| 變數 | 預設值 | 說明 |
|------|--------|------|
| `DATABASE_URL` | `sqlite:///./sbom.db` | dev SQLite；生產建議 `postgresql+pg8000://sbom_user:PASS@127.0.0.1:5432/sbom`（`setup-macos.sh INSTALL_POSTGRES=1` 自動產） |
| `SECRET_KEY` | `change-me-in-production` | JWT 簽名金鑰，**`DEBUG=false` 時必改**（預設值會讓 backend 拒啟動） |
| `ADMIN_USERNAME` | `admin` | 管理員帳號 |
| `ADMIN_PASSWORD` | `sbom@2024` | 管理員密碼，**`DEBUG=false` 時必改** |
| `DEBUG` | `false` | dev 設為 `true` 跳過上述守衛 |
| `JWT_EXPIRE_HOURS` | `8` | 登入 Token 有效時間（小時） |
| `ALLOWED_ORIGIN` | `http://localhost:3000` | 對外 origin（單一），CORS / OIDC redirect 用 |
| `SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_FROM` / `_TLS` | 空 | Email 通知（可選） |
| `NVD_API_KEY` | 空 | NVD API Key（無 5 req/30s；有 50 req/30s）— 申請步驟見 [`docs/api-keys-setup.md`](docs/api-keys-setup.md) |
| `GITHUB_TOKEN` | 空 | GHSA 查詢 rate limit（無 60/h；有 5000/h）— 申請步驟見 [`docs/api-keys-setup.md`](docs/api-keys-setup.md) |
| `OIDC_ISSUER` / `_CLIENT_ID` / `_CLIENT_SECRET` / `_REDIRECT_URI` | 空 | OIDC SSO（留空關閉） |
| `FRONTEND_URL` | `http://localhost:3000` | 忘記密碼信件用 |
| `UPLOAD_DIR` | 空 | SBOM 上傳目錄；空 = `<backend>/uploads`，相對路徑會錨定到 backend/ |

---

## 資料存放位置

| 路徑 | 說明 |
|------|------|
| `backend/sbom.db` | SQLite 資料庫（不進 git） |
| `backend/uploads/` | 上傳的 SBOM 檔案（不進 git） |
| `backend/uploads/brand/` | 品牌 Logo（不進 git） |

> **注意：** 資料庫和上傳檔案不會隨 git 同步。換機器後需重新建立資料（客戶 → 產品 → 版本 → 上傳 SBOM）。

---

## 功能一覽

### SBOM 拆解 / 生成
| 功能 | 端點 | 工具 |
|------|------|------|
| 上傳既有 SBOM（CycloneDX / SPDX JSON） | `POST /api/releases/{id}/sbom` | 內建 parser |
| SBOM 格式互轉 | `POST /api/convert?target=...` | 內建（CycloneDX JSON ↔ XML ↔ SPDX JSON） |
| **原始碼 zip → SBOM** | `POST /api/releases/{id}/sbom-from-source` | Syft |
| **Binary / firmware → SBOM** | `POST /api/releases/{id}/sbom-from-binary` | Syft |
| 容器映像 → SBOM | `POST /api/releases/{id}/scan-image` | Trivy |
| IaC（Terraform / K8s / Dockerfile）→ SBOM + misconfig | `POST /api/releases/{id}/scan-iac` | Trivy |
| 韌體深度解包 | （獨立 firmware scan 流程） | EMBA（GPL-3.0，自選） |
| Reachability（漏洞函式可達性分析） | `POST /api/releases/{id}/upload-source` | 內建 Python AST（JS/Java 擴展計畫見 [`.knowledge/decisions/`](.knowledge/decisions/reachability-js-java-issue.md)）|

### 核心功能
| 功能 | 說明 |
|------|------|
| CVE 掃描 | 透過 OSV.dev API 自動掃描（v1/querybatch + 並行詳情,200 元件 SBOM 從 ~200 次 HTTP → 1+M 次） |
| VEX 狀態管理 | open / in_triage / not_affected / affected / fixed |
| 批次 VEX 更新 | 多選漏洞一次更新狀態 |
| 重新掃描 | 對現有元件重新查詢最新 CVE |
| 漏洞抑制（Suppression） | 獨立於 VEX，含到期時間，自動觸發到期通知 |

### 漏洞情資
| 功能 | 說明 |
|------|------|
| EPSS 整合 | FIRST.org 利用可能性分數（0–100%） |
| CISA KEV | 已知被利用漏洞標記 |
| NVD 豐富化 | 補充 CVE 描述、CWE、CVSS v3/v4、參考連結 |

### 報告與匯出
| 功能 | 說明 |
|------|------|
| PDF 報告 | 含品牌 Logo、公司名稱、主題色（CJK 字型自動偵測） |
| CSV 匯出 | 漏洞清單 / 稽核日誌（formula injection 防護） |
| CSAF VEX | CSAF 2.0 格式 VEX 文件 |
| 證據包 ZIP | PDF + CSAF + SBOM 原始檔 + 清單 |
| IEC 62443-4-1 SDL | SM-9 / DM-1~5 / SUM-1~5 |
| IEC 62443-4-2 元件層級 | CR-1~4 |
| IEC 62443-3-3 系統層級 | FR-1~7 |
| NIS2 Article 21 | 5 項可量化控制項 |
| TISAX VDA ISA 6.0 | 69 控制項自評（含 GDPR 個資保護模組） |
| SBOM 脫敏分享連結 | 時效 token、可選擇隱藏內部元件、無需登入下載 |

### 合規與管理
| 功能 | 說明 |
|------|------|
| CRA 事件管理 | Article 14 事件狀態機（24h/72h/14d 期限） |
| Policy 引擎 | 自訂規則自動偵測違規（如 Critical > 7 天未修補） |
| 版本比對 Diff | 兩個版本間的漏洞差異分析 |
| SBOM 完整性驗證 | SHA-256 驗證 SBOM 檔案未被竄改 |
| 版本鎖定 | 鎖定後禁止修改，保護已核准版本 |

### 分析儀表板
| 功能 | 說明 |
|------|------|
| 儀表板 | 嚴重度分布、處理狀態、修補追蹤 |
| 跨客戶風險總覽 | 各組織風險排行（未修補 Critical/High 計分） |
| 修補追蹤 | 修補率圓環圖、平均修補天數 |
| VEX 歷程 | 每次狀態變更記錄（含備註、時間戳） |

### 其他
| 功能 | 說明 |
|------|------|
| JWT 登入驗證 | Token 有效期 8 小時 |
| Webhook 通知 | 新漏洞發現時 POST（支援 Slack/Teams） |
| Email 通知 | 新漏洞發現時寄送 Email |
| 全域元件搜尋 | 跨所有客戶搜尋元件名稱 |
| 報告品牌化 | Logo 上傳、公司名稱、主題色、頁尾文字 |
| 說明中心 | 內建 Help Center（/help），24 篇文章，全文搜尋 |

---

## 技術架構

```
後端：FastAPI + SQLAlchemy + Pydantic v2（port 9100）
前端：React 18 + Vite + Tailwind CSS（port 3000）
資料庫：SQLite（dev）/ PostgreSQL 16（生產推薦）
Schema 遷移：main.py 啟動時 ALTER TABLE 跨 SQLite/Postgres helper（無 Alembic）
```

### 資料模型（cascade delete）
```
Organization → Product → Release → Component → Vulnerability → VexHistory
                               └── VexStatement（release 層級，CSAF 匯出用）
                               └── ComplianceMap

CRAIncident（org 層級，獨立）
User / PolicyRule / BrandConfig / AlertConfig（全域）
```

### 外部 API
| API | 用途 |
|-----|------|
| OSV.dev | CVE 掃描 |
| FIRST.org EPSS | 利用可能性分數 |
| CISA KEV | 已知被利用漏洞清單 |
| NVD API 2.0 | CVE 詳情（描述/CWE/CVSS） |

---

## API 文件

後端啟動後，開啟：**http://localhost:9100/docs**

離線版 API 參考文件：[docs/api-reference.md](docs/api-reference.md)

---

## 說明文件

| 文件 | 說明 |
|------|------|
| [docs/user-manual.md](docs/user-manual.md) | 顧問操作 SOP（8 步驟 + 情境） |
| [docs/api-reference.md](docs/api-reference.md) | 完整 API 端點參考 |
| [docs/api-keys-setup.md](docs/api-keys-setup.md) | NVD / GitHub PAT 申請步驟（5–10 分鐘,可選；有 key 後 enrichment 快 10× / 83×）|
| [docs/architecture.md](docs/architecture.md) | 系統架構（資料模型、服務層、技術棧、設計決策）|
| [docs/db-schema.md](docs/db-schema.md) | 資料表欄位說明 |
| [docs/phase2-spec.md](docs/phase2-spec.md) | Phase 2 功能規格 |
| [deploy/MACMINI_SETUP.md](deploy/MACMINI_SETUP.md) | 生產環境部署指南（Mac Mini + launchd + Homebrew + Postgres + nginx + Trivy + Syft） |
| [`.knowledge/decisions/reachability-js-java-issue.md`](.knowledge/decisions/reachability-js-java-issue.md) | Wave D sprint #3 規劃：JS/TS + Java reachability 擴展 |
| [`.knowledge/decisions/reachability-corpus-cve-mapping.md`](.knowledge/decisions/reachability-corpus-cve-mapping.md) | 39-fixture ground-truth corpus 的 CVE→symbol 對照 |
| [NOTICE.md](NOTICE.md) | 第三方開源元件清單與授權聲明 |

平台內建說明中心：登入後點選導覽列 **說明**，或直接開啟 `http://localhost:3000/help`

---

## 開源授權與合規

本平台建構於開源元件之上。完整清單與授權義務說明於：

- [`NOTICE.md`](NOTICE.md) — 所有依賴的版本、license、源碼 URL，分 7 節含**下游使用者合規 checklist**
- 線上版（產品執行中可訪問）：`http://<your-host>/about` 或 `GET /api/notice`（公開、無需登入）

**License 摘要**：
- **核心依賴 100% 為 permissive license**（MIT / BSD / Apache-2.0 / HPND / ISC）— 商業閉源使用零限制，無 LGPL/GPL 義務
- **PDF 生成**：`fpdf2` (LGPL-3.0) 已換成 `reportlab` (BSD-3-Clause)，透過 `app/services/pdf_shim.py` 提供的 fpdf2-相容 API 包裝層，6 個既有報告檔幾乎免改
- **Postgres driver**：`psycopg2-binary` (LGPL) 已換成 `pg8000` (BSD-3)
- **EMBA 為 GPL-3.0**，本產品**從不打包 EMBA**；透過 subprocess 在使用者自願安裝後呼叫，arms-length 模式不會讓 GPL 義務擴及本產品

如需將本平台整合進企業產品 / OEM 出貨，請參考 [`NOTICE.md`](NOTICE.md) §7「下游使用者合規 checklist」。

---

## 常見問題

**Q: 後端啟動後 port 9100 被占用**
```bash
# 找出並終止佔用 9100 的程序
netstat -ano | findstr :9100
taskkill /PID <PID號碼> /F
```

**Q: `bcrypt` 出現警告訊息**
```
(trapped) error reading bcrypt version
```
此為 passlib 與新版 bcrypt 的相容性警告，**不影響功能**，可忽略。

**Q: NVD 更新很慢**
沒有 API Key 時限速 7 秒/次。完整申請步驟（NVD + GitHub PAT,各約 5 分鐘,免費）見 [`docs/api-keys-setup.md`](docs/api-keys-setup.md)。

**Q: 大型 SBOM 掃描花太久**
v2.x 已將 OSV 改成 batch + parallel detail fetches —— 200 元件 / 50 唯一漏洞的 SBOM 從 ~200 次 HTTP 降到 1 + 50 次。如果還是慢,通常是 NVD enrichment（無 key 時 5 req/30s）—— 申請 NVD key 後降到原本的 1/10 時間。
