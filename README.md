# SBOM Management Platform

適用於 ICS/OT 製造商的 SBOM 管理平台，符合 EU CRA 與 IEC 62443 法規要求。

---

## 系統需求

| 項目 | 版本 |
|------|------|
| Python | 3.11 以上 |
| Node.js | 18 以上 |
| 作業系統 | Windows 10/11（無 Docker） |

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

## 預設帳號

| 帳號 | 密碼 |
|------|------|
| `admin` | `sbom@2024` |

---

## 環境變數說明（`backend/.env`）

| 變數 | 預設值 | 說明 |
|------|--------|------|
| `SECRET_KEY` | `change-me-in-production` | JWT 簽名金鑰，建議正式環境修改 |
| `ADMIN_USERNAME` | `admin` | 管理員帳號 |
| `ADMIN_PASSWORD` | `sbom@2024` | 管理員密碼 |
| `JWT_EXPIRE_HOURS` | `8` | 登入 Token 有效時間（小時） |
| `SMTP_HOST` | 空 | Email 通知 SMTP 伺服器 |
| `SMTP_PORT` | `587` | SMTP 連接埠 |
| `SMTP_USER` | 空 | SMTP 帳號 |
| `SMTP_PASSWORD` | 空 | SMTP 密碼 |
| `SMTP_FROM` | 空 | 寄件人 Email |
| `NVD_API_KEY` | 空 | NVD API Key（無 key 限速 5 req/30s；有 key 50 req/30s）申請：https://nvd.nist.gov/developers/request-an-api-key |

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

### 核心功能
| 功能 | 說明 |
|------|------|
| SBOM 上傳 | 支援 CycloneDX JSON、SPDX JSON |
| CVE 掃描 | 透過 OSV.dev API 自動掃描 |
| VEX 狀態管理 | open / in_triage / not_affected / affected / fixed |
| 批次 VEX 更新 | 多選漏洞一次更新狀態 |
| 重新掃描 | 對現有元件重新查詢最新 CVE |

### 漏洞情資
| 功能 | 說明 |
|------|------|
| EPSS 整合 | FIRST.org 利用可能性分數（0–100%） |
| CISA KEV | 已知被利用漏洞標記 |
| NVD 豐富化 | 補充 CVE 描述、CWE、CVSS v3/v4、參考連結 |

### 報告與匯出
| 功能 | 說明 |
|------|------|
| PDF 報告 | 含品牌 Logo、公司名稱、主題色 |
| CSV 匯出 | 漏洞清單 CSV |
| CSAF VEX | CSAF 2.0 格式 VEX 文件 |
| 證據包 ZIP | PDF + CSAF + SBOM 原始檔 + 清單 |
| IEC 62443 報告 | 11 項 SM/DM/SUM 要求評估 PDF |

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

---

## 技術架構

```
後端：FastAPI + SQLAlchemy + SQLite（port 9100）
前端：React + Vite + Tailwind CSS（port 3000）
資料庫：SQLite（backend/sbom.db）
Schema 遷移：main.py 啟動時 ALTER TABLE（無 Alembic）
```

### 資料模型（cascade delete）
```
Organization → Product → Release → Component → Vulnerability
CRAIncident（org 層級，獨立）
VexHistory（vulnerability 層級）
PolicyRule（全域）
BrandConfig（全域單筆）
AlertConfig（全域單筆）
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
沒有 API Key 時限速 7 秒/次。申請免費 NVD API Key 後填入 `.env`，速度提升 10 倍：
https://nvd.nist.gov/developers/request-an-api-key
