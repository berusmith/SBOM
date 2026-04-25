# 系統架構文件

## 目錄結構

```
D:\projects\SBOM\
├── backend/
│   └── app/
│       ├── main.py          # FastAPI 應用入口、DB migration、路由註冊
│       ├── core/
│       │   ├── config.py    # Pydantic Settings（環境變數）
│       │   ├── database.py  # SQLAlchemy 設定、SQLite WAL 模式
│       │   ├── deps.py      # JWT 驗證、Admin 權限判斷
│       │   └── security.py  # 密碼雜湊、JWT 產生
│       ├── models/          # SQLAlchemy ORM 實體
│       ├── api/             # FastAPI 路由（每個資源一個檔案）
│       ├── schemas/         # Pydantic v2 Schema（Organization、Product、Release）
│       └── services/        # 業務邏輯（SBOM 解析、掃描、豐富化、報告、通知）
├── frontend/
│   └── src/
│       ├── App.jsx          # React Router 設定、Auth Guard
│       ├── api/client.js    # Axios 實例（JWT 自動注入）
│       └── pages/           # 每個路由對應的 React 元件
├── deploy/                  # 生產環境部署腳本
└── docs/                    # 參考文件
```

---

## 技術棧

| 層級 | 技術 |
|------|------|
| Backend 框架 | FastAPI（Python async web framework） |
| 資料庫 | SQLite（WAL 模式，支援並發讀取） |
| ORM | SQLAlchemy v1.4+ |
| 認證 | JWT Bearer Token（HS256，8 小時 TTL） |
| PDF 生成 | fpdf2（Latin-1 字元集） |
| Frontend 框架 | React 18 + React Router v6 |
| HTTP Client | Axios |
| 樣式 | Tailwind CSS |
| 狀態管理 | Local React Hooks（無 Redux/Zustand） |
| Build 工具 | Vite（dev proxy `/api` → `localhost:9100`） |

**外部 API：**
- OSV.dev — 漏洞掃描
- NVD API 2.0 — CVE 詳細資訊、CVSS
- FIRST.org EPSS — 漏洞被利用機率
- CISA KEV — 已知被利用漏洞清單

---

## 資料模型

```
Organization (1:N)
  └─→ Product (1:N)
       └─→ Release (1:N)
            ├─→ Component (1:N)
            │    └─→ Vulnerability (1:N)
            │         └─→ VexHistory（僅附加，審計日誌）
            ├─→ VexStatement（Release 層級，供 CSAF 匯出）
            └─→ ComplianceMap（IEC 62443 評分）

CRAIncident（全局，無 FK 到 Organization）
User / PolicyRule / BrandConfig / AlertConfig（全局單例）
```

**設計原則：**
- 所有主鍵為 UUID
- FK 關係使用 `cascade="all, delete-orphan"`（父刪子跟著刪）
- VEX 狀態內嵌於 Vulnerability 表（不另設表）
- Release 鎖定後禁止修改（合規稽核用）
- CRA Incident 跨產品範圍（法規事件不綁定單一產品）

---

## API 層

11 個 Router，除 `/api/auth/login` 外全部需要 JWT：

| Router | Prefix | 主要端點 |
|--------|--------|----------|
| `auth.py` | `/api/auth` | POST `/login`, GET `/me` |
| `organizations.py` | `/api/organizations` | CRUD + `/{id}/products` |
| `products.py` | `/api/products` | CRUD + `/{id}/releases`, `/vuln-trend`, `/diff` |
| `releases.py` | `/api/releases` | SBOM 上傳/掃描/豐富化/合規報告/證據包 |
| `vulnerabilities.py` | `/api/vulnerabilities` | PATCH status, 批量更新, 歷史紀錄 |
| `cra.py` | `/api/cra` | 事件 CRUD + 狀態機推進 |
| `stats.py` | `/api/stats` | 全平台統計、風險總覽、Top Threats |
| `search.py` | `/api/search` | 元件全文搜尋 |
| `settings.py` | `/api/settings` | 品牌設定、告警 Webhook/SMTP |
| `policies.py` | `/api/policies` | 合規規則 CRUD、違規偵測 |
| `users.py` | `/api/users` | 使用者 CRUD（Admin only） |

---

## 服務層

| 服務 | 職責 |
|------|------|
| `sbom_parser.py` | CycloneDX / SPDX JSON 解析 → `[{name, version, purl, license}]` |
| `vuln_scanner.py` | OSV.dev 查詢（每個 PURL），`(component_id, cve_id)` 去重 |
| `nvd.py` | NVD API 2.0（描述、CWE、CVSS v3/v4），5 req/30s 限速，429 自動退讓 |
| `epss.py` | FIRST.org EPSS 批量查詢（500 CVE/次）|
| `kev.py` | CISA KEV 清單，標記 `is_kev=True` |
| `pdf_report.py` | fpdf2 PDF 生成，品牌客製化，文字經 `_s()` 過濾非 Latin-1 字元 |
| `iec62443_report.py` | IEC 62443-4-1 SDL 合規報告（SM-9, DM-1~5, SUM-1~5） |
| `iec62443_42_report.py` | IEC 62443-4-2 元件安全報告（CR-1~4） |
| `iec62443_33_report.py` | IEC 62443-3-3 系統安全報告（FR-1~7） |
| `alerts.py` | Webhook POST + SMTP 電子郵件通知 |

---

## Frontend 路由

| Route | 頁面 | 說明 |
|-------|------|------|
| `/` | Dashboard | CRA 倒數、嚴重度圖表、修補統計 |
| `/organizations` | Organizations | 組織 CRUD，進入產品層級 |
| `/organizations/:orgId/products` | Products | 產品列表 |
| `/products/:productId/releases` | Releases | 版本列表 |
| `/releases/:releaseId` | ReleaseDetail | 核心頁面：SBOM 上傳、漏洞分類、報告下載 |
| `/releases/diff` | ReleaseDiff | 兩版本差異比對 |
| `/cra` / `/cra/:id` | CRAIncidents / Detail | 法規事件追蹤 |
| `/risk-overview` | RiskOverview | 跨組織風險排行 |
| `/policies` | Policies | 合規規則管理 |
| `/settings` | Settings | 品牌 + 通知設定 |
| `/search` | Search | 全平台元件搜尋 |
| `/help` | Help | 24 篇內建說明（全文搜尋） |

---

## 部署架構

### 開發環境
- Backend：`python -m uvicorn app.main:app --port 9100 --reload`
- Frontend：`npm run dev`（Vite，port 3000，proxy `/api` → `9100`）
- 啟動捷徑：根目錄 `start_backend.bat` / `start_frontend.bat`

### 生產環境
- 主機：Mac Mini(macOS),部署根 `$HOME/sbom/`,user-level launchd 管理服務
- 部署：`SBOM_DEPLOY_HOST=mac-mini.local bash deploy/deploy.sh`(本地 build frontend → tar+ssh → `launchctl reload`)
- 靜態模式：後端設定 `STATIC_DIR` 後直接服務 React `dist/`(單一進程,LAN-only 場景可省 nginx)
- Nginx(可選): Homebrew 安裝,反向代理 + 靜態快取,僅在公網/TLS 場景需要
- 資料庫：`$HOME/sbom/data/sbom.db`(SQLite + WAL,持久化)
- 上傳檔案：`$HOME/sbom/data/uploads/`
- Log：`$HOME/sbom/logs/backend.{out,err}.log`
- 詳細部署指南見 `deploy/MACMINI_SETUP.md`

---

## 關鍵設計決策

| 決策 | 原因 |
|------|------|
| SQLite + WAL | 避免複雜 DB 設定，1GB RAM 足夠 |
| Inline migration（`main.py`） | 小團隊無需 Alembic，只支援 `ADD COLUMN` |
| Python 3.9 相容 | 生產伺服器限制，使用 `from __future__ import annotations` |
| UUID 主鍵 | 防止 ID 猜測，安全友好 |
| Latin-1 PDF | fpdf2 限制，`_s()` helper 自動過濾 |
| 錯誤訊息繁體中文 | 台灣合規顧問使用情境 |
| VEX 欄位內嵌 Vulnerability | 單表設計，查詢簡單 |
| CRA Incident 無 FK | 法規事件跨產品範圍，不綁定單一組織 |
