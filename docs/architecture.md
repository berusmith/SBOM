# 系統架構文件

最後更新:2026-04-26(對應 Wave A/B/C UX 完成 + Reachability fixture corpus 完成的狀態)

## 目錄結構

```
SBOM/                              # repo root
├── backend/
│   └── app/
│       ├── main.py                # FastAPI 入口、inline DB migration、lifespan
│       ├── core/
│       │   ├── config.py          # Pydantic Settings
│       │   ├── database.py        # SQLAlchemy + WAL + days_between() cross-DB helper
│       │   ├── deps.py            # JWT + API Token + scope 守衛
│       │   ├── plan.py            # Starter/Standard/Professional 功能 gating
│       │   └── security.py        # bcrypt + JWT + 密碼策略 helper
│       ├── models/                # 14 個 SQLAlchemy ORM 表
│       ├── api/                   # 17 個 router(每資源一檔)
│       ├── schemas/               # Pydantic v2(Organization/Product/Release)
│       └── services/              # 19+ 個業務邏輯模組
├── frontend/
│   └── src/
│       ├── App.jsx                # Router、Auth Guard、route lazy-load
│       ├── api/client.js          # Axios + JWT 自動注入
│       ├── components/            # Modal/Toast/Button/PasswordInput/Skeleton/...
│       ├── constants/             # colors / chart-colors(SVG hex 集中)
│       ├── hooks/useFocusTrap.js  # WAI-ARIA modal 共用 focus 邏輯
│       ├── i18n/                  # zh-Hant + en,300+ keys
│       ├── pages/                 # 22 個 route 頁面
│       └── utils/                 # validate / errors / plan / date helpers
├── tools/
│   ├── sbom-cli/                  # Python stdlib CLI(upload / gate / diff)
│   ├── sbom-action/               # GitHub Actions composite action
│   └── sbom-gitlab-ci/            # GitLab CI 範本
├── deploy/
│   ├── MACMINI_SETUP.md           # 生產部署指南
│   ├── setup-macos.sh             # Homebrew bootstrap(無需 sudo)
│   ├── com.sbom.backend.plist     # launchd user agent
│   ├── deploy.sh / first-deploy.sh
│   ├── nginx-sbom.conf            # 反向代理(僅公網 + TLS 場景)
│   ├── backup.sh                  # SQLite 14 天備份
│   └── migrate-sqlite-to-postgres.py
├── docs/
│   ├── architecture.md            # 本檔
│   ├── api-reference.md
│   ├── api-keys-setup.md          # NVD / GitHub PAT 申請指引
│   ├── db-schema.md
│   ├── user-manual.md
│   ├── phase2-spec.md
│   └── TISAX_MODULE_PLAN.md
├── .knowledge/                    # ADR + 決策日誌(隨 git 追蹤)
│   ├── decisions/                 # 包含 Wave D reachability 規劃 + 39-fixture corpus mapping
│   ├── patterns/
│   ├── pitfalls/
│   └── references/
└── (root)
    ├── CLAUDE.md                  # AI 協作守則(專案範圍)
    ├── README.md                  # 入口
    ├── CHANGELOG.md               # Keep a Changelog 格式
    ├── NEXT_TASK.md               # roadmap + 已完成清單
    ├── NOTICE.md                  # 第三方 OSS attribution(7 節)
    ├── SECURITY.md                # 安全披露流程
    ├── test_all.py                # 54 項 stdlib regression suite
    ├── start_backend.bat / start_frontend.bat
    └── docker-compose.yml         # dev only,生產不用 Docker
```

`backend/tests/fixtures/reachability/` 另詳見「Reachability 與 fixture corpus」段落。

---

## 技術棧

| 層級 | 技術 | 備註 |
|------|------|------|
| Backend 框架 | FastAPI 0.120+ | lifespan context(從 deprecated `on_event` 遷移) |
| Python | 3.11+ | 用 `from __future__ import annotations` 維持向前相容 |
| 資料庫 | SQLite(WAL)/ PostgreSQL 16+ | 跨 DB 透過 `core/database.py:days_between()` |
| Postgres driver | **pg8000**(BSD-3,純 Python) | 舊版 psycopg2-binary(LGPL)已棄用 |
| ORM | SQLAlchemy 2.x | UUID 主鍵全表通用 |
| 認證 | JWT HS256 + OIDC SSO + API Token(scope) | RevokedToken 黑名單支援登出即失效 |
| PDF 生成 | **reportlab 4.4**(BSD-3) | 透過 `services/pdf_shim.py` 提供 fpdf2-相容 API,6 個既有報告檔 import 一行改完 |
| Frontend 框架 | React 18.3 + React Router v6 | 路由 lazy load + 動態 import |
| HTTP Client | Axios | 上傳進度條 + JWT 攔截器 |
| 樣式 | Tailwind CSS 3.4 | 設計 token(colors/font-size/z-index/transition)集中於 `tailwind.config.js` |
| 狀態 | Local React Hooks | 無 Redux/Zustand |
| Build 工具 | Vite 5 | dev proxy `/api` → `localhost:9100` |
| i18n | react-i18next 17 | `<html lang>` 隨切換同步 |

**外部服務(平台 client 角色):**

| 服務 | 用途 | 速率(無 key / 有 key) | 程式檔 |
|------|------|----------------------|--------|
| OSV.dev | CVE 漏洞比對(主) | 無公開上限 | `vuln_scanner.py` |
| NVD API 2.0 | CVE 描述 / CWE / CVSS v3+v4 | 5/30s / **50/30s** | `nvd.py` |
| FIRST.org EPSS | 利用機率(0–1) | 寬鬆批次 | `epss.py` |
| CISA KEV | 已知被利用清單 | catalog 一次抓 | `kev.py` |
| GitHub Advisory(GHSA) | GHSA-only / URL | 60/h / **5000/h** | `ghsa.py` |
| OIDC IdP | SSO 登入 | — | `auth.py` |

NVD / GitHub key 申請流程詳見 [`api-keys-setup.md`](api-keys-setup.md)。

**外部 CLI(平台 wrapper 角色):**

| 工具 | License | 用途 | 必要性 |
|------|---------|------|--------|
| Trivy | Apache-2.0 | 容器映像 / IaC 掃描 | 可選(沒裝就 503) |
| Syft | Apache-2.0 | 原始碼 zip / binary → SBOM | 可選 |
| Sigstore cosign | Apache-2.0 | SBOM 簽章驗證(透過 ECDSA/RSA 直接驗,**不打包 cosign**) | 簽章功能可選 |
| EMBA | **GPL-3.0** | 韌體深度解包 | 可選,**本產品不打包**,subprocess 模式 |

---

## 資料模型

```
Organization (UUID, plan: starter|standard|professional)
  └─→ Product
       └─→ Release(sbom_hash, locked, sbom_signature, signer_identity)
            ├─→ Component(name, version, purl, license)
            │    └─→ Vulnerability(cve_id, cvss, EPSS, KEV, GHSA, reachability, VEX, suppression)
            │         └─→ VexHistory(append-only audit log)
            ├─→ VexStatement(release-level, CSAF export)
            └─→ ComplianceMap(IEC 62443 控制項評分)

CRAIncident(global,跨產品,Article 14 狀態機)
ShareLink(release-level,token + expires_at + mask_internal + download_count)
FirmwareScan(EMBA 結果,UUID,async background thread)
PasswordResetToken(SHA-256 hash,30 分鐘 TTL)
RevokedToken(JWT 黑名單,jti claim,登出即失效)

User(role admin|viewer,nullable hashed_password 支援 SSO-only,nullable organization_id)
APIToken(prefix sbom_,scope read|write|admin,雜湊存)
TISAXAssessment + TISAXControl(VDA ISA 6.0,69 控制項)
PolicyRule / BrandConfig / AlertConfig(全域單例)
AuditEvent(append-only,21 種事件型別)
```

**設計原則:**
- 所有主鍵 UUID(防止 ID 猜測)
- FK 全部 `cascade="all, delete-orphan"`(父刪子跟著刪)
- VEX 狀態 + 抑制 + reachability 全內嵌於 Vulnerability(單表查詢)
- Release 鎖定後禁止任何修改(合規稽核需要)
- CRA Incident **無 FK 到 Organization** —— 法規事件可跨產品線
- `BrandConfig` / `AlertConfig` 永遠只有一列(GET 缺則自動建立預設)

---

## API 層

17 個 router,除 `/api/auth/login` + `/api/notice` + `/api/share/{token}` 外全部需 JWT(或 API Token):

| Router | Prefix | 主要端點 |
|--------|--------|----------|
| `auth.py` | `/api/auth` | login / me / oidc/* / change-password / forgot-password / reset-password / logout |
| `organizations.py` | `/api/organizations` | CRUD + `/{id}/products` + PATCH `/{id}/plan`(admin only) |
| `products.py` | `/api/products` | CRUD + releases / vuln-trend / diff |
| `releases.py` | `/api/releases` | SBOM 上傳 / Trivy / Syft / 簽章驗證 / 報告 / 合規 / Policy Gate / 證據包 |
| `notice.py` | `/api/notice` | **公開** OSS attribution(NOTICE.md plain text) |
| `vulnerabilities.py` | `/api/vulnerabilities` | PATCH status / batch / suppress / history |
| `cra.py` | `/api/cra` | 事件 CRUD + start-clock / advance / close-not-affected |
| `stats.py` | `/api/stats` | 全平台 / risk-overview / top-threats / sbom-quality-summary / cve-impact |
| `convert.py` | `/api/convert` | CycloneDX ↔ SPDX 互轉 |
| `share.py` | `/api/releases/{id}/share-link` `/api/share/{token}` | 公開分享連結(可選 mask_internal) |
| `search.py` | `/api/search` | 元件全文搜尋 |
| `settings.py` | `/api/settings` | brand / alerts / Logo 上傳 |
| `policies.py` | `/api/policies` | 合規規則 CRUD |
| `users.py` | `/api/users` | Admin only — username/password/role/email/org_id/is_active |
| `admin.py` | `/api/admin` | activity audit + CSV export |
| `firmware.py` | `/api/firmware` | EMBA 韌體上傳 + scan 進度查詢 + import-as-release |
| `tokens.py` | `/api/tokens` | API Token CRUD,scope 強制 |

使用者面 4xx / 409 錯誤訊息使用繁體中文。

---

## 服務層

| 模組 | 職責 |
|------|------|
| `sbom_parser.py` | CycloneDX + SPDX JSON 解析 → 元件清單 + dependencies / relationships(支援依賴圖) |
| **`vuln_scanner.py`** | OSV.dev `/v1/querybatch`(1000 PURL/批)+ 並行 `/v1/vulns/{id}` 詳情(20 worker)。200 元件 / 50 唯一漏洞 SBOM:200 → 51 次 HTTP |
| `nvd.py` | NVD API 2.0,5 / 50 req/30s 自動退讓 |
| `epss.py` | FIRST.org 批次查詢 |
| `kev.py` | CISA KEV catalog 一次抓 |
| `ghsa.py` | GitHub Advisory REST,multi-ecosystem(npm/pypi/maven/nuget/cargo/gem/go) |
| `reachability.py` | 三階段:Phase 1 regex import → Phase 2 test 路徑過濾 → Phase 3 **Python AST call graph**(alias tracking、route decorator detection、1-hop call graph) |
| **`pdf_shim.py`** | fpdf2-相容 API,底層用 reportlab(BSD-3),6 個既有報告檔 import 一行改完 |
| `pdf_report.py` | 主 PDF 報告(品牌客製化、CJK 字型自動偵測 via `font_manager.py`) |
| `iec62443_report.py` | 4-1 SDL: SM-9, DM-1~5, SUM-1~5 |
| `iec62443_42_report.py` | 4-2 元件層: CR-1~4 |
| `iec62443_33_report.py` | 3-3 系統層: FR-1~7 |
| `tisax_pdf.py` | VDA ISA 6.0 自評報告 |
| `nis2_report.py` | NIS2 Article 21 控制項 |
| `csaf.py` | CSAF 2.0 VEX JSON 匯出 |
| `signature_verifier.py` | ECDSA / RSA-PSS / RSA-PKCS1 SBOM 簽章驗證,X.509 cert 解析 signer identity |
| `trivy_scanner.py` | Trivy wrapper:容器 / IaC 掃描;503 if not installed |
| `syft_scanner.py` | Syft wrapper:zip(zip-bomb safe,500MB cap)+ binary;503 if not installed |
| `firmware_service.py` | EMBA wrapper + async background thread + Windows demo 模式 |
| `converter.py` | CycloneDX JSON ↔ SPDX JSON ↔ XML 互轉 |
| `monitor.py` | 持續監控背景 thread:依 BrandConfig.monitor_interval_hours 重掃所有未鎖 release,新 CVE 時觸發 alert |
| `alerts.py` | Webhook(Slack Block Kit / Teams MessageCard 自動偵測)+ SMTP,SSRF 防護(loopback / 私網 / 雲 metadata 拒絕) |
| `font_manager.py` | CJK 字型自動偵測(Windows / macOS / Linux 三平台路徑) |

---

## 多租戶 + Plan 分層(`core/plan.py`)

```
starter < standard < professional
```

- **Starter**:1 org / 3 products / 10 releases,基本漏洞掃描,**不含** CRA / IEC / TISAX
- **Standard**:無限量,加 CRA / IEC 62443-4-1 / EPSS / GHSA / 持續監控 / SSO
- **Professional**:全功能,加 IEC 62443-4-2/3-3 / TISAX / Reachability / Trivy / Sigstore 簽章

實作:
- `FEATURE_PLAN` dict 對應 feature key → 最低 plan
- `require_plan(feature)` FastAPI dependency,Plan 不足回 **402 Payment Required**
- `check_starter_limit(db, org_id, resource)` 檢查 Starter 上限
- **Admin 永遠繞過**所有 Plan 檢查(便於管理 + 故障恢復)
- 切換:Organizations 頁 admin 直接下拉,後端 `PATCH /organizations/{id}/plan`

---

## 安全模型

| 層 | 機制 |
|----|------|
| 啟動 | `DEBUG=false` 時若 `SECRET_KEY` / `ADMIN_PASSWORD` 仍是預設值 → `sys.exit(1)`(不允許用預設值上線) |
| 認證 | JWT HS256(8h TTL)+ jti claim;OIDC SSO(`#fragment` 傳 token,不落 Referer / log)|
| 授權 | role(admin/viewer)+ scope(read/write/admin,API Token)+ org_scope(每 endpoint `_assert_*_org`) |
| 跨組織 | 所有 `_assert_release_org` / `_assert_vuln_org` 等 helper 在 endpoint 入口檢查 |
| 登出 | RevokedToken 黑名單(jti),啟動時清除過期 |
| 速率 | 登入 10 / 5min + 全域 300 / min / IP(滑動視窗 middleware)|
| CSRF | OIDC state cookie + httpOnly + SameSite=Lax |
| Webhook SSRF | `_validate_webhook_url()` DNS 解析所有 A/AAAA,拒絕 loopback / 私網 / link-local / 雲 metadata(`169.254.169.254`)|
| Logo XSS | 副檔名白名單,**拒收 SVG**;media_type 由 server 從副檔名決定 |
| Path traversal | `Path(file.filename).name` 過濾 + `resolve_under_backend()` 錨定到 backend/ |
| Header injection | `safe_attachment_filename()` 過濾 `"\r\n\\` |
| CSV formula injection | `csv_safe()` helper(OWASP-recommended `'` 前綴) |
| 密碼 | bcrypt + 統一策略(10 字元 + 字母 + 數字)`is_password_acceptable()` |
| Forgot password | SHA-256 token hash 存 DB,30 分鐘 TTL,SMTP 寄信 |
| 稽核 | 21 種事件型別,append-only,CSV 匯出帶篩選條件 |
| 簽章 | Sigstore / cosign 公鑰驗證(ECDSA / RSA-PSS / RSA-PKCS1)|

詳細披露流程:[`SECURITY.md`](../SECURITY.md)。Phase 0 + Phase 1 修復清單見 `CHANGELOG.md`。

---

## Frontend 路由(22 頁)

| Route | 頁面 | 說明 |
|-------|------|------|
| `/login` `/forgot-password` `/reset-password/:token` | 登入 / 忘記 / 重設 | OIDC SSO + 本地登入 |
| `/` | Dashboard | CRA 倒數、嚴重度、SLA 逾期、Top Risky Components、修補 |
| `/organizations` | Organizations | 客戶管理 + Plan 切換(admin)|
| `/organizations/:orgId/products` | Products | 跨版本趨勢圖 |
| `/products/:productId/releases` | Releases | 版本列表 + 新增 |
| `/releases/:releaseId` | **ReleaseDetail** | 平台最複雜頁:三 tab(元件 / 漏洞 / 依賴圖)+ Policy Gate + 簽章 + 報告 + 證據包 |
| `/releases/diff` | ReleaseDiff | 兩版本差異 |
| `/cra` `/cra/:id` | CRAIncidents / Detail | Article 14 狀態機 + 倒數 |
| `/risk-overview` | RiskOverview | 跨組織 Critical/High 排行 |
| `/policies` | Policies | 規則 CRUD |
| `/firmware` | FirmwareUpload | 韌體上傳 + EMBA 進度 + 匯入為版本 |
| `/tisax` `/tisax/:id` | TISAXAssessments / Detail | VDA ISA 6.0 自評 |
| `/admin/users` | Users | 帳號管理(admin)|
| `/admin/activity` | AdminActivity | 稽核日誌 + CSV 匯出 |
| `/settings` | Settings | 品牌 + 通知 |
| `/profile` | Profile | 個人資料 + 改密 + 登出 |
| `/search` | Search | 全平台元件搜尋 |
| `/help` | Help | 24 篇內建說明 + 全文搜尋 |
| `/about` | About | OSS attribution(讀取 `/api/notice`)|

**a11y 與 RWD 標準**(2026-04 Wave A/B/C audit 完成):
- WCAG 2.2 AA 對比(text-gray-600 為主,`text-gray-500` 已全面收斂到 `bg-gray-100` badge)
- Apple HIG 觸控目標 ≥ 44×44 px(行動版 nav)
- iOS Safari 防 focus-zoom(mobile-only `font-size: 16px`)
- WAI-ARIA modal 標準(role=dialog + aria-modal + focus trap + body scroll lock,共用 `useFocusTrap` hook)
- `prefers-reduced-motion` 全域支援(動效 → 1ms)
- `:focus-visible` only(滑鼠點擊不殘留 ring)
- 所有 `<th>` `scope="col"`、所有 `<label>` `htmlFor` + `useId`、所有 SVG 顏色 → `chart-colors.js`
- viewport-fit=cover + `env(safe-area-inset-*)` 支援 iPhone 瀏海

---

## Reachability 與 Fixture Corpus

`reachability.py` 三階段:

```
Phase 1  regex 掃 import 語句(任何語言)→ presence dict {pkg: {main, test}}
Phase 2  test/scripts 路徑過濾(_TEST_SEGMENTS 集合)
Phase 3  Python AST call graph(僅 Python 檔):
           - _FileAnalyser:alias tracking(import as / from-import)
           - 路由裝飾器偵測(@app.route / @get / @post / FastAPI / Flask / Django-ninja)
           - 1-hop call graph(從 entry-point file 出發)
         → ast_reachable: set[pkg]

classify_vulns()  → {vuln_id: function_reachable | reachable | test_only | not_found | unknown}
```

**Wave D 規劃中的擴展**(JS/TS + Java):
- 規格:[`.knowledge/decisions/reachability-js-java-issue.md`](../.knowledge/decisions/reachability-js-java-issue.md)
- Ground truth:39-fixture corpus 已就緒,位於 `backend/tests/fixtures/reachability/`
- CVE → symbol 對照表:[`.knowledge/decisions/reachability-corpus-cve-mapping.md`](../.knowledge/decisions/reachability-corpus-cve-mapping.md)

**Fixture Corpus 結構**(`backend/tests/fixtures/reachability/`):

```
_schema/meta.schema.yaml       # 欄位 / enum / cross-field 規則
_tools/validate_meta.py        # 純 stdlib + PyYAML,無 jsonschema 依賴
_tools/corpus_stats.py         # per-language / per-track 統計,失敗則拒印
_runner/run_corpus.py          # 將 fixture zip 餵給 scan_zip()、報 FP/FN
python/p01..p10/               # 10 個 Python fixture
javascript/j01..j16/           # 15 個 JS fixture(j12 移到 typescript/)
typescript/j12-lodash-ts-type-only/
java/v01..v13/                 # 13 個 Java fixture
README.md                      # 怎麼跑 / 怎麼加 fixture
```

每個 fixture 包含 `meta.yaml`(ground truth)+ `requirements.txt` / `package.json` / `pom.xml`(Maven)+ `src/`(production code)+ 視需要的 `tests/`。

**目前 baseline**(2026-04-26):5 PASS / 5 FP / 0 FN / 29 SKIP(JS/TS/Java SKIP 因 analyzer 還是 Python-only;Wave D sprint 完成後 baseline 應為 39 PASS / 0 FP / 0 FN)。

---

## 部署架構

### 開發環境(Windows / macOS / Linux)
- Backend:`python -m uvicorn app.main:app --port 9100 --reload`
- Frontend:`npm run dev`(Vite,port 3000,proxy `/api` → `9100`)
- 啟動捷徑:repo root 雙擊 `start_backend.bat` / `start_frontend.bat`(Windows)

### 生產環境(Mac Mini)
- 主機:macOS,部署根 `$HOME/sbom/`,**user-level launchd**(無需 sudo)
- 部署:`SBOM_DEPLOY_HOST=mac-mini.local bash deploy/deploy.sh`(本地 build frontend → tar+ssh → `launchctl reload`)
- 服務監督:`~/Library/LaunchAgents/com.sbom.backend.plist`(KeepAlive,RSS ~400MB)
- 反向代理:nginx(Homebrew 安裝,**僅公網 + TLS 場景**;LAN-only / Tailscale 可省)
- 資料庫:Postgres 16(Homebrew,推薦)或 SQLite(WAL,1GB RAM 仍可)
- 上傳:`$HOME/sbom/data/uploads/`
- Log:`$HOME/sbom/logs/backend.{out,err}.log`
- 備份:`deploy/backup.sh` cron(SQLite `.backup` 命令,保留 14 天)

詳細部署指南見 [`deploy/MACMINI_SETUP.md`](../deploy/MACMINI_SETUP.md)。

---

## 關鍵設計決策

| 決策 | 原因 |
|------|------|
| Inline migration(`main.py`) | 小團隊無需 Alembic,只支援 `ADD COLUMN`(SQLite 不支援 DROP/RENAME) |
| SQLite + WAL(可選 Postgres) | 1GB RAM 場景 SQLite 夠用;企業 / 多並發切 Postgres |
| pg8000(BSD-3)取代 psycopg2-binary(LGPL) | License 路線 B:核心 dep 100% permissive |
| reportlab(BSD-3)+ pdf_shim 取代 fpdf2(LGPL) | 同上;shim 6 個既有報告檔 import 一行改完 |
| EMBA 不打包(GPL-3.0) | 使用者自願 install,subprocess 呼叫(arms-length 不擴展 GPL 義務) |
| UUID 主鍵 | 防 ID 猜測,跨資料庫 portable |
| VEX + suppression 內嵌 Vulnerability | 單表查詢,API 簡單 |
| CRA Incident 無 FK | 法規事件可跨產品線,設計上不綁定單一 organization |
| 錯誤訊息繁體中文 | 主要使用者為台灣合規顧問 |
| 設計 token(Tailwind) | UI 一致性 + 主題切換預留 |
| `useFocusTrap` hook 抽出 | Modal/ConfirmModal/Mobile menu 共用 WAI-ARIA modal 模式 |
| OSV `/v1/querybatch` + 並行詳情 | 200 元件 SBOM HTTP 次數 200 → 51,失敗降級不中斷上傳 |
| API token scope 強制 | read 對應 GET、write 對應 POST/PATCH/PUT、admin 對應 DELETE / 帳號 / Plan 操作 |
| Reachability 三階段 + AST | 比純 import-presence 精確,但只 Python 真的有 AST 層,JS/Java 在 Wave D 規劃中 |
