# Changelog

所有版本的重要異動記錄。格式依照 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.0.0/)。

---

## [Unreleased]

### 文件 / 測試(Reachability Fixture Corpus — Phase 1:Python 10 fixtures + 工具鏈)
完整 ground-truth corpus 規劃見 `.knowledge/decisions/reachability-corpus-cve-mapping.md`(rev 2,39 fixture 全清單)。本 commit 落實 Phase 1:Python 10 個 fixture(P1–P10)+ schema/validator/stats/runner 工具鏈,作為 Wave D sprint #3(JS/Java reachability)的 acceptance ground truth。

- **Schema + 工具**(`backend/tests/fixtures/reachability/`):
  - `_schema/meta.schema.yaml`:human-readable schema spec(field/enum/cross-field 規則)
  - `_tools/validate_meta.py`:純 stdlib + PyYAML(無新 dep);ASCII-safe 輸出(Windows cp950)
  - `_tools/corpus_stats.py`:per-language / per-track / FP-FN baseline 統計;**先驗 schema,失敗則拒印**避免 typo'd label 扭曲數字
  - `_runner/run_corpus.py`:把 fixture 打包成 zip → 餵給現有 `app.services.reachability.scan_zip()` → 比對 `expected_label` → 報 FP/FN
- **10 個 Python fixture**:覆蓋 4 個 CVE × 多種 reachability label
  - P1/P2/P3:CVE-2020-1747 PyYAML(load reachable / dump only / load test_only)
  - P4/P5:CVE-2019-19844 django(PasswordResetForm reachable / 無 password reset)
  - P6/P7:CVE-2022-40023 Mako(Template() compile reachable / 無 Template)— **修正常見誤解**:trigger 是編譯時 `Lexer.parse`,不是 `.render()`
  - P8/P9:CVE-2023-50447 Pillow(`ImageMath.eval` reachable / 純 Image.open)
  - P10:PyYAML alias edge(`import yaml as yl`)— 測 Phase 3 alias tracking
- **Schema gate 結果**(寫到 #10 時 user-mandated checkpoint):
  - **抓到 schema design hole**:PyPI name ≠ import name(pyyaml→yaml、pillow→PIL),原本只有 `package` 欄位無法 lookup → **新增 `import_names: list[str]` 必填欄位**(寫進 schema、validator、runner)
  - **5 PASS / 5 FP / 0 FN baseline**:
    - 0 FN = 所有 reachable fixture 全捕捉到(含 P10 alias)
    - 5 FP 全部來自同一限制(package-level granularity,無法分辨 `yaml.load` vs `yaml.safe_load`)— 這正是 Wave D sprint #3 要關掉的 gap
- **下一步**:Phase 2 寫 16 個 JS/TS fixture,Phase 3 寫 13 個 Java fixture,各自獨立 commit

### 文件 / 測試(Reachability Fixture Corpus — Phase 2:JS/TS 16 fixtures)
- **15 個 JavaScript fixture**(`backend/tests/fixtures/reachability/javascript/`):
  - J1/J2/J3:CVE-2019-10744 lodash defaultsDeep(prototype pollution)reachable / merge-only / test_only
  - J4/J5:CVE-2021-23337 lodash template(command injection)ES6 default import / dead named import
  - J6/J7:CVE-2022-24999 qs.parse(prototype pollution)reachable / stringify-only
  - J8/J9:CVE-2022-25883 semver.satisfies(ReDoS)reachable / valid-only
  - J10:CommonJS namespace edge(`const _ = require('lodash'); _.template(...)`)— 測 CJS alias tracking
  - J11:ES6 named alias edge(`import { template as t }; t(...)`)
  - J13:JSX wiring framework_mechanism — 測 `<VulnComp data={...} />` 是否被認出為 runtime call
  - J14:CVE-2024-29041 express `res.location` / `res.redirect`(open redirect)
  - J15:dynamic import honesty test(`await import(\`./mods/${userChoice}\`)`)— 測 analyzer 出 `unknown` 不亂猜
  - J16:reflective dispatch honesty test(`handlers[methodName](input)`)— production-realistic dispatch table
- **1 個 TypeScript fixture**(`typescript/`):
  - J12:`import type { TemplateOptions } from 'lodash'` — TS-only 構造,編譯時消除,naïve regex 會誤判 reachable
- **Schema 沒新增欄位**:Phase 1 的 `import_names` + `fixture_type` + `transitive_only` 全部夠用,16 個 fixture 全部一次驗證通過
- **Phase 2 baseline**(現有 Python analyzer 對 JS/TS 全部 skip):
  - 26 fixtures 中:5 Python PASS / 5 Python FP / 0 FN / 16 SKIP(全部 JS/TS — analyzer 不支援該語言)
  - 預期 sprint #3 完成後 baseline 變化:13 reachable 全 PASS / ~12 unreachable 全 PASS(現在會是 FP)/ 2 unknown_acceptable 全 PASS(現在 SKIP)
- **下一步**:Phase 3 寫 13 個 Java fixture(13 = 5 reachable + 6 unreachable + 1 test_only + 1 framework_mechanism),完成後 corpus 達 39 個,Wave D sprint 可正式啟動

### 效能(OSV 掃描重寫:per-PURL → 批次 + 唯一漏洞詳情並行)
- `vuln_scanner.scan_components()` 從 N 次 `/v1/query`(每 PURL 一次)改成兩階段:
  - **Phase 1**:`POST /v1/querybatch`,一次最多 1000 個 PURL,只回 `{id, modified}` 輕量 stub
  - **Phase 2**:跨所有 PURL 收集**唯一** vuln id,以 20 worker 並行 `GET /v1/vulns/{id}` 抓完整資料(severity / aliases / CVSS vectors)
- 200 元件 / 50 個唯一漏洞的 SBOM:從 ~200 次 HTTP → **1 + 50 = 51 次**(漏洞重複出現在多個元件時節省更明顯)
- 公開 API contract 不變(`scan_components(components) -> dict[purl -> list[...]]`),所有呼叫點(`releases.py` × 4、`monitor.py` × 1)零修改
- 失敗降級:單一 batch HTTP 失敗 → 該 batch 視為「無漏洞」,不會中斷整次上傳;單一 vuln 詳情失敗 → 跳過該 vuln,其餘正常處理
- Smoke test 驗證:`lodash@4.17.20` (5)、`django@3.0.0` (30)、`log4j-core@2.14.0` (7,含 Log4Shell `CVE-2021-45046` critical/9.5)三個 PURL 5.9 秒回傳完整資料

### 文件(外部情資 API key 申請指引)
- 新增 `docs/api-keys-setup.md`:
  - **NVD API Key**(5–10 分鐘):申請步驟 + 寫入 `.env` + 驗證生效;速率 5 → 50 req/30s(10×)
  - **GitHub fine-grained PAT**(2 分鐘):2026 新版只勾 `Public Repositories: Read`;速率 60 → 5000 req/h(83×)
  - 兩把都免費、無需信用卡、純讀取漏洞情資
  - 包含安全注意事項(token 輪換、別 commit `.env`)+ 常見問題
- 兩把 key **完全可選**,平台不申請也能跑;申請後大型 SBOM enrichment 從幾分鐘降到幾十秒

### 變更(UI/UX/RWD 系統性審視 — Wave A + B + C 全部完成)
完整 6 階段 audit:Discovery → Audit(7 維度)→ Findings(36 項,P0=0/P1=12/P2=15/P3=9)→ Plan → Implementation(19 commits,每 issue 一 commit)→ Verification。詳細追蹤見 `audit-report.md` + `plan.md`。

- **Wave A — 基礎(設計 token + 動效偏好 + focus 行為)**(1 commit)
  - `frontend/tailwind.config.js` 新增語意 token:colors(surface/fg/brand/danger 系列)、fontSize(modular 1.2 比例,caption~h1)、zIndex(base/raised/dropdown/sticky/modal/toast/tooltip)、transitionDuration(instant/fast/base/slow)、maxWidth(page/form/prose);取代散落於各檔的 raw `bg-blue-600` / `z-50` 等魔術值
  - `index.css` 新增 `@media (prefers-reduced-motion: reduce)` 覆蓋所有 `animation-duration` → 1ms(尊重作業系統「減少動態效果」設定);`:focus-visible` 顯示 ring,`:focus:not(:focus-visible)` 取消 ring(滑鼠點擊不再殘留藍色光環)
  - `body` 套 `env(safe-area-inset-*)` 防 iPhone 瀏海擋住內容
  - mobile-only `input/select/textarea { font-size: 16px }` 防 iOS Safari 對焦時自動縮放(< 16px 會觸發)
- **Wave B — 8 項 a11y quick wins**(8 commits)
  - **UX-001**`<html lang>` 隨 i18n.changeLanguage 同步(`zh-Hant` ↔ `en`),語音閱讀器選對發音引擎
  - **UX-003**`<meta viewport>` 加 `viewport-fit=cover` + `theme-color`,iPhone 安全區域可控
  - **UX-008**Skeleton 加 `role="status" aria-busy aria-live="polite"` + sr-only "Loading..." 標籤(語言依 `<html lang>` 切換 EN/ZH)
  - **UX-013**Modal close + Toast dismiss 的 `aria-label` 從 hardcoded "Close" / "Dismiss" 改 i18n key(`common.close` / `common.dismiss`)
  - **UX-014**Modal/Toast 從 `z-50` 改 `z-modal` / `z-toast` token,層疊次序明確
  - **UX-020**`PageLoading` 文案讀 `<html lang>` 而非 localStorage(SSO 回流時 localStorage 還沒寫入)
  - **UX-021**Mobile hamburger menu 抽取 `useFocusTrap` hook(與 Modal 共用):open 時 trap Tab、Esc 關閉、body scroll lock、close 時還焦點到 hamburger 按鈕
  - **UX-024**新增 `favicon.svg`(brand 色盾牌 + checkmark),分頁標籤不再顯示 Vite 預設 logo
- **Wave C — 10 項深度 a11y / consistency / 元件化**(9 commits)
  - **UX-002**所有 `<th>` 加 `scope="col"`(86 處 / 12 個頁面,Python 正則批次):螢幕閱讀器列表格時能讀出欄名
  - **UX-006**`text-gray-500` → `text-gray-600` 共 137 處(WCAG AA 1.4.3 contrast):`text-gray-500` 在白底僅 4.0:1 < 4.5:1 標準;`text-gray-100` 背景上的 badge 保留 gray-500(背景非白,對比足夠)
  - **UX-007**Dashboard top-risky-components 表的 `<tr onClick={navigate}>` 改成 `<Link>`(鍵盤可到、Right-Click 可開新分頁、scope="col" 補齊);TISAXDetail 的 disclosure `<div onClick>` 改 `<button aria-expanded>`
  - **UX-009**Mobile nav 觸控目標 ≥ 44×44 px(Apple HIG):links `py-2.5` → `py-3`,語言切換 `min-w-[44px]`
  - **UX-011**SVG 顏色十六進制提取到 `constants/chart-colors.js`(SEVERITY_HEX / GRAPH_NODE_FILL / CHART_AXIS_STROKE 等):TrendChart + DependencyGraph 不再 hardcoded `#fca5a5` / `#d1d5db`
  - **UX-012**Layout 內 emoji glyph(🔒 / ⌕)改 lucide icon(`<Lock>` / `<Search>`)+ `aria-hidden`:跨平台字形一致(Windows / macOS / Linux 不再各畫一套表情符)
  - **UX-015**Modal/Toast/Tooltip z-index 改 token(同 UX-014,Wave A 的 token 化現在實際採用)
  - **UX-017**新增 `Button` component(`variant=primary|secondary|danger|ghost` × `size=sm|md|lg`、`loading` 自動 spinner + aria-busy + 防雙擊、`focus-visible` 才出 ring、`type="button"` 預設不誤觸 form submit);Login + Profile + ForgotPassword + ResetPassword 共 8 個 CTA 改用
  - **UX-019**所有 `<label>` 透過 `useId` 配 `htmlFor` ↔ `id`(10 個頁面,共 ~30 個欄位):VoiceOver/NVDA 對焦不再讀出「edit text, blank」,點 label 也能聚焦欄位;password 欄位順手補 `autoComplete="current-password|new-password"`
- **驗證**:
  - 每個 commit 後 `npm run build` 通過(最終 index 302.48 kB / gzip 102.34 kB,比起點 +6.5 kB / +2.3 kB gzip,主要來自 Button 元件 + useId hooks)
  - 靜態回歸檢查:`grep "z-50"` = 0、`grep "<th"` 無漏掉 `scope="col"`、`grep "text-gray-500"` 僅剩 3 處(全在 `bg-gray-100` badge 中,對比足夠)
  - components/ 內 SVG 已無 hardcoded hex literal
- **延後到後續 roadmap(Wave D)**:ReleaseDetail.jsx 約 20 個 form htmlFor 配對(檔案最大、含多個條件子 modal,需獨立 commit pass);Button 元件對其餘 ~70 處 `<button>` 的全面採用(增量遷移較安全);UX-022/026/031..036 等 P3 細節

### 變更(License 簡化 — 路線 B 全部完成,runtime 0 LGPL)
- **PDF 生成:`fpdf2` (LGPL-3.0) → `reportlab` (BSD-3-Clause) via shim**
  - 新檔 `backend/app/services/pdf_shim.py`(~470 行):fpdf2-相容 API 在 reportlab Canvas 之上,翻譯坐標系(fpdf2 Y-down → reportlab Y-up)、處理 footer/header 不再觸發無限遞迴 page-break、支援 set_xy/get_x/rect/line/image/cell/multi_cell/add_font 等所有現用 API
  - 6 個既有 PDF 生成檔(`pdf_report.py` / `iec62443_report.py` / `iec62443_42_report.py` / `iec62443_33_report.py` / `nis2_report.py` / `tisax_pdf.py`)+ `cjk_pdf.py` 共用基類:**只改 import 一行** `from fpdf import ...` → `from app.services.pdf_shim import ...`,所有 PDF 內部邏輯零改動
  - `requirements.txt`:`fpdf2==2.8.7` → `reportlab==4.4.4`
  - 驗證:6 個 PDF 全部生成成功(總 ~180 KB),fpdf2 從 venv 完全移除後仍可運作
- **Postgres driver:`psycopg2-binary` (LGPL-3.0) → `pg8000` (BSD-3-Clause)**
  - `requirements.txt` 改成 `pg8000==1.31.2`(純 Python,無 C extension)
  - DSN scheme 全鏈路同步:`postgresql+psycopg2://` → `postgresql+pg8000://`(`.env.production` / `setup-macos.sh` PG_DSN / `migrate-sqlite-to-postgres.py` 範例 / `MACMINI_SETUP.md` 範例 / `README.md` 範例)
- **路線 B 完整成果**:
  - `NOTICE.md` 第 1.2 節從「LGPL 元件」變成「**There are currently no LGPL-licensed runtime dependencies**」附遷移對照表
  - `README.md` 「License 摘要」從「96% permissive」變成「**100% permissive**」(MIT/BSD/Apache/HPND/ISC)
  - 客戶法務(OEM 整合 / 白標)的 review surface 進一步縮小,只剩 attribution 義務
  - **EMBA(GPL-3.0)的處理不變**:本產品從不打包,使用者自願安裝後 subprocess 呼叫的 arms-length 模式

### 修正(安全強化 — Phase 0:14 項 Critical/High)
- **C-1 multi-tenant breach**:`releases.py:upload_sbom` 接收 `org_scope` 但未呼叫 `_assert_release_org`,viewer 知道 release_id(UUID)即可覆寫他組 SBOM。**僅補 1 行 `_assert_release_org(release, org_scope, db)` 即修復**
- **C-2 path traversal**:`firmware.py:upload_firmware` 直接拼接使用者 `file.filename`,改 `Path(file.filename).name` 過濾路徑分隔符
- **H-1/H-2 firmware 全面加固**:upload/list/get 改 `require_admin`;500MB 大小上限(`await file.read(MAX+1)` 防 OOM);`import-as-release` 改用 product 真實 `organization_id`,不信 client `payload.org_id`
- **H-3 share.py IDOR**:create/list/revoke share-link 三端點全加 `_assert_release_org` 檢查 release 是否屬於 caller 組織
- **H-4 Content-Disposition header injection**:share.py / convert.py / releases.py CSV 匯出全套用新 `safe_attachment_filename()` 過濾 `"`/`\r`/`\n`/`\\`
- **H-5 settings 寫入端點缺 admin 守衛**:PATCH /alerts、test-webhook、test-email、PATCH /brand、POST/DELETE /brand/logo、POST /monitor/trigger 等 6 個端點全加 `require_admin`
- **H-6 webhook SSRF**:`alerts.send_webhook()` 加 `_validate_webhook_url()` ── DNS 解析所有 A/AAAA 拒絕 loopback/private/link-local/multicast/reserved + 雲端 metadata(`169.254.169.254`);關掉 redirect-follow 防 302 繞過
- **H-7 Logo 上傳 SVG XSS**:副檔名白名單 `{.png/.jpg/.jpeg/.gif/.webp}`;拒收 SVG;`media_type` 由 server 從副檔名決定,不信 client content-type
- **H-8 OIDC JWT in URL**:callback 從 `?sso_token=xxx`(query string,落 Referer/proxy log/瀏覽器歷史)改為 `#sso_token=xxx`(URL fragment,不送 server);前端 `Login.jsx` 讀完立刻 `replaceState` 清除
- **H-9 OIDC empty username**:userinfo 缺 email/name/preferred_username/sub 時 502 拒絕,避免建立空字串 username 的殼帳戶
- **H-10 vuln history IDOR**:`get_vuln_history` 加 `_assert_vuln_org` 檢查,viewer 不能跨組讀 VEX 異動史
- **H-11 SECRET_KEY/ADMIN_PASSWORD 預設值守衛**:啟動時若 `DEBUG=false` 且 `SECRET_KEY ∈ {change-me-in-production, please-change-this-to-a-random-64-char-string, ...}` 或 `ADMIN_PASSWORD ∈ {sbom@2024, please-change-this-password, ...}`,直接 `sys.exit(1)`;`DEBUG=true` 仍只 warning
- **H-12 plist 綁定與文檔不一致**:保留 `127.0.0.1` 綁定(最小暴露原則),改文檔說明對外存取**必須**經 nginx / SSH tunnel / Tailscale + nginx;`deploy.sh` 末「直連 backend」誤導訊息修正

### 修正(Phase 1:6 項 Medium/Low)
- **M-1 CORS 收緊**:`allow_methods=["*"]` → 列出 6 個動詞;`allow_headers=["*"]` → 列出 5 個必要 header;新增 `expose_headers=["content-disposition"]` 支援檔案下載
- **M-6 CSV formula injection**:新 `csv_safe()` helper(OWASP-recommended `'` 前綴),套用到 `admin.py` 稽核匯出、`releases.py` 漏洞匯出、`tisax.py` 三個 CSV 端點
- **M-7 密碼策略統一**:抽出 `is_password_acceptable()` + `PASSWORD_POLICY_MESSAGE` 到 `core/security.py`,replace 所有 5 處(create_org/create_user/update_user/change-password/reset-password) ── 一致 10 字元 + 字母 + 數字
- **M-8 delete_product 缺 require_admin**:加 1 行守衛,與 `update_product` 對齊
- **M-13 UPLOAD_DIR 相對路徑風險**:新 `BACKEND_DIR` + `resolve_under_backend()` helper;UPLOAD_DIR / FIRMWARE_UPLOAD_DIR / BRAND_UPLOAD_DIR 全錨定到 backend/ 絕對路徑,cwd 變動不影響
- **L-4 convert.py Content-Disposition CRLF**:套用 `safe_attachment_filename`(同 H-4 共用 helper)

### 修正(安全性 / 生產就緒)
- **依賴套件升級**:清除 9 個已知 CVE(`pip-audit` 掃描結果)
  - `fastapi` 0.115.0 → 0.120.4
  - `starlette` 0.38.6 → 0.49.2（CVE-2024-47874、CVE-2025-54121、CVE-2025-62727）
  - `python-multipart` 0.0.12 → 0.0.26（CVE-2024-53981、CVE-2026-24486、CVE-2026-40347）
  - `requests` 2.32.3 → 2.33.0（CVE-2024-47081、CVE-2026-25645）
  - `pillow` 10.4.0 → 12.2.0（CVE-2026-25990、CVE-2026-40192）
- **`/health` 誤報修正**：`monitor.get_status()` 加入 `running` 欄位反映 scheduler thread 實際狀態,取代先前永遠為 `false` 的假值（uptime monitor 會被誤判）
- **移除重複 `/health` endpoint**:`main.py` 末端的精簡版會覆蓋詳細版的 bug 隨之消失（雖然因為 FastAPI 先註冊優先,原本詳細版還是贏,但還是死程式碼）
- **從 `@app.on_event` 遷移至 `lifespan` context manager**：`on_event` 自 FastAPI 0.109 deprecated,改成 `@asynccontextmanager` 統一管理 startup/shutdown
- **FastAPI `version` 欄位同步**:`FastAPI(version="0.1.0")` → `"2.0.0"`,與 `/health` 回傳的 `version` 一致

### 變更（部署目標調整）
- **棄用 Oracle Cloud,改部署到 Mac Mini**:刪除 `deploy/ORACLE_CLOUD_SETUP.md` / `deploy/sbom-backend.service`(systemd) / `deploy/setup.sh`(dnf)
- **新增 launchd 服務定義**:`deploy/com.sbom.backend.plist`(KeepAlive on Crash、ResidentSetSize ~400MB、user-level agent)
- **新增 macOS bootstrap**:`deploy/setup-macos.sh`(Homebrew python@3.11 + 建目錄 + venv + plist 安裝;`INSTALL_NGINX=1` 可選裝 nginx)
- **重寫 deploy 腳本**:`deploy.sh` / `first-deploy.sh` 改 env 變數驅動(`SBOM_DEPLOY_HOST` / `_USER` / `_DIR` / `_SSH_KEY` / `_SSH_OPTS`),不再硬編碼伺服器 IP
- **新增部署指南**:`deploy/MACMINI_SETUP.md`(前置 SSH/Homebrew、首次部署、三種對外連線:LAN-only / Tailscale / 公網+TLS、launchd 維運指令、Postgres 切換)
- **更新預設路徑**:部署根從 `/var/www/sbom` 改為 `$HOME/sbom`(無需 sudo);`backup.sh` 路徑同步更新
- **修整文件**:`CLAUDE.md` / `README.md` / `NEXT_TASK.md` / `docs/architecture.md` / `docs/competitor-gap.md` 的 Oracle Cloud / `opc` / `161.33.130.101` 等痕跡全數移除;`backend/app/services/font_manager.py` 字型路徑註解去掉 "Oracle Linux"

### 變更（資料庫:Postgres 為新預設,SQLite 仍支援）
- **修 SQLite-specific bug**:`stats.py:74` 的 `func.julianday(...)` 在 Postgres 不存在(會 500),抽成 `core/database.py:days_between(later, earlier)` cross-DB helper(SQLite 走 `julianday()` 差,Postgres 走 `extract('epoch', ...) / 86400`)
- **`setup-macos.sh` 加 Postgres 自動安裝**:`INSTALL_POSTGRES=1` 觸發 `brew install postgresql@16` + `brew services start` + 建立 `sbom_user` role(隨機 32 字元密碼)+ `sbom` database + `GRANT ON SCHEMA public`(Postgres 15+ 必要)+ 印出完整 `DATABASE_URL` 給使用者貼進 `.env`;支援 `PG_USER`/`PG_PASS`/`PG_DB` 覆寫
- **新增 SQLite → Postgres 遷移腳本**:`deploy/migrate-sqlite-to-postgres.py`(SQLAlchemy `Base.metadata.sorted_tables` 處理 FK 順序、欄位交集處理 schema 演進、單一 transaction 全成或全 rollback、`--force` 強制覆寫 / `--dry-run` 試跑)
- **`backup.sh` 雙模式**:自動讀 `backend/.env` 偵測 `DATABASE_URL` scheme,SQLite 走 `sqlite3 .backup`(產 `.db`),Postgres 走 `pg_dump --format=custom --no-owner --no-acl`(產壓縮 `.dump`,可 `pg_restore`),兩者都自動輪替 `KEEP_DAYS`(預設 14)
- **`.env.production` 預設改 Postgres**:`DATABASE_URL=postgresql+psycopg2://sbom_user:CHANGE_ME_FROM_setup-macos.sh@127.0.0.1:5432/sbom`(SQLite 保留為註解選項)
- **`first-deploy.sh` 同步攜帶遷移腳本**:把 `migrate-sqlite-to-postgres.py` 一併 scp 到 Mac Mini 的 `~/sbom-bootstrap/`
- **`MACMINI_SETUP.md` 新增「資料庫」章節**:SQLite vs Postgres 對照表、自動/手動安裝、SQLite 遷移流程、psql 互動操作、切回 SQLite 提示;FAQ 更新對應 Postgres 服務排錯
- **驗證範圍**:Step 1(`days_between` cross-DB 抽象)在 SQLite 上跑 54/54 全綠,dashboard `/api/stats/` 200 OK;Postgres 端驗證受 Windows 開發機 WDAC 政策阻擋(已記錄 `.knowledge/pitfalls/wdac-blocks-unsigned-binaries.md`),延後到 Mac Mini 部署時做 ground-truth

### 新增(SBOM 拆解能力 — Syft 整合)
- **`syft_scanner.py` service**:`is_syft_available()` / `scan_source(zip_bytes)` / `scan_binary(file_bytes, filename)`,內含 zip-bomb 防護(500MB 累計上限 + 路徑沙箱拒絕 `..` / 絕對路徑 / 解壓溢出)
- **新端點 `POST /api/releases/{id}/sbom-from-source`**:接受原始碼 zip,Syft 識別 manifest(`package.json` / `requirements.txt` / `go.mod` / `Cargo.toml` / `pom.xml` 等)→ CycloneDX → 合併進現有元件清單(by purl,additive)→ 自動 OSV/EPSS/KEV;100MB 上限;`require_plan("syft")`
- **新端點 `POST /api/releases/{id}/sbom-from-binary`**:接受單一 binary(`.exe` / `.so` / `.dll` / `.jar` / `.whl` / firmware image),Syft binary cataloguers 抽 Go/.NET/Java/Python/Rust 嵌入版本資訊;200MB 上限;`require_plan("syft")`
- **共用 `_import_syft_cdx()` helper**:parse → upsert components by purl → OSV scan → EPSS/KEV enrich → audit;與 `scan-image` 的 pipeline 一致,downstream 無差別
- **plan 註冊**:`FEATURE_PLAN["syft"] = "professional"`
- **填補能力缺口**:此前僅有 reachability(`upload-source` 是分析既有 SBOM,不產 SBOM)、Trivy(只能容器/IaC)、EMBA(GPL-3.0,需自選);Syft 補上**原始碼 → SBOM** 與 **binary → SBOM** 兩個重要場景,且 license 乾淨(Apache-2.0)

### 新增(OSS 合規 / 路線 A 完成)
- **`NOTICE.md`**(186 行):完整盤點所有 OSS 元件、License、版本、源碼 URL;分 7 節 ── permissive 14 個 / LGPL 2 個(`fpdf2`/`psycopg2-binary`,SaaS 動態 import 場景無源碼公開義務)/ 外部 subprocess 工具(Trivy/Syft Apache-2.0 + EMBA GPL-3.0 但**不打包**)/ 外部資料來源(OSV/NVD/KEV/EPSS/GHSA)/ CycloneDX & SPDX spec / License 全文索引 / **下游使用者合規 checklist**(4 條給整合本產品的客戶)
- **`GET /api/notice` 公開端點**:`backend/app/api/notice.py`,回 `text/markdown; charset=utf-8`,**無認證**(auditors / 法務不需帳號即可驗證合規);快取於 import time 避免重複 I/O
- **前端 About 頁(路徑 `/about`,公開)**:`frontend/src/pages/About.jsx` 抓 `/api/notice` 渲染;不引入 markdown 套件(遵守 CLAUDE.md「No new npm packages」),改用內建 monospace + 自動 linkify URL
- **Layout footer 加入連結**:`SBOM Platform · v2.0.0 │ 開源授權聲明 · NOTICE.md`,i18n 中英對應 key 已加 (`nav.openSourceNotices`)
- **`INSTALL_TRIVY=1` / `INSTALL_SYFT=1` 旗標**(setup-macos.sh):`brew install` 對應工具,Apache-2.0 license 直接安裝
- **`INSTALL_EMBA=1` 旗標**:**只印安裝指南**,本產品從不下載 / 打包 EMBA(GPL-3.0)。明確劃清 license 邊界 ── arms-length subprocess 模式不會把 GPL 義務擴及產品本體
- **`MACMINI_SETUP.md` 新增「拆解能力啟用」章節**:Trivy / Syft / EMBA 三表並列,標清各自 license 風險與啟用方式

### 文件
- `SECURITY.md`:版本支援表更新(1.5.x → 2.0.x 為最新)
- `CLAUDE.md`:Python 版本 3.9 → 3.11 更正;測試數 39 → 54 更正;路由表新增 `/sbom-from-source` `/sbom-from-binary` `/api/notice`;services 表新增 `syft_scanner.py`
- 新增 `.knowledge/`:跨輪次知識庫(ADR / patterns / pitfalls / references)
- 新增 `NOTICE.md`(見上「OSS 合規」章節)

### 計畫中
- 部署到自家 Mac Mini 生產環境(所有功能已完成)
- ~~Binary SBOM 生成(Syft,等客戶需求)~~ ✅ 已完成 ── Syft 整合(原始碼 + binary 兩個端點)
- FDA Pre-market 合規報告(等醫材客戶)
- ~~路線 B:psycopg2 → pg8000;fpdf2 → reportlab~~ ✅ 全部完成,runtime 已無 LGPL/GPL 元件
- (架構級)前端 JWT 改 httpOnly cookie ── 影響面廣,留待有具體 OEM 客戶安全要求時再做

---

## [2.0.0] — 2026-04

### 安全性修正（P1）
- **DELETE /releases 權限修正**：加入 `require_admin` 守衛，viewer 無法刪除 release
- **SBOM 品質評分 DB 快取**：上傳時計算 score/grade 寫入 `releases` 表，`/stats/sbom-quality-summary` 不再每次讀全部 SBOM 檔案
- **top-risky-components SQL 聚合**：改用 SQL `GROUP BY` + `SUM(CASE)`，不再載入全部 Component 到 Python
- **CRA incident 多租戶隔離**：合規報告（IEC 62443-4-1/3-3、NIS2）的 CRA incident 查詢加入 `org_id` 過濾
- **SSO 帳號需審批**：OIDC 自動建立的帳號預設 `is_active=False`，需管理員啟用

### 效能與 UX 改善（P2）
- **ReleaseDetail re-render 優化**：~15 個下載/匯出 useState 合併為 `busy` 物件
- **useMemo 優化**：`displayedVulns`、`severityCounts` 加 `useMemo`，只在篩選條件變更時重算
- **Dashboard AbortController**：5 個 API 請求加 AbortController，離開頁面自動取消
- **合規報告去重複查詢**：移除 4 處重複的 Product/Org 查詢，直接使用 `_assert_release_org` 回傳值
- **Dashboard i18n 補齊**：高風險元件表格 6 處硬編碼中文改用 `t()`

### 其他改善
- **使用者管理強化**：編輯帳號支援修改登入帳號（username）；新增帳號表單加入 Email 欄位；列表新增 Email 欄
- **測試修正**：viewer 建立測試加 `organization_id`；測試數從 39 → 55 項
- **移除重複 /health 端點**（死碼）
- **React Router v7 future flag 警告消除**

### 修正（TISAX 功能補強）
- **個資保護模組（Data Protection）**：新增 4 項 GDPR 相關控制項（DP-9.1 個資保護政策、DP-9.2 個資識別與分類、DP-9.3 資料主體權利管理、DP-9.4 個資洩漏事件 72h 通報）；建立評估時可選「個資保護（4 項，GDPR）」；VDA ISA 6.0 控制項從 65 → 69 項
- **Plan 檢查補齊**：`GET /assessments/{id}`、`PATCH /controls/{id}`、`DELETE /assessments/{id}` 補加 `require_plan("tisax")`，所有端點一致要求 Professional plan
- **TISAX 稽核紀錄整合**：建立 / 控制項更新 / 刪除評估寫入 `audit_events`（`tisax_create / tisax_control_update / tisax_delete`）；AdminActivity 頁加入對應事件標籤

### 改善（通知與搜尋）
- **漏洞文字搜尋**：ReleaseDetail 漏洞篩選列新增文字輸入框，支援 CVE ID 和元件名稱模糊搜尋（不分大小寫），納入「清除篩選」重置
- **通知規則（Alert Rules）**：`AlertConfig` 新增 `alert_min_severity / alert_kev_always / alert_epss_threshold` 三欄；`_passes_alert_rule()` 過濾函式；Settings 頁新增「通知規則」卡片（嚴重度下拉 / EPSS 滑桿 / KEV 一律通知 checkbox）；規則全不通過時靜默跳過
- **多收件人 Email**：`alert_email_to` 改支援逗號分隔多地址；`send_email()` 拆分 recipients 清單；測試信同樣寄送所有收件人
- **抑制到期通知**：`monitor.py` 每次掃描後查詢 `suppressed_until < now`，自動清除到期抑制並觸發通知（受通知規則篩選）

### 新增（競品落差補強）
- **NIS2 Directive Article 21 合規報告**：`nis2_report.py` 評估 5 個 SBOM 可量化控制項（21.2(b) 事件處理、(d) 供應鏈安全、(e) 漏洞管理、(h) 加密政策 CWE-326/327/310、(i) 資產管理 NTIA）；`GET /api/releases/{id}/compliance/nis2` → PDF；繼承 CjkPDF 支援中文；ReleaseDetail 匯出選單加入
- **Slack / Teams 格式化通知**：`send_webhook()` 自動偵測 URL 類型；`hooks.slack.com` → Block Kit（fields + 顏色 attachment）；`webhook.office.com` → MessageCard（Adaptive Cards 格式）；其他 URL → 原有通用 JSON，不影響現有設定
- **GitLab CI 範本**（`tools/sbom-gitlab-ci/`）：`sbom-upload` + `sbom-gate` 兩個 job；純 stdlib 無外部依賴；支援 `SBOM_FILE / SBOM_API_URL / FAIL_ON_GATE` 變數；rules: main + merge_request；附 README 含 Syft SBOM 生成範例

### 改善
- **組織刪除二次確認**：`ConfirmModal` 新增 `requireTypeName` 屬性；刪除組織時必須輸入組織名稱才能啟用確認按鈕，防止誤刪
- **JWT 登出即失效**：`revoked_tokens` 資料表（jti, expires_at）；JWT 加 `jti` claim；`get_current_user` 查黑名單；`POST /auth/logout`；啟動時自動清除過期 token；Layout/Profile 登出前先呼叫 API
- **Release 版本號編輯**：`PATCH /api/releases/{id}/version`（鎖定版本不可改）；Releases 頁加「編輯」按鈕 + modal
- **Webhook 失敗重試**：`send_webhook()` 指數退避最多 3 次（1s、2s 間隔）
- **SBOM 上傳進度條**：Axios `onUploadProgress` → 藍色進度條；傳輸中顯示百分比；傳輸完成顯示「解析中...」
- **User email 欄位**：`users.email`（nullable）；Profile 頁顯示/編輯；Users 頁表格帳號下方顯示；忘記密碼支援以 email 查詢；`PATCH /auth/profile` 自助更新
- **Product 編輯**：`PATCH /api/products/{id}`；Products 頁加「編輯」按鈕 + modal
- **稽核紀錄 CSV 匯出**：`GET /api/admin/activity/export`（後端 CSV，max 5000 筆）；AdminActivity 頁改呼叫後端，自動帶入篩選條件
- **ReleaseDiff UI 改善**：補「不變」數量卡片；新增漏洞嚴重度分布 badge；匯出 CSV；空狀態改善
- **忘記密碼流程**：`PasswordResetToken` 資料表；`POST /forgot-password`（always 204）+ `/reset-password`；SMTP 寄 30 分鐘時效連結；Login 頁加連結；ForgotPassword / ResetPassword 頁面
- **SQLite 自動備份**：`deploy/backup.sh`（sqlite3 .backup，保留 14 天）
- **Share link 上限**：同一 release 最多 20 條，超過回 400
- **Monitor 跳過通知**：`_last_skip_dt` 記錄、`get_status()` 回傳、Settings 頁橘色警示
- **Release 備註欄位**：`releases.notes`；`PATCH /releases/{id}/notes`；ReleaseDetail 可編輯區塊
- **Health Check endpoint**：`GET /health`（無需登入、不計 rate limit）；回傳 `status/version/db/monitor/timestamp`；DB 掛掉時回 `degraded`；供 UptimeRobot / load balancer / cron 監控
- **Async I/O 修正**：`upload_source`（Python AST call graph）與 `scan_iac_archive`（Trivy subprocess）改用 `asyncio.to_thread`，長時間掃描不再阻塞 event loop，其他使用者請求不受影響
- **Rate Limiting**：`core/rate_limit.py` 滑動視窗（純 stdlib，無外部依賴）；登入端點 10 次/5 分鐘/IP（成功後重置）；全域 API middleware 300 次/分鐘/IP；支援 nginx `X-Forwarded-For`；超限回 429 + Retry-After
- **列表端點分頁保護**：`GET /releases/{id}/components` 新增 `skip/limit`（預設 2000，硬上限 5000），回傳 `{total, skip, limit, items}`；`list_vulnerabilities` 早有 max=1000 ✅
- **稽核紀錄覆蓋率補齊**：`audit_events` 表從 8 種事件擴展至 21 種，新增 `org_create/update/plan_change/delete`、`product_create`、`vex_update`、`vex_batch_update`、`vuln_suppress/unsuppress`、`token_create/revoke`、`share_link_create/revoke`、`release_lock/unlock`、`signature_deleted`、`password_change`；VEX 變更記錄 CVE ID 與狀態轉換，Plan 變更記錄新舊方案名稱

### 修正（安全 / 效能 / 併發）
- **OIDC CSRF 修補**：`/oidc/callback` 加入 state cookie 驗證，防止 authorization code 注入攻擊
- **Migration SQL Injection 防護**：`_list_columns` / `_add_column` 加入 `_ALLOWED_TABLES` 白名單，table 名稱不在清單時 raise ValueError
- **IDOR 修補**：`/rescan` endpoint 補加 `_assert_release_org()` org scope 檢查
- **併發安全**：`_active_enrichments` 的 check-then-add 改以 `threading.Lock` 保護原子性，防止雙重執行
- **資料完整性**：`vulnerabilities` 加 `UniqueConstraint("component_id","cve_id")`，migration 同步建立 `UNIQUE INDEX`，防止並發 rescan 產生重複 CVE
- **N+1 查詢消除**：`list_components`、PDF report、CSV export、compliance report 共 6 處 component 查詢加 `selectinload(vulnerabilities)`，多元件 release 從 N+1 次降為 2 次 SQL
- **啟動安全警告**：`SECRET_KEY` 使用預設值或短於 32 bytes 時記錄 WARNING

### 新增
- **IEC 62443 PDF CJK 字型支援**：`font_manager.py` 自動偵測字型（Windows `msyh.ttc`、Linux NotoSansSC、自動下載 fallback）；`CjkPDF` 基礎類別供三份報告（4-1/4-2/3-3）繼承；組織名稱、產品名稱等中文欄位可正確渲染至 PDF
- **SBOM 脫敏分享連結**：Professional plan；`POST /api/releases/{id}/share-link` 建立時效 token；`GET /api/share/{token}` 無需登入公開下載；`mask_internal` 過濾 `internal://` / `private://` 元件；記錄下載次數；ReleaseDetail 面板含複製、撤銷
- **UI/UX 全面修正（19 項）**：Plan 降級確認 modal、批次 VEX 操作回饋、Dashboard 錯誤提示、Plan 鎖定功能灰色圖示、麵包屑補抓、骨架屏、SBOM 上傳引導 toast、TISAX/CRA 空白頁說明、角色切換確認、簽章鎖定提示、分享連結 toast、i18n 補完、clipboard 錯誤、Token 只顯示一次警告加強
- **Plan 分層系統**：Starter / Standard / Professional 三層；後端 `require_plan()` FastAPI dependency（非 admin 回 402）；前端 `utils/plan.js` + Layout badge + 按鈕/頁面自動隱藏；Organizations 頁 admin 可即時切換 plan
- **SSO / OIDC 整合**：`OIDC_ISSUER` / `CLIENT_ID` / `CLIENT_SECRET` 設定後自動啟用；`/oidc/login` redirect + `/oidc/callback` JWT 回傳；支援 Azure AD / Google / Keycloak；`oidc_sub` 欄位；Login 頁 SSO 按鈕
- **Postgres 後端選項**：`_is_sqlite` 分支 + `_add_column_safe()` migration helper；切換只需改 `DATABASE_URL`
- **持續監控**：`monitor.py` 背景排程（6/12/24/48/72h 可選）+ 手動觸發；Settings UI 顯示上次執行時間和下次排程
- **SBOM 格式互轉**（`POST /api/convert`）：CycloneDX JSON ↔ SPDX JSON、CycloneDX ↔ XML
- **SBOM 品質評分 Dashboard**：`/stats/sbom-quality-summary` A/B/C/D 分布卡片
- **CVE 影響查詢**：`/stats/cve-impact?cve=CVE-xxx` + Dashboard 即時查詢框
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
