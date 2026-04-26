# 下一項工作詳細計畫

最後更新:**2026-04-26**(本 session 結束時間)

---

## 現階段優先順序

### 🟢 已完成,沒有阻塞物

1. License Path B(runtime 100% permissive)— 完成
2. Phase 0/1 安全修復(14 Critical/High + 6 Medium/Low)— 完成
3. P2 效能優化(5 項)— 完成
4. UI/UX/RWD 系統性 audit(36 項 → Wave A/B/C 19 commits 修完 P0/P1/P2)— 完成
5. OSV 批次掃描重寫(200 元件 SBOM HTTP 次數 200 → 51)— 完成
6. Reachability 39-fixture ground-truth corpus + 工具鏈 — 完成

### 🟡 等使用者執行(各約 5–10 分鐘,純 user-side action,不阻塞開發)

| 動作 | 連結 | 效果 |
|------|------|------|
| 申請 NVD API key 填到 `.env` | [`docs/api-keys-setup.md`](docs/api-keys-setup.md) §1 | NVD enrichment 速率 10× |
| 申請 GitHub fine-grained PAT 填到 `.env` | [`docs/api-keys-setup.md`](docs/api-keys-setup.md) §2 | GHSA 速率 83× |
| 在 GitHub 開 Wave D issue | [`.knowledge/decisions/reachability-js-java-issue.md`](.knowledge/decisions/reachability-js-java-issue.md) 全文貼上 | sprint #3 正式啟動 |
| 部署到 Mac Mini | [`deploy/MACMINI_SETUP.md`](deploy/MACMINI_SETUP.md) | 上線 |

### 🔵 下一個正式 sprint:Wave D — JS/TS + Java reachability 擴展

**目標**:把 `app/services/reachability.py` 從 Python-only 擴成多語言;sprint #3 PR merge 條件 = 39-fixture corpus 的 FP/FN 趨近 0,J15/J16 必須輸出 `unknown`(誠實認輸)。

**ground truth 已就緒**:
- 規格:[`.knowledge/decisions/reachability-js-java-issue.md`](.knowledge/decisions/reachability-js-java-issue.md)
- CVE → symbol 對照(rev 2,經過 GHSA verification 修正):[`.knowledge/decisions/reachability-corpus-cve-mapping.md`](.knowledge/decisions/reachability-corpus-cve-mapping.md)
- 39 個 fixture:`backend/tests/fixtures/reachability/`(10 Python + 16 JS/TS + 13 Java)
- Validator / stats / runner 工具:`backend/tests/fixtures/reachability/_tools/` + `_runner/`

**估時**:~14 工作天(1 sprint)
- Tree-sitter 設置 + JS prototype:2 天
- JS alias tracking + call graph:3 天
- TypeScript 支援(extends JS):1 天
- javalang 設置 + Java alias tracking:2 天
- Java route annotation detection(Spring/JAX-RS):2 天
- 文件 + integration:2 天
- Performance pass + cache:1 天
- 修 corpus 暴露的 baseline gap:1 天

**技術選型**:
- JS/TS:`tree-sitter` + `tree-sitter-javascript` + `tree-sitter-typescript`(MIT,純 wheel,**不需 Node.js runtime**)
- Java:`javalang`(BSD-3,純 Python)
- 兩者皆 permissive license,符合 Path B 路線

---

## 未來可能 sprint(Wave D 之後,優先順序未排)

### Reachability 進階
- Go / Rust / Ruby 擴展(Wave D 完成後再評估,看用戶實際 SBOM 語言分佈)
- 跨檔案 call graph(目前只 1-hop)
- Type-flow / data-flow analysis(taint tracking)

### 整合與工具鏈
- npm 發包 sbom-cli(目前 Python 版,未來考慮 Node 版)
- IntelliJ / VS Code plugin(SBOM viewer + Policy Gate 提示)
- Dependabot 整合(自動觸發 rescan)

### 合規面
- ISO/SAE 21434(汽車網安管理體系)
- TISAX VDA ISA 6.1 升版(目前 6.0)
- ENISA Cybersecurity Certification Framework(EU CC)

### 效能
- Background job queue(Celery / RQ),目前是同步 + ThreadPoolExecutor
- 漏洞資料 incremental sync(只抓上次以來變動的,目前每次重抓)

---

## 本 session 完成的 commits(2026-04-26)

按時間正序:

### 一、License 路線 B 完成
| Commit | 說明 |
|--------|------|
| `047f9b3` | 替換 psycopg2-binary(LGPL)→ pg8000(BSD-3) |
| `fbe9592` | 替換 fpdf2(LGPL)→ reportlab(BSD-3) via pdf_shim |

### 二、Phase 0 + Phase 1 安全修復(本 session 之前已完成,2026-04-25)
| Commit | 說明 |
|--------|------|
| `49b53cd` | 14 Critical/High + 6 Medium/Low(`SECRET_KEY` guard、IDOR、SSRF、path traversal、CSV formula injection、token scope、密碼策略統一等)|
| `1079166` | 升級依賴清除 9 個已知 CVE(`fastapi` / `starlette` / `python-multipart` / `requests` / `pillow`)|
| `af88df4` | `/health` 監控誤報 + `lifespan` 遷移 + 移除重複 endpoint |

### 三、UI/UX/RWD 全面 audit(本 session,Wave A/B/C 19 commits)
| Wave | 範圍 |
|------|------|
| A(1 commit)| 設計 token + `prefers-reduced-motion` + `:focus-visible` |
| B(8 commits)| 8 項 a11y quick wins(lang sync、viewport、Skeleton、Modal/Toast aria、focus-trap、favicon、theme-color、PageLoading)|
| C(9 commits)| `<th scope>`(86 處)、contrast(137 處)、`<Button>` 元件、`<label htmlFor>`(30+ 處)、SVG token(2 檔)、touch targets、emoji→lucide、z-index token、semantic links |
| 文件 | `f6ac260` CHANGELOG Wave A/B/C 摘要 |

### 四、效能與可達性建設(本 session)
| Commit | 說明 |
|--------|------|
| `2d5b639` | OSV 批次 API + API key 申請指引(N → 1+M HTTP) |
| `72987b7` | Wave D issue body 草稿(`reachability-js-java-issue.md`) |
| `7a15624` | 39-fixture CVE→symbol 對照表 rev 1 |
| `5e82196` | mapping rev 2(per review:requests 對丟、Mako symbol 修、3 Java unreachable 補強、`fixture_type` + `transitive_only` 入 schema)|
| `f03834a` | Phase 1 corpus:10 Python fixtures + schema/validator/stats/runner |
| `f5500e3` | Phase 2 corpus:16 JS/TS fixtures(JSX、CJS、ES6 alias、TS type-only、dynamic import、reflective dispatch)|
| `4c95b09` | Phase 3 corpus:13 Java fixtures(Log4Shell × 3、Spring4Shell × 2、Text4Shell × 2、static/wildcard import、JAX-RS、classpath-only、DI dead bean、test_only)|

### 五、文件總整理
| Commit | 說明 |
|--------|------|
| (本 commit) | README 加 Wave D / OSV batch / api-keys-setup 連結;architecture.md 全面改寫(舊目錄路徑、舊 services 清單、舊技術棧、舊 frontend 路由全更新);NEXT_TASK 整合 Wave D roadmap |

---

## 已完成功能總覽(累積到 2026-04-26)

### 核心功能
- API Token scope(read / write / admin)
- 首屏性能(路由 lazy + 依賴圖延後 fetch)
- License 風險分類 + 通知測試按鈕
- GitHub Actions / GitLab CI 整合(`tools/sbom-{action,gitlab-ci}/`)+ Python CLI(`tools/sbom-cli/`)
- SBOM Sigstore 簽章驗證(ECDSA / RSA,Policy Gate 第 6 項)
- TISAX 模組(VDA ISA 6.0,69 控制項,AL2/AL3 gap 分析,含 GDPR 個資保護模組)
- Trivy 容器 / IaC 掃描(`POST /scan-image` `/scan-iac`)
- Syft 原始碼 / binary → SBOM(`/sbom-from-source` `/sbom-from-binary`)
- GHSA 漏洞情資補強(GitHub Advisory Database)
- Reachability Phase 1/2/3(import / test 路徑過濾 / Python AST call graph)
- i18n 國際化(zh-Hant / en,300+ keys)
- SBOM 格式互轉(CycloneDX ↔ SPDX ↔ XML)
- SBOM 品質評分 Dashboard
- CVE 影響查詢(Dashboard)
- Postgres 後端選項(pg8000)
- SSO / OIDC(Azure AD / Google / Keycloak)
- Plan 分層(Starter / Standard / Professional)
- SBOM 脫敏分享連結
- IEC 62443 PDF CJK 字型(Windows/Linux/下載)
- 行動版 UI/UX 全面優化
- 安全/效能/併發修正(OIDC CSRF、IDOR、N+1、UniqueConstraint、Lock)
- 稽核紀錄 21 種事件型別 + CSV 匯出(帶篩選條件)
- Rate Limiting(登入 10/5min + 全域 300/min/IP)
- 列表分頁保護(硬上限 5000)
- Health Check endpoint
- Async I/O(`upload_source` + `scan_iac` 改 `asyncio.to_thread`)
- 忘記密碼 / 重設(SMTP,30 分鐘 TTL)
- SQLite 自動備份(14 天)
- Share link 上限(20 條 / release)
- Monitor 跳過通知(Settings 警示)
- Release 備註 / 版本號編輯
- User email 欄位
- Product 編輯
- ReleaseDiff UI 改善
- JWT 登出即失效(RevokedToken 黑名單)
- Webhook 失敗重試(3 次指數退避)
- SBOM 上傳進度條
- 組織刪除二次確認(typeName)
- 漏洞文字搜尋
- 通知規則(min_severity / epss_threshold / kev_always)
- 多收件人 Email
- 抑制到期通知(monitor 自動清除 + 通知)
- NIS2 Article 21 PDF
- Slack / Teams 格式化通知(Block Kit / MessageCard)
- GitLab CI 範本
- 使用者管理強化

### License 與 OSS
- runtime 100% permissive(MIT / BSD / Apache-2.0 / HPND / ISC)
- pg8000 取代 psycopg2-binary
- reportlab + pdf_shim 取代 fpdf2
- EMBA 不打包(arms-length GPL 隔離)
- NOTICE.md 7 節(含下游使用者合規 checklist)
- `/api/notice` 公開 endpoint + `/about` 頁面

### 測試與品質
- 39-fixture reachability ground-truth corpus(Wave D acceptance gate)
- 54 項 stdlib regression suite(`test_all.py`)
- Python AST analyzer baseline(5 PASS / 5 FP / 0 FN — 5 FP 是 Wave D 要關掉的 gap)

### UX / a11y / RWD(Wave A/B/C 完成,2026-04-26)
- 設計 token(colors / font-size / z-index / transition / max-width 全集中於 `tailwind.config.js`)
- WCAG 2.2 AA 對比(text-gray-600 為主)
- Apple HIG 觸控目標 ≥ 44 px
- iOS Safari 防 focus-zoom
- WAI-ARIA modal(focus trap + body scroll lock + Escape close,共用 `useFocusTrap` hook)
- `prefers-reduced-motion` 全域支援
- `:focus-visible` only(滑鼠不殘留 ring)
- `<th scope="col">` 全 86 處
- `<label htmlFor>` + `useId` 全 30+ 處(10 個頁面)
- SVG hex 全集中於 `chart-colors.js`
- emoji → lucide(跨平台一致)
- favicon + theme-color
- viewport-fit=cover + safe-area-inset

---

## 已知問題 / 低優先

| 項目 | 說明 |
|------|------|
| API token timing attack | SQL hash 比對可改 `hmac.compare_digest`;實際風險極低 |
| OIDC 自動建立新使用者 | 可加 email domain 白名單;需 OIDC 設定者授權才能觸發 |
| ReleaseDetail.jsx 約 20 個 form 缺 `htmlFor` | 檔案最大,含多個條件子 modal,Wave D 開始前獨立一輪 pass |
| `<Button>` 元件對其餘 ~70 處 `<button>` 的全面採用 | 增量遷移較安全,觸碰時順手換 |
| CRA `start-clock` 在已 `clock_running` 時回 409 | 設計如此,非 bug |

---

## 取消 / 不做

| 項目 | 原因 |
|------|------|
| Binary/PDF 盤點引導 | 已被 Syft `sbom-from-binary` 取代 |
| Webpack alias 路徑解析 | 需要讀 `tsconfig.json` / `webpack.config.js`,已從 reachability v1 scope 排除 |
| 動態 import 路徑反推 | 不可靜態決定,通過 J15 fixture 確認 analyzer 必須輸出 `unknown` |

---

## 部署到生產(任何時候都可開始)

```bash
# 在開發機上,設定 Mac Mini 連線資訊後執行首次部署
export SBOM_DEPLOY_HOST=mac-mini.local
export SBOM_DEPLOY_USER=peter
bash deploy/first-deploy.sh

# 之後每次更新
SBOM_DEPLOY_HOST=mac-mini.local bash deploy/deploy.sh
```

詳細步驟見 [`deploy/MACMINI_SETUP.md`](deploy/MACMINI_SETUP.md)(包含前置作業、launchd ops、三種對外連線方式)。
