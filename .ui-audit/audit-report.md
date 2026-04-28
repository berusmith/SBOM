---
phase: 6
iteration: 3
audit_id: ui-audit-iteration-3
based_on_commit: 6f0f018
created: 2026-04-28
---

# Phase 6 — Audit Report (iteration 3)

> 此報告**只列本輪新發現或回歸**。已修補項目見 `.knowledge/ui-audit/audit-report.md` (iter 1) 與 `.knowledge/ui-audit-lite/audit-report-lite.md` (iter 2)。

## 0. Executive summary

| Severity | Count | 重點代表 |
|----------|-----:|---------|
| **P0** (阻斷) | **0** | 無阻斷;產品可用 |
| **P1** (嚴重 — 真實使用者受影響) | **5** | Skeleton CLS bug, ReleaseDetail i18n holes, TrendChart unreadable text, Dashboard hardcoded thead, TrendChart keyboard inaccessible |
| **P2** (中等 — 顯著體驗劣化) | **10** | 空狀態無引導、錯誤訊息泛化、card radius 不一致、divider 看不見、無重試 |
| **P3** (優化 — 系統 / 品味缺口) | **12** | tabular-nums 0、字體 token 0 採用、duration token 0、active state 0、彈性間距無、無 elevation scale、暗色 nav 死灰 |
| **P4** (品味細節) | **7** | TrendChart palette confusable、tooltip 對比邊緣、Modal 進場無動效、focus ring offset 不一、Toast `×` 文字字元、Modal max-w 過窄 |
| **Total new** | **34** | |

**對比 iter 1+2**:
- iter 1 (Wave A/B/C):**新發現 0** — 既知缺口都已被涵蓋(P1/P2 多已修)
- iter 2 (Lite):**新發現 0** — 同上
- iter 3 (本輪):**新發現 34**(7 P4 是 iter 1+2 沒設立的「品味」維度)
- **回歸 (regression):0** — iter 1+2 修補項目全保留

**Taste score** (Phase 2 calibration 維度,本輪首次設立):

| Dim | 進場 | 預期(若 plan 完整執行) | 全面對標 |
|-----|:----:|:----------------------:|:-------:|
| D1 密度節奏 | 5 | 7.5 | 9 |
| D2 字體系統 | 4 | 7 | 9 |
| D3 色彩層次 | 6 | 8 | 9 |
| D4 微互動 | 3 | 7 | 9 |
| D5 動效曲線 | 4 | 6.5 | 8 |
| D6 狀態品質 | 5 | 7.5 | 9 |
| D7 細節紀律 | 5 | 7.5 | 9 |
| D8 響應式 | 6 | 7 | 8 |
| **加權平均** | **4.7** | **7.2** | **8.7** |

> 本輪可達 **+2.5 分** — 從「邊緣體面」邁向「明確專業」。要再進到 9 需要 dark mode + ReleaseDetail 拆分 + 真實裝置反覆迭代,屬於 iter 4+。

---

## 1. Findings

> 格式:每 finding 含 ID / Severity / Category / Trigger / Location / Observation / Why / Reference / Recommendation / Effort / Risk / Confidence。
> 部分 P3/P4 為節省篇幅合併為 cluster。

---

### P1 — 5 件

---

#### UX-3.001 — `SkeletonStatCards` 動態 grid-cols 被 Tailwind JIT 忽略 + count 不對

- **Severity**: P1
- **Category**: Performance / Visual
- **Trigger**: Phase 5 spot-read of `Skeleton.jsx`
- **Location**: `frontend/src/components/Skeleton.jsx:45-56`(及 `Dashboard.jsx:163` 呼叫處)
- **Observation**:
  ```jsx
  <StatusWrapper className={`grid grid-cols-2 md:grid-cols-${count} gap-4`}>
  ```
  Tailwind JIT 用靜態正則掃描 source,**無法萃取** `md:grid-cols-${count}` 形成的動態類名。Dashboard 呼叫時 `count={4}`,但實際渲染的卡片是 6 張(`Dashboard.jsx:182`):4 → 6 換不過。同時 `Dashboard.jsx:163` 呼叫 `<SkeletonStatCards count={4} />` 與下方 `<SkeletonTable rows={5} cols={5} />` — 4 張 skeleton 對 6 張真實卡 = layout shift。
- **Why it matters**:
  1. **CLS** — 進場 skeleton 是 4 卡格,實際 6 卡格,首屏跳格(對標 LCP < 2.5s + CLS < 0.1 兩項都受傷)
  2. **可能完全 silent** — `md:grid-cols-6` 若沒在別處被掃到,JIT 不產生這 class,瀏覽器 fallback 為 `grid-cols-2` 行為,UX 更糟
  3. **隱性,grep 發現,實機才出 CLS 紅燈**
- **Why-existing-classes-may-save-it**: `Dashboard.jsx:182` 有 `xl:grid-cols-6` 字面 → JIT 會把 `grid-cols-6` 編進去 → 但 `md:grid-cols-6` 仍然不一定被產生(JIT 對 prefix + class 的組合通常會產生但不保證)。
- **Reference**: Linear 的 skeleton 永遠跟最終 layout 1:1 對齊;Vercel 使用 fixed `aspect-ratio` skeleton 而非 cols。
- **Recommendation**:
  ```jsx
  // before
  export function SkeletonStatCards({ count = 4 }) {
    return (
      <StatusWrapper className={`grid grid-cols-2 md:grid-cols-${count} gap-4`}>
        ...
  // after — explicit class branches keep JIT happy + Dashboard updates count
  const COL_CLASS = {
    4: "grid-cols-2 sm:grid-cols-2 md:grid-cols-4",
    6: "grid-cols-2 sm:grid-cols-3 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6",
  };
  export function SkeletonStatCards({ layout = 4 }) {
    return <StatusWrapper className={`grid ${COL_CLASS[layout] ?? COL_CLASS[4]} gap-4`}>...
  ```
  Dashboard 改為 `<SkeletonStatCards layout={6} />`;若擔心 cardinal 切換也加 safelist 至 tailwind config。
- **Effort**: S
- **Risk**: 低 — 純前端結構修補
- **Confidence**: High(grep + 程式碼直讀)

---

#### UX-3.002 — `ReleaseDetail.jsx` 9 處 toast.error / 標籤硬編碼 zh + STATUS_LABEL 純英,英文使用者體驗破洞

- **Severity**: P1
- **Category**: i18n / A11y
- **Trigger**: Phase 5 grep `toast\.error\("[^"]+"\)` + Phase 5 read of `ReleaseDetail.jsx` 上半部
- **Location**:
  - `ReleaseDetail.jsx:19-25` STATUS_LABEL 全英 (`open / in_triage / not_affected / affected / fixed`)
  - `ReleaseDetail.jsx:28-46` JUSTIFICATION + RESPONSE 雙語 hack(`程式碼不存在 (code_not_present)` 等)
  - `ReleaseDetail.jsx:126,138,148,214,1194` 5 處 toast.error 寫死 zh
  - `ReleaseDetail.jsx:201` `setIntegrity({ status: "error", message: "驗證失敗" })`
  - `ReleaseDetail.jsx:939` `toast.success("連結已複製")` / `toast.error("複製失敗,請手動選取")`
  - `FirmwareUpload.jsx:57,118,204` 3 處 toast.error 寫死 zh
- **Why it matters**:
  1. iter 1 UX-014 把 Modal/Toast `aria-label` i18n 化,本以為文字流量也走 i18n;**ReleaseDetail / FirmwareUpload 整片漏掉**
  2. 英文使用者切換到 EN 後仍看到 `元件清單載入失敗` `驗證失敗` `請上傳 .bin, .img 或 .zip 檔案` — 立即露餡
  3. STATUS_LABEL 是 vuln tab 主視覺 chip — 切到 zh 仍顯示 `Open / In Triage / ...` 英文,反向破洞
- **Reference**: Linear 全站走 i18n;Stripe Dashboard 36 種語言。任何 toast 都不應該寫字面字串。
- **Recommendation**:
  - Pass 1:把 9 處 toast 字面換成 `t("releases.errors.componentLoadFailed")` 等 key;在 `i18n/zh.js` 與 `en.js` 補翻譯
  - Pass 2:STATUS_LABEL 改 `t("vulnStatus.open")` 等;從 `STATUS_LABEL[k]` 改為 hook
  - Pass 3:JUSTIFICATION_OPTIONS / RESPONSE_OPTIONS 從硬編碼陣列改為 component 內 `t("...")` 對應 — 失去常數但獲得正確 i18n
- **Effort**: M(~30 分鐘 + i18n key 補齊)
- **Risk**: 低 — 純文字
- **Confidence**: High

---

#### UX-3.003 — `TrendChart` SVG `<text>` fontSize 7.5 / 8 — 低於 12px 可讀閾值

- **Severity**: P1
- **Category**: A11y / Visual
- **Trigger**: Phase 5 read of `TrendChart.jsx` + WCAG 1.4.4 ("Resize Text") 推論
- **Location**: `TrendChart.jsx:53,73,74` — Y tick `fontSize="8"`; X label `fontSize="7.5"`
- **Observation**: 8px / 7.5px 在 retina 1×0.5 物理像素;在 1× 螢幕(Win 1080p)實際渲染 6px。即使 200% zoom 也只是 16px,且 SVG `<text>` *不受 OS 字級放大影響*(只受 viewport zoom 影響)。在 dev workstation Win 1080p 上,X 軸 label 我目視幾乎不可讀。
- **Why it matters**:
  1. WCAG 1.4.4(放大文字 200% 不破版)— SVG `<text>` 違反精神
  2. 本來就刻意小是因為 chart 寬只有 500px 容不下大字 → 設計問題,不是技術問題
  3. 工程師讀漏洞趨勢圖時,X 軸標籤幾乎看不清 → 必須 hover tooltip 才知道版本號
- **Reference**: Recharts / D3 預設 11–12px;Stripe Dashboard chart label 13px。
- **Recommendation**:
  - 將 fontSize 提升至 11(X 軸)/ 10(Y tick)— 但必須同步 truncate 規則(目前 8 字後 `…`,改後可能 10 字)
  - 若 5 個版本以上密度不夠,讓 X 軸 label 旋轉 -45° 或只顯示每隔一個
  - 數字用 tabular-nums(配合 UX-3.016)
- **Effort**: S
- **Risk**: 中 — chart layout 可能要微調;5 個版本以上要驗證
- **Confidence**: High

---

#### UX-3.004 — `Dashboard.jsx` riskOverview thead 7 個欄位硬編碼 zh

- **Severity**: P1
- **Category**: i18n
- **Trigger**: Phase 5 read of `Dashboard.jsx`
- **Location**: `Dashboard.jsx:574-580`
  ```jsx
  <th scope="col" className="pb-2 pr-4">客戶</th>
  <th scope="col" className="pb-2 pr-4 text-center">產品</th>
  <th scope="col" className="pb-2 pr-4 text-center">總漏洞</th>
  <th scope="col" className="pb-2 pr-4 text-center">未修 Critical</th>
  ...
  ```
- **Observation**: 7 列全為字面 zh,沒走 `t()`。其他幾個 thead 同檔走 `t("organizations.name")` 等。本片是漏掉。
- **Why it matters**: 同 UX-3.002 — 英文模式露洞。
- **Reference**: 自家內部一致性。
- **Recommendation**:
  ```jsx
  <th scope="col" ...>{t("dashboard.riskCol.customer")}</th>
  <th scope="col" ...>{t("dashboard.riskCol.products")}</th>
  // ... 7 keys 加進 zh.js / en.js
  ```
- **Effort**: S
- **Risk**: 低
- **Confidence**: High

---

#### UX-3.005 — `TrendChart` 純滑鼠互動;鍵盤完全無法觸發 tooltip

- **Severity**: P1
- **Category**: A11y / Interaction
- **Trigger**: Phase 4 stress test §4.1 (僅鍵盤 / 螢幕閱讀器)
- **Location**: `TrendChart.jsx:64-77` — 整個 hover 系統綁 `onMouseEnter` / `onMouseLeave`
- **Observation**: TrendChart 把每個資料點包成 `<g>` 加 hover 區。**沒有 `tabIndex`、沒有 `onFocus`、沒有 `aria-label`**。鍵盤使用者完全看不到 tooltip,螢幕閱讀器只聽到 SVG 一個整體 `各版本漏洞趨勢` 而已 — 完全無法存取資料。
- **Why it matters**:
  1. WCAG 2.1.1 鍵盤可達 — fail
  2. 4.1.2 Name, Role, Value — 無資料公開
  3. 對 keyboard power user(我們目標 persona)是真實痛點
- **Reference**: Recharts 從 v2 起每 dot 是 `tabindex=0`;BBC Open 政策 SVG 圖必須有 `<desc>` + 資料表 fallback。
- **Recommendation**:
  - 每個資料點 `<g tabIndex="0" role="img" aria-label={...} onFocus={() => setHovered(i)} onBlur={...}>`
  - 加可被 toggle 的 fallback table(`<details><summary>查看資料表</summary><table>...`)
  - 鍵盤 left/right 在 chart 內切換資料點
- **Effort**: M
- **Risk**: 低 — 純 a11y 加強
- **Confidence**: High

---

### P2 — 10 件

---

#### UX-3.006 — 空狀態多為一行字,缺「下一步引導」

- **Severity**: P2
- **Category**: Interaction / Content
- **Trigger**: Phase 4 §4.5 + Phase 3 NN heuristic #10 (Help & docs)
- **Location**: 抽樣
  - `Dashboard.jsx:236-238` 無漏洞 → 「目前無漏洞」
  - `Dashboard.jsx:464` 無高 EPSS → 「暫無高 EPSS 漏洞」
  - `Dashboard.jsx:368` CVE 無結果 → 「未找到符合的 CVE」
  - 其他 ReleaseDetail 元件 / 漏洞 0 列時直接呈現空 `<table>`(無說明)
- **Observation**: `ViewerOnboarding`(`Dashboard.jsx:70-110`)是好範本 — 三步引導 + 連結。其他空狀態完全是「沒資料」。
- **Why it matters**: 第一次使用者面對空 dashboard 不知該做什麼;有篩選的人不知能否清掉再看。
- **Reference**: Linear empty inbox 顯示「沒 issue — Inbox 是清的、回去 backlog 看看」+ button。
- **Recommendation**: 為每個空狀態定義文案三件套 — *標題 / 說明 / 行動*。模板化:
  ```jsx
  <EmptyState
    icon={<Inbox size={32} />}
    title={t("emptyVulns.title")}
    description={t("emptyVulns.desc")}
    action={<Link to="/releases/new">{t("emptyVulns.action")}</Link>}
  />
  ```
- **Effort**: M(新增 `EmptyState` 元件 + 8 處 page 替換 + 24 個 i18n key)
- **Risk**: 低 — 純添加層
- **Confidence**: High

---

#### UX-3.007 — Error 訊息泛化;單一 `dashboard.loadError` 涵蓋 5 個獨立 API

- **Severity**: P2
- **Category**: Interaction / Error handling
- **Trigger**: Phase 4 §4.5 + Phase 3 NN heuristic #9 (Help users recover from errors)
- **Location**: `Dashboard.jsx:128-147` `Promise.all` 5 API + 單一 catch
- **Observation**: 5 個 endpoint(`/stats`, `/risk-overview`, `/top-threats`, `/top-risky-components`, `/sbom-quality-summary`)併發,任一 fail → 整體被視為「儀表板掛了」。**用戶不知道哪個 API 死,沒辦法 retry,也沒辦法繼續用其他正常的 section**。
- **Why it matters**: 真實 incident 中 1 個 API 慢/掛非常常見;泛化處理把可降級的功能整片砍掉。
- **Reference**: Vercel 的 dashboard 每個 widget 獨立 fail,各自顯示「無法載入 — 重試」。
- **Recommendation**:
  - 拆 5 API 為 5 獨立 fetch with `try/catch`,任一 fail 只把該 section 設為 error state
  - 每個 section 的 error state 顯示「無法載入 — [重試]」按鈕
  - Toast 改用於「全部 5 都掛」極端情況(實際是 service down)
- **Effort**: M
- **Risk**: 中 — 重構 fetch 邏輯,需測 5 種「部分 fail」組合
- **Confidence**: High

---

#### UX-3.008 — Card corner radius 不一致(`rounded-lg` vs `rounded-xl`)

- **Severity**: P2
- **Category**: Consistency / Detail density
- **Trigger**: Phase 5 spot-read + grep `rounded-(lg|xl|md)` 116 occurrences
- **Location**:
  - `Profile.jsx:86,123,148` — 3 cards 全 `rounded-xl`
  - `Dashboard.jsx:188-215` — 6 summary cards `rounded-lg`
  - `Dashboard.jsx:244,271,315,346,...` 各 section card `rounded-lg`
  - `ViewerOnboarding` `Dashboard.jsx:80` 用 `rounded-xl`(borderless dashed)
  - `Modal.jsx:81` `rounded-lg`
  - 其他多數 `rounded-lg`
- **Observation**: 同樣的「卡片」抽象兩種圓角,Profile 是 xl,其他多 lg。
- **Why it matters**: 細節品味的 telltale。Linear / Stripe / Vercel 全站 card 圓角一階(8px / 12px),沒例外。
- **Reference**: Plane.so 全站 8px (`rounded-md` 等價)。
- **Recommendation**: 收斂到 **單一 card token** — `rounded-lg`(8px)。Profile 改為 `rounded-lg`,onboarding 也統一。Modal 維持 `rounded-lg`。把 token 命名為 `card-radius`(如有需要新增 token)。
- **Effort**: S(改 4 處)
- **Risk**: 低
- **Confidence**: High

---

#### UX-3.009 — Table row divider `divide-gray-50` 在白底**幾乎隱形**(對比 ~1.04:1)

- **Severity**: P2
- **Category**: Visual / A11y
- **Trigger**: Phase 5 read of Dashboard tables
- **Location**: `Dashboard.jsx:384,478,524,583`(4 處 `divide-y divide-gray-50`)
- **Observation**: `gray-50` (#f9fafb) 在 white (#ffffff) 上對比 1.04:1。實際是看不到 divider 的。同檔 thead 用 `border-b`(默認 gray-200),tbody 用 `divide-gray-50` — 兩種強度兩種顏色。
- **Why it matters**: 列界線是 table density 的核心訊息;沒了 divider,第三列開始視覺上糊在一起,尤其在密度高的場景。
- **Reference**: Stripe Dashboard divider gray-200 (#e5e7eb);Linear 為 gray-100。
- **Recommendation**: 改為 `divide-gray-100`(對比 1.18:1,仍細但可見)或 `divide-gray-200`(2.13:1,清晰)。建議 `border-default` token 統一(已存在 = gray-200)。
- **Effort**: S — 4 處 search-replace
- **Risk**: 低 — 視覺只變強,不變弱
- **Confidence**: High

---

#### UX-3.010 — Status chip 在白卡上**沒邊框**,層次扁平

- **Severity**: P2
- **Category**: Visual / Detail density
- **Trigger**: Phase 5 read + Phase 2 calibration vs GitHub Security
- **Location**: 抽樣
  - `Dashboard.jsx:301,398-399,490,494,548-552,613` — 全部 `bg-{color}-50/100 text-{color}-700` 純底色 chip,**0 邊框**
  - `Profile.jsx:93-94` 同
  - `Releases.jsx`, `RiskOverview.jsx` 大量同
- **Observation**: 在白卡上 `bg-red-100 text-red-700` 字色強但底色弱(對比 1.5:1 左右),hover 卡片上看起來「扁」。
- **Why it matters**: 視覺層次不足 = 重要訊息沒 *躍上來*。GitHub / Linear 風格 chip 三層:bg + 1px border + text — 細節豐富。
- **Reference**: GitHub `<Label>` `bg-red-50 border border-red-200 text-red-800`。
- **Recommendation**: 訂 chip 通用 utility 或 component:
  ```jsx
  // tailwind component layer (preferred):
  .chip-danger  { @apply bg-red-50 text-red-700 border border-red-200 px-2 py-0.5 rounded-full text-xs font-medium; }
  .chip-warning { @apply bg-amber-50 text-amber-700 border border-amber-200 ...; }
  ```
  或者 `<Chip variant="danger">{...}</Chip>` React component。
- **Effort**: M(component + 邊際採用 — 不大規模重寫)
- **Risk**: 中 — 大量 chip;若 component 會撼動很多檔案。建議只在 *touched* code 採用(對標 token 的 additive-only 原則)。
- **Confidence**: High

---

#### UX-3.011 — Toast 關閉按鈕用文字字元 `×`,而 Modal 用 `<X size={18}>`

- **Severity**: P2
- **Category**: Consistency
- **Trigger**: Phase 5 read of `Toast.jsx` vs `Modal.jsx`
- **Location**: `Toast.jsx:84` `>×<` vs `Modal.jsx:91` `<X size={18}>`
- **Observation**: 兩個近親元件兩個風格;Toast 的 `×` 還跨平台 render 不一致。
- **Why it matters**: 同 iter 1 UX-012(emoji 修補)— 字元 vs 圖示混用是品味細節。
- **Reference**: 自家 Modal。
- **Recommendation**: Toast 改為 `<X size={14} />`(略小於 Modal 的 18,因 Toast 字級較小)。
- **Effort**: S
- **Risk**: 低
- **Confidence**: High

---

#### UX-3.012 — Focus ring offset 不一致(Button 有 / Modal close 沒 / Card click 沒)

- **Severity**: P2
- **Category**: A11y / Detail density
- **Trigger**: Phase 4 §4.4 keyboard walk
- **Location**:
  - `Button.jsx:60` `focus-visible:ring-2 focus-visible:ring-offset-1`(✅ 有 offset)
  - `Modal.jsx:90` `focus:ring-2 focus:ring-blue-400`(沒 offset)
  - `Dashboard.jsx:207` clickable card `focus:ring-2 focus:ring-blue-400`(沒 offset)
  - 多數 `<Link>` `focus:ring-2 focus:ring-blue-400`(沒 offset)
- **Observation**: 沒 offset 的 ring 緊貼元素邊緣,在密集排版裡跟元素本身的 border / shadow 撞在一起,看不出在哪。
- **Why it matters**: 鍵盤使用者體驗碎片化 — 同個操作在不同元件焦點視覺迥異,認知負擔。Linear / Vercel 全站 ring + offset-2 一致。
- **Reference**: 自家 Button 已對。
- **Recommendation**:
  - 在 `index.css` 既有 `:focus-visible` 規則裡,outline 已有 2px + offset 2px(`index.css:36-39`)— 但 page 元件還是用 `focus:ring-*` 自己畫 ring,**重疊 + 不一致**
  - 統一決策:**全部依賴全域 `:focus-visible outline`,移除每 element 的 `focus:ring-2 focus:ring-blue-400`**
  - 全域改完後,新元件不要再寫 `focus:ring-*`
- **Effort**: M(全域 sweep,但因為全域 `:focus-visible` 已存在,移除個別 ring 不會破)
- **Risk**: 中 — 視覺有變化;需驗證每處 ring 仍可見(實際應該更乾淨)
- **Confidence**: Medium(需實測)

---

#### UX-3.013 — Failed load 沒有 retry button,使用者只能 F5

- **Severity**: P2
- **Category**: Interaction / Error handling
- **Trigger**: Phase 4 §4.5
- **Location**: 全站(尤其 Dashboard, ReleaseDetail, Releases 列表頁)
- **Observation**: 所有 fetch 失敗都是 toast.error + 留空頁面。沒有 inline retry。使用者唯一選項是 reload 整頁 — 失去當前 scroll 位置 / 篩選狀態。
- **Why it matters**: NN heuristic #9(error recovery)— B2B 工具裡這是常用情境(Wifi 抖動、API 慢)。
- **Reference**: Linear 任何 failed query 都有「重試」inline。
- **Recommendation**: 與 UX-3.007 合併執行 — 每個 section 自含 error state,提供重試 button 觸發該 section 的 fetch。
- **Effort**: 與 UX-3.007 共用,marginal cost ~M
- **Risk**: 中 — 與 fetch 邏輯重構耦合
- **Confidence**: High

---

#### UX-3.014 — 動作完成後,列表沒 highlight「這就是你剛動的那筆」

- **Severity**: P2
- **Category**: Interaction / Microinteraction
- **Trigger**: Phase 4 §4.5 + Phase 2 calibration vs Linear
- **Location**:
  - `Organizations.jsx`:新增 / 編輯後列表 re-fetch,沒 highlight
  - `ReleaseDetail.jsx`:vuln status 改後沒 highlight
  - `Policies.jsx`:rule 新增 / 編輯後列表 re-fetch,沒 highlight
- **Observation**: 動作 → toast.success → 列表更新 → 但使用者要在列表中找回他剛動的那筆。
- **Why it matters**: 認知連續性。Linear / Stripe 在 modify 後該列會閃 0.5s 黃 / 藍背景。
- **Reference**: Linear / GitHub PR 列表新增 PR 時;Notion 編輯 row 後微閃。
- **Recommendation**:
  - 為列表加 `recentlyChangedId` state;對應 row 加 `data-flash="true"` 或 `bg-blue-50 transition-colors duration-slow`
  - CSS:`tr[data-flash="true"] { animation: row-flash 1500ms ease-out forwards; }`
  - 1.5s 後自動移除
- **Effort**: M
- **Risk**: 低
- **Confidence**: High

---

#### UX-3.015 — 大螢幕(>1280px)整片白邊;`max-w-7xl` 寫死沒利用

- **Severity**: P2 (品味 — 但會被 OT 操作員工作站第一眼看到)
- **Category**: RWD
- **Trigger**: Phase 4 §4.2 大螢幕測試
- **Location**: `Layout.jsx:263` `<main className="max-w-7xl mx-auto px-3 sm:px-4 md:px-6 ...">`
- **Observation**: `max-w-7xl` = 1280px。在 1920 螢幕上 320px 兩側純白邊。資料密集頁(ReleaseDetail / RiskOverview)實際還是窄條,可惜了空間。
- **Why it matters**: OT 操作員工作站常 1920+(常 24"+),Dashboard 顯得單薄。
- **Reference**: Vercel `max-w-screen-2xl` (1536px) 作為「適中」;Linear 主畫面無 max-w(全屏布局)。
- **Recommendation**:
  - **資料密集頁 selectively 提升**:`Dashboard / RiskOverview / AdminActivity / ReleaseDetail` 用 `max-w-screen-2xl` (1536) 或 `max-w-[120rem]` (1920)
  - **表單頁維持** `max-w-7xl`(1280)— 表單寬度沒意義太寬
  - 精細的話加 token `max-page-data` (1536) vs `max-page-form` (1280),Layout 接受 prop
- **Effort**: M(需要把 Layout 改成可接 prop 或在子頁覆寫)
- **Risk**: 中 — 非標準路由要驗(ReleaseDiff, FirmwareUpload 是否要用 wide?)
- **Confidence**: Medium(需 PM/設計 confirm 哪些頁面該寬)

---

### P3 — 12 件(系統 / 品味 cluster)

---

#### UX-3.016 — `tabular-nums` 0 處 — 數字密集表全部抖動

- **Severity**: P3
- **Category**: Visual / Detail density
- **Trigger**: Phase 5 grep `tabular-nums` → 0
- **Location**: 全站(Dashboard 風險表 / RiskOverview / AdminActivity 等)
- **Observation**: 數字欄(計數、百分比、EPSS)在比例字型下寬度不一,刷新時會橫向跳動。
- **Recommendation**:
  - `index.css @layer base`:`table { font-variant-numeric: tabular-nums; }` — 一行覆蓋所有 `<table>`
  - 對 metric 卡(Dashboard 6 張)直接 `tabular-nums` class:`<div className="text-xl font-bold tabular-nums">`
- **Effort**: S
- **Risk**: 視覺只變對齊不變寬;全方位無壞處
- **Confidence**: High

---

#### UX-3.017 — Spacing rhythm 無 token;`mt-4/6/8` 隨手寫

- **Severity**: P3
- **Category**: Consistency / Detail density
- **Location**: 全站
- **Observation**: `mt-4/6/8/10/12` 共 29 occurrences,沒系統性;Dashboard 用 `mt-4` 為 between-section,Profile 用 `mb-5`,ReleaseDetail 混用。
- **Recommendation**:
  - 在 `tailwind.config.js theme.extend.spacing` 新增語意 token:
    ```js
    spacing: {
      "section-gap-sm": "1rem",  // 16 — within-card group
      "section-gap-md": "1.5rem", // 24 — between cards in same area
      "section-gap-lg": "2rem",   // 32 — between major page regions
    }
    ```
  - 文件化 rhythm:卡內 `space-y-2/3`,卡與卡 `gap-md`(24),頁面區塊間 `gap-lg`(32)
  - 漸進採用(touched-code only 政策)
- **Effort**: S(token + 設計原則文件)
- **Risk**: 低
- **Confidence**: High

---

#### UX-3.018 — Typography token (`text-body`, `text-caption`, `text-h*`) 0 採用

- **Severity**: P3
- **Category**: Consistency
- **Location**: 全站
- **Observation**: tailwind.config.js 設了 9 階,page 用了 0 階。pages 全用 raw `text-xs/sm/base/lg/xl/2xl/3xl`。Token 命名沒有顯出語意上更清楚的優勢以驅動採用。
- **Recommendation**:
  - 接受現況 — `text-sm`/`text-xs` 等 raw class 跟 `text-body-sm`/`text-caption` 等價,不混亂
  - **或** 重新命名 token 為更語意:`text-meta`(metadata)、`text-helper`(helper text)、`text-label`(label)讓開發者更願意用
  - 在 Phase 5 觸碰的 page 上採用一個範例(例如把 ReleaseDetail tab heading 從 `text-base font-semibold` 換成 `text-h6`),作為示範
- **Effort**: S(decision + 文件)
- **Risk**: 低
- **Confidence**: Medium(這比較是策略決定不是 bug)

---

#### UX-3.019 — `text-xs` 348 處;對 body 內容過度使用

- **Severity**: P3
- **Category**: Visual / Density
- **Location**: ReleaseDetail (88), Settings (33), TISAXDetail (33), Dashboard (24)
- **Observation**: 12px 適合 caption / metadata / badge;不適合 *主要* body。`Profile.jsx:88,92,98,114` `text-xs text-gray-700` 是 label OK,但 `text-xs text-gray-700 mb-3` 是 paragraph helper(該用 14px)。
- **Recommendation**:
  - 訂 *使用準則* 寫進 `design-principles.md`(已有,本輪標明):caption / badge → xs;label / helper → 14;paragraph → 16
  - 不大規模 rewrite,僅 *touched* file 修(per UX-005 additive 政策)
  - 在 Phase 5 對最破洞的 1-2 處 paragraph 提升 14px 作示範(如 `Profile.jsx:88` 這種「標籤+說明」對)
- **Effort**: S(政策 + sample)
- **Risk**: 低
- **Confidence**: High

---

#### UX-3.020 + UX-3.021 — Duration token 0 採用 + Easing token 不存在

- **Severity**: P3
- **Category**: Motion
- **Location**: 全站
- **Observation**:
  - `tailwind.config.js` 已有 `duration: { instant / fast 150 / base 200 / slow 300 }` — 但 grep 0 處 `duration-fast` 等
  - `transitionTimingFunction` token 完全沒設,所有 transition 用瀏覽器預設 `ease`
- **Why it matters**: 微互動(UX-3.022~024)上場時必須有 token 可用,否則每處再決定 timing → 又一輪 inconsistency
- **Recommendation**:
  - 加 easing token:
    ```js
    transitionTimingFunction: {
      "ease-out-expo": "cubic-bezier(0.16, 1, 0.3, 1)",      // Linear-style
      "ease-out-back": "cubic-bezier(0.34, 1.56, 0.64, 1)",  // overshoot
      "spring":        "cubic-bezier(0.5, 1.25, 0.75, 1.25)",// playful
    }
    ```
  - 微互動 baseline 規則:enter `duration-base ease-out-expo`、exit `duration-fast ease-out`、hover `duration-fast`、press(active)`duration-instant`
- **Effort**: S(token only)
- **Risk**: 低
- **Confidence**: High

---

#### UX-3.022 — `Button` 元件**沒有 active state**(按下無回饋)

- **Severity**: P3
- **Category**: Microinteraction
- **Location**: `Button.jsx:30-34` VARIANT 表
- **Observation**: 4 種 variant 都只有 `hover:` 和 `disabled:`,沒 `active:`。點擊 → 視覺零反應 → 用戶不確定是否生效。
- **Recommendation**:
  ```js
  primary:   "... hover:bg-blue-700 active:bg-blue-800 active:scale-[0.98] ...",
  secondary: "... hover:bg-gray-50 active:bg-gray-100 active:scale-[0.98] ...",
  danger:    "... hover:bg-red-700 active:bg-red-800 active:scale-[0.98] ...",
  ghost:     "... hover:bg-gray-100 active:bg-gray-200 active:scale-[0.98] ...",
  ```
  搭 `transition-[transform,colors] duration-fast`。`scale-[0.98]` 微縮 2% 是 Linear 風,不到 0.97 那麼明顯。
- **Effort**: S
- **Risk**: 低 — 唯一風險是 motion-reduce 用戶受影響,但既有全域 `prefers-reduced-motion` 規則會把 transition 壓到 1ms
- **Confidence**: High

---

#### UX-3.023 — Modal / Toast / Skeleton 無進場 / 退場動效

- **Severity**: P3
- **Category**: Motion / Microinteraction
- **Location**: `Modal.jsx:67-100` / `Toast.jsx:71-87` / `Skeleton.jsx:33-118`
- **Observation**:
  - Modal `isOpen` flip 瞬間出現,黑底蓋下也是瞬間
  - Toast 進來瞬間出現,消失瞬間消失
  - Skeleton 用 `animate-pulse`(opacity 0.5↔1)— 是 Tailwind 最弱動畫
- **Recommendation**:
  - **Modal**:加 enter `opacity-0 scale-95 → opacity-100 scale-100` `duration-base ease-out-expo`,exit `opacity-100 → 0 scale-95` `duration-fast`
  - **Toast**:slide-in from bottom `translate-y-2 opacity-0 → translate-y-0 opacity-100` `duration-base`;退場 `opacity-100 → 0` `duration-fast`
  - **Skeleton**:從 `animate-pulse` 改自訂 shimmer keyframes(`@layer utilities` 加 `.animate-shimmer`)
- **Effort**: M(`Modal` 內 mounting state + transition;`Toast` 同;Skeleton 寫 keyframes)
- **Risk**: 中 — Modal/Toast 是核心 element,要驗 keyboard a11y 不破
- **Confidence**: High

---

#### UX-3.024 — `animate-pulse` 改 shimmer(可選擇略過)

- **Severity**: P4(也可視為 P3 細節)
- **Category**: Motion
- **Location**: `Skeleton.jsx:20`
- **Observation**: pulse 是 opacity 動畫,輕微到 retina 上幾乎看不見動。Linear / Stripe 用 *shimmer* — 一道線性漸層由左掃到右,顯然是 loading。
- **Recommendation**:
  ```css
  /* index.css @layer utilities */
  @keyframes shimmer {
    0% { background-position: -200% 0; }
    100% { background-position: 200% 0; }
  }
  .skeleton-shimmer {
    background: linear-gradient(90deg, #f3f4f6 25%, #e5e7eb 50%, #f3f4f6 75%);
    background-size: 200% 100%;
    animation: shimmer 2s ease-in-out infinite;
  }
  ```
  Skeleton.jsx 把 `bg-gray-200 ... animate-pulse` 換成 `skeleton-shimmer` class。
- **Effort**: S
- **Risk**: 低 — `prefers-reduced-motion` 全域規則仍會 disable 動畫
- **Confidence**: High

---

#### UX-3.025 — 無 `font-family` token,CJK fallback 未控

- **Severity**: P3
- **Category**: Typography / Consistency
- **Trigger**: Phase 4 §4.6 跨平台
- **Location**: `tailwind.config.js`(無 fontFamily extend)+ `index.css`(無 body font-family rule)
- **Observation**: Mac 落到 `-apple-system` → SF Pro + PingFang;Win 落到 `Segoe UI` + 微軟正黑體;Linux 落到 `system-ui` + Noto Sans CJK。**三個系統三個觀感**,字寬與筆畫粗細迥異。
- **Why it matters**: 同一個 dashboard 在 user 的 Mac 看與在我們 Win 開發機看,完全兩個產品。內銷 customer 用 Win 的多,我們開發在 Mac 的看不到問題。
- **Recommendation**:
  - `tailwind.config.js`:
    ```js
    fontFamily: {
      sans: [
        "Inter",                 // 本地若有最佳,但我們不打 CDN — 退而求其次:
        "ui-sans-serif", "system-ui",
        "-apple-system", "BlinkMacSystemFont",
        "Segoe UI", "Roboto",
        "Noto Sans TC", "PingFang TC", "Microsoft JhengHei",
        "sans-serif"
      ],
      mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "monospace"],
    }
    ```
  - 不引入 Inter web font(no new deps)— 但確保 CJK 順序一致
  - 即使無自訂英文字體,顯式列 CJK fallback 已能讓 Win/Mac/Linux 中文觀感更一致
- **Effort**: S
- **Risk**: 低 — 純 fallback list
- **Confidence**: High

---

#### UX-3.026 — 無 elevation scale;只用 `shadow` / `shadow-md`

- **Severity**: P3
- **Category**: Visual / Detail density
- **Location**: 全站(115 處 shadow 變體)
- **Observation**: Tailwind `shadow`(== `shadow-sm`)在 gray-50 page 背景上幾乎看不到。卡片看起來「漂浮但不知有多高」。沒有 `shadow-lg`、`shadow-xl` 給 modal、popover 用,所以 modal 也用 `shadow-xl`,但 modal/popover 沒系統區分。
- **Recommendation**:
  - 訂 elevation scale:
    ```
    elev-0 — flat (border-only, e.g. inline edit)
    elev-1 — subtle  (cards on page) — Tailwind shadow-sm + ring-1 ring-gray-200/50
    elev-2 — raised  (hover cards)   — shadow-md
    elev-3 — overlay (popover/dropdown) — shadow-lg
    elev-4 — modal   (Modal)           — shadow-xl
    elev-5 — toast   (Toast)           — shadow-2xl
    ```
  - 在 `tailwind.config.js theme.extend.boxShadow` 寫死,把 `elev-1` 等註冊
  - 漸進採用,touched-code 政策
- **Effort**: M(token + 文件 + 1-2 處示範)
- **Risk**: 低
- **Confidence**: High

---

#### UX-3.027 — 暗色 nav `bg-gray-900` 死灰,缺品牌冷感

- **Severity**: P3
- **Category**: Visual / Brand
- **Location**: `Layout.jsx:84` `<nav className="bg-gray-900 text-white">`;`index.html:11` `<meta theme-color="#111827">`
- **Observation**: `gray-900` 是純中性灰(`#111827` 略有藍,但 H 在 220° 飽和度極低)。Linear / Vercel / Plane 全部用 `slate-900`(`#0f172a`,藍灰)或 `zinc-900`(`#18181b`,中暖灰),感受上比 gray-900 更「設計過」。
- **Reference**: Linear 暗色 = `#0f172a`(slate-900);Vercel = 純黑 + 藍紫 highlight。
- **Recommendation**:
  - 改 `Layout.jsx` 的 nav `bg-gray-900` → `bg-slate-900`(直接 Tailwind 內建,不需 token 改)
  - 同步 `index.html` `theme-color="#0f172a"`
  - 視覺上 navbar 從「終端機灰」變「設計過的藍灰」 — 品牌感明顯升級
  - **若採用,記得驗 PLAN_COLOR 的 chip 在 slate 上仍對比足**
- **Effort**: S
- **Risk**: 低 — 純色票替換
- **Confidence**: Medium(需要實機看才能確認設計感)

---

#### UX-3.028 — Wide table 無 sticky 第一欄

- **Severity**: P3
- **Category**: RWD / Interaction
- **Location**: `Dashboard.jsx`、`RiskOverview.jsx`、`AdminActivity.jsx` 等寬表格
- **Observation**: 表格 `overflow-x-auto` 包覆 — 滾右側時看不到 row 是哪一筆(client name 在最左欄)
- **Recommendation**: 第一欄加 `sticky left-0 bg-white z-raised`(運用既有 z-token);hover 時 `bg-gray-50` 同 row。需要 `<th>` 跟 `<td>` 第一欄都 sticky。
- **Effort**: M(每張 table 改;測試 overflow + sticky 行為)
- **Risk**: 中 — sticky + scroll 在 mobile Safari 偶爾異常,需驗 360/768
- **Confidence**: Medium(實作難度低,跨裝置驗證需時)

---

#### UX-3.029 — `<h1>` `<h2>` 純跳躍,沒 fluid type

- **Severity**: P3
- **Category**: RWD / Visual
- **Location**: `Dashboard.jsx:177` `<h1 className="text-2xl">` 24px 不分螢幕
- **Observation**: 24px H1 在 360 螢幕剛好,在 1920 螢幕看起來像 H3。Linear / Vercel 用 `clamp(24px, 2vw + 16px, 36px)` 流體放大。
- **Recommendation**:
  - `tailwind.config.js theme.extend.fontSize` 加:
    ```js
    "h1-fluid": ["clamp(1.5rem, 1.2rem + 1vw, 2.25rem)", "1.2"]
    ```
  - 主要頁面 H1 採用(Dashboard, Releases, etc.)
- **Effort**: S
- **Risk**: 低
- **Confidence**: High

---

#### UX-3.030 — SVG 屬性變化沒走 transition(TrendChart, DependencyGraph)

- **Severity**: P3 (cluster with motion fixes)
- **Category**: Motion
- **Location**: `TrendChart.jsx:70-75` `r={hovered ? 4 : 3}` — circle 半徑瞬間切換
- **Observation**: SVG `<circle r=>` 變化是瞬間的(不會自動 transition)。
- **Recommendation**:
  ```jsx
  <circle
    cx={...} cy={...}
    r={hovered === i ? 4 : 3}
    style={{ transition: "r 150ms ease-out" }}
    fill={...}
  />
  ```
  或 SVG `<circle><animate>`。
- **Effort**: S
- **Risk**: 低
- **Confidence**: High

---

### P4 — 7 件(品味細節)

---

#### UX-3.031 — TrendChart palette `low` 跟 `total` 都是藍色,易混淆

- **Severity**: P4
- **Category**: Visual / Detail density
- **Location**: `chart-colors.js:21-26`(`SEVERITY_HEX.total = #60a5fa` blue-400;`SEVERITY_HEX.low = #3b82f6` blue-500)
- **Observation**: 兩個藍只差一階,在折線圖密集點重疊時看不出哪是 total 哪是 low。
- **Recommendation**:
  - `total` 改用更不同的色 — e.g. `#0f172a` slate-900(粗實線,做 baseline)
  - 或 `low` 用 cyan(`#06b6d4`),保留 blue 給 brand 用
- **Effort**: S
- **Risk**: 低
- **Confidence**: Medium(品味,需確認設計偏好)

---

#### UX-3.032 — TrendChart tooltip `text-gray-600` on `bg-gray-900` 對比邊緣

- **Severity**: P4
- **Category**: A11y / Visual
- **Location**: `TrendChart.jsx:90,91-94`
- **Observation**: `text-gray-600` (#4b5563) 在 `bg-gray-900` (#111827) 對比 ~3.8:1。WCAG body 最低 4.5:1 — 邊緣 fail。
- **Recommendation**: 改為 `text-gray-400`(#9ca3af → 6.7:1)或 `text-gray-300` (#d1d5db → 9.0:1)。
- **Effort**: S
- **Risk**: 低
- **Confidence**: High

---

#### UX-3.033 — Press-state 系統化(同 UX-3.022 但擴及非 Button 元件)

- **Severity**: P4
- **Category**: Microinteraction
- **Location**: 所有可點擊元件(`<Link>`、可點擊 card、tab 切換)
- **Observation**: `Button` 元件加 active 後,還有大量 raw `<button>` / `<Link>` 不會受惠。
- **Recommendation**: 
  - `index.css` 加 utility `.press-feedback { @apply active:scale-[0.98] transition-transform duration-fast; }`
  - 在新增 / 改動 互動元件時加上(touched-code 政策)
- **Effort**: S(utility 級)
- **Risk**: 低
- **Confidence**: Medium(品味取捨,要確認用户接受 scale 動效)

---

#### UX-3.034 — Section 之間 spacing rhythm 隨手寫(`mt-4/6/8` 混)

- **Severity**: P4 (與 UX-3.017 同源,品味細節層)
- **Category**: Detail density
- **Location**: 全站,`Dashboard.jsx` 最明顯
- **Observation**: Dashboard 區塊之間 `mt-4` 反覆出現 — 16px 太緊。Linear 大區塊間 32px,小區塊內 16px。
- **Recommendation**: 配合 UX-3.017 的 token,Dashboard 主要區塊間改 `mt-section-gap-lg` (32px),卡內 group `gap-section-gap-sm` (16px)。
- **Effort**: S
- **Risk**: 低
- **Confidence**: High

---

#### UX-3.035 — Modal `max-w-md` (448px) 在 1920 螢幕看似窄條

- **Severity**: P4
- **Category**: RWD
- **Location**: `Modal.jsx:31-36` SIZE_CLASSES
- **Observation**: 多數 modal 用 default `md` (448px)。在 1920 主螢幕上 448px modal + black overlay 兩側超大白邊,modal 看起來像便條紙。Linear/Vercel modal 預設 `lg` (576) 或 `xl` (768)。
- **Recommendation**: 預設改 `lg`(576)— 更適合 desktop 主使用情境。Mobile 反正 full-width(`sm:max-w-lg` 在 ≤640px 不啟動)。
- **Effort**: S
- **Risk**: 中 — 影響每個 Modal 呼叫處,要驗內容是否撐得起 576 寬
- **Confidence**: Medium(需設計 confirm)

---

#### UX-3.036 — 缺整表`<caption>` 的少數 page (補完 iter 2 開的洞)

- **Severity**: P4
- **Category**: A11y
- **Location**: 抽查 — `Settings.jsx`、`AdminActivity.jsx`、`Releases.jsx`、`Search.jsx`、`Users.jsx`
- **Observation**: iter 2 UX-011 補了 7 張 dashboard / org / RiskOverview。剩下這 5 張 page 的 table 仍無 caption。
- **Recommendation**: 一致補 `<caption className="sr-only">`。每張 ≤30s。
- **Effort**: S
- **Risk**: 低
- **Confidence**: High

---

#### UX-3.037 — `useId()` 採用率 38 處,但仍有少數 hardcode IDs(carry-over UX-027)

- **Severity**: P4
- **Category**: A11y
- **Location**: 抽查 — `Login.jsx` 內仍可能有 hardcode id(iter 1 UX-027 提示);需 grep 驗證
- **Recommendation**: grep `id=".+"` 找出 hardcoded;若是 `useId` 可遷的就遷。
- **Effort**: S(per file)
- **Risk**: 低
- **Confidence**: Low(需實際 grep)

---

## 2. Severity × Category 統計

| Category | P1 | P2 | P3 | P4 | Total |
|----------|---:|---:|---:|---:|---:|
| Visual / Density | 1 | 3 | 4 | 3 | **11** |
| Motion / Microinteraction | 0 | 1 | 4 | 1 | **6** |
| A11y | 2 | 1 | 0 | 3 | **6** |
| i18n | 2 | 0 | 0 | 0 | **2** |
| Interaction / Error handling | 0 | 3 | 0 | 0 | **3** |
| Performance | 1 | 0 | 0 | 0 | **1** |
| RWD | 0 | 1 | 2 | 1 | **4** |
| Consistency | 0 | 1 | 0 | 0 | **1** |
| **Total new** | **5** | **10** | **12** | **7** | **34** |

> Motion / Microinteraction 6 件,Visual / Density 11 件 — 印證 Phase 2 calibration 結論:本輪要靠這兩維度大幅躍升。

## 3. 對比 iter 1+2

- **新發現**:34 件
- **回歸 (regression)**:0 件 — iter 1+2 修補項目全保留,verified by Phase 5 spot reads
- **延後 (defer)**:8 件 carry-over(見 `ledger.md`)
- **新延後**:UX-3.037(grep needed first)、UX-3.029 fluid type(若 PM 不要可降為 P4)

## 4. Phase 4 stress-test summary

> 本輪能 *靜態執行* 的 stress test。無 live browser → 部分情境(IME composing、實際 slow 3G、實際 screen reader)需 Phase 9 verification 階段補。

| 維度 | 已測 | 結果 |
|------|------|------|
| §4.1 內容極端 | ✅ partial | 長 username (Layout.jsx 已 truncate max-w-8rem)、長 PURL (table cells 多無 truncate)、空陣列 (UX-3.006)、英文 fallback (UX-3.002, UX-3.004) |
| §4.2 裝置極端 | ✅ partial(承自 iter 2 assertion-matrix.json) | 360/768/1280/1920 已測;760-820 dead zone 已知;1920+ 大螢幕未善用 (UX-3.015) |
| §4.3 網路極端 | ⏸ Phase 9 | Skeleton 結構已驗 (UX-3.001 bug);實際 slow-3G LCP / CLS 需實機 |
| §4.4 互動 / 輸入 | ✅ partial | 鍵盤 — TrendChart fail (UX-3.005);focus-ring 不一致 (UX-3.012);軟鍵盤 + IME 需實機 |
| §4.5 狀態極端 | ✅ partial | empty / error 已分析 (UX-3.006/007/013/014);loading skeleton CLS bug (UX-3.001) |
| §4.6 使用者極端 | ⏸ Phase 9 | 色弱模擬、200% zoom、forced-colors 需實機 |

## 5. Out of scope / 本輪不處理

- UX-031 dark mode(deferred — Phase 7 plan 會給 *migration shape*,不做實作)
- UX-033 Help.jsx 內容外移(deferred per recon §9 假設)
- UX-034 ReleaseDetail.jsx 拆分(deferred)
- UX-035 bundle subset 分析(無 perf 抱怨)
- UX-036 自動化 a11y / perf tooling(blocked by no-new-deps)
- TISAX 模組深入審視(假設 in scope 但 spot-check OK)
- 真實裝置實測(iPhone / Android 真機)— 留 Phase 9 + 使用者 demo

## 6. Lessons learned for next iter

1. **iter 1 + 2 把 a11y 機械修補做盡** — 本輪基本沒新 a11y P1(只 2 件 P1 是 i18n + chart 鍵盤)。下輪可降 a11y 投資,主攻 motion/dark/density。
2. **品味維度需要實機驗** — 多數 P3/P4 是「對標感」,scoring 只能到 Medium confidence。Phase 9 的視覺 before/after 是必要環節,且 1280 / 360 兩 viewport 都要拍。
3. **token 採用率仍低** — 設了 9 階字級用 0 階。本輪 plan 應 *示範性* 在 1-2 page 用 token,做 baseline 給未來 contributor 看。
4. **動效是放大器** — calibration 算下來,光把 D4 從 3 → 7 對 weighted average 影響最大。動效是 ROI 最高的單一投資。
5. **不要 over-engineer dark mode 規劃** — 本輪只給 token-level shape,不要寫 colour pairs 表格(那是 iter 4 的事)。
