---
phase: 2
iteration: 3
audit_id: ui-audit-iteration-3
created: 2026-04-28
---

# Phase 2 — World-Class Reference Calibration

> 不在「誰比較好看」上花時間 — 對標的目的是把品味缺口「物件化」,讓 Phase 5/6 可以指認並修。
> 評分基準:**1–3 抵不到入門**, **4–6 能用**, **7–8 體面**, **9 對標頂尖**, **10 重新定義領域**。

## 1. 對標產品池(挑 5 個有理由)

| 產品 | 為何選它 | 哪一維度它最強 |
|------|---------|---------------|
| **Linear** | 同類 B2B SaaS,密度與品味的黃金標準 | 資訊密度節奏、微互動、動效曲線 |
| **Stripe Dashboard** | 金融級表格 + 數字精度,跟我們漏洞表很像 | 字體系統、表格密度、tabular 數字 |
| **Vercel Dashboard** | Motion-forward + dark mode native + 部署感 | 動效、暗色模式、空狀態文案 |
| **Plane.so** | 開源 Tailwind dashboard,同 stack,**最誠實的可達距離** | 系統一致性、token 紀律 |
| **GitHub Security tab / Dependabot** | 唯一功能對標(漏洞 + SBOM + advisory) | 色彩語意層次、嚴重度視覺、空/錯狀態 |

> 為何不選 Apple HIG / Material:它們是 OS 規範不是 dashboard 範例;我們 web B2B,直接對標 web B2B。
> 為何不選 Notion / Figma:它們是內容工具,不是密集 dashboard,密度/層次目標不同。

---

## 2. 八維度逐項對比

### D1. 資訊密度與留白節奏

> Linear 的 issue list 一頁能擠 50 列同時不擁擠;Stripe Dashboard payment list 同樣。
> 關鍵:**節奏**(行高 32–40px 規律)、**清晰邊界**(分隔線細到剛好可見)、**留白成為層次**(group 之間 24/32/48 階梯)。

**現況評分:5 / 10** ┃ **對標目標:9 / 10**

證據:
- `mt-4` `mt-6` `mt-8` 出現 29 處,**沒有規律** — `Dashboard.jsx` 每個 section 都用 `mt-4`(16px)、`Profile.jsx` cards 之間用 `mb-5`(20px)、`ReleaseDetail.jsx` 各區塊混用 `mt-3/4/6/8`。沒有「8 → 16 → 24 → 32」階梯感,看起來是隨手寫的。
- 表格 row padding 不一:`Dashboard.jsx:483 py-3` vs `Dashboard.jsx:535 py-2.5` vs `Dashboard.jsx:589 py-2.5` — 三個表格在同一頁三種高度。
- Cards 預設 `p-5`(20px)— 但 modal 內表單 `p-5 sm:p-6`,inline edit form `px-3 py-2`。多種 padding 並存,沒有 token 級規則。
- 欠缺 *負空間紀律*:Section heading `mb-3/4/6` 都看過,沒明確選擇。Linear 標題到內容固定 16px(對應 `mb-4`)。

差距關鍵:
1. 沒有 spacing rhythm token(`section-gap`、`card-pad`、`row-pad`)
2. 既有 raw Tailwind 數值滲透,看起來工程師決定的不是設計師決定的
3. Group 之間缺「呼吸點」— Dashboard 6 卡片直接接 5 區塊,沒有 sectional 分隔

→ Phase 6 候選 **UX-3.{rhythm}** 系列

---

### D2. 字體系統與排版細節

> Stripe Dashboard 字體階層只有 5 階(11px metadata / 13px body / 14px label / 16px H3 / 20px H1),但每階都有用途。
> Linear 全站只用 Inter + tabular-nums + ligatures off。
> 我們 token system 設了 9 階,實際只用了其中 3 階。

**現況評分:4 / 10** ┃ **對標目標:9 / 10**

證據:
- Token system 有 `caption / body-sm / body / h1-h6` 9 階,但**幾乎沒被使用** — 0 處 `text-body`、0 處 `text-caption`(實測 Phase 1)。pages 全用 `text-xs/sm/base` 三階。
- `text-xs` 358 處 / 28 檔 = 全站平均 12 處 — 過度依賴。`ReleaseDetail.jsx` 88 處,`Settings.jsx` 33 處,`TISAXDetail.jsx` 33 處。其中很多是 *body 內容*,不是 caption。
- `tabular-nums` **0 處**。`riskOverview` 表格的「總漏洞 / 未修 Critical / 未修 High / 修補率 / 風險評分」5 列數字完全不對齊 — 數字一刷新就跳。對於漏洞 dashboard 這是實際痛點。
- `font-medium` / `font-semibold` / `font-bold` 三階混用沒原則。`Dashboard.jsx` H2 `font-semibold`,卡片數字 `font-bold`,表格 row `font-medium` 都看到。
- 預設字體完全 Tailwind default — `system-ui, -apple-system, BlinkMacSystemFont, ...`。沒指定 font-family。這在 Mac/Win/Linux 之間呈現差異很大,**特別是中文 fallback 完全不可控**(Mac 落到 PingFang、Win 落到 Microsoft JhengHei、Linux 落到 Noto Sans CJK,字寬與筆畫粗細迥異)。
- TrendChart 內 SVG text fontSize="7.5" / "8" — 7.5px **低於可讀閾值**,即使 retina 也吃力。

差距關鍵:
1. Token 設了不用,等於沒設
2. `text-xs` body 化 — Refactoring UI 直指的反模式
3. 沒 tabular-nums = 數字密集表格永遠看起來不專業
4. 字體 fallback 沒控制 = 兩台機器看起來像兩個產品

→ Phase 6 候選 **UX-3.{type-system}** 系列、**UX-3.tabular-nums**、**UX-3.font-stack**

---

### D3. 色彩與層次

> GitHub Security tab 的嚴重度 chip 是設計過的:不只是紅橘黃藍綠;暗色背景、亮色文字、邊框微對比,容器色降到 8% saturation。
> Vercel 的中性灰階是 9 階且每階都有用途。

**現況評分:6 / 10** ┃ **對標目標:9 / 10**

證據:
- Token 中性色相對完整(`fg-default/muted/subtle/disabled/on-inverse`),但 surface 只有 4 個(card/muted/inverse/page) — 沒有 elevation 層次概念。
- Severity 色碼 OK — `chart-colors.js` 有 SEVERITY_HEX 統一管;但 page 內 chip 顏色用 `bg-red-100 text-red-700` 直接 raw,**沒對應到 token 的 `danger`**。即 `chart-colors` 跟 page chips 是兩套色彩,未來要改 brand 同時要改兩處。
- 暗色 navbar(`bg-gray-900` = `#111827`)是死灰,沒微藍微暖偏 — 讀起來像終端機。Linear/Vercel/Plane 全部走「冷藍灰」(slate-900 / zinc-900 + a touch of blue),感受截然不同。
- Card 預設 `shadow`(== `shadow-sm` 的 Tailwind alias)— 在 `gray-50` page 背景上**幾乎看不到** — 這是 Tailwind 的固有問題,需要寫死或自訂 elevation。
- Hover 升起:`hover:shadow-md` 只在 Dashboard 6 卡 + Organizations 列表用。多數可點擊區域沒 hover elevation 變化。
- Status chip:`bg-red-50` / `bg-orange-50` / `bg-yellow-50` 等等。**沒邊框** = 在白底卡片內看起來像漏色。GitHub 風格會加 1px `border-{color}-200` 增強可讀性。
- `text-gray-300` 在白底是裝飾線/分隔線等同色,但 *也用作 placeholder dash*(`Dashboard.jsx:600 <span className="text-gray-300">—</span>`)— 在 a11y 上勉強過(裝飾性),但視覺上意思混亂(這橫線到底是「沒資料」還是「分隔」?)。

差距關鍵:
1. 沒有 elevation scale(0/1/2/3/4 = flat / subtle / raised / overlay / modal)
2. Chip 系統沒邊框,在 hover 卡片上層次不足
3. 暗色 nav 太死灰,缺品牌冷感
4. `chart-colors` 與 `bg-red-100` 兩套色系未統一

→ Phase 6 候選 **UX-3.elevation**、**UX-3.chip-border**、**UX-3.nav-cool-tint**

---

### D4. 微互動 (micro-interactions)

> Linear 的 button 按下會 *微縮 0.97× 約 80ms*,放開回彈 spring。Vercel 的下拉選單從 trigger 點 *origin-top-right scale-95 → 100*。Stripe 的 row hover 是 12ms `colors`,*非常快但有*。
> 這是「設計團隊在線」的 telltale。

**現況評分:3 / 10** ┃ **對標目標:9 / 10**

證據:
- **`active:` 只 8 處 / 4 檔** — 整個產品幾乎沒有「按下回饋」。`Button` 元件本身也沒 `active:` 狀態(只有 hover/focus-visible/disabled)— 點擊瞬間沒視覺反應。
- Toast 進出場 **完全沒動畫** — 直接 pop 出來、直接消失(`Toast.jsx:71-87`)。Linear/Stripe slide + fade。
- Modal 進場 **完全沒動畫** — `isOpen=true` 一開瞬間滿屏(`Modal.jsx:67`)。Vercel scale 95 → 100 + opacity 0 → 1 約 150ms。
- Skeleton 用 `animate-pulse`(opacity 0.5 ↔ 1)— 是 Tailwind 預設的最弱動畫;Linear/Stripe 用 *shimmer*(從左到右掃過的線性漸層),感知度高很多。
- Table row hover 只有 `hover:bg-gray-50`(150ms 預設),沒有額外 indicator(左 border?icon 出現?)。
- Button 元件用 `transition-colors`(只有 colors 過渡),hover 時不會有任何位移、scale、ring expansion — 跟死的一樣。
- Dependency Graph SVG node hover 沒任何回饋(`DependencyGraph.jsx`)— pointer 變 cursor 但圖形不動。
- Tab 切換 `setTab("vulns")` 是瞬間切換,沒有 layout transition / fade。

差距關鍵:
1. 沒有 active state 系統 — `Button` 元件本身就缺
2. Modal / Toast / Skeleton 三大 surface 全部無動畫
3. 沒有 spring easing token(只有 ease)— 不感覺自然
4. Skeleton-to-content swap 是 hard cut

→ Phase 6 候選 **UX-3.button-active**、**UX-3.modal-enter**、**UX-3.toast-motion**、**UX-3.skeleton-shimmer**

---

### D5. 動效曲線 (motion)

> 頂尖產品的 easing 不是 Tailwind 預設 `ease`(== cubic-bezier(0.4, 0, 0.2, 1))。Linear 用 `cubic-bezier(0.16, 1, 0.3, 1)` (出場 ease-out);Vercel 用 `cubic-bezier(0.4, 0, 0.2, 1)` 但 200ms。Apple Spring 是 stiffness/damping。
> **時長**:hover 80–150ms,enter 200–300ms,exit 150–200ms。

**現況評分:4 / 10** ┃ **對標目標:8 / 10**

證據:
- Token 有 `instant/fast 150 / base 200 / slow 300` — 合理,但**沒被使用** — 0 處 `duration-fast` / `duration-base`。pages 全用 Tailwind 預設 `transition-colors`(150ms,不可控)。
- Easing 完全沒 token — `tailwind.config.js theme.extend` 沒 `transitionTimingFunction`。所有 transition 用瀏覽器預設 `ease`。
- 沒有「進場 / 退場」差別 — 同個元素 enter 和 exit 用同曲線。
- TrendChart hover 切換 dot 大小 (`r={hovered ? 4 : 3}`) — 但 SVG circle 屬性變化沒在 transition 範圍 → 瞬間跳。
- `transition-all` 出現過 — 危險(會 transition layout 屬性,可能 reflow)。需 audit 哪幾處。

差距關鍵:
1. Token 設了不用
2. 沒有 easing token,品味曲線無從統一
3. 進/退場曲線一致 — 違背物理直覺(出場應該更快)
4. SVG 屬性變化沒 transition

→ Phase 6 候選 **UX-3.duration-token-adopt**、**UX-3.easing-token**、**UX-3.svg-transition**

---

### D6. 空 / 錯 / 載入狀態

> Linear 的空 issue 列表會說「沒有 issue 在你的篩選下 — 試試清除篩選 / 看看 Backlog」+ button。
> Stripe Dashboard 沒有交易時會有插畫 + 引導語 + 文件連結。
> GitHub Dependabot 沒漏洞時會說「沒漏洞 — 上次掃描 5 分鐘前 — 設定通知」。

**現況評分:5 / 10** ┃ **對標目標:9 / 10**

證據(各狀態抽樣):

**Loading**:
- `Skeleton` 元件齊全,但 `SkeletonStatCards` 預設 `count=4`(`Skeleton.jsx:45`),**Dashboard 實際是 6 卡** — 進場時 skeleton 4 卡 → 真實 6 卡 = layout shift。
- `Skeleton.jsx:47 grid-cols-${count}` — Tailwind purge 殺動態類名,實際運行時 `grid-cols-6` 可能根本沒生成 → skeleton 排版錯。**這是隱性 bug**。
- `SkeletonInline` (`ReleaseDetail.jsx:8` 用)是泛用骨架,沒對映實際內容形狀 → swap 時必 jump。

**Empty**:
- `Dashboard.jsx:236-238 — "目前無漏洞"`,單行,沒下一步引導。
- `Dashboard.jsx:464 — "暫無高 EPSS 漏洞"`,單行。
- `Dashboard.jsx:368 — "未找到符合的 CVE"`,單行,沒「再試其他 CVE / 看 KEV 列表」之類引導。
- `ReleaseDetail.jsx` 多處無 component / vuln 時直接渲染空 `<table>` — 用戶看到表頭沒列。
- 有用心的:`ViewerOnboarding`(`Dashboard.jsx:70-110`)— 三步引導,**這是好的範本**。

**Error**:
- `Dashboard.jsx:144 toast.error(t("dashboard.loadError", "儀表板資料載入失敗,請重新整理頁面"))` — 整個 Dashboard 共用一個錯誤訊息,看不出哪個 endpoint 死了(api/stats、api/stats/risk-overview、api/stats/top-threats、api/stats/top-risky-components、api/stats/sbom-quality-summary 五個併發 API 任一掛全部視為「儀表板掛了」)。
- `ReleaseDetail.jsx:126,138,148,201` — 4 個 toast.error 寫死 zh 字面("元件清單載入失敗" / "漏洞清單載入失敗" / "版本資料載入失敗" / "驗證失敗") **完全沒 i18n**。
- 沒有 error 區分 401 / 403 / 404 / 500 / network — 全部 toast `操作失敗`。
- 沒有「重試」button — 用戶要刷新整頁。
- 沒有 error boundary。

**Success**:
- Toast success 用 3.5s,合理。
- 但是,新增 / 修改 / 刪除這類動作完成後,**列表沒有 highlight 該列**(Linear 會閃爍 0.5s 表示「這就是你剛動的」),也沒有 inline confirm icon。

差距關鍵:
1. Skeleton 形狀不對 → 進場 jump
2. 空狀態多為「沒資料」一行,缺引導
3. Error 訊息泛化,缺重試與類型區分
4. 動作完成後沒 highlight 回饋
5. ReleaseDetail i18n 漏洞 = 英文使用者看到 "元件清單載入失敗"

→ Phase 6 候選 **UX-3.skeleton-shape**、**UX-3.empty-with-action**、**UX-3.error-typed**、**UX-3.action-feedback**、**UX-3.releasedetail-i18n**

---

### D7. 細節密度 (detail density / 視覺紀律)

> Linear 的 button corner radius 全站 6px。Stripe 全站 4px。Vercel 全站 6/8 兩階(button/card)。
> 我們:`rounded` `rounded-md` `rounded-lg` `rounded-xl` `rounded-full` 五階混用,沒原則。

**現況評分:5 / 10** ┃ **對標目標:9 / 10**

證據:
- `rounded` 系列無紀律 — `Profile.jsx` cards 用 `rounded-xl`(`:86, :123, :148`),`Dashboard.jsx` cards 用 `rounded-lg` (`:188-215`),`Toast` items 用 `rounded-lg`,`Login.jsx` 預期 `rounded`(較舊),`Modal` 用 `rounded-lg`。**同樣的「卡片」三種圓角**。
- Border 紀律不一 — Profile 用 `border border-gray-200`,Dashboard 直接用 `shadow` 無 border。Linear 全站 1px border + subtle shadow 雙層。
- Divider 細緻度:表格 `divide-y divide-gray-50` — gray-50 在白底**幾乎看不見**(對比 1.04:1)。應為 gray-100 或 gray-200。`Dashboard.jsx:384` 用 `border-b` 之類,但 row 之間用 `divide-y divide-gray-50` — 兩種寫法。
- Icon 一致性:hampered by `🔒` 和 `⌕` 已經 Iter 1 修了,但 `Toast.jsx:84 ×` 是文字字元(不是 lucide `<X>`)— 跟 `Modal.jsx:91 <X size={18}>` 不一致。
- focus-ring 厚度 `ring-2`(2px)全站一致,**但** offset 不一致:`Button.jsx` `ring-offset-1`,`Modal.jsx close button` 沒 offset,`Dashboard.jsx` clickable card 沒 offset。Linear 全站 ring-2 + offset-2 + bg-current。
- Number 對齊全站 `text-center`,但有時數字 `tabular-nums` 應該存在但沒(D2)。

差距關鍵:
1. Card radius 三套(lg / xl)
2. Divider 用 gray-50(看不見)
3. Toast `×` 不是 lucide
4. Focus ring offset 不統一
5. Border 用法 split(有些 shadow-only 有些 border-only 有些雙層)

→ Phase 6 候選 **UX-3.radius-rule**、**UX-3.divider-visible**、**UX-3.toast-x-icon**、**UX-3.ring-offset**、**UX-3.card-edge**

---

### D8. 響應式優雅度

> Linear 在 320px 寬度仍可閱讀 issue list(關鍵欄會折疊但不破版)。Vercel 在 1920+ 用 `max-w-screen-2xl` 與 grid 自適應,不留死白。
> 響應式不是 "mobile + desktop two states",是 *光譜*。

**現況評分:6 / 10** ┃ **對標目標:8 / 10**

證據(自 iter 2 已大幅改善,但仍有缺):
- `max-w-7xl`(1280px)鎖死 — 1920+ 螢幕 320px 兩側留白,**沒做事**。Linear / Vercel 在 wide screen 會放更多欄、或讓表格擴展。
- 表格在 1280–1920 之間沒利用空間 — `xl:` `2xl:` 斷點 4 / 0 處(iter 1 量化)。
- 768px 是已知 dead zone(iter 2 verification.md 已記錄)— 11 link nav + search + user 在 800px 寬度撐爆。
- 表格 `overflow-x-auto` 包覆是 OK 解,但**沒有 sticky 第一欄** — 滾右側時看不出是哪一筆。
- `text-xs` 在 mobile 下 12px(iOS 自動 16px 例外只對 input)— 小螢幕讀體驗差。
- Modal `sm:max-w-md` 等對應的 max-width 是 mobile-first,但 modal 內表單在 desktop 沒善用空間(`max-w-md` = 448px,在 1920 螢幕看像窄條)。
- 圖片 / 圖示沒有 `srcset` — 但實際只有 favicon 是圖片,基本不適用。
- 沒有 fluid typography(`clamp(...)`)— 標題 `text-2xl` `text-3xl` 純跳躍。
- Container query 0 處 — 但這需要 Tailwind 3.5+,我們在 3.4。

差距關鍵:
1. 大螢幕沒善用(>1280 純兩側白)
2. 表格沒 sticky 第一欄
3. 768 dead zone 已知未補
4. 沒 fluid type

→ Phase 6 候選 **UX-3.wide-screen**、**UX-3.sticky-first-col**、**UX-3.fluid-type-h1**

---

## 3. 加權總分

| Dim | 現況 | 目標 | 缺口 | 影響權重 |
|-----|:----:|:----:|:---:|:-------:|
| D1 密度節奏 | 5 | 9 | -4 | 高 |
| D2 字體系統 | 4 | 9 | -5 | 極高 |
| D3 色彩層次 | 6 | 9 | -3 | 中 |
| D4 微互動 | 3 | 9 | -6 | 高 |
| D5 動效曲線 | 4 | 8 | -4 | 中 |
| D6 狀態品質 | 5 | 9 | -4 | 高 |
| D7 細節紀律 | 5 | 9 | -4 | 中 |
| D8 響應式 | 6 | 8 | -2 | 低(已大幅補) |
| **加權平均** | **4.7** | **8.7** | **-4.0** | — |

> 加權方式:極高×3 / 高×2 / 中×1.5 / 低×1。
> 結論:**現況約 「能用 + 邊緣體面」**,要躍升到「對標頂尖」最大投資點按優先序是:
> 1. **D2 字體系統**(影響極高、缺口最大、修補 mostly mechanical)
> 2. **D4 微互動**(幾乎沒做,起步 ROI 巨大)
> 3. **D1 密度節奏 / D6 狀態品質**(中度修補,顯著感受提升)
> 4. **D3 色彩層次 / D7 細節紀律**(refactor 相對侷限)
> 5. **D5 動效曲線**(以 D4 為前提才有意義)
> 6. **D8 響應式**(已 iter 2 大改,本輪低投資)

---

## 4. 對標指引(進 Phase 5/6 用)

每當 Phase 5 / 6 寫 finding 時,回頭問:
- 「Linear 會怎麼處理這個 row hover?」 → 12ms `colors` + 1px left border indicator(可能)
- 「Stripe 會怎麼擺這欄數字?」 → tabular-nums + right-aligned + monospace 不需要
- 「Vercel 會怎麼設這 modal 進場?」 → scale-95 → 100 + fade 200ms ease-out
- 「GitHub Security 會怎麼設這 chip?」 → bg-red-50 + border-red-200 + text-red-800
- 「Plane 會怎麼整這 token?」 → 全部 design system 驅動,無 raw hex

我會把這「對標思考」內嵌到每個 P1/P2 finding 的 `Reference:` 欄位。
