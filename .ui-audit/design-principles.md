# SBOM Platform — Design Principles

> 從 iteration 1–2 的審視紀錄與已實裝模式中萃取。每次迭代結尾,把本輪學到的新原則加進來。
> 這份檔案是「給未來 contributor 一頁讀完」 — 比 audit-report 短,但會老化得比 audit-report 慢。

## 1. Token-first, additive-only
- 所有顏色、字級、z-index、duration、max-width 走 `tailwind.config.js` 的 token。
- 既有 raw Tailwind utilities (`text-gray-700`, `bg-blue-600`, `z-50`) 不做大規模 search-and-replace。**新程式碼用 token;改到的程式碼順便換 token**。
- 例外:SVG 屬性 (fill/stroke) 不能吃 class — 改吃 `frontend/src/constants/chart-colors.js`。
- 不寫 inline 數值。`px-[18px]`、`text-[13px]`、hex literal 都不被允許(除 chart-colors 例外)。

## 2. Mobile-first + iOS-aware
- Tailwind 預設 mobile-first(`min-width` queries)。
- 表單 input 在 ≤640px 強制 16px(在 `index.css`,不重複寫到每個 page)。
- 導覽列在 ≤768px 走 hamburger;觸控目標 `min-h-[44px]`(Apple HIG 44pt)。
- `safe-area-inset-*` 已 wired up;新增 sticky bottom UI 時自動受惠。
- `viewport-fit=cover` 已在 index.html。

## 3. A11y is a hard constraint, not an option
- 每個 `<th>` 必須帶 `scope`(目前 100% 覆蓋,維持)。
- 每個 input 必須有 `<label>`(可 `sr-only`),用 `useId()` 配對。
- 每個 modal 用 `Modal` 元件 — 內建 focus trap + Esc + restore focus + i18n close button。
- 每個 sortable column 用 `<button>` 在 `<th>` 內,並在 `<th>` 上 `aria-sort`。
- 不用 `<tr onClick>` 做導覽 — 在 cell 內放 `<Link>`,row hover 提供視覺回饋。
- 鍵盤可達:每個互動元件 Tab 可達,Enter/Space 啟動。
- 動效尊重 `prefers-reduced-motion`(已全域禁用)。
- Focus ring 永遠在(`:focus-visible` global rule);不要 `outline-none` 不配 ring。
- 互動 `<button>` / `<a>` 一律有可訪問名稱 — 圖示按鈕 `aria-label` 必填且 i18n。

## 4. Visual hierarchy via weight + colour, not size (Refactoring UI)
- 強調用 `font-medium` / `font-semibold` + `text-fg-default`,不要把所有強調都拉成 `text-h*`。
- 灰階:body 用 `text-gray-700+`(或 `text-fg-muted`);secondary 用 `text-gray-600`(或 `text-fg-subtle`);decorative-only 才用 gray-300/400。
- `text-xs`(12px)只給 caption / badge / 表格 metadata,不給 primary body。
- 資訊密度可以高(B2B 工具),但密度必須有層次,不能扁平。

## 5. State coverage is a checklist
每個資料畫面必須處理:
- **Loading** — 用 `Skeleton*` 元件;`role="status"` + `aria-busy`。
- **Empty** — 文案要解釋「為什麼空 + 下一步該做什麼」,不只「沒有資料」。
- **Error** — 區分網路 / 權限 / 驗證錯誤;顯示在 `Toast` 或 inline,提供重試。
- **Success** — `Toast` 確認;不要靜默成功。
- **Skeleton-to-content swap** 不能 jump(避免 CLS)。

## 6. Token-driven elevation
- `shadow` (subtle) — 卡片預設。
- `shadow-md` — hover 升起。
- `shadow-xl` — modal only(透過 `Modal` 元件)。
- 沒有 `shadow-2xl` 或 inline `box-shadow`。

## 7. i18n is the default, not the patch
- 所有面向使用者文字走 `t("...")`。例外:`Help.jsx` 是內容類資料,刻意不 i18n。
- `aria-label` 也要 i18n(已 fixed `Modal.aria-label="Close"` → `t("common.close")`)。
- `<html lang>` 由 i18n `languageChanged` 自動同步;不要手動寫死。

## 8. Performance hygiene
- 動畫只用 `transform` / `opacity` / `colors`(目前 25 處 transition-* 都符合)。
- 沒有 `width` / `height` / `top` 動畫(會 reflow)。
- Skeleton 是唯一 `animate-pulse`;尊重 `motion-reduce`。
- `lazy()` + `Suspense` 包所有 route(已在 App.jsx)。

## 9. No new npm deps
- 任何「就裝個套件吧」的衝動必須先寫 ADR 或在審視中討論並等使用者同意。
- 替代方案:`lucide-react`(已在)、純 SVG、CSS。

---

## 10. Motion layer (added iter 3)
- Easing tokens:`ease-out-expo`(進場 / 通用)、`ease-out-back`(確認 overshoot)、`spring`(俏皮)。 Tailwind class form: `ease-out-expo` 等。
- Duration tokens:`duration-fast` 150ms(hover / micro)、`duration-base` 200ms(進場)、`duration-slow` 300ms(slow)。
- Modal / Toast / Skeleton 進出動效規範:
  - **Enter**: opacity 0 + transform → 1,duration-base ease-out-expo
  - **Exit**: opacity → 0,duration-fast ease-out
  - 進場比退場慢(物理直覺)
- Button active state:`active:bg-{darker} active:scale-[0.98] transition-[transform,colors] duration-fast`
- 一般可點擊元素用 `.press-feedback` utility(同效果)
- SVG 屬性變化(`r`, `cx`, `cy`)用 inline `style={{ transition: 'r 150ms cubic-bezier(...)' }}`
- 動效一律 motion-reduce 安全(`prefers-reduced-motion: reduce` 全域 1ms clamp)

## 11. State quality conventions (added iter 3)
- **Empty state**:用 `<EmptyState icon title description? action?>` — 不要寫單行 "沒有資料"
- **Loading**:`Skeleton*` + `.skeleton-shimmer`(取代 `animate-pulse`),保持 cell 數 = 真實內容 cell 數(避免 CLS)
- **Error**:Section 級 fail 用 `Promise.allSettled` + 頁面級 `partialLoadError` banner + retry button;Toast 只在「全部 fail」時觸發
- **Action 完成**:列表行加 `data-flash` / `.row-flash`(1500ms 黃→透),讓使用者「眼睛跟上」剛剛的變更

## 12. Elevation scale (added iter 3)
- `shadow-elev-0` flat(border only)
- `shadow-elev-1` 卡片預設(取代 raw `shadow`)
- `shadow-elev-2` hover 升起
- `shadow-elev-3` overlay / dropdown
- `shadow-elev-4` Modal(取代 raw `shadow-xl`)
- `shadow-elev-5` Toast(在 Modal 上)
- 不再用 `shadow-2xl`;`shadow-md` 等 Tailwind default 仍可用但新元件採用 elev-*

## 13. Spacing rhythm (added iter 3)
- 卡內 group 間距:`space-y-2/3` 或 `gap-section-sm`(16px)
- 同一區塊內卡片間距:`gap-section-md`(24px)
- 主要頁面區塊間距:`mt-section-lg`(32px)— 不用 `mt-4`
- 不要混用 `mt-3/mt-4/mt-6/mt-8` 在主要 layout — 用語意 token

## 14. Tabular numerals (added iter 3)
- 全站 `<table>` 預設 `tabular-nums`(在 `index.css @layer base`)
- 數字 metric 卡顯式加 `tabular-nums` class
- 散裝數字(badge / 內聯)在 *touched code* 加(touched-code 政策)

## 15. Chip system (added iter 3)
- `.chip-{danger,warning,success,info,brand,neutral}` utility classes
- 每個 chip 含 bg-{color}-50 + text-{color}-700 + border-{color}-200(三層,不只兩層)
- 既有 inline chip(`bg-red-100 text-red-700`)在 *touched code* 補 `border border-{color}-200`

## 16. Slate-anchored dark surfaces (added iter 3)
- 暗色 chrome (navbar) 用 `slate-*` 不用 `gray-*`(冷藍灰 vs 死灰)
- 既有 `bg-gray-900` `bg-gray-700` 等在 *navbar* 全部 → `slate-*`
- 暗色背景上的 muted text 至少 `text-slate-400`(不可 `text-gray-500/600`,對比 fail)

## 17. Font stack (added iter 3)
- `tailwind.config fontFamily.sans` 顯式列 CJK fallback (`Noto Sans TC`, `PingFang TC`, `Microsoft JhengHei`)
- `index.css body { font-family: theme('fontFamily.sans') }` 確保 fallback chain 受控
- 不引入 web font(no new deps)

## 18. Fluid H1 (added iter 3)
- 主要頁面 H1 用 `text-h1-fluid`(clamp 24→36px)
- Auth / detail 頁面 H1 維持 `text-xl`(narrower context)

---

## Open principle questions (still unresolved)

- **Dark mode**:仍 0 處 `dark:` 變體 — 規劃 shape 已寫於 plan.md §8,實作留 iter 4+
- **Density tokens**:`text-xs` 仍 ~350 處;是否新增 `text-meta` 語意 token?— 留 iter 4 設計討論
- **Focus ring system**:UX-3.012 延後,iter 4 需做 option A(global outline)或 option B(focus-visible:ring + offset)的設計選擇
