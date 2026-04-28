---
phase: 7
iteration: 3
audit_id: ui-audit-iteration-3
based_on_commit: 6f0f018
created: 2026-04-28
status: awaiting user "go"
---

# Phase 7 — Implementation Plan

> 等你說「go」(或 "go A"/"go A+B" 等部分 wave)我才進 Phase 8。
> 整 plan 含 35 件 finding,但**建議單次迭代不要全做** — 見 §3 Recommended scope。

## 0. Wave 結構

| Wave | 主題 | 件數 | 估時 | Taste 增益 | 必要性 |
|------|------|----:|----:|:--------:|------|
| **A** | Token 基礎(blocks 後續所有 motion/visual 工作) | 4 | 30 min | +0.3 | **必做** |
| **B** | P1 must-fix(資料正確性 / a11y 紅燈 / i18n 漏洞) | 5 | 60 min | +0.5 | **必做** |
| **C** | Microinteraction 升級(本輪 ROI 最高) | 5 | 90 min | +1.0 | 強烈建議 |
| **D** | Visual layer 細節 | 8 | 60 min | +0.5 | 建議 |
| **E** | Information / state quality | 4 | 60 min | +0.3 | 選擇性 |
| **F** | P4 mop-up | 4 | 30 min | +0.1 | 看時間 |
| **共** | | **30** | **5h30m** | **+2.6** | |

> Tier 1 = A+B(9 件,~90 min)= 立刻能修,沒爭議
> Tier 2 = +C+D(22 件,~3h30m)= 視覺與微互動雙升級
> Tier 3 = +E+F(30 件,~5h30m)= 全面到位

> 若你只給「半個工作天」(4h),建議 Tier 2(共 22 件)。
> 若給「整天」(7-8h),做 Tier 3 + Phase 9 verification。

---

## 1. Wave 細目

### Wave A — Token 基礎(必做,blocks 後續)

每個一個 commit;commit message `feat(ui): [UX-3.0NN] xxx`。

| Order | ID | 動作 | Effort | Risk | 註 |
|---:|------|------|:--:|:--:|------|
| A1 | UX-3.020+021 | `tailwind.config.js` 加 `transitionTimingFunction: { ease-out-expo, ease-out-back, spring }`(durations 已有) | S | 低 | 純 token 加法,沒有舊行為改變 |
| A2 | UX-3.025 | `tailwind.config.js theme.extend.fontFamily.sans` 加 CJK fallback list;`index.css body { font-family: theme('fontFamily.sans'); }` | S | 低 | 不引入新字體 |
| A3 | UX-3.017 | `theme.extend.spacing` 加 `section-gap-{sm,md,lg}` semantic spacing | S | 低 | 純加 token,不改既有 |
| A4 | UX-3.026 | `theme.extend.boxShadow` 加 elevation 6 階(`elev-0`~`elev-5`) | S | 低 | 純加 token |

**Wave A 結果**:全是新 token,**沒有任何 page 改動**。寫完 `npm run build` 應 0 diff(token 加但沒用是 OK 的)。

---

### Wave B — P1 must-fix(必做)

| Order | ID | 動作 | Effort | Risk | 註 |
|---:|------|------|:--:|:--:|------|
| B1 | UX-3.001 | `Skeleton.jsx`: `SkeletonStatCards` 改 `layout` enum + 顯式 class branches;`Dashboard.jsx:163` 傳 `layout={6}` | S | 低 | 隱性 bug,實機 visible 改善 |
| B2 | UX-3.002 | `ReleaseDetail.jsx` + `FirmwareUpload.jsx` 9 處 toast.error 改 `t("...")`;STATUS_LABEL 改 `t()` 函式;JUSTIFICATION/RESPONSE_OPTIONS 移到 component 內 useMemo + `t()`;補 `i18n/zh.js` + `en.js` 約 25 個 key | M | 低 | 純文字,但 key 多 |
| B3 | UX-3.003 + UX-3.030 + UX-3.032 | `TrendChart.jsx`: SVG `<text>` X 軸 fontSize 11 + truncate 改 12 字、Y tick fontSize 10、tooltip `text-gray-300`(取代 gray-600 對比 fail);`<circle>` 加 `style={{ transition: 'r 150ms ease-out' }}` | S | 中 | layout 微調,需驗 5+ 版本時不擠 |
| B4 | UX-3.004 | `Dashboard.jsx:574-580` 7 個 thead 加 `t("dashboard.riskCol.*")`;補 i18n key | S | 低 | |
| B5 | UX-3.005 | `TrendChart.jsx`: 每 `<g>` 資料點加 `tabIndex="0"` + `role="img"` + `aria-label` + `onFocus/onBlur`;新增 `<details>` summary fallback table | M | 低 | 純 a11y 加強 |

**Wave B 結果**:5 個 visible 改善;首頁/趨勢圖/版本詳情/英文模式 體感升級。

---

### Wave C — Microinteraction(強烈建議,本輪 ROI 最高)

依賴 Wave A 的 easing/duration tokens。

| Order | ID | 動作 | Effort | Risk | 註 |
|---:|------|------|:--:|:--:|------|
| C1 | UX-3.022 + UX-3.033 | `Button.jsx` VARIANT 4 種加 `active:bg-{color}-{darker}` + `active:scale-[0.98]`;`transition-[transform,colors] duration-fast`;新增 `index.css .press-feedback` utility | S | 低 | `prefers-reduced-motion` 全域已壓 1ms,無 motion side-effect |
| C2 | UX-3.023a Modal | `Modal.jsx`: 用 unmount delay + transition class — `enter: opacity-0 scale-95 → opacity-100 scale-100` `duration-base ease-out-expo`,`exit: opacity-100 scale-100 → opacity-0 scale-95` `duration-fast ease-out`;backdrop fade 同步 | M | 中 | Modal 是核心 — 必須驗 focus trap 仍正常、Esc 仍 work |
| C3 | UX-3.023b Toast | `Toast.jsx`: 進場 `translate-y-2 opacity-0 → translate-y-0 opacity-100` `duration-base`;退場 `opacity-0` `duration-fast` | S | 低 | ToastProvider 已有 list management,只加 `<Transition>` 層或 CSS class |
| C4 | UX-3.024 | `index.css @layer utilities`:加 `@keyframes shimmer` + `.skeleton-shimmer`;`Skeleton.jsx:20` `bg-gray-200 animate-pulse` → `skeleton-shimmer` | S | 低 | `prefers-reduced-motion` 仍在 scope |
| C5 | UX-3.022 (Button) verify | 順手把 `Login.jsx`/`Profile.jsx` 等已用 `Button` 元件的 page 在實機看 active 是否舒適;若不舒適微調 `scale-[0.97]`/`[0.99]` | S | 低 | 純 visual 觀察 |

**Wave C 結果**:Modal 進出有靈魂、Toast 滑進來、Button 按下會「撳」、Skeleton shimmer。
**Phase 2 D4 評分預期 3 → 7。**

---

### Wave D — Visual layer 細節(建議)

| Order | ID | 動作 | Effort | Risk | 註 |
|---:|------|------|:--:|:--:|------|
| D1 | UX-3.008 | `Profile.jsx` 3 處 `rounded-xl` → `rounded-lg`;`Dashboard.jsx ViewerOnboarding rounded-xl` → `rounded-lg`;統一 `rounded-lg` | S | 低 | |
| D2 | UX-3.009 | `Dashboard.jsx` 4 處 `divide-gray-50` → `divide-gray-100` | S | 低 | |
| D3 | UX-3.011 | `Toast.jsx:84` `>×<` → `<X size={14} aria-hidden="true" />`;import 自 `lucide-react` | S | 低 | |
| D4 | UX-3.016 | `index.css @layer base`:`table { font-variant-numeric: tabular-nums; }`;Dashboard 6 metric 卡 `<div className="text-xl font-bold tabular-nums">` | S | 低 | 一行 base CSS 影響全站表格 |
| D5 | UX-3.012 | sweep `focus:ring-2 focus:ring-blue-400` → 移除(全域 `:focus-visible` outline 已蓋);保留 `focus-visible:ring-*` 風格(`Button` 已對) | M | 中 | 每處需手測;若有疑問先記到 followups,不批量改 |
| D6 ❓ | UX-3.027 | `Layout.jsx:84` `bg-gray-900` → `bg-slate-900`;`index.html theme-color #0f172a` | S | 低 | **需要你確認**;若不要保留現狀 |
| D7 ❓ | UX-3.029 | `tailwind.config.js fontSize` 加 `h1-fluid`;`Dashboard.jsx`/`Releases.jsx`/`RiskOverview.jsx` H1 改用 | S | 低 | **需要你確認**;若不要可降為 P4 留 iter 4 |
| D8 | UX-3.010 | 在 `index.css @layer components` 加 `.chip-{danger,warning,success,info,brand}`;**只在 Dashboard / RiskOverview 內**改 3-5 個關鍵 chip 作示範,其他保留(touched-code 政策) | M | 中 | 若大規模改 risk 高 — 嚴格 scope |

**Wave D 結果**:細節品味顯著升級,色彩層次更專業。

---

### Wave E — Information / state quality(選擇性)

| Order | ID | 動作 | Effort | Risk | 註 |
|---:|------|------|:--:|:--:|------|
| E1 | UX-3.006 | 新增 `components/EmptyState.jsx`(icon + title + desc + action props);**只在 Dashboard 3 處 + ReleaseDetail 1 處 substitute**(touched-code) | M | 低 | 元件 + i18n key 約 12 個 |
| E2 | UX-3.007 + UX-3.013 | `Dashboard.jsx` 5 個 API fetch 拆 5 個獨立 try/catch + 各自 sectionError state + retry button;Toast 改用於「全 5 都 fail」極端 | M | 中 | 重構 fetch 邏輯;測「部分 fail」3 種組合 |
| E3 | UX-3.014 | `Organizations.jsx` + `Policies.jsx` 加 `recentlyChangedId` state + row 加 `data-flash` + CSS keyframe(`row-flash 1500ms`) | M | 低 | 純前端 state |
| E4 | UX-3.015 + UX-3.028 | `Layout.jsx` 加 `wide` prop;`RiskOverview.jsx` 設 `<Layout wide>`;wide 模式 `max-w-screen-2xl`;同時 `RiskOverview.jsx` 表格第一欄 `sticky left-0 bg-white z-raised` | M | 中 | 實機驗 360 mobile 仍可橫滾 |

**Wave E 結果**:dashboard 部分掛掉時不會「整個壞掉」,空狀態有引導,大螢幕有用。

---

### Wave F — P4 mop-up(看時間)

| Order | ID | 動作 | Effort | Risk |
|---:|------|------|:--:|:--:|
| F1 | UX-3.031 | `chart-colors.js` `low` 從 `#3b82f6` → `#06b6d4` (cyan-500),解決 total/low 同色 | S | 低 |
| F2 | UX-3.034 | `Dashboard.jsx` 主要區塊間 spacing 用 Wave A 的 `mt-section-gap-lg` 取代散裝 `mt-4` | S | 低 |
| F3 ❓ | UX-3.035 | `Modal.jsx SIZE_CLASSES.md` 改 `sm:max-w-lg` 作預設 | S | 中 — 需 confirm |
| F4 | UX-3.036 | `Settings.jsx`/`AdminActivity.jsx`/`Releases.jsx`/`Search.jsx`/`Users.jsx` 的 5 張 table 各加 1 行 `<caption className="sr-only">` | S | 低 |

---

## 2. 排序與依賴圖

```
A1 (easing tokens) ─────────┐
A2 (font-family)            │
A3 (spacing tokens)         ├─→  C1 (Button active) ──┐
A4 (elevation tokens)       │    C2 (Modal motion)    │
                            │    C3 (Toast motion)    ├─→  Wave D 細節
                            │    C4 (Skeleton shimmer)│
                            └─→  D7 (fluid type)      │
B1 (Skeleton bug) ──────────────────────────────────→ │
B2 (i18n holes) ────────────────────────────────────→ │
B3 (TrendChart text + transitions) ─────────────────→ │
B4 (Dashboard thead i18n) ──────────────────────────→ │
B5 (TrendChart keyboard a11y) ──────────────────────→ │
                                                     ↓
                                                 Wave E (state quality)
                                                     ↓
                                                 Wave F (mop-up)
                                                     ↓
                                                 Phase 9 verification
```

**硬依賴**:Wave A 必須先完(C1-C4 / D7 用到 token)
**軟依賴**:B5 a11y 改完後 D4 tabular-nums 才會看到效果(數字穩 + tooltip 對比)

---

## 3. Recommended scope(建議)

我的建議是 **Tier 2(Wave A + B + C + D,共 22 件,~3h30m)**:

**為什麼不全做(34 件)**:
- E + F 屬於「品質提升」,但 Wave A-D 完成後,主觀體感升幅已達瓶頸
- E2(per-section error state)是真實 refactor 風險,獨立一輪做更穩
- 全做完不留時間 verification,違背 protocol "Phase 9 必做"
- iter 1+2 的 lessons learned 都指向「批次小、commit 小、驗證細」

**為什麼不只做 Tier 1(A+B,9 件)**:
- 沒有 Wave C 微互動,從體感 4.7 升到 5.5,**升不到「明顯專業」**
- Wave C 是本輪 ROI 最高的單一投資(D4 維度 3→7,加權影響極大)
- 不補 Wave C 等於這一輪沒踩到品味躍升點

**Tier 2 包含**:
- Wave A:4 件(全 token,30 min)
- Wave B:5 件(P1 修補,60 min)
- Wave C:5 件(微互動,90 min)
- Wave D:8 件(細節,60 min — 含 ❓ 兩件待你決定)
- 共 22 件,~3h30m

**Tier 2 預期結果**:
- Phase 2 加權 taste 評分:**4.7 → 6.5**(+1.8)
- 視覺體感:從「看起來 OK」到「看起來像 2024-2026 級 SaaS」
- a11y / i18n / RWD 已 iter 2 修盡 — 本輪沒退步,小幅補強

---

## 4. 待你確認的不確定點(❓ 標記)

我會把答案寫進 plan.md `final` 區塊,然後執行。

| ID | 決定點 | 預設(不答則用) |
|----|------|----------------|
| ❓ UX-3.027 | 暗色 nav 改 `slate-900`、`zinc-900`、保留 `gray-900`?| **改 `slate-900`**(對標 Linear);若不喜歡可隨時 revert |
| ❓ UX-3.029 | H1 fluid type 這輪做嗎? | **做**(影響 4 個主要頁面,1 commit) |
| ❓ UX-3.035 | Modal default 改 `lg`(576px)還是保留 `md`(448px)? | **保留 `md`** — 改 lg 影響每個 modal callsite 風險高 |
| ❓ UX-3.018 | typography token rename / 接受現況 / 強推? | **接受現況**(本輪不動 token 命名;留作 iter 4 討論) |
| ❓ Wave 進場順序 | A→B→C→D→E→F 還是 B→A→C→...?| **A→B→C→D→E→F**(token 先,fix 次,微互動,細節,狀態,polish) |
| ❓ Tier 範圍 | Tier 1 / Tier 2 / Tier 3 ? | **Tier 2** |

---

## 5. Phase 8 執行規則(從 protocol 抄寫,提醒自己)

- **一次一個邏輯單位** — 不批 commit
- Commit message:`feat(ui): [UX-3.0NN] short description` 或 `fix(ui): [UX-3.0NN] ...`
- 看到順手想改 → 寫到 `.ui-audit/followups.md`,**不在這個 commit 動**
- 改動 token 或共用元件前,先列出影響面再動手
- 每完成一個 issue:對照原 finding 的 Recommendation 做 self-review,問「Linear / Stripe 會這樣做嗎?」
- 改不下去先停,寫 follow-up,進下一個

## 6. 高風險項目 / 回滾策略

| ID | 風險 | 回滾策略 |
|----|------|---------|
| C2 (Modal motion) | focus trap / Esc 互動可能被 transition 干擾 | revert 該 commit;Modal 是獨立元件,不影響其他 |
| D5 (focus ring sweep) | 移除 ring 後若全域 outline 在某些元件被 reset 沒覆蓋,焦點看不見 | 若發現,僅該元件 keep ring(以 follow-up 處理) |
| E2 (Dashboard fetch refactor) | 把 5 API 拆獨立可能引入新 bug | per-section state 用 setter 函式封裝,從 Promise.all 改 5 個 useEffect 不會難回滾;如有疑問先停在重構半路 commit |
| E4 (sticky first column) | iOS Safari `position: sticky` + `overflow-x` 偶爾異常 | 該 page 加 feature flag(prop)即可關閉 |
| D6 ❓ slate-900 nav | 設計感主觀 — 你不喜歡需要 revert | 1-line revert |
| D7 ❓ fluid H1 | 大螢幕變太大;某些 H1 實際在窄欄內(modal 標題)變形 | 限定主頁面 H1,不到處用 |

## 7. Phase 9 verification 預埋(等 Phase 8 完做)

- 為 Wave C 微互動拍 before / after screenshot(`Modal` open / `Toast` enter / `Button` press)
- 跑 Lighthouse(本機:Performance / A11y / Best Practices / SEO)before vs after
- Manual keyboard walk: Login → Dashboard → ReleaseDetail tabs → Vuln status edit → Logout
- 螢幕閱讀器(macOS VoiceOver 或 Win Narrator)spot check Dashboard + TrendChart + Modal
- assertion-matrix(若 Phase 9 有 Playwright 環境)— 重跑 iter 2 的 4 viewport probe,驗 0 regression
- 更新 ledger.md + design-principles.md(本輪新規則: easing tokens / shimmer / chip border / row flash 等)

---

## 8. Dark mode migration shape(Phase 6 lesson 5 — 不實作,只給形狀)

> 給未來 iter 4 / 5 接 baton 用,不在本輪執行。

要落地需要:

1. **CSS variables 取代 Tailwind extend.colors** — 因為 Tailwind v3 不能 runtime 切換 token。改用 `var(--surface)` 等 + `[data-theme="dark"]` 切換。
2. **Token rename**:`bg-surface`/`text-fg-default` 等 → CSS var。Phase 1 工作量 ~80% 可機械改,~20% 要視覺驗證。
3. **chart-colors.js** 要分 `LIGHT` / `DARK` 兩組 hex(SEVERITY、GRAPH 各對應 dark variant),由 `useTheme()` hook 提供。
4. **page-level component scan**:每個 page 過一次 `bg-white` `bg-gray-50` 是否該變;`text-gray-700` 等是否要 dark variant。
5. **Brand chip / status chip**:`bg-red-50` 這類 light tint chip 在 dark theme 要改 `bg-red-900/30` 反向。
6. **Charts**:axis 灰要從 `#e5e7eb` 變 `#374151`;tooltip 反向。
7. **Storybook-less drift check**:每個 page 在 dev 跑一次手動暗色切換,看有無 unexpected white block。

預估 1.5–2 週工。**不在 iter 3 範圍。**

---

## 9. 等你回應

請答覆以下其中一行(或更精細的指令):

```
go                    → Tier 2 全做(預設 ❓ 用我的預設答案)
go A                  → 只做 Wave A
go A+B                → Wave A + B(Tier 1)
go A+B+C              → +微互動(Tier 2 -D)
go all                → Tier 3 全做(包 E+F)
hold UX-3.027 / 029 / 035  → 列出哪些 ❓ 要 hold,其他用預設
```

或先問 ❓ 細節再決定。
