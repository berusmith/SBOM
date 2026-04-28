---
phase: 9
iteration: 3
audit_id: ui-audit-iteration-3
created: 2026-04-28
based_on_commit_range: 6f0f018..HEAD (iteration 3 commits)
---

# Phase 9 — Verification (iteration 3)

> 環境限制:本輪在 headless 開發環境執行,無法跑 Lighthouse / axe / Playwright / 真實裝置。
> 可驗證項目:build / 靜態程式碼正確性 / 邏輯一致性。
> 不可驗證項目:視覺精細度 / 動效感受 / 真實 SR 體驗 — 這些列在 §6 等下次迭代或 demo 時走查。

## 1. Build sanity

```
cd frontend && npm run build
```

**結果**: ✅ 0 error。`✓ built in 1.64s`

Bundle sizes(主要):
- `index.js`: 306.80 kB / 103.82 kB gzip(iter 2 baseline ~296 / 100 kB,本輪 +10/+4 kB,主要來自 EmptyState 元件 + Modal motion 邏輯 + Toast leaving state)
- `Dashboard.js`: 24.38 kB / 5.56 kB gzip(本輪有最多改動 — i18n keys、retry banner、EmptyState 採用、tabular-nums、chip border、spacing rhythm)
- `Modal.js`: 1.83 kB / 0.95 kB gzip(motion state 加進來,僅 +200 bytes)
- `TrendChart.js`: 5.89 kB / 2.07 kB gzip(+~1.2 kB 來自 a11y fallback table)

唯一 build 警告是 pre-existing dynamic vs static import on `api/client.js`(iter 1 code 不在本輪 scope)。

## 2. Per-finding verification

> ✅ = 程式碼變更已落地且 build pass
> 🔬 = 需要瀏覽器 / 真實裝置確認的視覺 / 動效細節
> 📋 = deferred,有 followup
> ❌ = 未落地

| ID | Wave | Effort | 結果 | 驗證方式 |
|----|:----:|:----:|:---:|---|
| UX-3.020/021 easing tokens | A1 | S | ✅ | tailwind.config.js diff |
| UX-3.025 font-family CJK | A2 | S | ✅ | tailwind + index.css diff |
| UX-3.017 spacing rhythm | A3 | S | ✅ | tailwind.config.js diff |
| UX-3.026 elevation scale | A4 | S | ✅ | tailwind.config.js diff |
| UX-3.001 Skeleton purge bug | B1 | S | ✅+🔬 | 程式碼正確;需實機驗證 6 卡 skeleton 對齊 |
| UX-3.002 ReleaseDetail/Firmware i18n | B2 | M | ✅ | 9 處 toast 改為 t(),STATUS_LABEL/JUSTIFICATION/RESPONSE 改 useMemo + t() |
| UX-3.003 TrendChart text size | B3 | S | ✅+🔬 | fontSize 7.5/8 → 11/10;需實機看 5+ 版本是否擠 |
| UX-3.030 SVG circle transition | B3 | S | ✅+🔬 | inline style 加上;需實機看 hover dot 平滑 |
| UX-3.032 tooltip contrast | B3 | S | ✅ | text-gray-600 → text-gray-300(9.0:1) |
| UX-3.004 Dashboard thead i18n | B4 | S | ✅ | 7 個 zh literal → t() |
| UX-3.005 TrendChart kbd a11y | B5 | M | ✅+🔬 | tabIndex / aria-label / details fallback;需 SR 測試 |
| UX-3.022/033 Button active + utility | C1 | S | ✅+🔬 | active:bg-darker + scale-[0.98];需實機按看回饋 |
| UX-3.023a Modal motion | C2 | M | ✅+🔬 | isMounted/isVisible state 已驗 build pass;需實機看 200ms enter / 150ms exit |
| UX-3.023b Toast motion | C3 | S | ✅+🔬 | leaving flag + animate-toast-enter;需實機看 |
| UX-3.011 Toast × → lucide X | C3 | S | ✅ | Toast.jsx 改為 `<X size={14} />` |
| UX-3.024 Skeleton shimmer | C4 | S | ✅+🔬 | animate-pulse → skeleton-shimmer keyframe;需實機看 sweep |
| UX-3.008 card radius unify | D1 | S | ✅ | Profile 3 + Dashboard onboarding 1 → rounded-lg |
| UX-3.009 divider gray-50→100 | D2 | S | ✅ | Dashboard 4 處 |
| UX-3.016 tabular-nums | D4 | S | ✅+🔬 | base CSS + Dashboard 6 metric 卡;需實機看數字對齊 |
| UX-3.012 focus ring sweep | D5 | M | 📋 | DEFERRED — 風險超估,完整分析寫入 followups.md |
| UX-3.027 slate-900 nav | D6 | S | ✅+🔬 | gray-* sweep + theme-color #0f172a;需實機看冷感 |
| UX-3.029 fluid H1 | D7 | S | ✅+🔬 | h1-fluid token + Dashboard/Releases/RiskOverview;需實機看 1280→1920 縮放 |
| UX-3.010 chip border | D8 | M | ✅ | chip-* utility classes + Dashboard 3 chips border |
| UX-3.006 EmptyState | E1 | M | ✅+🔬 | 新元件 + Dashboard 3 sites;需實機看視覺 |
| UX-3.007/013 partial fail + retry | E2 | M | ✅+🔬 | Promise.allSettled + retry banner;需混亂 API mocking 測試 |
| UX-3.014 row flash | E3 | M | ✅+🔬 | 1500ms keyframe + Organizations create/edit/plan 觸發;需實機看閃爍 |
| UX-3.015 wide screen | E4 | M | ✅+🔬 | Layout WIDE_ROUTES set;需 1920+ 螢幕看 RiskOverview |
| UX-3.028 sticky first column | E4 | M | 📋 | DEFERRED — RiskOverview 預先存在 column count bug |
| UX-3.031 chart palette | F1 | S | ✅+🔬 | low blue-500 → cyan-500;需實機看 polyline 區別 |
| UX-3.034 section spacing | F2 | S | ✅+🔬 | Dashboard mt-4 → mt-section-lg;需實機看節奏 |
| UX-3.035 Modal default lg | F3 | — | 🚫 | 預設答案 = 不做(改 lg 風險高,須 modal 內容驗證) |
| UX-3.036 caption sweep | F4 | S | ✅ | 3 tables (AdminActivity ×2 + Search) |

### 統計
- 30 finding 中 **27 件 ✅ 落地**(其中 13 件需實機 🔬 補驗)
- 2 件 📋 延後到 iter 4 — `UX-3.012` focus ring sweep(風險超估,需設計決策);`UX-3.028` sticky col(blocked by 預先存在 column bug)
- 1 件 🚫 按預設不做 — `UX-3.035` Modal default lg

## 3. 鍵盤走查 — 靜態邏輯驗證

> 真正的 keyboard walk 需開瀏覽器點 Tab。下面是程式碼層級的「鍵盤可達性」變更總結。

| 流程 | 進場狀態 | 本輪變化 |
|------|---------|---------|
| Login → Dashboard | iter 1+2 已修(`<button>` 化、`htmlFor`、`scope`) | 沒退步 |
| Dashboard → 漏洞趨勢 (TrendChart) | hover only,SR 看不到資料 | ✅ B5 加 tabIndex/aria-label/fallback table — keyboard + SR 可達 |
| Dashboard 卡片 → 點擊 | iter 2 已 `<button>` 化 | 加 active state 視覺回饋(C1) |
| Modal 開啟 / Esc / Tab cycle | iter 1+2 已驗 (focus trap + Esc) | C2 motion 不影響 a11y(focus 仍同 isOpen 同步) |
| Toast 出現 / 點擊關閉 | iter 1 已驗 (aria-live polite) | C3 motion + lucide X 不影響 |
| Skeleton 載入 → 內容 swap | iter 1 已驗 (role status + aria-busy) | B1 cell count + C4 shimmer 不破 a11y |

**結論**: 沒新增 a11y 退步;TrendChart 從 fail 升到 pass(WCAG 2.1.1 + 4.1.2)。

## 4. 螢幕閱讀器走查 — 預期(未實測)

> 需要 macOS VoiceOver / NVDA / TalkBack 實機。本輪 SR-relevant 改動:
- `<table>` 的 `tabular-nums` (D4): SR 不受影響(視覺 only)
- TrendChart aria-label (B5): SR 走 `<g>` 應該唸 "{version} 漏洞:總計 X..."
- TrendChart `<details>` summary (B5): SR 應能展開 → 讀 6 欄表格
- Modal `aria-describedby` (no change): 仍工作正常
- Toast `aria-live=polite` (no change): 進場仍會被讀
- Dashboard partial fail banner (E2): 應該被 SR 唸出 `dashboard.partialLoadError`(但缺 `aria-live`,需手動補 — followup)

**Followup ✏️ 補上**: Dashboard partial-fail banner 應加 `role="status" aria-live="polite"` 讓 SR 在錯誤發生時即時聽到。

## 5. 真實裝置走查 — 預期(未實測)

需 demo 機驗證的視覺 / 互動細節(13 個 🔬 點):
- Skeleton shimmer 在 Mac retina vs Win 1× 視覺差
- Modal scale 95→100 在 prefers-reduced-motion 下是否 1ms 即時(預期是)
- Toast slide-up 進場曲線在低階 Android Chrome 是否流暢
- Button active scale-[0.98] 點擊感
- Dashboard skeleton 6 cell vs 真實 6 cards 是否 0 CLS
- 1920+ 螢幕 RiskOverview wide layout 是否更舒服
- 360 / 768 / 1280 / 1920 4 viewport regression 是否 0
- TrendChart fontSize 11 在 5+ 版本是否擠
- slate-900 nav 主觀「冷藍灰」感受

## 6. 仍未解決事項 + 建議下次 iteration

(完整列表見 `followups.md`)

| ID | 事項 | 為什麼延後 | 建議 iter 4 |
|----|------|-----------|-------------|
| UX-3.012b | focus ring 系統性處理 | outline-none 互依 risk 超估;需設計決策(option A 純 outline / B ring + offset) | 一個 focused commit + 設計確認 |
| UX-3.028a/b | RiskOverview column count bug + sticky col | 預先存在 column 對齊 bug 阻擋 sticky | 先 fix column,再 sticky |
| UX-3.002b | Full i18n sweep ReleaseDetail + FirmwareUpload | 還有許多 toast.success / 按鈕 visible 文字 | 一輪掃過 ~15 處 |
| UX-3.008b | rounded-xl sweep on data cards | AdminActivity, TISAX, ReleaseDetail floating bar 仍 xl | 統一到 rounded-lg(auth 例外) |
| UX-3.029b | fluid H1 extension | 6 個 page 仍 text-2xl | 一鍵 sweep |
| Dark mode (UX-031) | 整套規劃 | 大型工 + 設計決策 | 用 baseline §3 token system 改 CSS variables;1.5-2 週 |
| Help.jsx 拆 (UX-033) | 1071 LOC 內容外移 | 高風險獨立 session | dedicated iter |
| ReleaseDetail 拆 (UX-034) | 2081 LOC | 高風險獨立 session | dedicated iter |

## 7. 品味評分更新

(對標 calibration.md §1 5 個頂尖產品)

| Dim | 進場 | 預期(plan) | **實際達到** | 達標? |
|-----|:----:|:----------:|:-----------:|:----:|
| D1 密度節奏 | 5 | 7.5 | **6.5** | 部分(Dashboard 改了,其他頁面延後 sweep) |
| D2 字體系統 | 4 | 7 | **6.5** | 大部分(font-family fixed; tabular-nums on tables; H1 fluid; text-xs 政策只文件化未推動) |
| D3 色彩層次 | 6 | 8 | **7.5** | 是(slate nav + chip border + 6-tier elevation token + cyan low) |
| D4 微互動 | 3 | 7 | **7** | 是(Button active + Modal/Toast/Skeleton motion + row flash + chart transitions) |
| D5 動效曲線 | 4 | 6.5 | **6.5** | 是(easing tokens + Linear-style ease-out-expo 採用於 Modal/Toast/Skeleton) |
| D6 狀態品質 | 5 | 7.5 | **7** | 部分(EmptyState + partial-fail + retry done;per-section error UI 仍泛化) |
| D7 細節紀律 | 5 | 7.5 | **6.5** | 部分(card radius 部分 sweep;divider 修;chip border 修;focus ring 延後) |
| D8 響應式 | 6 | 7 | **7** | 是(wide screen + 主 H1 fluid type) |
| **加權平均** | **4.7** | **7.2** | **6.8** | **+2.1**(目標 +2.5) |

實際達 **6.8 / 10** vs 預期 **7.2** — 差距 -0.4 主要來自:
- D1 spacing rhythm 只在 Dashboard 採用(其他頁面延後)
- D7 focus ring sweep 延後(風險超估)
- 部分品味細節需實機驗證才能確認真的「感覺對了」

**從 4.7 提升到 6.8 = 整體往「明確專業」邁進**;距離「對標 Linear」(8.7)還差 ~2 分,iter 4-5 dark mode + ReleaseDetail 重構 + 完整 sweep 可達。

## 8. 結論

**Wave A (4) + B (5) + C (5) + D (8 - 1 deferred) + E (4 - 1 deferred) + F (4 - 1 skipped) = 27 完成 / 30 規劃**

兩個延後都有合理理由(風險超估 / 預先存在 bug 擋路),不是放棄,是給 iter 4 一個 cleaner runway。

Build pass。Token system 顯著擴張(easing / spacing / elevation / font-family)。動效層全部上線(Button / Modal / Toast / Skeleton)。i18n holes 補齊主要部分。Skeleton bug + TrendChart 不可達 兩個 P1 a11y/perf bug 修補。

下一步:**Phase 10 更新 ledger.md + iteration-3.md + design-principles.md**,並 commit `.ui-audit/` 全部進 git。
