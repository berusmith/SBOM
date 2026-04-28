# Iteration 3 — Followups

> Phase 8 執行中順手發現但**不在本 commit 範圍**的事。執行完 Phase 9 後再決定要不要做。

## i18n holes spotted while doing UX-3.002 (out of scope of B2)

UX-3.002 was scoped to the specific 9 toast.error / setIntegrity / 2-on-L939
sites + STATUS_LABEL + JUSTIFICATION/RESPONSE_OPTIONS. While editing those
files I noticed *more* hardcoded zh strings in the same files but in
unrelated flows:

**`ReleaseDetail.jsx`** (added below the 9 fixed in B2):
- L234 `toast.success("簽章已移除")` — sister of signature flow; needs key
- L1193 `toast.success("備註已儲存")` — notes save flow
- L941 visible button `>複製<` — Copy button label
- L1199–1213 visible button `>儲存<` / `>儲存中...<` / `>取消<` etc. — notes editor
- Plus likely many more (this page is 2081 LOC — full sweep is its own task)

**`FirmwareUpload.jsx`**:
- L70 `toast.success(\`韌體上傳成功: ${...}\`)` — upload-success toast
- L133 `toast.success(\`版本建立成功: ...\`)` — import-as-release success
- L159-166 `getStatusBadge` 4 labels (`✓ 完成`, `⟳ 掃描中`, `✕ 失敗`, `⏳ 等待中`)
- L173 page subtitle "上傳韌體映像檔，自動生成 SBOM 元件清單"
- L214 button "上傳中..." / "開始上傳"

**Recommendation**: bundle as a follow-up `UX-3.002b — full i18n sweep of
ReleaseDetail.jsx + FirmwareUpload.jsx`, schedule for iter 4 (or next time
either file is being touched anyway).

## Card radius (UX-3.008 sweep extension)

D1 commit fixed Profile.jsx (3) + Dashboard.jsx ViewerOnboarding (1).
Other `rounded-xl` general-purpose cards still exist:
- AdminActivity.jsx:139,175,225 (3 cards)
- TISAXAssessments.jsx:96,144,158 (3 cards)
- TISAXDetail.jsx:266,275,333,356,362,397 (6 cards)

Auth pages keep `rounded-xl` deliberately (Login/ForgotPassword/ResetPassword
are centred hero cards, different visual context).
ReleaseDetail.jsx:1789 floating bar uses rounded-xl on a dark overlay — also
a different context (floating action), keep.

Recommend a single sweep commit `UX-3.008b — rounded-xl sweep on data cards`
when next touching AdminActivity / TISAX pages.

## UX-3.012 focus-ring sweep — DEFERRED with analysis

The plan asked to sweep `focus:ring-2 focus:ring-blue-400` (97 occurrences
across 24 files) and rely on the global `:focus-visible` outline added in
iter 1. Investigation while attempting this revealed it's NOT a safe
mechanical sweep:

**Why it's not safe**: Most pages pair `focus:ring-2 focus:ring-blue-400`
with `outline-none` and/or `focus:outline-none`. The `outline-none` class
selector beats the global `:focus-visible { outline: 2px }` rule on CSS
specificity (0,2,0 vs 0,1,0), so the global outline NEVER fires on those
elements. The per-element ring is the *only* visible focus indicator on
all 97 sites. Mechanical removal = invisible focus = WCAG 2.4.7 fail.

**Correct fix is bigger than estimated**:
1. Remove `outline-none` + `focus:outline-none` everywhere first
2. THEN either rely on global outline (option A) OR convert
   `focus:ring-*` → `focus-visible:ring-*` + add `ring-offset-2` (option B)
3. Each element manually verified — some inputs/cards/tabs may need
   custom handling (e.g. inputs that already have a visible border may
   double-up with outline)

**Recommendation**: schedule an `UX-3.012b — focus-state systemisation`
iter 4 task with explicit budget. Need a design call between option A
(simpler, less visual weight on focus) and option B (closer to current
look, takes longer).

**Current state**: Button uses option B correctly (focus-visible:ring-2
focus-visible:ring-offset-1). Other components mix focus:ring (incorrect:
fires on click) with outline-none (incorrect: kills global outline on
keyboard). The result is functional but not consistent.

## UX-3.029 fluid H1 — extend to remaining data pages

D7 commit applied `text-h1-fluid` to Dashboard / Releases / RiskOverview
per plan. Other data pages with the same `text-2xl font-bold text-gray-800`
H1 pattern that should also adopt for consistency:
- Organizations.jsx:110
- Products.jsx:95
- Policies.jsx:167
- Users.jsx:113
- FirmwareUpload.jsx:172
- CRAIncidents.jsx:63
- About.jsx:70

Auth pages (Login / ForgotPassword / ResetPassword / Profile) and detail
pages (CRAIncidentDetail / TISAXAssessments / AdminActivity) keep
text-xl — they're narrower contexts where 36px would feel oversized.

## UX-3.028 sticky first column — DEFERRED + RiskOverview column count bug

E4 commit landed wide-screen container (UX-3.015). The companion sticky-
first-column work was blocked by a pre-existing column count mismatch in
`RiskOverview.jsx`:

- thead renders 10 cells: # + 6 SORT_FIELDS + 修補率 + 進行中事件 + (action)
- tbody renders 9 cells: # + risk_score + unpatched_critical + unpatched_high
  + total_vulns + org_name + PatchBar + incidents + action

That's a real off-by-one (header has both `patch_rate` AND `修補率` columns,
but tbody only renders one PatchBar cell). The sortable header's
`patch_rate` column has no tbody counterpart — sort still works but the
column visually merges with neighbours. Plus org_name/PatchBar are swapped
relative to header order.

Sticky-first-column is unsafe to add until the column structure is fixed
(otherwise the sticky cell may attach to the wrong column). Recommend a
focused commit `UX-3.028a — RiskOverview column structure fix` that aligns
thead↔tbody, then `UX-3.028b — sticky first column` as a follow-up.

Other wide tables (AdminActivity, ReleaseDetail vuln table) are candidates
for the same sticky-col treatment in a future iter — not blocking.

## UX-3.036 caption sweep — extension

F4 commit added `<caption className="sr-only">` to 3 tables:
- AdminActivity per-customer summary
- AdminActivity event feed
- Search results

8 more tables on other pages still lack captions and should receive one
when those files are next touched (touched-code policy):
- Help.jsx:793
- FirmwareUpload.jsx:286 (scan list)
- CRAIncidents.jsx:89
- ReleaseDiff.jsx:177 + 200 (component diff + vuln diff)
- ReleaseDetail.jsx:1017 (vuln history sub-table — may be intentional)
- TISAXDetail.jsx:366 + 401 (control / gap tables)
