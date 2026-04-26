---
internal: true
phase: 4
audit_id: 2026-04-26-security-code-review
methodology: Phase 1 recon + Phase 2 STRIDE + Phase 3 (25 findings) → Phase 4 synthesis
deployment_mode: lan_only
commercialization_planned: true
created: 2026-04-26
status: draft for user review before Phase 5 remediation gate
---

# Phase 4 — Executive Summary + Risk Heatmap + Top-10 Must-Fix

This file is the synthesis of Phases 1–3. Three sub-sections:
1. **Executive summary** (one page, non-technical)
2. **Risk heatmap** (severity × exploitation_complexity, dual deployment context)
3. **Top-10 must-fix priority list** (sequenced by Phase 5 ROI)

---

## 1. Executive Summary (one page)

**System under audit**:SBOM Management Platform(FastAPI + React + multi-tenant),Mac mini LAN-only deployment 2026-04-26;commercialisation as B2B SaaS planned for industrial security teams within 12 months.

**Audit shape**:Phase 1 reconnaissance(17 routers / 100+ endpoints / 22 frontend routes catalogued),Phase 2 STRIDE threat modelling(21 top-level threats + 3 attack trees + 10 abuse cases),Phase 3 finding production(**25 findings** across security + SDLC + supply-chain),plus dynamic PoC for the 5 highest-priority confirmable items.

**Headline numbers**:

| metric | count |
|--------|-------|
| Total findings | 25 |
| confirmed leaks (PoC executed) | 4 (SEC-001a/b/d + SEC-002 timing-confirmed) |
| structurally confirmed (PoC inconclusive but code unambiguous) | 1 (SEC-001c) |
| open findings awaiting Phase 5 patch | 21 |
| confirmed-N/A (heuristic false positives or already-secure) | 2 (SEC-004 subprocess + 1 from heuristic 7-file pre-PoC) |
| deferred (not applicable today) | 1 (SEC-020 LLM — re-open at commercialisation) |
| architectural cross-cutting findings | 1 (SDLC-001) |

**Severity distribution under LAN-only context**:0 Critical / 0 High / **6 Medium** / 12 Low / 1 Info / 4 N-A (parents + N/A + deferred + non-applicable).

**Severity distribution under public-deployment context**:0 Critical / **5 High** / 11 Medium / 2 Low / 1 Info / 4 N-A. **15 of 21 open findings carry `blocks_commercialization: true` or `partial`** — meaning B2B SaaS launch needs them resolved or risk-accepted formally.

**Top three risks**(detailed in Top-10 list below):
1. **Multi-tenant isolation gaps in `/violations/*` endpoint family**(SEC-001a/b/c/d)— 4 confirmed cross-tenant data exposures in licenses + policies routers. **Single biggest blocker for commercialisation**.
2. **Three architectural cross-cutting findings**(rev-3 split):
   - **SDLC-001 auth/scope mandatory middleware gap** — explains why SEC-001a/b/c/d happened twice in 5 days unnoticed (narrowed from rev-2 broad scope after Phase 3 expected_recurrence 50% hit rate revealed over-extension)
   - **SDLC-002 perimeter & transport hardening gap** — explains SEC-003 XFF spoof + SEC-018 nginx headers as systemic, not isolated;split out from SDLC-001 in rev-3
   - **SDLC-003 audit / logging maturity gap** — explains SEC-013 audit-log tamper + lack of structured log pipeline;split out from SDLC-001 in rev-3
3. **Backup at rest unencrypted**(SEC-014)— 14-day SQLite backup chain stored in `$HOME/sbom/backups/` with no encryption;disk theft / failure / commercialisation customer concern.

**What's working well**(not a finding,but worth noting):
- Phase 0 / Phase 1 historical fixes(14 Critical/High + 6 Medium/Low completed 2026-04-25)held up under verification — `_assert_release_org` pattern in releases.py is correctly applied to 30 callsites;subprocess wrappers are list-form and immune to command injection;JWT crypto uses explicit algorithm whitelist closing alg-confusion;OIDC token transport via URL fragment correctly avoids Referer leakage.
- Token authentication infrastructure(JWT + API Token scope + revocation list)is well-designed;no major flaws identified.
- Recently introduced OSV scan refactor and License Path-B work did not introduce new attack surface beyond what was already there.

**LAN-only caveat**:home WiFi is not a zero-trust boundary. Same-subnet IoT devices / personal laptops have lateral-movement reach. Findings tagged `severity_lan_only: Low` are not "safe forever";they're "contained to insider-attacker scenarios" today.

**Recommendation**:proceed to Phase 5 remediation in priority order(Top-10 below). Estimated full remediation effort:**~3 sprints**(~6 weeks)including SDLC-001 architectural rework,SEC-001a/b/c/d patches with PoC re-verification,backup encryption,CI baseline,and nginx hardening.

---

## 2. Risk Heatmap

### 2.1 LAN-only context (current state)

```
Y = severity        X = exploitation_complexity (T=trivial, L=low, M=medium, H=high)

severity_lan_only:
  Critical│
      High│
       Med│ T:SEC-002              L:SEC-010 SEC-014                    M:SEC-015 SDLC-001
       Low│ T:SEC-001a SEC-001b    L:SEC-003 SEC-005 SEC-006 SEC-007    M:SEC-009 SEC-021
            T:SEC-001c SEC-001d    L:SEC-008 SEC-016 SEC-019            M:SEC-013
                                   L:SEC-001 (parent — n/a own sev)
      Info│                        L:SEC-018
       N/A│ SEC-004 (confirmed-N/A)  SEC-020 (deferred)
           └────────────────────────────────────────────────────────
            T            L                M                       H
```

### 2.2 If-public context (post-commercialisation)

```
severity_if_public:
  Critical│
      High│ T:SEC-003*             L:SEC-014 SEC-015 SEC-017
                                   L:SDLC-001
       Med│ T:SEC-002              L:SEC-005 SEC-006 SEC-008 SEC-010    M:SEC-013 SEC-018
            T:SEC-001a/b/c/d       L:SEC-011 SEC-012 SEC-016 SEC-019    M:SEC-021
       Low│                        L:SEC-007 SEC-009
       N/A│ SEC-004 SEC-020
           └────────────────────────────────────────────────────────
            T            L                M                       H
```

* SEC-003 X-Forwarded-For:exploitation_complexity is `trivial` (one header) but severity_if_public is High because it bypasses login rate-limit and audit log integrity simultaneously — top-right corner finding.

### 2.3 Heatmap reading

LAN-only:no Critical or High;the audit deliberately avoided severity inflation. Concentrations:
- **8 findings in the trivial-exploitation column** — most expensive to NOT fix because attack window is one curl request away
- **2 Medium severity in trivial column**(SEC-002 XML bomb,SDLC-001)— first sprint targets

If-public:5 High concentrate in low-medium exploitation complexity → **once internet-exposed, the platform is brittle**. Top corner is SEC-003 (XFF spoof) — single-header request. Phase 5 must close before any public exposure.

---

## 3. Top-10 Must-Fix(prioritised by Phase 5 ROI)

Each row scored on:
- **Severity**(higher = more urgent)
- **Effort**(lower = better)
- **Blast radius reduction**(higher = better — does fixing this remove other findings' exposure?)
- **Compliance leverage**(higher = better — does this unblock SOC 2 / ISO 27001 evidence?)

### Top-10 ranked (rev-3 — architecture-first + scaffold-first per user round-3 review)

**rev-3 rationale**:rev-2 排序為 pure ROI(1-line fix 先做)。rev-3 改成 **scaffold-first + architecture-first**:
- **SEC-017 CI baseline 拉到 #0 (sprint 0)**:後續 10+ commit 都需 SAST / SCA / secret scan 在 PR 上跑。沒這層 = 閉著眼睛改 security code。SDLC-001 大改動沒 SAST 攔截尤其風險高。
- **SDLC-001 拉到 #1**:若先修 SEC-001a/b/c/d 才做 SDLC-001,4 個 endpoint 要 refactor 兩次(先手動 fix,再轉 middleware)。SDLC-001 先做、4 個 sub-finding 直接套用新 middleware = 一次到位,commit 少,Phase 6 verification 簡單(只驗 middleware 本身 + 4 個 endpoint 都套用)。

**rev-4 amendment**:SEC-022(Python version floor)拆出獨立 finding(從 SEC-002 secondary fix 中分離出),排在 SEC-017 與 SEC-002 之間。維持 Top-10 規模,**SEC-014 backup encryption 移到 P2 backlog**(仍追蹤,但不在這次 Phase 5 sprint 衝刺範圍)。

| # | finding | severity (lan/pub) | effort | rationale |
|---|---------|--------------------|--------|-----------|
| **0** | **SEC-017** (CI SCA + SAST + secret scan) | Med / High | M (~3h) | **腳手架** — sprint 0 先架,後續每 fix commit 在 CI 監督下進。SOC 2 CC8.1 evidence 同步 unlock。沒這層 SDLC-001 大改動風險不可控 |
| **1** | **SDLC-001** (auth/scope mandatory middleware,**rev-3 縮 scope** + **rev-4 加 enforcement test**) | Med / High | M (~5h) | **architecture-first** — 引入 `require_release_in_scope` Depends-based 守衛 + CI enforcement test 防 30 個 callsite 漏掉;SEC-001a/b/c/d 直接套用 |
| 2 | SEC-001a (licenses summary disclosure)        | Med / High | S | 用 SDLC-001 helper 一行套上;LEAK_CONFIRMED PoC 已有 |
| 3 | SEC-001b (licenses release IDOR)              | Med / High | S | 用 `assert_release_in_scope` + 404 not 403 |
| 4 | SEC-001c (policies summary disclosure)        | Med / High | S | 同 #2 pattern |
| 5 | SEC-001d (policies release IDOR)              | Med / High | S | 同 #3 pattern;封閉 violations endpoint family |
| 6 | SEC-003 (X-Forwarded-For spoof)               | Low / High | S | nginx + rate_limit;trivial complexity → 最 cost-effective |
| **7** | **SEC-022** (Python version floor in pyproject.toml) — **rev-4 NEW** | Low / Med | S | 拆自 SEC-002 — supply-chain 類別獨立 commit;與 SEC-017 互鎖(CI lock + packaging lock 雙防);SEC-002 application fix 在此之後跑安全 |
| 8 | SEC-002 (XML billion-laughs DoS)              | Low / Med  | S | 2-line pre-parse rejection;application-level guard。**rev-4** 移除原本的 secondary python_requires fix(改 SEC-022 處理) |
| 9 | SEC-018 (nginx security headers)              | Info / Med | S | 5-line nginx config;CSP 留待 frontend audit |

**P2 backlog**(rev-4 移出 Top-10 但仍追蹤):
- SEC-014 (backup at-rest encryption) | Med / High | M | gpg-encrypt SQLite backup + off-host transfer;ISO 27001 A.8.13。Phase 5 結束後立刻動,商業化部署前必修。

### Total estimated effort:**~3 sprints(1.5 senior engineer-weeks)**(rev-3 數值維持;SDLC-001 加 enforcement test 多 1h,SEC-022 補回 30min,SEC-014 移到 P2 抵消)
- Sprint 0:**SEC-017 CI baseline**,~3h(腳手架)
- Sprint 1:**SDLC-001 middleware + enforcement test + SEC-001a/b/c/d 套用**,~2d
- Sprint 2:SEC-003 + SEC-022 + SEC-002 + SEC-018 batch,~1d
- Phase 6 verification(re-run all PoCs + new tests):0.5d
- P2 backlog clearance(SEC-014 backup):~1d (post-Phase-6)

### Findings 11–25 (deferred to subsequent sprints)

Detailed in `security-audit-batch-tlt-2-21.md`. Summary:
- SEC-005 webhook DNS rebinding (M effort, Medium / Medium severity)
- SEC-007 JWT aud/iss claims (S)
- SEC-008 admin/scope tightening (S)
- SEC-013 audit log INSERT-only constraint (M)
- SEC-015 DoS resilience (M)
- SEC-016 frontend localStorage migration (Long — multi-sprint)
- SEC-019 launchd hardening (M)
- SEC-021 NTP / clock integrity (M)
- SEC-020 LLM threats (deferred)
- SEC-006 OIDC state cookie (S — easy verify post-fix)
- SEC-009 PDF/CSAF stored XSS (S)
- SEC-010 webhook_url DB encryption (M)
- SEC-011 race conditions (M)
- SEC-012 firmware EMBA inheritance (S — documentation)

---

## 4. Compliance gap summary (for commercialisation planning)

Aggregating `compliance_impact` across all 25 findings:

| Framework | Distinct controls hit | findings citing |
|-----------|----------------------|-----------------|
| SOC 2 CC6.1 (Logical access) | 1 | SEC-001a/b/c/d, SEC-010 |
| SOC 2 CC6.3 (Need-to-know) | 1 | SEC-001a/b/c/d |
| SOC 2 CC6.7 (Boundary protection) | 1 | SEC-003 |
| SOC 2 CC7.1 (System operations / DoS) | 1 | SEC-002, SEC-015 |
| SOC 2 CC7.2 (System monitoring / audit) | 1 | SEC-003, SEC-013, SDLC-001 |
| SOC 2 CC8.1 (Change management) | 1 | SDLC-001, SEC-017 |
| ISO 27001 A.5.15 (Access control policy) | 1 | SEC-001a/c |
| ISO 27001 A.5.18 (Object access rights) | 1 | SEC-001b/d |
| ISO 27001 A.8.3 (Information access restriction) | 1 | SEC-001a/c |
| ISO 27001 A.8.13 (Backup) | 1 | SEC-014 |
| ISO 27001 A.8.16 (Monitoring) | 1 | SEC-003 |
| ISO 27001 A.8.32 (Change management) | 1 | SEC-002 |
| GDPR Art.32 (Security of processing) | 1 | SEC-001a/b/c/d, SEC-010 |
| GDPR Art.5(1)(e) (Storage limitation) | 1 | SEC-013 |
| IEC 62443-4-1 SI-1 (Secure implementation) | 1 | SEC-001a/b/c/d, SEC-002 |
| IEC 62443-4-1 SM-9 (Process improvement) | 1 | SEC-001d (the recurrence-loop closing finding), SDLC-001 |
| IEC 62443-4-1 SUM-3 (Update management) | 1 | SEC-013 |
| IEC 62443-4-1 SVV-3 (Vuln assessment) | 1 | SEC-003 |

**Most-cited frameworks**:GDPR Art.32 + SOC 2 CC6.x — both expected for B2B SaaS with EU customers + US enterprise customers respectively. Phase 5 remediation will close most of these (Top-10 covers ~70% of the listed control gaps).

---

## 5. Phase 5 remediation gating (rev-3 reorder + commit-discipline)

**Schema is frozen** since Phase 3 round-2 approval. Phase 5 sequence follows rev-3 Top-10:

0. **SEC-017** CI baseline(sprint 0 — 腳手架先架)
1. SDLC-001 mandatory middleware(architecture-first)
2-5. SEC-001a/b/c/d 套用 SDLC-001 middleware
6. SEC-003 X-Forwarded-For + 7. SEC-002 + 8. SEC-018(small batch)
9. SEC-014 backup encryption

### Phase 5 commit discipline (rev-3 amendment;rev-4 verification type 分類)

**每個 fix commit 必須包含**(non-negotiable):

1. **Verification — 三類擇一**:
   - **`poc-rerun`**:有可重跑 PoC 的 finding(SEC-001a/b/c/d, SEC-002, SEC-003)。
     Before fix 跑一次(LEAK CONFIRMED)+ after fix 跑一次(NOT REPRODUCED)。
   - **`infrastructure-verify`**:新增基礎設施類 fix(SEC-017 CI, SEC-018 nginx headers, SEC-014 backup gpg)。
     不是修 bug 是新增 capability,verify 改成可重現的 infrastructure check:
     - CI baseline → 故意 PR 引入 known-vulnerable lodash 看 CI 擋下
     - nginx headers → `curl -I` 看 5 個 header 都在 + value 對
     - backup gpg → run + 試解密 + 改 ciphertext 1 byte 看 verify fail
   - **`structural-verify`**:架構引入類 fix(SDLC-001 middleware introduction)。
     自身沒 PoC,但「下游 finding 在 commit 之後跑 PoC 應仍 LEAK CONFIRMED
     (endpoint 還沒套 decorator),套 decorator 的 commit 之後才 NOT REPRODUCED」
     這條鏈 commit message 要明示。

2. **Regression suite pass**(所有 commit 一律):
   - CI baseline 上線後,每 commit PR 要過 SAST / SCA / 既有 test
   - `python test_all.py` 必須過(54 個 stdlib regression test)
   - 加新測試:positive + negative + boundary + security test 各 1 個

**Commit message format(rev-4 — 加 Verification type 欄位)**:
```
fix(security): [SEC-NNN] short description

Verification type: poc-rerun | infrastructure-verify | structural-verify
Before fix: <PoC verdict | "N/A — infrastructure fix">
After fix:  <PoC verdict | infrastructure check result | "deferred to SEC-NNN commit">
Regression: test_all.py 54/54 pass + CI green
```

**Examples**:
```
# SEC-017 CI baseline (infrastructure-verify)
Verification type: infrastructure-verify
Before fix: N/A — adding capability not fixing bug
After fix:  test PR with lodash@4.17.20 dep → CI blocked (pip-audit + bandit)

# SDLC-001 middleware introduction (structural-verify)
Verification type: structural-verify
Before fix: deferred — SEC-001a-d PoCs still LEAK CONFIRMED at this commit
After fix:  helper unit tests pass; downstream verification 由 SEC-001a-d
            commit 接手執行 PoC re-run

# SEC-001a (poc-rerun)
Verification type: poc-rerun
Before fix: SEC-001a-licenses-summary-leak.py → LEAK CONFIRMED (admin total=2)
After fix:  SEC-001a-licenses-summary-leak.py → [NO LEAK] HTTP 403
```

**No new dependencies** unless documented(per CLAUDE.md);SEC-010 webhook encryption 可用 `cryptography`(已是 `python-jose[cryptography]` 子依賴,等於 0 新 dep)。

### Monitor mode (rev-4 amend per user round-4)

Phase 5 動工後 stop gate 撤掉,Claude Code 自主推進。但**任一條件**自動暫停回報:

1. **Python version regression** — fix 過程發現實際 runtime <3.11.4 → SEC-002 翻 High,Top-10 順序動
2. **PoC re-run after-fix 沒出 NOT REPRODUCED** — fix 失敗,需 root-cause
3. **Regression suite 有 test fail** — `test_all.py` 不再 54/54
4. **Enforcement test 跑出 missing decorator endpoint** — SDLC-001 scope_not_reviewed 盲點落實,需重新評估 review boundary
5. **任何 finding fix 過程發現 severity 估錯一級以上** — 例如 SEC-XXX 從 Low 變 Critical
6. **Mirror push 失敗 / grep check 有可疑 hit** — Phase 5 動工 hard gate

其他全不停。Phase 6 verification 完成才下次回報。

Phase 6 verification produces final report with before/after evidence + Top-10 全 commit hash 列表 + 執行過的 PoC 列表。

---

## 6. Self-checks (Phase 4)

| Question | Answer |
|----------|--------|
| Did Phase 4 resolve all schema gaps surfaced in Phase 3? | Yes — heatmap uses exploitation_complexity X-axis (per Phase 3 amendment), severity bands are dual (LAN/public). |
| Are the Top-10 fixes ROI-ranked or severity-ranked? | ROI-ranked. SEC-001a/b/c/d come first (cheap fix + biggest exposure reduction), SDLC-001 comes 5th not 1st despite cross-cutting status because it requires SEC-001 patches first to validate. |
| Honest Phase 3 self-check applied? | Yes — `expected_recurrence` validation found 1 of 4 predictions wrong (TLT-7), removed from SDLC-001 traceability rather than rationalising backwards. |
| Is the report consumable by both technical and non-technical audiences? | Section 1 is non-technical (one page); Section 3 is the technical action list. Sections 2 / 4 are reference material. |
| Risk of over-confidence in confirmed-N/A items? | Acknowledged — SEC-004 subprocess and SEC-001-cleared 5 files were verified by READING SOURCE only. No fuzzing. Phase 6 verification round will spot-check with adversarial inputs. |
