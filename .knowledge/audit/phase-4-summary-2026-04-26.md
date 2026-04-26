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
2. **Cross-cutting absence of mandatory authorization middleware**(SDLC-001)— architectural finding;explains why SEC-001a/b/c/d happened twice in 5 days unnoticed,and why TLT-3 / TLT-13 / TLT-18 follow the same convention-not-enforcement anti-pattern.
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

### Top-10 ranked

| # | finding | severity (lan/pub) | effort | rationale |
|---|---------|--------------------|--------|-----------|
| 1 | **SEC-001a** (licenses summary disclosure)         | Med / High  | S    | LEAK_CONFIRMED PoC;1-line `require_admin` patch closes immediately;biggest commercialisation blocker;unlocks SEC-001c via shared pattern |
| 2 | **SEC-001b** (licenses release IDOR)               | Med / High  | S    | LEAK_CONFIRMED PoC;`assert_release_in_scope` helper deploys in same commit as SDLC-001 prep;404-not-403 detail prevents enumeration oracle |
| 3 | **SEC-001c** (policies summary disclosure)         | Med / High  | S    | structurally confirmed;identical patch shape to #1;same commit acceptable |
| 4 | **SEC-001d** (policies release IDOR)               | Med / High  | S    | LEAK_CONFIRMED PoC;same patch as #2;closes the violations endpoint family entirely |
| 5 | **SDLC-001** (mandatory auth middleware)           | Med / High  | M    | Cross-cutting;**prevents SEC-001-class recurrence**;commercialisation differentiator (process maturity);also closes pre-conditions for #6 |
| 6 | **SEC-003** (X-Forwarded-For spoof)                | Low / High  | S    | nginx config + 1 line in rate_limit.py;blocks login brute-force + audit log integrity in one fix;trivial exploitation complexity = most cost-effective Top-10 entry |
| 7 | **SEC-002** (XML billion-laughs DoS)               | Low / Med   | S    | 2-line pre-parse rejection;closes the DoS vector;timing-confirmed PoC |
| 8 | **SEC-014** (backup at-rest encryption)            | Med / High  | M    | gpg-encrypt the SQLite backup script + off-host transfer;ISO 27001 A.8.13 evidence |
| 9 | **SEC-017** (CI SCA + SAST + secret scan)          | Med / High  | M    | one-time setup unlocks ongoing detection of new CVEs;SOC 2 CC8.1 evidence;closes precondition for SEC-014 / SEC-018 / future findings |
| 10 | **SEC-018** (nginx security headers)              | Info / Med  | S    | 5-line nginx config addition;defensive headers come free;closes XSS / clickjacking risk surface ahead of any commercialisation |

### Total estimated effort:**~6 sprints(2 senior engineer-weeks)**
- Top-4 (SEC-001 family):1 sprint(includes PoC re-verification post-fix)
- SDLC-001 + helpers:0.5 sprint
- SEC-003 + SEC-002 + SEC-018:0.5 sprint(small fixes batch)
- SEC-014 (backup) + SEC-017 (CI):1 sprint
- Defense in depth (CI lint rule,test_multi_tenant_isolation.py):0.5 sprint
- Verification round (Phase 6):0.5 sprint(re-run all PoCs,confirm regression suite catches reverts)

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

## 5. Phase 5 remediation gating

**Schema is frozen** since Phase 3 round-2 approval. Phase 5 begins on user "go" — sequence will be:

1. SEC-001a/b/c/d patches (one commit per finding, per Phase 5 protocol)
2. SDLC-001 helper introduction(`assert_release_in_scope` + Depends-based variant + CI lint rule)
3. SEC-002 / SEC-003 / SEC-018(small batch)
4. SEC-014 / SEC-017(infrastructure)
5. PoC2 re-run after each patch — must produce post-fix verdict

Each commit message follows the protocol:`fix(security): [SEC-NNN] short description`. Each commit includes new tests (positive + negative + boundary + security test). Per CLAUDE.md no new dependencies introduced unless documented (SEC-010 webhook encryption may use `cryptography` which is already a sub-dep of `python-jose`).

Phase 6 verification produces final report with before/after evidence.

---

## 6. Self-checks (Phase 4)

| Question | Answer |
|----------|--------|
| Did Phase 4 resolve all schema gaps surfaced in Phase 3? | Yes — heatmap uses exploitation_complexity X-axis (per Phase 3 amendment), severity bands are dual (LAN/public). |
| Are the Top-10 fixes ROI-ranked or severity-ranked? | ROI-ranked. SEC-001a/b/c/d come first (cheap fix + biggest exposure reduction), SDLC-001 comes 5th not 1st despite cross-cutting status because it requires SEC-001 patches first to validate. |
| Honest Phase 3 self-check applied? | Yes — `expected_recurrence` validation found 1 of 4 predictions wrong (TLT-7), removed from SDLC-001 traceability rather than rationalising backwards. |
| Is the report consumable by both technical and non-technical audiences? | Section 1 is non-technical (one page); Section 3 is the technical action list. Sections 2 / 4 are reference material. |
| Risk of over-confidence in confirmed-N/A items? | Acknowledged — SEC-004 subprocess and SEC-001-cleared 5 files were verified by READING SOURCE only. No fuzzing. Phase 6 verification round will spot-check with adversarial inputs. |
