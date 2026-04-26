---
internal: true
phase: 3
audit_id: 2026-04-26-security-code-review
methodology: STRIDE-driven; static + dynamic PoC; heuristic separated
deployment_mode: lan_only
commercialization_planned: true
created: 2026-04-26
revised: 2026-04-26 (Phase 3 review amendment — schema + structure)
gates:
  - SEC-001a_schema_review_before_bulk
status: in-progress (parent SEC-001 + SEC-001a + SDLC-001 written; b/c/d skeleton; bulk paused)
---

# Phase 3 — Security Audit: Findings

Schema and structure per Phase 3 review amendment(`audit(phase-3)` commit `09728a8` was umbrella v0;this is split v1).

Active findings:
- **SEC-001 (parent)** — multi-tenant isolation pattern failure;RCA + systemic remediation pointer;no own severity
- **SEC-001a** — `licenses.py /violations/summary` cross-tenant disclosure
- **SEC-001b** — `licenses.py /releases/{id}/violations` IDOR
- **SEC-001c** — `policies.py /violations/summary` cross-tenant disclosure
- **SEC-001d** — `policies.py /releases/{id}/violations` IDOR
- **SDLC-001** — architectural:lacks mandatory release-ownership middleware

Schema-review gate per user direction:**SEC-001a written fully(含 PoC2 evidence)→ user review → 才批量寫剩 20 條 TLT finding**。

---

## SEC-001 (parent) — Multi-tenant isolation: pattern failure across release-scoped endpoints

**Status:**parent / tracking only / no own severity / no own CVSS

This finding is the parent for SEC-001a/b/c/d. It exists to record the systemic pattern, not to be patched directly. Patches happen on the children.

### Root-cause analysis

Phase 1 heuristic flagged 7 router files that query `Release / Component / Vulnerability / Product` without invoking an `_assert_*_org` helper. Phase 3 verification:

| File | Verdict | Mechanism |
|------|---------|-----------|
| `stats.py` | confirmed-N/A | inline `if org_scope: q = q.filter(Product.organization_id == org_scope)` repeated at every query (and a `_vuln_base_query()` helper) |
| `products.py` | confirmed-N/A | inline `if org_scope and product.organization_id != org_scope: raise 403` repeated at every endpoint |
| `search.py` | confirmed-N/A | inline scope filter (line 27-28) |
| `firmware.py` | confirmed-N/A | admin-only routes + 1 scoped import endpoint |
| `organizations.py` | confirmed-N/A | admin-only / scoped per-endpoint |
| **`licenses.py`** | **2 confirmed leaks** (SEC-001a, SEC-001b) | helper missing AND inline pattern not applied |
| **`policies.py`** | **2 confirmed leaks** (SEC-001c, SEC-001d) | same |

**The pattern**:every other router has one of two isolation forms:
1. `_assert_release_org(release, org_scope, db)` helper call (used 30 times in `releases.py`)
2. Inline `if org_scope and resource.organization_id != org_scope: raise 403` (used in `products.py`, `firmware.py:import-as-release`)
3. Filter chain `.filter(Product.organization_id == org_scope)` (used everywhere in `stats.py`, `search.py`, `organizations.py`)

`licenses.py` and `policies.py` use **none of these patterns**. The `/violations/summary` endpoints have no `org_scope` parameter at all (signature is just `db: Session = Depends(get_db)`); the `/releases/{id}/violations` endpoints either accept `org_scope` and ignore it (licenses.py) or omit it entirely from the signature (policies.py).

### Why this happened (process diagnosis — IEC 62443-4-1 SM-9 input)

- Both routers were added in 2026-04-21 (`e207d53` policies) and 2026-04-22 (`4bb8a75` licenses). Pre-existing routers had the org_scope pattern in place by then.
- The new routers were modelled on `settings.py` (config CRUD) which is intrinsically global. The author copied that template without adding org_scope.
- No CI lint rule existed to catch endpoints that take a `_id` path parameter without an ownership check.
- Code review (single author / no second pair of eyes) didn't catch the pattern absence.

### Systemic remediation

See **SDLC-001** below — the architectural finding that introduces a mandatory `@require_release_ownership(release_id)` decorator + a CI lint rule. Patching SEC-001a/b/c/d alone treats symptoms; SDLC-001 prevents recurrence.

### Compliance impact (parent-level summary; per-child details in each finding)

```yaml
compliance_impact:
  - framework: SOC2
    control: CC6.1   # Logical access controls
    gap_type: control_partial
  - framework: SOC2
    control: CC6.3   # Need-to-know
    gap_type: control_missing
  - framework: ISO27001
    control: A.5.15  # Access control policy
    gap_type: control_partial
  - framework: GDPR
    control: Art.32  # Security of processing
    gap_type: control_partial
  - framework: IEC62443-4-1
    control: SM-9    # Process improvement (this finding's existence = SM-9 evidence of need)
    gap_type: control_partial
  - framework: IEC62443-4-1
    control: SI-1    # Secure implementation
    gap_type: control_partial
```

---

## SEC-001a — `licenses.py:118` `/api/licenses/violations/summary` returns platform-wide license violation counts to any authenticated viewer

### Metadata

| field                     | value |
|---------------------------|-------|
| finding_id                | SEC-001a |
| traceability              | TLT-1 (multi-tenant); attack-tree-#1.path-A.leaf-2 (cross-tenant exfil via stats / aggregate endpoint); abuse-case ABU-7 partial |
| status                    | open |
| discovered_phase          | 3 |
| verification_method       | static + dynamic-poc |
| first_observed_commit     | `4bb8a75` (2026-04-22, "feat: license compliance policy engine") |
| exploitation_complexity   | **low** (requires authenticated viewer JWT; one GET request; no payload crafting) |
| severity_lan_only         | **Medium** |
| severity_if_public        | **High** |
| blocks_commercialization  | **true** |
| confidence                | **High** (4 confirmed lines of code, no inference; PoC scripted; LAN exposure window 4 days from commit to audit) |
| category                  | Multi-tenant / Authz / Information Disclosure |
| cwe                       | [CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) + [CWE-200 Information Exposure](https://cwe.mitre.org/data/definitions/200.html) |
| owasp                     | OWASP API3:2023 Broken Object Property Level Authorization + A01:2021 Broken Access Control |
| cvss_3_1                  | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **6.5 (Medium)** lan_only;`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` = **7.7 (High)** if_public(scope changes when tenants are competitors)|

### compliance_impact

```yaml
compliance_impact:
  - framework: SOC2
    control: CC6.1
    gap_type: control_partial
    note: |
      Logical access controls present at JWT layer but
      missing at object level (per-organisation isolation).
  - framework: SOC2
    control: CC6.3
    gap_type: control_missing
    note: Need-to-know not enforced for license violation aggregates.
  - framework: ISO27001
    control: A.5.15
    gap_type: control_partial
  - framework: ISO27001
    control: A.8.3
    gap_type: control_missing
    note: Information access restriction at the resource granularity.
  - framework: GDPR
    control: Art.32(1)(b)
    gap_type: control_partial
    note: |
      Confidentiality of processing not maintained between
      controllers (each tenant being a separate data controller).
  - framework: IEC62443-4-1
    control: SI-1
    gap_type: control_partial
```

### Location

- `backend/app/api/licenses.py:118-136` (function `violations_summary`)
- Mounted: `main.py:314` `app.include_router(licenses.router, dependencies=_auth)` — auth required, but per-org authorization missing

### Affected Assets

- **A1** Customer SBOM contents (component license metadata aggregated across tenants)
- **A9** Customer org_id mapping (per-rule counts allow inference of tenant existence and license posture)

### Attacker Profiles

- **AT-4** Authenticated viewer in tenant A — primary realised threat
- **AT-5** Authenticated viewer in tenant B wanting tenant A data — same path
- (LAN-only context)**AT-1 / AT-2** only realisable if attacker first compromises a credential

### Observation

```python
# backend/app/api/licenses.py:118-136
@router.get("/violations/summary")
def violations_summary(db: Session = Depends(get_db)):
    """Platform-wide license violation counts per rule."""
    _seed_defaults(db)
    rules = db.query(LicenseRule).filter(LicenseRule.enabled == True).all()
    comps = db.query(Component).filter(Component.license != None, Component.license != "").all()
    # ^^ THIS query has NO org filter — returns components ACROSS ALL ORGANISATIONS

    summary = []
    for rule in rules:
        count = sum(1 for c in comps if _matches(rule.license_id, c.license or ""))
        summary.append({
            "rule_id":         rule.id,
            "license_id":      rule.license_id,
            "label":           rule.label or rule.license_id,
            "action":          rule.action,
            "violation_count": count,
        })
    total = sum(s["violation_count"] for s in summary)
    return {"total_violations": total, "by_rule": summary}
```

Function signature accepts only `db: Session = Depends(get_db)` — **no `org_scope` parameter**. Comment "Platform-wide license violation counts per rule" suggests admin intent; the missing `Depends(require_admin)` exposes it to all viewers.

### Evidence / PoC

**PoC script**: `.knowledge/audit/poc/SEC-001a-licenses-summary-leak.py`(stdlib urllib only;DO NOT RUN against production)
**Evidence file**: [`.knowledge/audit/evidence/2026-04-26/SEC-001a.md`](evidence/2026-04-26/SEC-001a.md)
**Status**:✅ **dynamic-poc executed 2026-04-26 — LEAK_CONFIRMED**

PoC ran against running dev backend on `http://localhost:9100` (master @ `91a5599`, pre-fix). Setup created two test orgs at run-time(`POC-001a-OrgA-1777202863` with one GPL-3.0 component;`POC-001a-OrgB-1777202863` with zero data),logged in as viewerB,hit `/api/licenses/violations/summary`,received identical response to admin:

```
[5] admin sees                          total=2, GPL-3.0 count=1
[7] viewerB's own org has 0 products    (zero baseline confirmed)
[8] viewerB sees                        total=2, GPL-3.0 count=1   ← LEAK
```

viewerB has zero components in its own org;the visible GPL-3.0 count must be orgA's data. **Cross-tenant disclosure proven dynamically**.

Cleanup ran successfully (cascade-delete via `Organization.cascade="all, delete-orphan"` removed both test orgs and their data; verified by re-querying admin summary post-cleanup).

After Phase 5 patch (primary_remediation = `require_admin`), the same PoC will re-run and is expected to print `[NO LEAK]` with viewerB receiving HTTP 403.

### Impact

**LAN-only today**:Insider with viewer credentials sees license violation counts across every organisation on the platform. Per-rule counts allow inference of:
- Total tenants on the platform (tenants without GPL components contribute 0; tenants with contribute n)
- License posture per tenant indirectly (e.g. organisation Y has "12 AGPL violations" — competitive intelligence)
- Existence of organisations otherwise unknown to viewer

**Commercialised SaaS**:Same insider-attacker becomes "any paying customer". B2B context where customers are competitors → cross-tenant leak between competing companies. Triggers SOC 2 CC6.1/CC6.3 material weakness, ISO 27001 A.8.3, GDPR Art.32 — likely 30-day-cure clauses in enterprise contracts. **Deal-breaker for industrial security customers** (target market).

### Likelihood

- **Discovery cost**: Trivial — endpoint listed at `/docs`; URL pattern is obvious
- **Exploitation cost**: Trivial — single GET with valid JWT
- **Stealth**: High — appears as normal API traffic; audit log entry "GET /api/licenses/violations/summary by user X" doesn't flag cross-tenant intent

### Recommendation

#### primary_remediation
**Make endpoint admin-only.** "Platform-wide" semantics in the docstring matches admin intent; per-tenant viewers should call `/releases/{release_id}/violations` for their own data instead.

```diff
-@router.get("/violations/summary")
-def violations_summary(db: Session = Depends(get_db)):
+@router.get("/violations/summary")
+def violations_summary(_admin: dict = Depends(require_admin),
+                       db: Session = Depends(get_db)):
     """Platform-wide license violation counts per rule (admin only)."""
```

If frontend currently calls this endpoint as a viewer (verify in `frontend/src/pages/Licenses.jsx`), add a tenant-scoped variant `/licenses/violations/my-summary` that filters by org_scope.

- **effort**: S (5-line change + frontend check)
- **risk_of_fix**: Low — only impacts current viewer-callers (likely none); rollback = 1-line revert

#### defense_in_depth
- Lint rule (CI): grep for `@router.get|.post|.patch|.delete` immediately followed by a function whose only `Depends` is `get_db` (i.e. no `get_current_user` / `org_scope` / `require_admin`). Should fail CI when any endpoint matches.
- Test: `tests/test_multi_tenant_isolation.py` (stdlib) — for every router, attempts cross-tenant access with viewer's token; assert 403/404.

- **effort**: M (~3h for lint + test)
- **risk_of_fix**: Low

#### compensating_control
**Hot-patch as `require_admin` immediately** (1-line, takes effect on backend restart). This eliminates the cross-tenant exposure for non-admin users while the proper org-scoped variant is designed.

- **effort**: S (single line; same as primary_remediation Patch A above)
- **risk_of_fix**: Low

#### monitoring_detection
- Structured log on each call to `/api/licenses/violations/summary`: `caller_user_id`, `caller_org_id`, `returned_record_count`. **Alert** when `returned_record_count > (count of components in caller's org)` — this catches any future regression that re-introduces cross-tenant leak.
- Phase 6 verification: PoC2 re-run after Phase 5 patch must produce 403 (compensating) or scoped result (primary_remediation).
- Long term: SOC 2 Type II evidence — quarterly run of `tests/test_multi_tenant_isolation.py` against production-like staging, log retained.

- **effort**: M (~2h for log+alert; ~1h for quarterly cron)
- **risk_of_fix**: None (pure observability)

### References

- CWE-285 Improper Authorization — https://cwe.mitre.org/data/definitions/285.html
- CWE-200 Information Exposure — https://cwe.mitre.org/data/definitions/200.html
- OWASP API3:2023 BOPLA — https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- OWASP A01:2021 Broken Access Control — https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- SOC 2 CC6.1 / CC6.3 — AICPA TSP section 100
- ISO 27001:2022 A.5.15 / A.8.3
- GDPR Art.32(1)(b) — Confidentiality of processing
- IEC 62443-4-1 SI-1 — secure implementation
- NIST SP 800-53 AC-3 — access enforcement (for monitoring_detection layer)

---

## SEC-001b — `licenses.py:139` `/api/licenses/releases/{release_id}/violations` IDOR via release_id

### Metadata

| field                     | value |
|---------------------------|-------|
| finding_id                | SEC-001b |
| traceability              | TLT-1; attack-tree-#1.path-C.leaf-2 (cross-tenant via guessable resource id); abuse-case — N/A |
| status                    | open |
| discovered_phase          | 3 |
| verification_method       | static + dynamic-poc-pending |
| first_observed_commit     | `4bb8a75` (2026-04-22) |
| exploitation_complexity   | **low** (need a release_id from another tenant — leakable via PDF / share link / log; UUIDs unguessable but not unfindable) |
| severity_lan_only         | **Medium** |
| severity_if_public        | **High** |
| blocks_commercialization  | **true** |
| confidence                | High |
| category                  | Multi-tenant / Authz / IDOR |
| cwe                       | [CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) + CWE-285 |
| owasp                     | OWASP API1:2023 BOLA + A01:2021 |
| cvss_3_1                  | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **6.5** lan_only / **7.7** if_public |

### compliance_impact

```yaml
compliance_impact:
  - framework: SOC2
    control: CC6.1
    gap_type: control_partial
  - framework: SOC2
    control: CC6.3
    gap_type: control_missing
  - framework: ISO27001
    control: A.5.15
    gap_type: control_partial
  - framework: GDPR
    control: Art.32
    gap_type: control_partial
  - framework: IEC62443-4-1
    control: SI-1
    gap_type: control_partial
```

### Location

- `backend/app/api/licenses.py:139-170`

### Observation

```python
@router.get("/releases/{release_id}/violations")
def release_violations(
    release_id: str,
    org_scope: str | None = Depends(get_org_scope),   # ← present in signature
    db: Session = Depends(get_db),
):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    # ^^ NO org_scope check — viewer of org A passes org B's release_id and gets through

    _seed_defaults(db)
    rules = db.query(LicenseRule).filter(LicenseRule.enabled == True).all()
    comps = db.query(Component).filter(Component.release_id == release_id).all()
    # ^^ Returns components for the OTHER org's release
    ...
```

`org_scope` is in signature but **never checked**. Classic CWE-639. The `_assert_release_org` helper from `releases.py:87` was not adopted here.

### Evidence / PoC

PoC script: `.knowledge/audit/poc/SEC-001b-licenses-release-idor.py`

Expected behaviour:
```
viewer A logs in → obtains org B's release_id (assume from leaked PDF / shared link / audit log)
GET /api/licenses/releases/{org_b_release_id}/violations as viewer A
→ 200 with org B's component license violations  ← LEAK
```

After fix:
```
GET /api/licenses/releases/{org_b_release_id}/violations as viewer A
→ 403 "此 release 不屬於您的組織"
```

### Impact

Direct cross-tenant browsing: per-release license posture of any tenant whose release_id leaks. Combined with SEC-001a (which exposes per-rule counts platform-wide), an attacker can pinpoint *which* tenant has *which* license violations.

### Likelihood

- Discovery cost: Low — endpoint pattern in `/docs`
- Exploitation cost: Low — one GET; needs a release_id from target tenant. UUID = unguessable but leakable via PDF report metadata, share-link list, public NOTICE.md file (currently NOTICE.md doesn't include release IDs but `evidence-package` zip outputs do)
- Stealth: High — log shows GET with a UUID; no obvious cross-tenant marker

### Recommendation

#### primary_remediation

```diff
+# In core/deps.py — add this once
+def assert_release_in_scope(release: "Release", org_scope: str | None) -> None:
+    if release is None:
+        raise HTTPException(status_code=404, detail="Release not found")
+    if org_scope and release.product.organization_id != org_scope:
+        raise HTTPException(status_code=403, detail="此 release 不屬於您的組織")

# In licenses.py:139
 @router.get("/releases/{release_id}/violations")
 def release_violations(
     release_id: str,
     org_scope: str | None = Depends(get_org_scope),
     db: Session = Depends(get_db),
 ):
     release = db.query(Release).filter(Release.id == release_id).first()
-    if not release:
-        raise HTTPException(status_code=404, detail="Release not found")
+    assert_release_in_scope(release, org_scope)
```

- effort: S (helper + 2-line replacement)
- risk_of_fix: Low

#### defense_in_depth
Same as SEC-001a:CI lint rule + `tests/test_multi_tenant_isolation.py`.

#### compensating_control
**No clean compensating control** for IDOR (can't `require_admin` the endpoint — viewers legitimately need to see their own release violations). Hot-fix = primary_remediation directly.

- effort: S
- risk_of_fix: Low (returning 403 to forged release_ids has no legitimate caller impact)

#### monitoring_detection
Structured log: `caller_user_id`, `caller_org_id`, `release_id`, `release.product.organization_id`. Alert when `caller_org_id ≠ release.product.organization_id` (which after fix should never happen → alert on >0 occurrences).

- effort: M (~2h log + alert)
- risk_of_fix: None

### References
Same as SEC-001a + Postgres Row-Level Security (long-term defence in depth) — https://www.postgresql.org/docs/current/ddl-rowsecurity.html

---

## SEC-001c — `policies.py:164` `/api/policies/violations/summary` returns platform-wide policy violations to any viewer

### Metadata

| field                     | value |
|---------------------------|-------|
| finding_id                | SEC-001c |
| traceability              | TLT-1; attack-tree-#1.path-A.leaf-2; abuse-case — N/A |
| status                    | open |
| discovered_phase          | 3 |
| verification_method       | static + dynamic-poc-pending |
| first_observed_commit     | `e207d53` (2026-04-21) |
| exploitation_complexity   | **low** (same as SEC-001a — one GET with viewer JWT) |
| severity_lan_only         | **Medium** |
| severity_if_public        | **High** (slightly higher than SEC-001a because policy violations expose vuln state, not just license posture; competitive intelligence richer) |
| blocks_commercialization  | **true** |
| confidence                | High |
| category                  | Multi-tenant / Authz / Information Disclosure |
| cwe                       | CWE-285 + CWE-200 |
| owasp                     | OWASP API3:2023 + A01:2021 |
| cvss_3_1                  | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **6.5** lan_only / **7.7** if_public |

### compliance_impact

```yaml
compliance_impact:
  - framework: SOC2
    control: CC6.1
    gap_type: control_partial
  - framework: SOC2
    control: CC6.3
    gap_type: control_missing
  - framework: ISO27001
    control: A.5.15
    gap_type: control_partial
  - framework: ISO27001
    control: A.8.3
    gap_type: control_missing
  - framework: GDPR
    control: Art.32(1)(b)
    gap_type: control_partial
  - framework: IEC62443-4-1
    control: SI-1
    gap_type: control_partial
  - framework: IEC62443-4-1
    control: SM-9
    gap_type: control_partial
    note: Same defective pattern in both licenses.py and policies.py = process gap (no review caught it twice).
```

### Location
- `backend/app/api/policies.py:164-181`

### Observation
```python
@router.get("/violations/summary")
def violations_summary(db: Session = Depends(get_db)):
    """Platform-wide violation counts per rule."""
    _seed_defaults(db)
    rules = db.query(PolicyRule).filter(PolicyRule.enabled == True).all()
    vulns = db.query(Vulnerability).all()       # ← ALL vulns across all tenants
    summary = []
    for rule in rules:
        count = sum(1 for v in vulns if _evaluate_rule(rule, v))
        ...
```

Identical shape to SEC-001a: no `org_scope`, returns aggregate over all tenants. Worse impact because policy violations include "Critical vuln older than 7 days" — directly exposes tenant security posture maturity.

### Evidence / PoC
PoC script: `.knowledge/audit/poc/SEC-001c-policies-summary-leak.py`. Same shape as SEC-001a PoC.

### Impact, Recommendation, References
**Same as SEC-001a** modulo the data type (vuln-policy violations vs license violations). Defer to SEC-001a body for full text; primary_remediation is again `require_admin` plus per-tenant `/violations/my-summary` if frontend needs viewer access.

---

## SEC-001d — `policies.py:184` `/api/policies/releases/{release_id}/violations` IDOR(no org_scope param at all)

### Metadata

| field                     | value |
|---------------------------|-------|
| finding_id                | SEC-001d |
| traceability              | TLT-1; attack-tree-#1.path-C.leaf-2; abuse-case — N/A |
| status                    | open |
| discovered_phase          | 3 |
| verification_method       | static + dynamic-poc-pending |
| first_observed_commit     | `e207d53` (2026-04-21) |
| exploitation_complexity   | **low** (worse than SEC-001b because there's not even an org_scope param to confuse a future maintainer) |
| severity_lan_only         | **Medium** |
| severity_if_public        | **High** |
| blocks_commercialization  | **true** |
| confidence                | High |
| category                  | Multi-tenant / Authz / IDOR |
| cwe                       | CWE-639 + CWE-285 |
| owasp                     | OWASP API1:2023 BOLA + A01:2021 |
| cvss_3_1                  | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **6.5** lan_only / **7.7** if_public |

### compliance_impact
Same as SEC-001b plus IEC 62443-4-1 SM-9 (process gap — same defect in two routers).

### Location
- `backend/app/api/policies.py:184-218`

### Observation
```python
@router.get("/releases/{release_id}/violations")
def release_violations(release_id: str, db: Session = Depends(get_db)):
    """Violations for a specific release."""
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    # ^^ no org_scope param at all in signature; pure IDOR
    ...
    components = db.query(Component).filter(Component.release_id == release_id).all()
    vulns = [v for c in components for v in c.vulnerabilities]
```

Worse than SEC-001b: `org_scope` is not even in the signature, so a maintainer reading the file can't tell isolation was intended.

### Recommendation
Same as SEC-001b: introduce `assert_release_in_scope` helper, use it after the lookup, plus add `org_scope: str | None = Depends(get_org_scope)` to the function signature.

```diff
 @router.get("/releases/{release_id}/violations")
-def release_violations(release_id: str, db: Session = Depends(get_db)):
+def release_violations(release_id: str,
+                       org_scope: str | None = Depends(get_org_scope),
+                       db: Session = Depends(get_db)):
     """Violations for a specific release."""
     release = db.query(Release).filter(Release.id == release_id).first()
-    if not release:
-        raise HTTPException(status_code=404, detail="Release not found")
+    assert_release_in_scope(release, org_scope)
```

monitoring_detection / defense_in_depth / compensating_control identical to SEC-001b.

---

## SDLC-001 — Architectural: lacks mandatory release-ownership middleware; release-scoped endpoints rely on per-developer manual filter (root cause of SEC-001a/b/c/d)

### Metadata

| field                     | value |
|---------------------------|-------|
| finding_id                | SDLC-001 |
| traceability              | TLT-1 (parent threat); attack-tree-#1 (entire tree); SEC-001a/b/c/d (symptoms) |
| status                    | open |
| discovered_phase          | 3 (extracted from SEC-001 RCA) |
| verification_method       | manual-review (process / architecture finding, not a runtime bug per se) |
| first_observed_commit     | n/a (architectural absence is "since beginning of project") |
| exploitation_complexity   | n/a (this enables future SEC-001-type bugs; itself not exploitable) |
| severity_lan_only         | **Low** (no immediate exploit beyond SEC-001a/b/c/d) |
| severity_if_public        | **Medium** (recurrence likelihood high; SOC 2 evidence finding) |
| blocks_commercialization  | **partial** (SOC 2 Type II will note "no preventive control for the SEC-001 pattern") |
| confidence                | High |
| category                  | SDLC / Architecture |
| cwe                       | n/a (architectural;CWE-285 is what it enables)|
| owasp                     | n/a |
| cvss_3_1                  | n/a (not a runtime vulnerability) |

### compliance_impact

```yaml
compliance_impact:
  - framework: SOC2
    control: CC8.1
    gap_type: control_missing
    note: Change management — code review process did not catch SEC-001a/b/c/d twice.
  - framework: SOC2
    control: CC7.2
    gap_type: control_missing
    note: System monitoring — no detective control for cross-tenant access patterns.
  - framework: ISO27001
    control: A.5.36
    gap_type: control_partial
    note: Compliance with policies for system security.
  - framework: IEC62443-4-1
    control: SM-9
    gap_type: control_missing
    note: |
      Process improvement requires evidence of recurring defect
      classification.  SEC-001a/b/c/d demonstrate a recurring class
      of defect; SDLC-001 is the systemic counter-measure.
  - framework: IEC62443-4-1
    control: SI-2
    gap_type: control_missing
    note: Secure implementation requires reusable safe patterns; current pattern is "remember to call _assert".
```

### Location

- Architectural absence:no enforcement layer between `@router.<method>` decorators and per-endpoint code that ensures release-scoped access checks
- Negative space:`backend/app/core/deps.py` has `get_org_scope`, `require_admin`, but no `require_release_in_scope(release_id)` decorator/dependency
- Partial example:`backend/app/api/releases.py:87` `_assert_release_org` is a private helper(not decorator);used by convention not by mandate

### Observation

The pattern:
```python
# Current — convention-based (used in 30 places in releases.py):
@router.get("/{release_id}/something")
def endpoint(release_id: str, org_scope = Depends(get_org_scope), db = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    _assert_release_org(release, org_scope, db)   # ← MUST remember to call
    # ... business logic
```

Problem:**convention is not enforcement**. Two new routers were added 2026-04-21 / 2026-04-22 without the call. Two endpoints in the existing licenses.py also lack it. **The pattern is "remember to do the right thing"** — fundamentally fragile.

### Recommendation

#### primary_remediation
**Introduce a FastAPI dependency that does the check** as part of the route signature, so forgetting it is impossible:

```python
# backend/app/core/deps.py — new dependency
from fastapi import Depends, Path, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.deps import get_org_scope

def require_release_in_scope(
    release_id: str = Path(...),
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    """FastAPI dependency: load Release, assert ownership, return release.
    Use it as a route parameter — forgetting becomes a syntax error,
    not a silent leak."""
    from app.models.release import Release
    release = db.query(Release).filter(Release.id == release_id).first()
    if release is None:
        raise HTTPException(status_code=404, detail="Release not found")
    if org_scope and release.product.organization_id != org_scope:
        raise HTTPException(status_code=403, detail="此 release 不屬於您的組織")
    return release
```

Usage at route:
```python
@router.get("/releases/{release_id}/violations")
def release_violations(release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    # release is already loaded + ownership-verified
    # business logic here
```

Apply to all release-scoped endpoints. Migrate `releases.py:_assert_release_org` callers progressively (each migration is independent).

- **effort**: M (~4h — write dependency, migrate ~30 callers in releases.py + the 4 SEC-001a-d sites)
- **risk_of_fix**: Low-Medium (extensive surface; per-router migration; covered by `tests/test_multi_tenant_isolation.py`)

#### defense_in_depth
- **CI lint rule**: ban `release_id: str` route parameter in any function whose signature does not include `Depends(require_release_in_scope)` or `Depends(require_admin)`. Implementation: simple grep-based check in `tools/lint/check-release-scope.py`.
- **Type-level**: change `Release` ORM model so direct `db.query(Release).filter(Release.id == ...)` outside the dependency is a flake8 violation (custom rule). Aggressive — defer to maintainer judgement.
- **DB layer (Postgres)**: enable Row-Level Security with policy `release.product.organization_id = current_setting('app.org_id')`. Defence-in-depth at storage layer means even a router bug can't leak.

- **effort**: M (CI lint ~1h) + L (RLS migration ~1 day)
- **risk_of_fix**: Low

#### compensating_control
N/A — architectural finding; per-incident compensations are in SEC-001a/b/c/d.

#### monitoring_detection
- **Quarterly architectural review**:run a scripted check that lists all release-scoped routes and confirms each uses `Depends(require_release_in_scope)`. Output → SOC 2 audit evidence file.
- **Audit log enrichment**:add `caller_org_id` + `target_resource_org_id` to every audit_event row. Periodic SQL `SELECT ... WHERE caller_org_id != target_resource_org_id` flags any cross-tenant access — alert on count > 0.

- **effort**: M (each — quarterly check 1h, audit log enrichment 4h with migration)
- **risk_of_fix**: None (observability)

### References
- FastAPI dependencies — https://fastapi.tiangolo.com/tutorial/dependencies/
- SOC 2 CC8.1 (Change Management) / CC7.2 (System Monitoring) — AICPA TSP section 100
- IEC 62443-4-1 SM-9 (Process Improvement) / SI-2 (Secure Implementation Resources)
- "Build Security In" — fail-safe defaults principle (Saltzer & Schroeder, 1975)

---

## Phase 3 first finding — SCHEMA REVIEW GATE(per amendment 第 5 步)

✅ Done in this round:
1. Schema:加 `first_observed_commit` + `exploitation_complexity`, status enum 加 `wont-fix-accepted-risk`, traceability 反向連到 attack-tree leaf
2. SEC-001 拆成 SEC-001 parent + SEC-001a/b/c/d sub-findings + SDLC-001 architectural parent
3. SEC-001a 完整版本(含 PoC plan + 4-layer recommendation 用新標籤名 `primary_remediation` / `defense_in_depth` / `compensating_control` / `monitoring_detection`)
4. SEC-001b/c/d 完整 metadata + observation + recommendation outline(評估後決定 referenced-by-001a 還是各自完整;目前是各自完整避免「點到 001a 才看得到」的查報表麻煩)
5. SDLC-001 完整版本(architectural finding,系統性根因)

⏳ Pending in this round(待執行):
- PoC2 actual run + evidence files at `.knowledge/audit/evidence/2026-04-26/SEC-001*.md`
- Private repo mirror setup(user 需先建 GitHub private repo)

**等你 review 確認:**
1. **新增 2 欄 + 改 status enum + traceability 細化** schema 對嗎?
2. **Split 結構**(parent SEC-001 RCA + 4 sub-findings + SDLC-001 architectural):落地對嗎?客戶 review 時資訊架構合理嗎?
3. **4-layer recommendation 用新標籤** + 加入 `monitoring_detection`:對嗎?
4. **SEC-001a 是 canonical example**;批量寫剩 20 條 TLT 的 finding 全用同 schema + 同 4-layer rec + 同 traceability 細化 → 確認嗎?
5. **SEC-001b/c/d 寫法**:目前每個都完整 metadata + 簡短 observation/recommendation(因為跟 a 高度共享,但不放 see SEC-001a 的省略寫法)— 對嗎?還是要 b/c/d 大幅簡化只留 metadata + diff?

回覆完即動 PoC2 + 批量。
