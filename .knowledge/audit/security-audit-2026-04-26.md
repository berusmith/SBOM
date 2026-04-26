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
- **SEC-001 (parent)** — `/violations/*` endpoint family systemically lacks release-ownership check (rev-2 reworded from "multi-tenant pattern" to the more precise endpoint-family scope);RCA + sub-system remediation pointer;no own severity
- **SEC-001a** — `licenses.py /violations/summary` cross-tenant disclosure
- **SEC-001b** — `licenses.py /releases/{id}/violations` IDOR
- **SEC-001c** — `policies.py /violations/summary` cross-tenant disclosure
- **SEC-001d** — `policies.py /releases/{id}/violations` IDOR
- **SDLC-001** — architectural:lacks mandatory release-ownership middleware

Schema-review gate per user direction:**SEC-001a written fully(含 PoC2 evidence)→ user review → 才批量寫剩 20 條 TLT finding**。

---

## SEC-001 (parent) — `/violations/*` endpoint family systemically lacks release-ownership check

**Status:**parent / tracking only / no own severity / no own CVSS
**Scope correction (rev-2 amend)**:**not** a "multi-tenant systemic" issue across the whole codebase — `stats.py`, `products.py`, `search.py`, `firmware.py`, `organizations.py` all have isolation in place. The systemic pattern is **confined to the violations-endpoint family** (`/api/licenses/violations/*` + `/api/policies/violations/*`). The broader cross-codebase systemic gap (no mandatory middleware) is captured in **SDLC-001** at cross-cutting scope, not here.

This finding is the parent for SEC-001a/b/c/d. It exists to record the family pattern, not to be patched directly. Patches happen on the children.

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
| parent_finding            | SEC-001 |
| status                    | open |
| discovered_phase          | 3 |
| verification_method       | static + dynamic-poc |
| first_observed_commit     | `4bb8a75` (2026-04-22, "feat: license compliance policy engine") |
| exploitation_complexity   | **low** (authenticated viewer JWT; one GET request; no payload crafting) |
| severity_lan_only         | **Medium** |
| severity_if_public        | **High** |
| blocks_commercialization  | **true** |
| confidence                | **High** (4 confirmed lines of code, no inference; PoC executed 2026-04-26 LEAK confirmed; LAN exposure window 4 days from commit to audit) |
| category                  | Multi-tenant / Authz / Information Disclosure |
| cwe                       | [CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) + [CWE-200 Information Exposure](https://cwe.mitre.org/data/definitions/200.html) |
| owasp                     | OWASP API3:2023 Broken Object Property Level Authorization + A01:2021 Broken Access Control |
| cvss_3_1                  | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **6.5 (Medium)** lan_only;`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` = **7.7 (High)** if_public(scope changes when tenants are competitors)|

### traceability

```yaml
traceability:
  threat: TLT-1                             # multi-tenant isolation
  parent_finding: SEC-001                   # /violations endpoint family
  attack_tree_leaf: attack-tree-1.branch-A.leaf-2   # cross-tenant aggregate-endpoint exfil
  abuse_cases: [abuse-7]                    # insider hides Critical to bypass Policy Gate (partial)
  # Note: there's no current ABU entry for "competitive intelligence via license posture";
  # future amendment may add ABU-11 and link here.
```

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

#### monitoring_detection (rev-2:aggregate-endpoint pattern,async pipeline)

SEC-001a is an aggregate endpoint — no per-record `caller_org_id` to compare to. Per-request DB count of viewer's owned releases is too heavy for the request critical path. Move alerting to the application log pipeline (Loki / CloudWatch / OpenSearch — whatever lands in commercialisation), do post-response async comparison.

```yaml
monitoring_detection:
  applies_to_finding: SEC-001a
  endpoint_class: aggregate                  # not record-level — see SEC-001b/d for IDOR pattern
  log_pipeline: post-response, async, structured (JSON)
  log_field:
    name: result_org_ids
    type: List[UUID]
    sourced_from: |
      SQL trace of the resolved Component query — capture the
      DISTINCT organisation_id values that ended up contributing
      to the per-rule counts.  Implementation: wrap the
      _matches() loop with an org_id collector populated from
      `comp.release.product.organization_id`.
  alert_rule: |
    any(org_id != caller_org_id for org_id in result_org_ids)
    # i.e. if the response was constructed from any org other
    # than the caller's, raise alert.
  notes: |
    For admin callers (org_scope=null), suppress alert — admin
    seeing all orgs is by design.  Filter on
    `caller_role != "admin"` before applying the rule.
```

- **effort**: M (~2h for the log + ~1h for alert wire-up in chosen log pipeline)
- **risk_of_fix**: None (post-response async log, never blocks the request)

Phase 6 verification: PoC2 re-run after Phase 5 patch must produce 403 (compensating_control) or scoped 0-count result (primary_remediation).
Long term: SOC 2 Type II evidence — quarterly run of `tests/test_multi_tenant_isolation.py` against production-like staging, log retained.

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
| parent_finding            | SEC-001 |
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

### traceability

```yaml
traceability:
  threat: TLT-1
  parent_finding: SEC-001
  attack_tree_leaf: attack-tree-1.branch-C.leaf-2   # cross-tenant via guessable resource id
  abuse_cases: []                                    # no current ABU entry; see SEC-001a notes
```

### compliance_impact

**(differentiated from SEC-001a — IDOR with viewer auth hits CC6.3 + A.5.18, not just A.5.15)**

```yaml
compliance_impact:
  - framework: SOC2
    control: CC6.1
    gap_type: control_partial
  - framework: SOC2
    control: CC6.3
    gap_type: control_missing
    note: |
      Need-to-know failure at object level (release_id is the key);
      SEC-001a is at aggregate level (no per-object key).
  - framework: ISO27001
    control: A.5.18      # rev-2: differentiated from SEC-001a's A.5.15
    gap_type: control_missing
    note: |
      Access rights — explicitly the wrong granularity (object level
      access without ownership check). Distinct from A.5.15 access
      control policy gap that hits the aggregate endpoint.
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
+# In core/deps.py — add this once.  Both branches return 404 to
+# avoid release_id enumeration oracle.
+def assert_release_in_scope(release: "Release", org_scope: str | None) -> None:
+    """Combined existence + ownership check.  Returns 404 in both
+    failure modes so an attacker cannot distinguish 'doesn't exist'
+    from 'exists but not yours' (CWE-204 Observable Response
+    Discrepancy)."""
+    if release is None:
+        raise HTTPException(status_code=404, detail="Release not found")
+    if org_scope and release.product.organization_id != org_scope:
+        raise HTTPException(status_code=404, detail="Release not found")

# In licenses.py:139
 @router.get("/releases/{release_id}/violations")
 def release_violations(
     release_id: str,
     org_scope: str | None = Depends(get_org_scope),
     db: Session = Depends(get_db),
 ):
-    release = db.query(Release).filter(Release.id == release_id).first()
-    if not release:
-        raise HTTPException(status_code=404, detail="Release not found")
+    release = (db.query(Release)
+               .options(joinedload(Release.product))   # for monitoring + ownership
+               .filter(Release.id == release_id)
+               .first())
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

#### monitoring_detection (rev-2:IDOR-endpoint pattern,in-handler blocking — implementation cost ≈ 0)

SEC-001b is a record-level IDOR — `release.product.organization_id` is already loaded by the handler (the primary_remediation patch has the handler check it before the 404). The monitoring is a logging side-effect of the same query, not extra DB work.

```yaml
monitoring_detection:
  applies_to_finding: SEC-001b
  endpoint_class: idor                          # record-level — opposite of SEC-001a's aggregate
  log_pipeline: in-handler, blocking            # because primary_remediation needs the same value
  log_fields:
    - name: caller_user_id
      type: UUID
    - name: caller_org_id
      type: UUID
    - name: requested_release_id
      type: UUID
    - name: target_release_org_id              # === release.product.organization_id
      type: UUID
  alert_rule: |
    target_release_org_id != caller_org_id
    # After fix this can never produce a 200; it WILL trigger if the fix
    # regresses (release loaded but check skipped) or if a different
    # endpoint reuses the same anti-pattern.
  notes: |
    Admin (caller_org_id == null OR caller_role == "admin"): suppress
    alert — admin cross-org access is by design.
    Implementation cost ≈ 0 because the load + ownership check is
    already in the primary_remediation patch; this layer just adds
    structured-log emission of the same fields.
```

**Co-located primary + monitoring(具體 5 行)**:

```python
# SEC-001b primary_remediation + monitoring_detection co-located
release = (
    db.query(Release)
      .options(joinedload(Release.product))
      .filter(Release.id == release_id)
      .first()
)
if release is None:
    raise HTTPException(404, detail="Release not found")
if org_scope and release.product.organization_id != org_scope:    # primary_remediation
    log.warning("idor_attempt", extra={                            # monitoring_detection
        "endpoint": "licenses.releases.violations",
        "caller_org_id": org_scope,
        "target_release_org_id": release.product.organization_id,
        "release_id": release.id,
    })
    raise HTTPException(404, detail="Release not found")           # ← 404 not 403, see below
```

**404 not 403 — IDOR oracle prevention(rev-2 amendment 套用所有 IDOR 類 finding)**:

回 403 「此 release 不屬於您的組織」會給 attacker 一個 oracle:

| Attacker GET `release_id=X` 拿到 | 結論 |
|---------------------------------|------|
| `200` + 違規清單 | release 屬於我,正常 |
| `403` 訊息「不屬於您」 | release **存在** + 屬於別組織 → release_id 是有效值 + 跨組 enumeration 已成立 |
| `404` 訊息「Release not found」 | release **可能**不存在 / 可能存在但不屬於我 → attacker 無法區分 |

403 直接洩漏 release_id 是否為有效 UUID + 是否跨組,變成 enumeration 工具。404 把「不存在」與「不屬於我」回應折成同一個,不給 oracle。

**套用範圍(rev-2 amendment)**:
- **SEC-001b / SEC-001d**(IDOR 類):primary_remediation 改 `raise HTTPException(404, "Release not found")`,**不**用 403
- **SEC-001a / SEC-001c**(endpoint-level role gate via `require_admin`):保留 `raise HTTPException(403, "此操作需要管理員權限")`,因為這是「endpoint 對 role 的可達性」非「resource 對 user 的可見性」,403 在語意上正確且不洩漏 resource 存在性

- effort: S (~30min — adds structured log line at the same point as the 404 raise)
- risk_of_fix: None (logging only;404 換 403 的 frontend 影響:任何依賴 403 訊息文字判斷「是否為跨組存取」的 client code 會看不到差異 — 反正它本來也不該依賴這個 oracle)

### References
Same as SEC-001a + Postgres Row-Level Security (long-term defence in depth) — https://www.postgresql.org/docs/current/ddl-rowsecurity.html

---

## SEC-001c — `policies.py:164` `/api/policies/violations/summary` returns platform-wide policy violations to any viewer

### Metadata

| field                     | value |
|---------------------------|-------|
| finding_id                | SEC-001c |
| parent_finding            | SEC-001 |
| status                    | open |
| discovered_phase          | 3 |
| verification_method       | static + dynamic-poc-pending |
| first_observed_commit     | `e207d53` (2026-04-21) |
| exploitation_complexity   | **trivial** (rev-2 differentiation:exposes vuln state directly,no per-CVE crafting needed,one GET) |
| severity_lan_only         | **Medium** |
| severity_if_public        | **High** (slightly higher than SEC-001a because policy violations expose vuln state, not just license posture; competitive intelligence richer) |
| blocks_commercialization  | **true** |
| confidence                | High |
| category                  | Multi-tenant / Authz / Information Disclosure |
| cwe                       | CWE-285 + CWE-200 |
| owasp                     | OWASP API3:2023 + A01:2021 |
| cvss_3_1                  | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **6.5** lan_only / **7.7** if_public |

### traceability

```yaml
traceability:
  threat: TLT-1
  parent_finding: SEC-001
  attack_tree_leaf: attack-tree-1.branch-A.leaf-2   # same aggregate-endpoint exfil branch as 001a
  abuse_cases: [abuse-7]                            # insider hides Critical to bypass Policy Gate
```

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

### Impact

**Higher than SEC-001a** because policy violations directly expose vuln state (e.g. "Critical-older-than-7d" rule count), not just license posture. For B2B SaaS commercialisation, this is competitive-intelligence rich:
- "Tenant X has 47 Critical-older-than-7d violations" → security maturity inferred
- Per-rule counts allow attacker to identify the worst-managed tenant (highest counts) and target social engineering / supply-chain attack at it

### Recommendation (per rev-2 sub-finding折衷:reuse SEC-001a layers, monitoring differs by endpoint class)

#### primary_remediation
**See SEC-001 §primary_remediation pattern** — same `require_admin` shape as SEC-001a's Patch A. Patch text:

```diff
-@router.get("/violations/summary")
-def violations_summary(db: Session = Depends(get_db)):
+@router.get("/violations/summary")
+def violations_summary(_admin: dict = Depends(require_admin),
+                       db: Session = Depends(get_db)):
     """Platform-wide policy violation counts per rule (admin only)."""
```

- effort: S
- risk_of_fix: Low

#### defense_in_depth
See SEC-001a §defense_in_depth(同 lint rule + 同 isolation test suite,both endpoints covered)。

#### compensating_control
See SEC-001a §compensating_control(同 hot-patch `require_admin`)。

#### monitoring_detection (rev-2:aggregate endpoint pattern,reuses SEC-001a structure)

See **SEC-001a §monitoring_detection** for the full schema. SEC-001c uses the same aggregate-endpoint async-pipeline pattern; only the source SQL changes:

```yaml
monitoring_detection:
  applies_to_finding: SEC-001c
  endpoint_class: aggregate
  log_pipeline: post-response, async, structured (JSON)
  log_field:
    name: result_org_ids
    type: List[UUID]
    sourced_from: |
      Wrap _evaluate_rule loop with org_id collector populated from
      `vuln.component.release.product.organization_id`.
  alert_rule: |
    any(org_id != caller_org_id for org_id in result_org_ids)
    # Suppress for caller_role == "admin"
```

- effort: M (~3h — slightly more than SEC-001a because vuln→component→release→product chain has 3 joins)
- risk_of_fix: None

### References
Same as SEC-001a + OWASP Multi-tenancy Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenancy_Cheat_Sheet.html

---

## SEC-001d — `policies.py:184` `/api/policies/releases/{release_id}/violations` IDOR(no org_scope param at all)

### Metadata

| field                     | value |
|---------------------------|-------|
| finding_id                | SEC-001d |
| parent_finding            | SEC-001 |
| status                    | open |
| discovered_phase          | 3 |
| verification_method       | static + dynamic-poc-pending |
| first_observed_commit     | `e207d53` (2026-04-21) |
| exploitation_complexity   | **low** (worse than SEC-001b in code-readability terms — no org_scope param at all in signature so a future maintainer can't tell isolation was intended; same exploit shape) |
| severity_lan_only         | **Medium** |
| severity_if_public        | **High** |
| blocks_commercialization  | **true** |
| confidence                | High |
| category                  | Multi-tenant / Authz / IDOR |
| cwe                       | CWE-639 + CWE-285 |
| owasp                     | OWASP API1:2023 BOLA + A01:2021 |
| cvss_3_1                  | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = **6.5** lan_only / **7.7** if_public |

### traceability

```yaml
traceability:
  threat: TLT-1
  parent_finding: SEC-001
  attack_tree_leaf: attack-tree-1.branch-C.leaf-2   # same IDOR branch as 001b
  abuse_cases: []
```

### compliance_impact

**(differentiated from SEC-001c — IDOR shape hits the same controls as SEC-001b plus the SM-9 process-gap finding from "same defect in two routers")**

```yaml
compliance_impact:
  - framework: SOC2
    control: CC6.1
    gap_type: control_partial
  - framework: SOC2
    control: CC6.3
    gap_type: control_missing
    note: |
      Need-to-know failure at object level — same gap as SEC-001b
      but with the additional code-readability degradation (no
      org_scope param means future maintainer can't even tell
      isolation was supposed to be there).
  - framework: ISO27001
    control: A.5.18
    gap_type: control_missing
    note: Object-level access rights — same as SEC-001b.
  - framework: ISO27001
    control: A.5.15
    gap_type: control_partial
  - framework: GDPR
    control: Art.32
    gap_type: control_partial
  - framework: IEC62443-4-1
    control: SI-1
    gap_type: control_partial
  - framework: IEC62443-4-1
    control: SM-9
    gap_type: process_gap
    rationale: |
      SEC-001b 與 SEC-001d 是同一 IDOR pattern 在 licenses + policies
      兩個 router 重複出現。單一 occurrence(SEC-001b 自身)屬
      individual slip,可由 code review 攔截;但 SEC-001d 證明 review
      process 連續兩次未攔截同一 anti-pattern,構成 process-level 缺陷,
      落入 SM-9(Security requirements review process)範圍。
      SEC-001a/c 是 missing-auth pattern(完全沒 org_scope),不是同一類
      缺陷,不重複計 SM-9。
      商業化做 IEC 62443-4-1 self-assessment 時這段 rationale 可直接引用。
```

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

### Recommendation (per rev-2 sub-finding 折衷)

#### primary_remediation
Same shape as SEC-001b but adds the missing `org_scope` to signature first:

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

- effort: S
- risk_of_fix: Low

#### defense_in_depth
See SEC-001b §defense_in_depth(同 lint rule + 同 isolation test suite,both endpoints covered)。

#### compensating_control
See SEC-001b §compensating_control(IDOR 沒有乾淨 compensating;hot-fix == primary_remediation)。

#### monitoring_detection (rev-2:IDOR endpoint pattern,reuses SEC-001b structure)

See **SEC-001b §monitoring_detection** for the full schema. SEC-001d uses identical IDOR-endpoint in-handler-blocking pattern; only the source endpoint differs:

```yaml
monitoring_detection:
  applies_to_finding: SEC-001d
  endpoint_class: idor
  log_pipeline: in-handler, blocking
  log_fields: [caller_user_id, caller_org_id, requested_release_id, target_release_org_id]
  alert_rule: target_release_org_id != caller_org_id
  notes: |
    Implementation cost ≈ 0 — adds structured log line at the same
    point where primary_remediation raises 403.  Same as SEC-001b.
```

- effort: S (~30min)
- risk_of_fix: None

---

## SDLC-001 — Architectural: **auth/scope mandatory middleware gap** (rev-3 narrowed scope)

**rev-3 scope narrowing**(per user round-3 review):
- **Old scope (rev-2)**:「整個 codebase 缺 mandatory middleware 文化」(broad)
- **New scope (rev-3)**:「auth / scope check 缺 mandatory middleware」(specific to authorization layer)
- **Why narrow**:Phase 3 batch self-check 顯示 expected_recurrence 命中率 50%(2 of 4 — 詳細表格見下)。2 條沒命中代表 SDLC-001 的 RCA 過度延伸,把 violations endpoint family 的 specific gap 誤判成全 codebase pattern。
- **拆分**:perimeter / transport / nginx 那類 cross-cutting issue 移到新增的 **SDLC-002 (perimeter & transport hardening)**;audit log integrity 系列移到 **SDLC-003 (audit/logging maturity)**。每個 SDLC-NNN 對應一個明確的 cross-cutting gap,Phase 4 architectural section 才有層次。

### Metadata

| field                     | value |
|---------------------------|-------|
| finding_id                | SDLC-001 |
| parent_finding            | null (top-level architectural finding) |
| **scope**                 | **cross-cutting** (rev-2 elevation:references multiple TLTs;Phase 4 報告放在 "Architectural / SDLC findings" section,不放在 per-TLT 列表)|
| status                    | open |
| discovered_phase          | 3 (extracted from SEC-001 RCA;**位階提升**:不只是 SEC-001 的 root cause,是跨 TLT 的 systemic gap)|
| verification_method       | manual-review (process / architecture finding, not a runtime bug per se) |
| first_observed_commit     | n/a (architectural absence is "since beginning of project") |
| exploitation_complexity   | n/a (this enables future authorization bugs across multiple endpoint classes; itself not exploitable) |
| severity_lan_only         | **Medium** (rev-2 raised from Low — recurrence already happened twice in violations endpoints, will keep happening at TLT-3 / TLT-7 / TLT-13 / TLT-18 surface as Phase 3 progresses) |
| severity_if_public        | **High** (rev-2 raised from Medium — SOC 2 Type II auditor will treat "no preventive control for systemic auth check" as a control deficiency, not a single-finding issue) |
| blocks_commercialization  | **true** (rev-2 raised from partial — without this finding being remediated, every new endpoint added by future engineers can re-introduce SEC-001-class bugs;client due-diligence will identify this as the highest-leverage SDLC fix) |
| confidence                | High |
| category                  | SDLC / Architecture |
| cwe                       | n/a (architectural; CWE-285 / CWE-639 are what it enables) |
| owasp                     | n/a |
| cvss_3_1                  | n/a (not a runtime vulnerability) |

### traceability

```yaml
traceability:
  threat: cross-cutting           # not single TLT; references multiple
  parent_finding: null
  attack_tree_leaf: null          # architectural — enables many leaves
  abuse_cases: []                 # architectural — enables many abuse cases
  references_findings:                  # rev-4 cleaned: only auth-middleware-specific symptoms
    - SEC-001a    # /api/licenses/violations/summary missing auth middleware
    - SEC-001b    # /api/licenses/releases/{id}/violations missing release-ownership middleware
    - SEC-001c    # /api/policies/violations/summary same shape as 001a
    - SEC-001d    # /api/policies/releases/{id}/violations same shape as 001b

  # rev-4 amend per user round-3 review: replace single "candidate_recurrence (none)"
  # claim with explicit audit-coverage boundary so future audit knows what was vs wasn't reviewed.
  candidate_recurrence:
    status: not_observed_in_current_audit
    scope_reviewed:
      - violations endpoint family (licenses.py + policies.py) — 4 confirmed leaks
      - Phase 1 heuristic 7 zero-`_assert_*_org` files — 5 cleared (stats / products
        / search / firmware / organizations) + 2 confirmed (licenses / policies)
      - releases.py 30 callsites of _assert_release_org — pattern correctly applied
    scope_not_reviewed:
      - admin endpoints' internal cross-org operations (users.py, admin.py — admin role
        is by-design cross-org; auth middleware gap could still allow viewer escalation
        if any non-admin route forgot require_admin_scope)
      - background threads (monitor.py / firmware async) — query paths not exhaustively
        traced for org_scope handling; monitor sends notifications across orgs by design
        but the per-tenant allowlisting hasn't been verified
      - future routers added after 2026-04-26 — SDLC-001 fix introduces middleware that
        will catch these automatically once landed, BUT until then any new release-
        scoped endpoint is at risk
      - releases.py:30 callsites verified for _assert_release_org call presence;
        argument-passing correctness (e.g. always passing org_scope, never None
        accidentally) was sampled not exhaustive
    next_audit_trigger:
      - any new router adding release_id / product_id / org_id path parameter
      - 6-month periodic review (SOC 2 Type II annual audit cadence aligned)
      - prior to commercialisation deployment (must re-verify entire surface)
      - any commit touching deps.py (helpers like require_admin / get_org_scope changes
        could silently regress isolation)
```

**rev-3 honesty note** (added after Phase 3 batch):initial Phase 2 prediction listed 4 expected recurrences;Phase 3 batch verification confirmed 2 fully (SEC-003, SEC-018) + 1 partially (SEC-013) + 1 rejected (TLT-7 JWT scope). After **rev-3 SDLC-001 scope narrowing**, SEC-003 / SEC-013 / SEC-018 were moved to **SDLC-002** (perimeter/transport) and **SDLC-003** (audit/logging maturity) respectively — SDLC-001 now references only auth-middleware-specific findings. The "candidate_recurrence (none)" claim from rev-3 was too absolute; rev-4 replaces with explicit scope_reviewed / scope_not_reviewed / next_audit_trigger so future auditors know what was vs wasn't covered.

**rev-2 rationale**:Phase 4 report will render this in its own "Architectural / SDLC findings" section (separate from per-TLT findings list). Customer due-diligence consumers value architectural findings disproportionately — they signal **process maturity**, not just defect count. Bumping severity reflects that this finding's resolution affects ALL future auth work, not just the 4 SEC-001 children.

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

---

## SDLC-002 — Architectural cross-cutting: perimeter & transport hardening gap (rev-3 split)

### Metadata

| field | value |
|-------|-------|
| finding_id | SDLC-002 |
| parent_finding | null (top-level architectural) |
| scope | cross-cutting |
| status | open |
| discovered_phase | 3 (extracted from SDLC-001 over-extended scope per rev-3 review) |
| verification_method | manual-review |
| first_observed_commit | n/a (architectural absence) |
| exploitation_complexity | n/a |
| severity_lan_only | Low (LAN-only — internet attacker absent today) |
| severity_if_public | High (commercialised exposes the perimeter) |
| blocks_commercialization | true |
| confidence | High |
| category | SDLC / Architecture / Perimeter |
| cwe | n/a |
| owasp | n/a |

### traceability

```yaml
traceability:
  threat: cross-cutting     # references TLT-3 / TLT-18 specifically
  parent_finding: null
  attack_tree_leaf: null
  references_findings:
    - SEC-003 (TLT-3 X-Forwarded-For — perimeter trust boundary mishandled)
    - SEC-018 (TLT-18 nginx security headers — defensive headers not policy-defined)

  # rev-4 amend: explicit audit-coverage boundary
  candidate_recurrence:
    status: partial_observation_in_current_audit
    scope_reviewed:
      - nginx-sbom.conf (full read);no add_header directives, no rate_limit_zone,
        no ModSecurity / WAF
      - rate_limit.py _client_ip flow (X-Forwarded-For trust)
      - alerts.py _validate_webhook_url (egress validation)
    scope_not_reviewed:
      - HTTPS / TLS configuration paths (nginx 預設 80;若客戶部署接 cert 路徑,沒檢查
        cert pinning / HSTS preload list / OCSP stapling 是否有設)
      - cors.py / FastAPI CORS middleware vs nginx CORS — 是否有 double-config 衝突
      - websocket / SSE endpoints(若 frontend 之後加,perimeter rules 可能不適用)
      - other egress points beyond webhooks(e.g. SMTP outbound to attacker-controlled
        MX, OIDC token-endpoint outbound, OSV API outbound — SEC-005 covers webhooks
        but full egress allowlist policy not reviewed)
    next_audit_trigger:
      - 任何 nginx config 改動(包括加 HTTPS / 新 location block)
      - 加任何新 outbound HTTP client(beyond `httpx` 既有用法)
      - 商業化部署前(對外 perimeter 全面重審 — TLS、WAF、DDoS protection)
      - 6-month 週期
```

### Observation
**Pattern**:邊界 / 傳輸層的安全控制散落在 nginx 個別 directive、application code 個別 header check,**沒有 policy-as-code 來 enforce 一致性**。

**已知症狀**:
- nginx config 缺 HSTS / XCTO / XFO / Referrer-Policy / CSP(SEC-018)
- nginx 預設用 `$proxy_add_x_forwarded_for`,client 可偽造 header(SEC-003)
- 沒 nginx-level rate limit(全靠 backend in-memory,SEC-021 重啟 reset)
- 沒 nginx-level WAF rule(防 path traversal / SQL injection probe / XSS payload)

### Recommendation

#### primary_remediation
**Introduce nginx config-as-code policy + minimal WAF**:
- `deploy/nginx-sbom.conf` 改成 template-driven(per-environment include),所有 security headers 在共用 include
- 加 `limit_req_zone` rate-limit at nginx layer(每 IP 100/min)— 不依賴 backend 重啟存活
- 評估 ModSecurity / nginx-OWASP-CRS(本機可選,不引入 service-level dep)

- effort:M (~3h initial,需手動測試 staging)
- risk_of_fix:Medium(改 nginx config 不慎可斷服務;rollback = revert + reload)

#### defense_in_depth
- CI rule:nginx config 改動需走 PR review,跑 `nginx -t` 語法檢查
- 文件化:`deploy/MACMINI_SETUP.md` 加 perimeter-hardening checklist

#### compensating_control
- LAN-only:nothing immediate(threat absent)
- Public:Cloudflare / WAF service 前置(off-host control)

#### monitoring_detection
- 結構化 log:nginx access log JSON,加 `client_ip`、`real_ip`、`forwarded_for_supplied`(client header是否現場偽造)等欄位
- Alert:`forwarded_for_supplied != "" && upstream_status == 200`

### References
- nginx limit_req_zone
- OWASP CRS

---

## SDLC-003 — Architectural cross-cutting: audit / logging maturity gap (rev-3 split)

### Metadata

| field | value |
|-------|-------|
| finding_id | SDLC-003 |
| parent_finding | null |
| scope | cross-cutting |
| status | open |
| discovered_phase | 3 |
| verification_method | manual-review |
| first_observed_commit | n/a |
| exploitation_complexity | n/a |
| severity_lan_only | Low |
| severity_if_public | Medium |
| blocks_commercialization | true (SOC 2 CC7.2 + GDPR storage limitation) |
| confidence | High |
| category | SDLC / Architecture / Audit |

### traceability

```yaml
traceability:
  threat: cross-cutting     # references TLT-13 + general audit completeness
  parent_finding: null
  references_findings:
    - SEC-013 (TLT-13 audit log tamper / no DB-level append-only constraint)

  # rev-4 amend: explicit audit-coverage boundary
  candidate_recurrence:
    status: partial_observation_in_current_audit
    scope_reviewed:
      - audit_event model schema (no UNIQUE / no INSERT-only constraint)
      - 21 種 audit event_type list (CLAUDE.md doc + grep-confirmed)
      - audit.record() callers (releases.py / users.py / cra.py 等)
      - monitor.py 跳過事件 logging gap (SEC-013 evidence)
    scope_not_reviewed:
      - hash chain implementation feasibility on SQLite (vs Postgres native)
      - GDPR Art.5(1)(e) IP retention — 沒實際測過自動清除是否會影響其他 query
      - 結構化 log pipeline 整合(Loki / CloudWatch / Sentry — 沒部署所以沒測對接)
      - SEC-001a/b/c/d 的 monitoring_detection 層完整性 — 如果商業化前真要落地,需驗證
        log pipeline + alert rule 在實際流量下不誤報 / 不漏報
      - 第三方工具(Trivy / Syft / EMBA)的 audit log 是否有對應的 platform-side
        record(目前 trivy_scanner 直接 subprocess.run,沒寫 audit_event)
    next_audit_trigger:
      - 任何 audit_event 模型 schema 改動
      - 部署 log pipeline 後 verify monitoring_detection alerts 真的會觸發
      - 加新 mutation endpoint 時驗證有 audit.record() 呼叫
      - 商業化前(SOC 2 Type II audit 必須驗證 audit log 完整 + immutable)
```

### Observation
**Pattern**:Audit log 是 application-level concern,沒有 DB-level integrity / immutability constraint,沒有 hash chain 防序列竄改,沒有 PII auto-redaction policy。每個 router 自己決定要不要 `audit.record()`。

**已知症狀**:
- `audit_event` 表 admin SQL UPDATE 可改 history(SEC-013)
- `ip_address` GDPR retention 無策略
- 沒結構化 log pipeline(Loki / Sentry / CloudWatch)讓 SEC-001a/c monitoring_detection 真正落地
- `monitor.py` 跳過事件不寫 audit log(只寫 in-memory `_last_skip_dt`)

### Recommendation

#### primary_remediation
**Audit pipeline policy**:
- DB-level INSERT-only(Postgres trigger / SQLite WAL-mode read-only constraint via app)
- Hash chain on every insert:`row.prev_hash + sha256(row)` → tamper detection
- IP retention:90 天 cron 把 `ip_address` 改 `[REDACTED]`(GDPR Art.5(1)(e))
- 結構化 log pipeline 部署(Phase 5 後期,搭配 monitoring_detection)

- effort:L (~6h)
- risk_of_fix:Medium

#### defense_in_depth
- CI rule:任何 mutation endpoint 必須 `audit.record(...)` 呼叫(grep-based check)
- Test:`tests/test_audit_completeness.py` — 每個 mutation 後 assert 對應 audit_event 存在

#### compensating_control
- 短期:每月手動 SQL `SELECT *, lag(...) OVER (...)` 檢查 audit timeline 連續性
- 文件化 incident-response runbook

#### monitoring_detection
- 同 primary_remediation 的 hash chain;periodic cron 驗證 chain 沒斷

### References
- SOC 2 CC7.2 / GDPR Art.5(1)(e) / IEC 62443-4-1 SUM-3

---

## Phase 5 開工 gating(等 user 看完 rev-3 amend)

待確認(以 4 件為單位):
1. ✅ SEC-002 升級 PoC 已跑 + severity 校準確認(Low/Medium 維持)
2. ✅ Top-10 reorder(SEC-017 → #0,SDLC-001 → #1,SEC-001a/b/c/d 跟在後面)
3. ✅ SDLC-001 縮 scope + SDLC-002 / SDLC-003 拆出
4. ⏳ Mirror URL — 等 user 提供

確認後,Phase 5 從 Sprint 0 SEC-017 CI baseline 開始,一路衝到 Phase 6,中間不停。
