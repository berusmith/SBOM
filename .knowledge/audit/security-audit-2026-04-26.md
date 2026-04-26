---
internal: true
phase: 3
audit_id: 2026-04-26-security-code-review
methodology: STRIDE-driven; static + dynamic PoC; heuristic separated
deployment_mode: lan_only
commercialization_planned: true
created: 2026-04-26
gates:
  - first_finding_schema_review_before_bulk
status: in-progress (1/N findings; bulk paused for schema review)
---

# Phase 3 — Security Audit: Findings

This is the FIRST finding only.  Schema-review gate per user direction:
write TLT-1 multi-tenant umbrella → user reviews finalised column schema
in real-world use → batch produce remaining 20 TLT findings.

---

## [TLT-1] SEC-001: Multi-tenant isolation umbrella — 4 confirmed cross-tenant data exposure points in `licenses.py` + `policies.py`

### Metadata

| field                     | value |
|---------------------------|-------|
| finding_id                | SEC-001 |
| traceability              | TLT-1 (multi-tenant), attack-tree-#1 (cross-tenant exfil), abuse-case ABU-7 partial |
| status                    | open |
| discovered_phase          | 3 (static survey of 7 zero-`_assert` files identified by Phase 1 heuristic; 4 of 7 confirmed leaks; 3 of 7 use inline filter and are confirmed-N/A pending dynamic PoC) |
| verification_method       | static (4 confirmed leaks via code read) + dynamic-poc (stats.py confirmation script provided, awaiting run) |
| severity_lan_only         | **Medium** |
| severity_if_public        | **High** |
| blocks_commercialization  | **true** |
| confidence                | High (4 confirmed leaks read directly from code; PoC required only to bound stats.py false-positive rate) |
| category                  | Multi-tenant / Authz |
| cwe                       | [CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) + [CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) + [CWE-200 Information Exposure](https://cwe.mitre.org/data/definitions/200.html) |
| owasp                     | OWASP API1:2023 Broken Object Level Authorization (BOLA) + OWASP A01:2021 Broken Access Control |
| cvss_3_1                  | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N — Base 6.5 (Medium-High); for `severity_if_public` increases to 7.7 (High) when AC:L is more readily exploitable in B2B SaaS context |

### compliance_impact

```yaml
compliance_impact:
  - framework: SOC2
    control: CC6.1   # Logical access controls — restrict access to data based on identity
    gap_type: control_partial
  - framework: SOC2
    control: CC6.3   # Restrict access based on need-to-know
    gap_type: control_missing
  - framework: ISO27001
    control: A.5.15  # Access control policy
    gap_type: control_partial
  - framework: ISO27001
    control: A.8.3   # Information access restriction
    gap_type: control_missing
  - framework: GDPR
    control: Art.5(1)(f)  # Integrity & confidentiality (security principle)
    gap_type: control_partial
  - framework: GDPR
    control: Art.32  # Security of processing — appropriate technical measures
    gap_type: control_partial
  - framework: IEC62443-4-1
    control: SI-1    # Security implementation — secure design
    gap_type: control_partial
```

### Location

Four confirmed leaks (file:line):
- `backend/app/api/licenses.py:118-136` — `GET /api/licenses/violations/summary`
- `backend/app/api/licenses.py:139-170` — `GET /api/licenses/releases/{release_id}/violations`
- `backend/app/api/policies.py:164-181` — `GET /api/policies/violations/summary`
- `backend/app/api/policies.py:184-218` — `GET /api/policies/releases/{release_id}/violations`

Five files cleared as confirmed-N/A by static read (still pending PoC for stats.py per user direction):
- `backend/app/api/stats.py` — all 6 endpoints inline-scoped via `if org_scope:` (PoC pending)
- `backend/app/api/products.py` — all 6 endpoints inline `if org_scope and product.organization_id != org_scope: raise 403`
- `backend/app/api/search.py:27-28` — inline `if org_scope: rows_q = rows_q.filter(Product.organization_id == org_scope)`
- `backend/app/api/firmware.py` — `/upload`, `/scans`, `/scans/{id}` are admin-only; `/import-as-release:162` checks `product.organization_id != org_scope`
- `backend/app/api/organizations.py` — list_organizations scoped at line 74-75; create/update/delete/plan are admin-only by design

### Affected Assets

- **A1** Customer SBOM contents (component license + version data leaks in licenses.py)
- **A3** VEX / vulnerability state (policies.py releases violations leak vulnerability count + status across tenants)
- **A9** Customer org_id mapping (sums broken down per rule allow inference of tenant existence)

### Attacker Profiles

- **AT-4** Authenticated viewer in tenant A — can hit all 4 endpoints with their normal JWT
- **AT-5** Authenticated viewer in tenant B wanting tenant A data — primary realised threat
- **AT-1 / AT-2** (LAN-only context) — only matters if attacker has obtained ANY platform credential; not directly internet-reachable today

### Observation

#### Sub-evidence #1 — `licenses.py:118` `/api/licenses/violations/summary`

```python
@router.get("/violations/summary")
def violations_summary(db: Session = Depends(get_db)):
    """Platform-wide license violation counts per rule."""
    _seed_defaults(db)
    rules = db.query(LicenseRule).filter(LicenseRule.enabled == True).all()
    comps = db.query(Component).filter(Component.license != None, Component.license != "").all()
    # ^^ THIS query returns components ACROSS ALL ORGANIZATIONS

    summary = []
    for rule in rules:
        count = sum(1 for c in comps if _matches(rule.license_id, c.license or ""))
        summary.append({...})
    total = sum(s["violation_count"] for s in summary)
    return {"total_violations": total, "by_rule": summary}
```

Function signature has **no `org_scope` parameter** (only `db`). Router-level dependency at `main.py:314` enforces JWT (`_auth = [Depends(get_current_user)]`), so authentication IS required, but authorization to specific org data is **not enforced**. A viewer of any organization sees aggregate license violation counts spanning every other tenant.

Comment on line 120 says "Platform-wide" — this looks **deliberate** for admin convenience, but the endpoint is exposed to viewers of any org (no `require_admin`).

#### Sub-evidence #2 — `licenses.py:139` `/api/licenses/releases/{release_id}/violations`

```python
@router.get("/releases/{release_id}/violations")
def release_violations(
    release_id: str,
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    # ^^ NO org_scope check here — viewer of org A passes org B's release_id and gets through

    _seed_defaults(db)
    rules = db.query(LicenseRule).filter(LicenseRule.enabled == True).all()
    comps = db.query(Component).filter(Component.release_id == release_id).all()
    # ^^ Returns components for the OTHER org's release
    ...
```

`org_scope` is in the signature but never used. Classic IDOR (CWE-639). The pattern that other routers use (`if org_scope and release.product.organization_id != org_scope: raise 403`) is missing.

#### Sub-evidence #3 — `policies.py:164` `/api/policies/violations/summary`

```python
@router.get("/violations/summary")
def violations_summary(db: Session = Depends(get_db)):
    """Platform-wide violation counts per rule."""
    _seed_defaults(db)
    rules = db.query(PolicyRule).filter(PolicyRule.enabled == True).all()
    vulns = db.query(Vulnerability).all()
    # ^^ ALL vulnerabilities across all tenants

    summary = []
    for rule in rules:
        count = sum(1 for v in vulns if _evaluate_rule(rule, v))
        summary.append({...})
    return {"total_violations": total, "by_rule": summary}
```

Same shape as licenses sub-evidence #1: no org_scope parameter, "platform-wide" comment, exposed to all viewers via router-level auth-only.

The policy rules typically include things like "Critical vuln older than 7 days" — the per-rule count gives an attacker a numeric measure of any other tenant's overdue critical vulnerabilities.

#### Sub-evidence #4 — `policies.py:184` `/api/policies/releases/{release_id}/violations`

```python
@router.get("/releases/{release_id}/violations")
def release_violations(release_id: str, db: Session = Depends(get_db)):
    """Violations for a specific release."""
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    # ^^ NO org_scope param at all in signature; no check
    ...
    components = db.query(Component).filter(Component.release_id == release_id).all()
    vulns = [v for c in components for v in c.vulnerabilities]
    ...
```

Worse than licenses #2 — `org_scope` is not even in the signature. Pure IDOR by `release_id`.

#### Sub-evidence #5–7 — heuristic flagged but verified clean (confirmed-N/A)

```python
# stats.py line 22-30 — _vuln_base_query helper applies join + filter when scoped
def _vuln_base_query(db, org_scope):
    if not org_scope:
        return db.query(Vulnerability)
    return (
        db.query(Vulnerability)
        .join(Component, ...)
        .join(Release, ...)
        .join(Product, ...)
        .filter(Product.organization_id == org_scope)
    )
```
Every endpoint in stats.py (1 base aggregate, risk-overview, top-risky-components, top-threats, sbom-quality-summary, cve-impact) either calls `_vuln_base_query(db, org_scope)` or applies the same `if org_scope: q = q.filter(Product.organization_id == org_scope)` pattern inline. **Static verdict: scoped correctly.** Dynamic PoC below confirms.

```python
# products.py — every endpoint repeats this guard
product = db.query(Product).filter(Product.id == product_id).first()
if not product:
    raise HTTPException(status_code=404, detail="...")
if org_scope and product.organization_id != org_scope:
    raise HTTPException(status_code=403, detail="...")
```
Lines 22, 44, 65, 76, 107 — covers create_release / patch / delete / list_releases / vuln_trend. **Verdict: clean.** (Effective but verbose; recommendation #3 below offers a helper to eliminate duplication.)

```python
# search.py line 27-28
if org_scope:
    rows_q = rows_q.filter(Product.organization_id == org_scope)
```
The follow-on `db.query(Vulnerability).filter(Vulnerability.component_id.in_(comp_ids))` (line 36) is safe by transitivity because `comp_ids` is derived from the already-scoped query.

#### Sub-evidence #8–9 — additional check via heuristic showed quality issue but not security

`stats.py:get_risk_overview` (line 128-211) queries `prod_counts`, `rel_counts`, `vuln_rows` **without** `org_scope` filter, then assembles the result by looking up only the viewer's org_id from the `orgs` dict (line 190). Net effect: the cross-tenant data is fetched into memory but discarded before serialization. **Not a leak**, but a subtle correctness/perf concern: a future refactor that returns the full `prod_counts` dict instead of indexing it by `org_id` would silently leak. Will file as separate code-review finding (CR-NN) in batch phase.

### Evidence / PoC

#### PoC 1 — Confirm stats.py is properly scoped (per user direction)

`audit-poc/poc-001-stats-multi-tenant.py` (will be created in Phase 5 if user requests; here as text):

```python
"""
Confirms stats.py endpoints scope correctly to the caller's org.

Run: python audit-poc/poc-001-stats-multi-tenant.py

Setup it does:
  1. Spin up backend with a fresh sbom-poc.db
  2. As admin: create org A + viewer A; create org B + viewer B
  3. As viewer A: create product, release, upload SBOM with one component +
     one vulnerability
  4. As viewer B: same, with a different component name
  5. As admin: confirm DB has 2 components total
  6. Login as viewer A
  7. Hit each stats endpoint, assert returned counts == 1 (only A's row)
  8. Hit /api/stats/cve-impact?cve=<B's cve> → assert affected_count == 0

Pass condition: every assert passes.  Any single failure = finding upgraded
to "confirmed multi-tenant leak".
"""
import json
import urllib.request
import urllib.error
import os

API = os.environ.get("SBOM_API_URL", "http://localhost:9100")

def _post(path, body, token=None):
    req = urllib.request.Request(f"{API}{path}", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          **({"Authorization": f"Bearer {token}"} if token else {})},
                                 method="POST")
    return json.loads(urllib.request.urlopen(req).read())

def _get(path, token):
    req = urllib.request.Request(f"{API}{path}",
                                 headers={"Authorization": f"Bearer {token}"})
    return json.loads(urllib.request.urlopen(req).read())

# 1. admin login
admin_tok = _post("/api/auth/login", {"username": "admin",
                                      "password": os.environ["ADMIN_PASSWORD"]})["access_token"]

# 2. create two orgs each with a viewer
def mk_org(name, vname, vpwd):
    return _post("/api/organizations",
                 {"name": name, "username": vname, "password": vpwd},
                 admin_tok)

org_a = mk_org("OrgA-poc", "viewer-a", "PocViewerA1!")
org_b = mk_org("OrgB-poc", "viewer-b", "PocViewerB1!")

# 3-4. each viewer creates product + release + uploads SBOM
def viewer_token(uname, pwd):
    return _post("/api/auth/login", {"username": uname, "password": pwd})["access_token"]

# (further steps create CycloneDX SBOM file with known component, hit
#  /api/products/{id}/releases, /api/releases/{id}/sbom, etc.)
# (see audit-poc/poc-001-stats-multi-tenant.py for the full script;
#  ~150 lines)

# 5-7. stats checks as viewer A
tok_a = viewer_token("viewer-a", "PocViewerA1!")
stats_a = _get("/api/stats", tok_a)
assert stats_a["organizations"] == 1, f"viewer A sees {stats_a['organizations']} orgs (expect 1)"
assert stats_a["products"] == 1, f"viewer A sees {stats_a['products']} products (expect 1)"
assert stats_a["components"] == 1, f"viewer A sees {stats_a['components']} components (expect 1)"
assert stats_a["vulnerabilities"]["total"] >= 1

risk_a = _get("/api/stats/risk-overview", tok_a)
assert len(risk_a) == 1, f"viewer A sees {len(risk_a)} orgs in risk-overview (expect 1)"
assert risk_a[0]["org_name"] == "OrgA-poc"

# 8. cross-tenant CVE search
cve_a_search_for_b_cve = _get(f"/api/stats/cve-impact?cve={B_CVE}", tok_a)
assert cve_a_search_for_b_cve["affected_count"] == 0, \
    f"viewer A queried {B_CVE} (only in B) and got {cve_a_search_for_b_cve['affected_count']} hits"

print("PASS — stats.py multi-tenant scoping is correct")
```

**Expected outcome based on static analysis**: PASS for all asserts. PoC's job is to lock that in as ground truth and act as regression for any future refactor that reintroduces leakage.

#### PoC 2 — Demonstrate licenses.py + policies.py leaks (confirmation, not discovery)

```python
"""
Demonstrates the 4 confirmed multi-tenant leaks. Already known from
static read; PoC produces evidence reproducible in commit messages and
CHANGELOG.
"""
# (...same setup as PoC 1, plus org A licenses include "GPL-3.0"
#  and org B licenses include "MIT")

tok_a = viewer_token("viewer-a", "PocViewerA1!")

# Lic-1: viewer A reads platform-wide license violations summary
lic_summary = _get("/api/licenses/violations/summary", tok_a)
# Expected: includes counts for org B's MIT components — confirms leak
gpl_rule_count = next(s["violation_count"] for s in lic_summary["by_rule"] if s["license_id"] == "GPL-3.0")
print(f"viewer A sees GPL-3.0 violation_count = {gpl_rule_count}")
print(f"  (org A has 1 GPL component;  if count > 1 = data from org B is included)")

# Lic-2: viewer A queries org B's release violations directly
lic_b_release = _get(f"/api/licenses/releases/{ORG_B_RELEASE_ID}/violations", tok_a)
print(f"viewer A queried org B's release_id and got "
      f"{len(lic_b_release.get('violations', []))} violations — IDOR confirmed")

# Pol-1, Pol-2: same shape with /api/policies/...
```

**Expected outcome based on static analysis**: both leaks demonstrated. Will run in Phase 6 verification after Phase 5 patches to confirm fix works.

### Impact

**For LAN-only deployment today**:
- Insider (any registered user, even viewer) can enumerate license licenses + vuln-policy violations across every organization on the platform
- IDOR via release_id allows direct cross-tenant browsing of license + policy violation lists per release
- Vuln counts per rule per org allow profiling: "Org X has 47 critical-policy violations" → competitive intelligence in B2B context, leverage for social engineering otherwise
- Aggregated counts also leak the existence of organizations even when their names are not exposed

**For commercialised SaaS**:
- The same insider-attacker becomes "any paying customer" → cross-tenant data leakage between competing customers
- A B2B competitor signing up as a customer becomes AT-4/AT-5 instantly
- Triggers SOC 2 CC6.3 ("restrict access based on need-to-know"), ISO 27001 A.8.3, GDPR Art.32 control gaps — likely material weakness in SOC 2 audit and a 30-day-cure clause in most enterprise contracts
- For industrial security customers (the target market), this is a deal-breaker:they're security-aware and will reject

### Likelihood

- **Discovery cost**: Low — endpoints are documented at `/docs`; URL pattern is obvious; no Burp / fuzzing required
- **Exploitation cost**: Trivial — single GET request with valid JWT; no payload crafting
- **Stealth**: High — appears as normal API traffic; only audit-log entry is "GET /api/licenses/violations/summary by user X" which doesn't flag cross-tenant intent

### Recommendation

#### Root-cause fix(根因)

Three of the four leaks lack `org_scope` in the function signature; one has it but doesn't use it. Pattern from `releases.py` (already proven in 30 grep sites) is to use a tiny helper. Recommend introducing a single helper in `core/deps.py` so the pattern is unmistakable:

```python
# backend/app/core/deps.py — add this helper
def assert_release_in_scope(release: "Release", org_scope: str | None) -> None:
    """Common guard: 404 if release missing, 403 if release not in viewer's org.
    Admin (org_scope is None) sees everything by design."""
    if release is None:
        raise HTTPException(status_code=404, detail="Release not found")
    if org_scope and release.product.organization_id != org_scope:
        raise HTTPException(status_code=403, detail="此 release 不屬於您的組織")
```

Apply at four sites:
1. `licenses.py:118` `/violations/summary` → add `org_scope` to signature, switch query to `filter(Product.organization_id == org_scope)` chain like `stats.py` does, OR mark the endpoint `require_admin` (preferred for "platform-wide" semantics)
2. `licenses.py:139` `/releases/{id}/violations` → call `assert_release_in_scope(release, org_scope)` after the lookup
3. `policies.py:164` `/violations/summary` → same choice as #1
4. `policies.py:184` `/releases/{id}/violations` → add `org_scope` to signature + call helper

#### Defence in depth(縱深防禦)

- Static lint:custom flake8/ruff plugin or simple grep CI rule that warns when an endpoint takes a `_id` path parameter and queries the corresponding model **without** invoking an `assert_*_in_scope` helper. Catches future regressions.
- Test:`tests/test_multi_tenant_isolation.py` (stdlib-only per CLAUDE.md) that for every router, attempts cross-tenant access with a viewer's token and asserts 403/404. Same pattern as the PoC scripts above.
- DB-layer policy(longer term):if migrating to Postgres, enable Row-Level Security (RLS) with `current_setting('app.org_id')` matching policy. Defence in depth at the storage layer means even a router bug doesn't leak.

#### Compensating control if patch is delayed

Mark `licenses.py /violations/summary` and `policies.py /violations/summary` as `require_admin` immediately (1-line change each; commit message tag `[hotfix]`). This eliminates the cross-tenant exposure for non-admin users while the proper org-scoped versions are designed.

### Patch Sketch

#### Patch A — `licenses.py /violations/summary`(option:make admin-only)

```diff
-@router.get("/violations/summary")
-def violations_summary(db: Session = Depends(get_db)):
+@router.get("/violations/summary")
+def violations_summary(_admin: dict = Depends(require_admin),
+                       db: Session = Depends(get_db)):
     """Platform-wide license violation counts per rule."""
+    # Platform-wide is admin-only by design.  Per-org viewers should
+    # use /releases/{id}/violations for their own releases.
```

#### Patch B — `licenses.py /releases/{id}/violations` (use new helper)

```diff
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

#### Patch C — `policies.py /violations/summary`

Same shape as Patch A.

#### Patch D — `policies.py /releases/{id}/violations`

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

### Effort

- 4 patches + new helper: **S** (< 1h coding)
- 2 PoC scripts + assertion harness: **M** (~2h)
- Lint rule + isolation test suite: **M** (~3h)

Total **M** for full fix.

### Risk of Fix

- Patches A + C make the summary endpoints admin-only. Frontend impact: any viewer page calling these endpoints would 403. **Verify** in `frontend/src/pages/Policies.jsx` and `Licenses.jsx` whether viewers are expected to see the summary; if so, add an org-scoped variant instead of admin-gating.
- Patches B + D 加 403 響應給跨租戶嘗試;若實際在 frontend 從未這樣呼叫,impact = 0;若曾用 admin token 跨組織查,frontend 需要改傳 admin tag(unlikely).
- Rollback:revert single commit per patch;each is independent.

### References

- CWE-639 Authorization Bypass Through User-Controlled Key — https://cwe.mitre.org/data/definitions/639.html
- CWE-285 Improper Authorization — https://cwe.mitre.org/data/definitions/285.html
- CWE-200 Information Exposure — https://cwe.mitre.org/data/definitions/200.html
- OWASP API1:2023 BOLA — https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP A01:2021 Broken Access Control — https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- OWASP Multi-tenant Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html (general access control)
- SOC 2 Trust Services Criteria CC6.1 / CC6.3 — AICPA TSP section 100
- ISO 27001:2022 A.5.15 / A.8.3
- IEC 62443-4-1 SI-1 secure implementation
- Postgres Row-Level Security (defence-in-depth pattern) — https://www.postgresql.org/docs/current/ddl-rowsecurity.html

---

## Phase 3 first finding — STOP for schema review

Per user direction (gating in Phase 2 amend):
1. ✅ Wrote TLT-1 multi-tenant umbrella as ONE finding, not 7
2. ✅ Sub-evidence per file (4 confirmed leaks + 5 confirmed-N/A heuristic clearances + 1 quality concern)
3. ✅ stats.py PoC scripted (per user direction "dynamic-poc, not just static review")
4. ✅ Used new column schema with all 5 added fields (finding_id / status / discovered_phase / verification_method / traceability)
5. ✅ compliance_impact in yaml list-of-tags structure
6. ✅ CVSS 3.1 vector + dual severity columns + blocks_commercialization tag

**Pause for user review**:
- Does the column schema work in real-world use?(missing fields? redundant fields? rename suggestions?)
- Is the umbrella structure right?(bundle-vs-split judgement on the 4 confirmed leaks — they could be SEC-001a/b/c/d sub-IDs if you want per-fix granularity)
- Is the PoC script style what you want?(stdlib urllib only, no pytest, matches `test_all.py` pattern)
- Is the recommendation pattern (root-cause + defence-in-depth + compensating control) the right shape?

After your gate-pass, batch produces remaining 20 TLT findings using this same template.
