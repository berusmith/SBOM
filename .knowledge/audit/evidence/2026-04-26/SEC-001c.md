---
finding_id: SEC-001c
verification_method: static + dynamic-poc-inconclusive
poc_script: ../../poc/SEC-001c-policies-summary-leak.py
verdict: STRUCTURALLY_CONFIRMED (dynamic blocked by environment data state)

poc_metadata:
  poc_id: SEC-001c
  executed_at: 2026-04-26T22:55:25+08:00
  executor: claude-code-instance
  environment: local-dev (commit 180bfb0, pre-fix)
  deployment_mode: lan_only
  destructive: false
  cleanup_verified: true
  side_effects:
    - 2 transient orgs created in dev sbom.db (deleted at end)
    - 1 SBOM uploaded with lodash@4.17.20 PURL — OSV scan returned no vulns at run-time
  reproducibility:
    seed_data_required: false
    backend_must_be_running: true
    runtime_seconds: ~10 (includes 3s wait for OSV scan)
    note: |
      OSV.dev result depends on external API.  Dynamic confirmation
      requires an SBOM whose components produce at least one
      Vulnerability row at scan time.  At run-time, the test PURL
      yielded zero vulns — ambiguous outcome (admin and viewer both
      see total=0).
---

# SEC-001c — Dynamic PoC evidence (inconclusive)

## What the PoC found

```
[5] admin sees total_violations=0
[7] viewerB sees total_violations=0
[NO DATA] OSV scan returned no vulns for the test PURL — cannot conclude
```

Both admin and viewerB saw zero. Two possible interpretations:
1. Endpoint correctly returns scoped result (viewer of zero-data org sees 0) — **inconsistent with structural analysis**
2. There was no platform-wide policy violation data at run-time, so both views happen to agree at 0 — **consistent with structural analysis**

To disambiguate would require either (a) an SBOM with reliably-vulnerable components that OSV indexes (try `log4j-core 2.14.1`, `lodash 4.17.10`, etc.) AND component licenses that match policy rules, or (b) seeding the DB with Vulnerability rows directly.

## Why static + structural confirmation is sufficient

The endpoint:

```python
# backend/app/api/policies.py:164-181
@router.get("/violations/summary")
def violations_summary(db: Session = Depends(get_db)):
    rules = db.query(PolicyRule).filter(PolicyRule.enabled == True).all()
    vulns = db.query(Vulnerability).all()       # ← UNSCOPED — full Vulnerability table
    summary = []
    for rule in rules:
        count = sum(1 for v in vulns if _evaluate_rule(rule, v))
        summary.append({...})
    return {"total_violations": sum(...), "by_rule": summary}
```

Line 169 `db.query(Vulnerability).all()` is unmistakable — there is no `org_scope` filter, no `_assert_*_org` helper, no JOIN that scopes by `Product.organization_id`. Whatever Vulnerability rows exist in DB at request time are aggregated and returned.

Same pattern as SEC-001a (`db.query(Component).filter(...)` with no org filter), which **was dynamically confirmed leaking** (SEC-001a evidence). SEC-001c uses an identical structural pattern on the Vulnerability table; the only reason this run produced no observable difference is the test environment's vuln state.

## Cross-reference to SEC-001a as analogous evidence

SEC-001a evidence (`SEC-001a.md`):
- viewer with 0 components in own org → saw `total_violations=2, GPL-3.0=1` matching admin view exactly
- Pattern: `db.query(Component).filter(Component.license != None, ...)` (no org scope)

SEC-001c (this finding):
- Same handler shape: `db.query(Vulnerability).all()` (no org scope)
- If any Vulnerability row exists for any org, viewerB's response would include it

Confidence remains **High** because:
1. Static reading of source code is unambiguous (line 169 is one line)
2. SEC-001a dynamic confirmation establishes that the platform's Component-table query has no hidden org-scoping middleware
3. Vulnerability table follows the same lifecycle (created during SBOM scan, no separate scope mechanism)

## Phase 5 verification expectation

Post-fix:
1. Dynamic re-test with a vulnerable PURL (e.g. `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`)
2. Both admin and viewerB views populated with vulns from orgA
3. viewerB GET `/api/policies/violations/summary` → HTTP 403 (compensating: require_admin) or 200 with empty/scoped response (primary_remediation)

If primary_remediation chosen:viewerB sees `total_violations=0` while admin sees the orgA-derived count → patch verified.

## Cleanup

```
[cleanup] org c39da7db-... -> 204
[cleanup] org 02e4a975-... -> 204
```
