---
finding_id: SEC-001d
verification_method: dynamic-poc
poc_script: ../../poc/SEC-001d-policies-release-idor.py
verdict: IDOR_CONFIRMED

poc_metadata:
  poc_id: SEC-001d
  executed_at: 2026-04-26T22:55:32+08:00
  executor: claude-code-instance
  environment: local-dev (commit 180bfb0, pre-fix)
  deployment_mode: lan_only
  destructive: false
  cleanup_verified: true
  side_effects:
    - 2 transient orgs created in dev sbom.db (deleted at end)
    - 1 product / release / SBOM uploaded (cascade-deleted)
  reproducibility:
    seed_data_required: false
    backend_must_be_running: true
    runtime_seconds: ~10

after_fix_verification:
  poc_id: SEC-001d
  executed_at: 2026-04-28T01:10:15+08:00
  executor: claude-code-instance
  environment: local-dev (commit 9a69fe2, post-fix; backend on 127.0.0.1:9100, DEBUG mode, --no-proxy-headers)
  fix_commits_responsible:
    - a604c56   # SDLC-001 — require_release_in_scope Depends middleware
    - f0355ec   # fix(security): [SEC-001c+d] policies.py: require_admin on summary, ownership on release violations
  poc_rerun_verdict: NOT_REPRODUCED
  observed_response:
    code: 404                       # not 403 — CWE-204 oracle prevention
    body: '{"detail":"Release not found"}'
    verdict_line: "[NO LEAK] 404 — release_id hidden from cross-tenant viewer (post-fix expected)"
  cleanup_verified: true            # both throwaway orgs deleted at end (HTTP 204)
  notes: |
    Pre-fix: endpoint had no org_scope param at all — any authenticated
    user could view violations for any release_id.
    Post-fix: viewerB → HTTP 404 (same code as "release truly missing",
    oracle-safe); require_release_in_scope Depends performs org_scope
    check before any DB lookup of components/vulns.
---

# SEC-001d — Dynamic PoC evidence

## Setup

- 2 test orgs created at run-time: orgA `c9716bb1-...`, orgB `dd60f77e-...`
- orgA release_id: `d45c4725-48df-4365-a809-d908bc5040e0`

## Execution timeline

```
[1] admin login OK
[2] orgA=c9716bb1-..., orgB=dd60f77e-...
[3] orgA release d45c4725-...
[4] SBOM uploaded -> HTTP 200
[5] viewerB logged in
[6] viewerB GET /api/policies/releases/d45c4725-.../violations -> HTTP 200
    response: violations=0 entries
```

## The IDOR

| Observation | Value | Interpretation |
|-------------|-------|----------------|
| viewerB JWT scope | orgB | confirmed by login |
| viewerB requests release_id of orgA | `d45c4725-...` | cross-tenant |
| HTTP response code | **200** | endpoint accepts cross-tenant release_id |
| violations field present | yes (`[]`) | response shape returned, not auth-blocked |

**The IDOR is the HTTP 200 itself**, not the count. If the endpoint had ownership verification, it would have returned 404 (or 403). Returning 200 with structured response shape proves the endpoint executed the query with cross-tenant `release_id` and would have included real data if the test PURL had triggered any policy rule match.

The empty `violations: []` is a side effect of the test SBOM not producing OSV-flagged vulns at run-time. The IDOR holds independent of result content — same pattern as SEC-001b where the count was non-zero.

## Comparison with SEC-001b

| Finding | Endpoint | Test result |
|---------|----------|-------------|
| SEC-001b | `licenses.releases.{id}.violations` | 200 + 2 violations (license rule rich because seeded by SBOM) |
| SEC-001d | `policies.releases.{id}.violations` | 200 + 0 violations (policy rules need vulns; OSV-dependent) |

Both returned HTTP 200 from cross-tenant request → both are CWE-639 IDOR confirmed.

## Phase 5 verification expectation

Post-fix(`assert_release_in_scope` returns 404):

```
viewerB GET /api/policies/releases/<orgA_release_id>/violations
→ HTTP 404 "Release not found"
```

PoC re-run after fix should print `[NO LEAK]`.

## Cleanup

```
[cleanup] org c9716bb1-... -> 204
[cleanup] org dd60f77e-... -> 204
```
