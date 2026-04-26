---
finding_id: SEC-001b
verification_method: dynamic-poc
poc_script: ../../poc/SEC-001b-licenses-release-idor.py
verdict: IDOR_CONFIRMED

poc_metadata:
  poc_id: SEC-001b
  executed_at: 2026-04-26T22:55:22+08:00
  executor: claude-code-instance
  environment: local-dev (commit 180bfb0, pre-fix)
  deployment_mode: lan_only
  destructive: false
  cleanup_verified: true
  side_effects:
    - 2 transient orgs created in dev sbom.db (deleted at end)
    - 1 product / 1 release / 1 component / 1 SBOM file (cascade-deleted)
    - audit_events rows persist (append-only by design)
  reproducibility:
    seed_data_required: false
    backend_must_be_running: true
    runtime_seconds: ~3
---

# SEC-001b — Dynamic PoC evidence

## Setup

- 2 test orgs created at run-time: orgA `0b46f2f3-...` (with GPL-3.0 SBOM), orgB `6154a9c4-...` (zero data)
- orgA release_id: `99a521fb-a53b-4b80-9989-4b4eeea87617`

## Execution timeline

```
[1] admin login OK
[2a] orgA created (id=0b46f2f3-9acb-44ca-bb26-88044a9e15b6)
[2b] orgB created (id=6154a9c4-87b6-450f-8418-1ca7c2ce9fe2)
[3]  orgA release created (id=99a521fb-a53b-4b80-9989-4b4eeea87617)
[4]  SBOM with GPL-3.0 uploaded to orgA's release
[5]  viewerB logged in
[6]  viewerB GET /api/licenses/releases/99a521fb-.../violations
     → HTTP 200
     → response: violations=2 entries
     → first: {license_id:"GPL-3.0", component:"poc-gpl-1777215322", version:"1.0.0", ...}
```

## The IDOR

| Observation | Value | Interpretation |
|-------------|-------|----------------|
| viewerB JWT scope | orgB | confirmed by login response |
| viewerB requests release_id of orgA | `99a521fb-...` (orgA's) | cross-tenant request |
| HTTP response code | **200** | endpoint accepts any release_id |
| Violations returned | 2 entries (GPL-3.0 + LGPL-3.0 substring match) | **orgA's data** disclosed to viewerB |

CWE-639 confirmed: viewerB performed a cross-tenant read by supplying orgA's `release_id` to an endpoint that lacks ownership verification.

## Cleanup

```
[cleanup] org 0b46f2f3-... -> 204
[cleanup] org 6154a9c4-... -> 204
```

## Phase 5 verification expectation

After patch (`assert_release_in_scope` returns 404 in both "not found" and "not yours" cases):

```
viewerB GET /api/licenses/releases/<orgA_release_id>/violations
→ HTTP 404 "Release not found"
```

PoC re-run after fix should print `[NO LEAK]` with HTTP 404 in step [6].

**Crucially**:404 (not 403) is required to prevent attacker using response code as oracle for "release_id is valid + not yours". See finding's monitoring_detection section for the rationale.
