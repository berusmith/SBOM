---
finding_id: SEC-001a
verification_method: dynamic-poc
poc_script: ../../poc/SEC-001a-licenses-summary-leak.py
run_at: 2026-04-26
backend_version: master @ 91a5599 (pre-audit-fix)
deployment_mode: lan_only (test against running dev backend on :9100)
verdict: LEAK_CONFIRMED
---

# SEC-001a — Dynamic PoC evidence

## Setup

- Backend: `http://localhost:9100`(dev backend on the auditor's Windows machine,running at the time of audit)
- Admin credentials:`admin` / `[REDACTED — sbom@2024 default]`
- Test orgs created at run-time:
  - `POC-001a-OrgA-1777202863` (id `9eab4a43-...`) — uploaded SBOM with 1× GPL-3.0 component
  - `POC-001a-OrgB-1777202863` (id `8a224e34-...`) — zero data

## Test data injected

Single CycloneDX 1.4 SBOM uploaded to orgA's release via `POST /api/releases/{id}/sbom`:

```json
{
  "bomFormat":   "CycloneDX",
  "specVersion": "1.4",
  "version":     1,
  "components": [
    {
      "type":     "library",
      "name":     "poc-gpl-1777202863",
      "version":  "1.0.0",
      "purl":     "pkg:generic/poc-gpl-1777202863@1.0.0",
      "licenses": [{"license": {"id": "GPL-3.0"}}]
    }
  ]
}
```

## Execution timeline

```
[1] admin login OK
[2a] orgA created (id=9eab4a43-f30b-42a3-b3fa-8d15271c9769)
[2b] orgB created (id=8a224e34-73e5-4bcd-9635-4c7191da9702)
[3a] product created in orgA (id=9b031a06-abdb-4657-97d3-06a3153ce84d)
[3b] release v1.0.0-poc created (id=16b497ed-e7a3-444b-8191-36385d47a53c)
[4] SBOM with 1x GPL-3.0 component uploaded to orgA's release
[5] admin sees total=2, GPL-3.0 count=1
[6] viewerB (zero-data org) logged in
[7] viewerB's own org has 0 products (expect 0)
[8] viewerB (zero own data!) sees total=2, GPL-3.0 count=1
```

## The leak

| Observation | Value | Interpretation |
|-------------|-------|----------------|
| viewerB's own products in own org | **0** | confirmed-clean baseline |
| Admin GET `/api/licenses/violations/summary` | total=2, GPL-3.0=1 | platform-wide truth |
| **viewerB GET `/api/licenses/violations/summary`** | **total=2, GPL-3.0=1** | **identical to admin → full cross-tenant disclosure** |

The viewerB account, with zero components in its own organisation, sees the same per-rule violation counts as an admin. The single GPL-3.0 count must be from orgA's component — there is no other source.

(The total=2 vs GPL-3.0=1 discrepancy means at least one other rule matched at least one other component already in the DB at run-time; that other component is also in orgA or a different unrelated org. Either way it is data viewerB has no business seeing.)

## Cleanup

```
[cleanup] deleted org 9eab4a43-f30b-42a3-b3fa-8d15271c9769  (orgA)
[cleanup] deleted org 8a224e34-73e5-4bcd-9635-4c7191da9702  (orgB)
```

Cascade-delete via `cascade="all, delete-orphan"` on Organization → Product → Release → Component → Vulnerability removes the test SBOM data automatically. Verified by re-running the admin summary check post-PoC (returns total=N-1, no GPL-3.0).

## Reproduction

```
cd <repo>
python .knowledge/audit/poc/SEC-001a-licenses-summary-leak.py
```

Override env to point at a different backend / admin:
```
POC_API_URL=http://other:9100 POC_ADMIN_USERNAME=admin POC_ADMIN_PASSWORD=... \
  python .knowledge/audit/poc/SEC-001a-licenses-summary-leak.py
```

## Phase 5 verification expectation

After Phase 5 patch (primary_remediation = `require_admin` on the endpoint):

Expected viewerB response: HTTP **403** with body `{"detail":"此操作需要管理員權限"}`.

If a tenant-scoped variant `/api/licenses/violations/my-summary` is added: viewerB GET returns `total=0, by_rule=[…all zeros…]` because viewerB's org has zero components.

PoC re-run after patch should print `[NO LEAK]` and exit 0.
