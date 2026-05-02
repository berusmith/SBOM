"""
Release use-cases — split of `backend/app/api/releases.py` (iter-1 PR-1 Stage D).

Each module owns one bounded concern:
  upload_sbom — POST /sbom (1 endpoint)
  enrich     — rescan + EPSS + NVD + GHSA enrichment (4 endpoints + helpers)
  reports    — PDF / CSAF / evidence / format export (10+ endpoints)
  signature  — upload / verify / delete signature (3 endpoints, J5 carve-out)
  scanners   — Trivy + Syft + reachability source scan (5 endpoints)
  lifecycle  — get / patch / delete / list / lock / gate / graph (12+ endpoints)

main.py includes each module's router with the same /api/releases prefix —
FastAPI merges the routes.  Each D.N commit moves endpoints from the original
backend/app/api/releases.py into the correct concern module.
"""
