import logging

from fastapi import APIRouter

from app.core.config import BACKEND_DIR, resolve_under_backend, settings as _cfg

logger = logging.getLogger(__name__)

# SBOM uploads.  `_cfg.UPLOAD_DIR` may be:
#   - absolute  → used as-is
#   - relative  → interpreted against backend/, NOT against process cwd
#                 (so launchd / tests / migration scripts all agree)
#   - empty     → defaults to backend/uploads
UPLOAD_DIR = resolve_under_backend(_cfg.UPLOAD_DIR) or (BACKEND_DIR / "uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

router = APIRouter(prefix="/api/releases", tags=["releases"])

# SLA_DAYS, is_suppressed, sla_info moved to backend/app/domain/{sla,suppression}.py in B.2 (2026-04-30).
# upload_sbom moved to backend/app/services/usecases/release/upload_sbom.py in D.2 (2026-04-30).
# _active_enrichments + _enrichment_lock + _enrich_kev/_epss/_ghsa + rescan + 3 enrich endpoints
#   moved to backend/app/services/usecases/release/enrich.py in D.3 (2026-04-30).
#   CODE-1.009 (rescan new-vuln detection) + CODE-1.016 (_enrich_ghsa unused return)
#   + ARCH-1.013 (__import__ magic) bundled fixes in the move.


# Legacy 403 ownership helper DELETED in D.8 (2026-05-01) — ARCH-1.003 contract
# evolution complete.  All callers (24 sites across 6 usecases modules + 3 sites
# in share.py admin endpoints) now use Depends(require_release_in_scope) (404
# oracle prevention).  See ledger D11 + plan §3.9 for the full evolution record.


# rescan + 3 enrich endpoints + 3 helpers + 2 module-state moved to enrich.py in D.3.


# 13 lifecycle endpoints (get / patch / delete / list / lock / gate / graph)
# moved to backend/app/services/usecases/release/lifecycle.py in D.7 (2026-04-30).


# 5 scanner endpoints (upload-source / scan-image / scan-iac / sbom-from-source
# / sbom-from-binary) + _import_syft_cdx helper moved to
# backend/app/services/usecases/release/scanners.py in D.6 (2026-04-30).


# highest_severity moved to backend/app/domain/severity.py in B.2 (2026-04-30).
