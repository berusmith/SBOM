import asyncio
import csv
import hashlib
import io
import json
import logging
import os
import threading
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func
from sqlalchemy.orm import Session, selectinload

from app.core import audit
from app.core.config import BACKEND_DIR, resolve_under_backend, settings as _cfg
from app.core.database import get_db
from app.core.deps import get_org_scope, require_admin, get_current_user, require_release_in_scope
from app.core.security import csv_safe, safe_attachment_filename
from app.domain.severity import highest_severity
from app.domain.sla import SLA_DAYS, sla_info
from app.domain.suppression import is_suppressed

logger = logging.getLogger(__name__)
from app.models.component import Component
from app.models.cra_incident import CRAIncident
from app.models.product import Product
from app.models.organization import Organization
from app.models.release import Release
from app.models.vulnerability import Vulnerability
from app.models.brand_config import BrandConfig
from app.services import sbom_parser, vuln_scanner, pdf_report, iec62443_report, iec62443_42_report, iec62443_33_report, nis2_report
from app.services.sbom_parser import check_ntia as _check_ntia_fn, score_sbom as _score_sbom
from app.services.alerts import notify_new_vulns
from app.services.nvd import enrich_vulns_nvd
from app.services.epss import fetch_epss
from app.services.kev import fetch_kev_cve_ids
from app.services.license_classifier import classify_license
from app.services.signature_verifier import verify_signature as _verify_sig, detect_algorithm, SUPPORTED_ALGORITHMS
from app.services import trivy_scanner as _trivy
from app.services import syft_scanner as _syft
from app.services.ghsa import fetch_ghsa_for_components as _fetch_ghsa
from app.services.scanners.reachability import scan_zip as _scan_zip, classify_vulns as _classify_vulns
from app.core.plan import require_plan, check_starter_limit

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
