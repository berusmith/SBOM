"""SBOM upload — POST /api/releases/{release_id}/sbom.

Moved from backend/app/api/releases.py:upload_sbom in D.2 (2026-04-30).
Decomposed into a thin orchestrator + 6 helpers per CODE-1.001.
Behavior bit-identical at the HTTP boundary.

Cross-module imports (D.8 cleanup state, 2026-05-01):
  - Ownership check: Depends(require_release_in_scope) from app.core.deps
    (404 oracle-safe per ARCH-1.003 contract evolution)
  - Enrichment: _enrich_epss / _enrich_kev / _enrich_ghsa from
    app.services.usecases.release.enrich (moved there in D.3)
  - UPLOAD_DIR from app.api.releases (still there post-Stage D; consolidating
    UPLOAD_DIR into a shared location is FU-candidate, not iter-1 scope)
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.deps import get_current_user, require_release_in_scope
from app.models.component import Component
from app.models.organization import Organization
from app.models.product import Product
from app.models.release import Release
from app.models.vulnerability import Vulnerability
from app.services import sbom_parser, vuln_scanner
from app.services.sbom_parser import score_sbom

# UPLOAD_DIR still from app.api.releases (path constant; consolidation deferred).
from app.api.releases import UPLOAD_DIR
from app.services.usecases.release.enrich import _enrich_epss, _enrich_ghsa, _enrich_kev

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/releases", tags=["releases"])

_MAX_SBOM_BYTES = 50 * 1024 * 1024  # 50 MB


# ── helpers ──────────────────────────────────────────────────────────────────

def _read_capped(file: UploadFile) -> bytes:
    content = file.file.read(_MAX_SBOM_BYTES + 1)
    if len(content) > _MAX_SBOM_BYTES:
        raise HTTPException(status_code=400, detail="SBOM 檔案超過 50MB 上限")
    return content


def _validate_and_parse(content: bytes, filename: str | None) -> list[dict]:
    try:
        sbom_parser.validate(content, filename)
        return sbom_parser.parse(content, filename)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # Deliberate broad-except: SBOM parser library-boundary — diverse parser failures translated to user-facing 400
        raise HTTPException(status_code=400, detail=f"SBOM 解析失敗：{e}")


def _save_and_score(release: Release, content: bytes, filename: str | None) -> None:
    """Persist SBOM file to disk + compute hash + cache quality grade.

    CODE-1.011 fix bundled (D.2): the prior `except Exception: pass` for the
    quality scoring becomes `logger.exception(...)` so silent failures
    surface in logs.  The semantic of "scoring failure does NOT abort upload"
    is preserved — only the observability changes.
    """
    safe_name = Path(filename or "sbom.json").name
    filepath = UPLOAD_DIR / f"{release.id}_{safe_name}"
    with open(filepath, "wb") as f:
        f.write(content)
    release.sbom_file_path = str(filepath)
    release.sbom_hash = hashlib.sha256(content).hexdigest()
    try:
        quality = score_sbom(json.loads(content))
        release.sbom_quality_score = quality["score"]
        release.sbom_quality_grade = quality["grade"]
    except Exception:  # Deliberate broad-except (b-fix CODE-1.011 PR-1 D.3 historical): SBOM scoring failures diverse — log + continue without grade
        logger.exception("SBOM quality grading failed for release %s; upload continues without grade", release.id)


def _snapshot_previous(db: Session, release: Release) -> tuple[set[str], set[str]]:
    """Return (prev_purls, prev_cves) from the latest other release of the same product."""
    prev_release = (
        db.query(Release)
        .filter(
            Release.product_id == release.product_id,
            Release.id != release.id,
            Release.sbom_file_path.isnot(None),
        )
        .order_by(Release.created_at.desc())
        .first()
    )
    if not prev_release:
        return set(), set()
    prev_comps = db.query(Component).filter(Component.release_id == prev_release.id).all()
    prev_purls = {c.purl for c in prev_comps if c.purl}
    prev_cves: set[str] = set()
    for pc in prev_comps:
        for pv in pc.vulnerabilities:
            prev_cves.add(pv.cve_id)
    return prev_purls, prev_cves


def _replace_components(db: Session, release_id: str, parsed: list[dict]) -> list[tuple]:
    """Wipe existing components for the release, insert new ones; return [(comp, purl), ...]."""
    db.query(Component).filter(Component.release_id == release_id).delete()
    db.commit()

    component_objs: list[tuple] = []
    for c in parsed:
        comp = Component(
            release_id=release_id,
            name=c["name"],
            version=c["version"],
            purl=c["purl"],
            license=c["license"],
        )
        db.add(comp)
        component_objs.append((comp, c["purl"]))
    db.commit()
    for comp, _ in component_objs:
        db.refresh(comp)
    return component_objs


def _scan_and_enrich(db: Session, release_id: str, component_objs: list[tuple], parsed: list[dict]) -> int:
    """Scan via OSV, persist deduplicated vulns, enrich with EPSS + KEV + GHSA. Returns vuln_count."""
    vuln_results = vuln_scanner.scan_components(parsed)
    vuln_count = 0
    for comp, purl in component_objs:
        seen_cves: set[str] = set()
        for v in vuln_results.get(purl, []):
            cve_id = v["cve_id"]
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)
            db.add(Vulnerability(
                component_id=comp.id,
                cve_id=cve_id,
                cvss_score=v["cvss_score"],
                severity=v["severity"],
                cvss_v4_vector=v.get("cvss_v4_vector"),
                status="open",
            ))
            vuln_count += 1
    db.commit()

    all_comps = db.query(Component).filter(Component.release_id == release_id).all()
    all_vulns = db.query(Vulnerability).join(Component).filter(Component.release_id == release_id).all()
    _enrich_epss(all_vulns, db)
    _enrich_kev(all_vulns, db)
    _enrich_ghsa(all_comps, all_vulns, db)
    return vuln_count


def _compute_diff(parsed: list[dict], component_objs: list[tuple], prev_purls: set[str], prev_cves: set[str]) -> dict | None:
    if not (prev_purls or prev_cves):
        return None
    new_purls = {c["purl"] for c in parsed if c.get("purl")}
    new_cves: set[str] = set()
    for comp, _ in component_objs:
        for v in comp.vulnerabilities:
            new_cves.add(v.cve_id)
    return {
        "components_added":   len(new_purls - prev_purls),
        "components_removed": len(prev_purls - new_purls),
        "vulns_added":        len(new_cves - prev_cves),
        "vulns_removed":      len(prev_cves - new_cves),
    }


def _audit(db: Session, user: dict, release: Release) -> None:
    product = db.query(Product).filter(Product.id == release.product_id).first()
    org = db.query(Organization).filter(Organization.id == product.organization_id).first() if product else None
    label = f"{org.name if org else ''} / {product.name if product else ''} / {release.version}"
    audit.record(db, "sbom_upload", user, resource_id=release.id, resource_label=label, org_name=org.name if org else None)
    db.commit()


# ── orchestrator ─────────────────────────────────────────────────────────────

@router.post("/{release_id}/sbom")
def upload_sbom(
    release_id: str,
    file: UploadFile = File(...),
    user: dict = Depends(get_current_user),
    release: Release = Depends(require_release_in_scope),
    db: Session = Depends(get_db),
):
    # release loaded + ownership-checked (404 oracle-safe) by Depends.
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定，無法上傳 SBOM")

    content = _read_capped(file)
    parsed = _validate_and_parse(content, file.filename)
    _save_and_score(release, content, file.filename)
    db.commit()

    prev_purls, prev_cves = _snapshot_previous(db, release)
    component_objs = _replace_components(db, release_id, parsed)
    vuln_count = _scan_and_enrich(db, release_id, component_objs, parsed)
    _audit(db, user, release)

    diff = _compute_diff(parsed, component_objs, prev_purls, prev_cves)
    # Add prev_version label if diff has data (for UI display per existing contract)
    if diff is not None:
        prev_release = (
            db.query(Release)
            .filter(
                Release.product_id == release.product_id,
                Release.id != release_id,
                Release.sbom_file_path.isnot(None),
            )
            .order_by(Release.created_at.desc())
            .first()
        )
        if prev_release:
            diff["prev_version"] = prev_release.version

    return {
        "components_found":      len(parsed),
        "vulnerabilities_found": vuln_count,
        "diff":                  diff,
    }
