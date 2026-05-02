"""Enrichment endpoints — rescan + EPSS + NVD + GHSA.

Moved from backend/app/api/releases.py in D.3 (2026-04-30).  Includes:
  - 4 endpoints: /rescan, /enrich-epss, /enrich-ghsa, /enrich-nvd
  - 3 helpers: _enrich_kev, _enrich_epss, _enrich_ghsa
  - 2 module-state objects: _active_enrichments + _enrichment_lock
    (single-process lock; see ARCH-1.007 / DEBT-012 for the multi-worker
     story when commercialised)

Fixes bundled (separable findings, but inseparable from the move per the
"address while you're touching the code" Tidy First spirit):
  - CODE-1.009: rescan_vulnerabilities new-vuln detection — replaced the
    "tricky" 3-attempt block with a clean newly_added list tracked during
    insertion; alert payload no longer relies on comp.vulnerabilities
    iteration order or [:new_count] slicing
  - CODE-1.016: _enrich_ghsa returned `new_count` that no caller used —
    return type changed to None
  - ARCH-1.013: enrich_ghsa's `__import__("app.core.config", ...)` magic
    replaced with a normal `from ... import` at module top
"""
from __future__ import annotations

import logging
import threading

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from app.core import audit
from app.core.config import settings as _cfg
from app.core.database import get_db
from app.core.deps import get_current_user, require_admin, require_release_in_scope
from app.models.component import Component
from app.models.organization import Organization
from app.models.product import Product
from app.models.release import Release
from app.models.vulnerability import Vulnerability
from app.services import vuln_scanner
from app.services.alerts import notify_new_vulns
from app.services.epss import fetch_epss
from app.services.ghsa import fetch_ghsa_for_components as _fetch_ghsa
from app.services.kev import fetch_kev_cve_ids
from app.services.nvd import enrich_vulns_nvd
# D.8 (2026-05-01): legacy ownership helper replaced by require_release_in_scope (404 oracle prevention).

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/releases", tags=["releases"])

# Per-process registry of releases currently being enriched.  Single-process
# assumption (single uvicorn worker); multi-worker deploys would each have
# their own set + lock with no coordination — see ARCH-1.007 / DEBT-012.
_active_enrichments: set[str] = set()
_enrichment_lock = threading.Lock()


# ── enrichment helpers (used by upload_sbom + the rescan/enrich endpoints) ───

def _enrich_kev(vulns: list, db: Session) -> None:
    """Mark vulns that appear in the CISA KEV catalog."""
    kev_ids = fetch_kev_cve_ids()
    if not kev_ids:
        return
    for v in vulns:
        v.is_kev = v.cve_id in kev_ids
    db.commit()


def _enrich_epss(vulns: list, db: Session) -> None:
    """Fetch EPSS scores and update vuln records in-place."""
    cve_ids = list({v.cve_id for v in vulns if v.cve_id})
    if not cve_ids:
        return
    scores = fetch_epss(cve_ids)
    for v in vulns:
        if v.cve_id in scores:
            v.epss_score = scores[v.cve_id]["epss"]
            v.epss_percentile = scores[v.cve_id]["percentile"]
    db.commit()


def _enrich_ghsa(components_raw, vulns: list, db: Session) -> None:
    """
    Fetch GHSA advisories for each component and:
    1. Match existing vulns by CVE ID → fill in ghsa_id / ghsa_url
    2. Create new vuln records for GHSA-only advisories (no CVE ID yet)

    CODE-1.016 (D.3): return type changed to None — the prior `int` return
    was never read by any caller (verified via grep at PR-1 prep).
    """
    comp_list = [{"purl": c.purl or "", "name": c.name, "version": c.version or ""} for c in components_raw]
    ghsa_data = _fetch_ghsa(comp_list)
    if not ghsa_data:
        return

    cve_to_vuln: dict[str, object] = {v.cve_id: v for v in vulns if v.cve_id}
    existing_ghsa: set[tuple] = {(v.component_id, v.ghsa_id) for v in vulns if v.ghsa_id}
    purl_to_comp = {c.purl: c for c in components_raw if c.purl}

    for purl, advisories in ghsa_data.items():
        comp = purl_to_comp.get(purl)
        if not comp:
            continue
        for adv in advisories:
            ghsa_id = adv.get("ghsa_id") or ""
            cve_id = adv.get("cve_id") or ""
            if not ghsa_id:
                continue

            if cve_id and cve_id in cve_to_vuln:
                v = cve_to_vuln[cve_id]
                if not v.ghsa_id:
                    v.ghsa_id = ghsa_id
                    v.ghsa_url = adv.get("url")
                    if not v.description and adv.get("description"):
                        v.description = adv["description"]
            elif (comp.id, ghsa_id) not in existing_ghsa:
                effective_cve = cve_id or ghsa_id
                db.add(Vulnerability(
                    component_id=comp.id,
                    cve_id=effective_cve,
                    ghsa_id=ghsa_id,
                    ghsa_url=adv.get("url"),
                    description=adv.get("description", ""),
                    cvss_score=adv.get("cvss_score"),
                    severity=adv.get("severity") or "unknown",
                    status="open",
                ))
                existing_ghsa.add((comp.id, ghsa_id))

    db.commit()


# ── endpoints ────────────────────────────────────────────────────────────────

@router.post("/{release_id}/rescan")
def rescan_vulnerabilities(release_id: str, admin: dict = Depends(require_admin),
                           release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    # release loaded + ownership-checked (404 oracle-safe) by Depends.
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定，無法重新掃描")

    components_raw = (db.query(Component).options(selectinload(Component.vulnerabilities)).filter(Component.release_id == release_id).all())
    if not components_raw:
        raise HTTPException(status_code=400, detail="尚未上傳 SBOM，無元件可掃描")

    comp_list = [{"name": c.name, "version": c.version, "purl": c.purl or ""} for c in components_raw]
    vuln_results = vuln_scanner.scan_components(comp_list)
    purl_to_comp = {c.purl: c for c in components_raw if c.purl}

    # CODE-1.009 fix (D.3): track newly-inserted vulns directly during the
    # insertion loop, instead of trying to recover the set later from
    # comp.vulnerabilities iteration order + [:new_count] slicing.  The
    # alert payload now contains EXACTLY the vulns added in this rescan.
    newly_added: list[tuple[Component, Vulnerability]] = []
    for purl, vulns in vuln_results.items():
        comp = purl_to_comp.get(purl)
        if not comp:
            continue
        existing_cves = {v.cve_id for v in comp.vulnerabilities}
        seen_in_scan: set[str] = set()
        for v in vulns:
            cve_id = v["cve_id"]
            if cve_id in existing_cves or cve_id in seen_in_scan:
                continue
            seen_in_scan.add(cve_id)
            new_v = Vulnerability(
                component_id=comp.id,
                cve_id=cve_id,
                cvss_score=v["cvss_score"],
                severity=v["severity"],
                cvss_v4_vector=v.get("cvss_v4_vector"),
                status="open",
            )
            db.add(new_v)
            newly_added.append((comp, new_v))
    db.commit()
    for _, v in newly_added:
        db.refresh(v)
    new_count = len(newly_added)

    # Refresh EPSS and KEV for ALL vulns (both change daily)
    all_vulns = db.query(Vulnerability).join(Component).filter(Component.release_id == release_id).all()
    _enrich_epss(all_vulns, db)
    _enrich_kev(all_vulns, db)

    if new_count > 0:
        product = db.query(Product).filter(Product.id == release.product_id).first()
        org = db.query(Organization).filter(Organization.id == product.organization_id).first() if product else None
        new_vuln_details = [
            {
                "cve_id": v.cve_id,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "epss_score": v.epss_score,
                "is_kev": bool(v.is_kev),
                "component": f"{comp.name}@{comp.version or ''}",
            }
            for comp, v in newly_added
        ]
        notify_new_vulns(db, {
            "org": org.name if org else "",
            "product": product.name if product else "",
            "version": release.version,
            "release_id": release_id,
        }, new_vuln_details)

    product = db.query(Product).filter(Product.id == release.product_id).first()
    org = db.query(Organization).filter(Organization.id == product.organization_id).first() if product else None
    label = f"{org.name if org else ''} / {product.name if product else ''} / {release.version}"
    audit.record(db, "vuln_scan", admin, resource_id=release_id, resource_label=label, org_name=org.name if org else None)
    db.commit()

    return {
        "components_scanned": len(comp_list),
        "new_vulnerabilities_found": new_count,
    }


@router.post("/{release_id}/enrich-epss")
def enrich_epss(release_id: str, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    vulns = db.query(Vulnerability).join(Component).filter(Component.release_id == release_id).all()
    if not vulns:
        raise HTTPException(status_code=400, detail="此版本尚無漏洞資料")
    _enrich_epss(vulns, db)
    _enrich_kev(vulns, db)
    epss_updated = sum(1 for v in vulns if v.epss_score is not None)
    kev_count = sum(1 for v in vulns if v.is_kev)
    return {"total_vulnerabilities": len(vulns), "epss_updated": epss_updated, "kev_count": kev_count}


@router.post("/{release_id}/enrich-ghsa")
def enrich_ghsa(
    release_id: str,
    background_tasks: BackgroundTasks,
    user: dict = Depends(get_current_user),
    release: Release = Depends(require_release_in_scope),
    db: Session = Depends(get_db),
):
    """手動補充 GitHub Security Advisories (GHSA) 情資。"""
    with _enrichment_lock:
        if release_id in _active_enrichments:
            raise HTTPException(status_code=409, detail="此版本的 GHSA 補充正在執行中，請稍後")
        _active_enrichments.add(release_id)
    # release loaded + ownership-checked (404 oracle-safe) by Depends — but Depends
    # runs BEFORE this function body, so for unknown release_id the user gets 404
    # WITHOUT _active_enrichments side-effect (cleaner; the "discard on 404" cleanup
    # that the legacy code did becomes unnecessary because Depends short-circuits
    # earlier).  The discard-on-no-components path below is still needed.
    all_comps = db.query(Component).filter(Component.release_id == release_id).all()
    if not all_comps:
        _active_enrichments.discard(release_id)
        raise HTTPException(status_code=400, detail="此版本尚無元件資料，請先上傳 SBOM")

    def _task():
        from app.core.database import SessionLocal
        _db = SessionLocal()
        try:
            _comps = _db.query(Component).filter(Component.release_id == release_id).all()
            _vulns = _db.query(Vulnerability).join(Component).filter(Component.release_id == release_id).all()
            _enrich_ghsa(_comps, _vulns, _db)
        except Exception as exc:
            logger.error("GHSA 補充失敗 release_id=%s: %s", release_id, exc)
        finally:
            _active_enrichments.discard(release_id)
            _db.close()

    background_tasks.add_task(_task)
    # ARCH-1.013 fix (D.3): replaced the original `__import__("app.core.config", ...)` magic
    # with a normal module-top import (_cfg).  Same value, less obscure.
    has_token = bool(_cfg.GITHUB_TOKEN)
    return {
        "status": "started",
        "components": len(all_comps),
        "message": f"GHSA 資料補充已在背景執行（{'已設定 GITHUB_TOKEN，速率 5000/h' if has_token else '未設定 GITHUB_TOKEN，速率 60/h，元件多時可能較慢'}）",
    }


@router.post("/{release_id}/enrich-nvd")
def enrich_nvd(release_id: str, background_tasks: BackgroundTasks, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    with _enrichment_lock:
        if release_id in _active_enrichments:
            raise HTTPException(status_code=409, detail="此版本的 NVD 補充正在執行中，請稍後")
        _active_enrichments.add(release_id)
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        _active_enrichments.discard(release_id)
        raise HTTPException(status_code=404, detail="Release not found")
    vulns = db.query(Vulnerability).join(Component).filter(Component.release_id == release_id).all()
    if not vulns:
        _active_enrichments.discard(release_id)
        raise HTTPException(status_code=400, detail="此版本尚無漏洞資料")
    unique_cves = len({v.cve_id for v in vulns if v.cve_id.startswith("CVE-")})
    delay = 0.7 if _cfg.NVD_API_KEY else 7.0
    est_seconds = int(unique_cves * delay)

    def _task():
        from app.core.database import SessionLocal
        _db = SessionLocal()
        try:
            _vulns = _db.query(Vulnerability).join(Component).filter(Component.release_id == release_id).all()
            enrich_vulns_nvd(_vulns, _db)
        except Exception as exc:
            logger.error("NVD 補充失敗 release_id=%s: %s", release_id, exc)
        finally:
            _active_enrichments.discard(release_id)
            _db.close()

    background_tasks.add_task(_task)
    return {
        "status": "started",
        "unique_cves": unique_cves,
        "estimated_seconds": est_seconds,
        "message": f"NVD 資料補充已在背景執行，預計約 {est_seconds} 秒完成",
    }
