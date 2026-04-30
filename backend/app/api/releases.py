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


def _assert_release_org(release: Release, org_scope: str | None, db) -> tuple:
    """Returns (product, org). Raises 403 if viewer tries to access another org's release.

    LEGACY 403 pattern — D.8 (ARCH-1.003 contract evolution) replaces all
    callers with Depends(require_release_in_scope) and deletes this helper.
    """
    product = db.query(Product).filter(Product.id == release.product_id).first()
    org = db.query(Organization).filter(Organization.id == product.organization_id).first() if product else None
    if org_scope and (not product or product.organization_id != org_scope):
        raise HTTPException(status_code=403, detail="無權存取此版本")
    return product, org


# rescan + 3 enrich endpoints + 3 helpers + 2 module-state moved to enrich.py in D.3.


@router.get("/{release_id}")
def get_release(release_id: str, org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    _assert_release_org(release, org_scope, db)
    return {
        "id": release.id,
        "version": release.version,
        "locked": release.locked or False,
        "has_sbom": bool(release.sbom_file_path),
        "sbom_hash": release.sbom_hash,
        "notes": release.notes,
        "created_at": release.created_at.isoformat() if release.created_at else None,
    }


@router.patch("/{release_id}/version")
def update_version(release_id: str, body: dict, _admin: dict = Depends(require_admin),
                   org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    """Rename a release version string (admin only)."""
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定，無法修改版本號")
    _assert_release_org(release, org_scope, db)
    new_version = (body.get("version") or "").strip()
    if not new_version:
        raise HTTPException(status_code=400, detail="版本號不可為空")
    release.version = new_version
    db.commit()
    return {"id": release_id, "version": release.version}


@router.delete("/{release_id}", status_code=204)
def delete_release(release_id: str, _admin: dict = Depends(require_admin), org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    _assert_release_org(release, org_scope, db)
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定，無法刪除")
    if release.sbom_file_path and os.path.exists(release.sbom_file_path):
        os.remove(release.sbom_file_path)
    db.delete(release)
    db.commit()


@router.get("/{release_id}/components")
def list_components(
    release_id: str,
    skip: int = 0,
    limit: int = 2000,
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    if limit > 5000:
        limit = 5000
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    _assert_release_org(release, org_scope, db)
    total = db.query(func.count(Component.id)).filter(Component.release_id == release_id).scalar()
    components = (db.query(Component)
                  .options(selectinload(Component.vulnerabilities))
                  .filter(Component.release_id == release_id)
                  .offset(skip).limit(limit).all())
    result = []
    for c in components:
        vulns = c.vulnerabilities
        result.append({
            "id": c.id,
            "name": c.name,
            "version": c.version,
            "purl": c.purl,
            "license": c.license,
            "license_risk": classify_license(c.license) if c.license else None,
            "vuln_count": len(vulns),
            "highest_severity": highest_severity(vulns),
        })
    return {"total": total, "skip": skip, "limit": limit, "items": result}


@router.get("/{release_id}/vulnerabilities")
def list_vulnerabilities(
    release_id: str,
    skip: int = 0,
    limit: int = 500,
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    if limit > 1000:
        limit = 1000
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    _assert_release_org(release, org_scope, db)
    order_expr = func.coalesce(Vulnerability.epss_score, Vulnerability.cvss_score, 0)
    rows = (
        db.query(Vulnerability, Component.name.label("comp_name"), Component.version.label("comp_version"))
        .join(Component, Component.id == Vulnerability.component_id)
        .filter(Component.release_id == release_id)
        .order_by(order_expr.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [
        {
            "id": v.id,
            "component_name": comp_name,
            "component_version": comp_version,
            "cve_id": v.cve_id,
            "cvss_score": v.cvss_score,
            "severity": v.severity,
            "status": v.status,
            "justification": v.justification,
            "response": v.response,
            "detail": v.detail,
            "epss_score": v.epss_score,
            "epss_percentile": v.epss_percentile,
            "is_kev": bool(v.is_kev),
            "description": v.description,
            "cwe": v.cwe,
            "nvd_refs": json.loads(v.nvd_refs) if v.nvd_refs else [],
            "cvss_v3_score": v.cvss_v3_score,
            "cvss_v3_vector": v.cvss_v3_vector,
            "cvss_v4_score": v.cvss_v4_score,
            "cvss_v4_vector": v.cvss_v4_vector,
            **sla_info(v),
            "suppressed":        is_suppressed(v),
            "suppressed_until":  v.suppressed_until.isoformat() if v.suppressed_until else None,
            "suppressed_reason": v.suppressed_reason,
        }
        for v, comp_name, comp_version in rows
    ]


@router.get("/{release_id}/vulnerabilities/export")
def export_vulnerabilities_csv(release_id: str, org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    _assert_release_org(release, org_scope, db)

    product = db.query(Product).filter(Product.id == release.product_id).first()
    components_raw = (db.query(Component)
                      .options(selectinload(Component.vulnerabilities))
                      .filter(Component.release_id == release_id).all())

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "CVE ID", "元件名稱", "元件版本",
        "CVSS v3", "CVSS v4", "嚴重度", "EPSS 分數", "EPSS 百分位", "CISA KEV",
        "CWE", "VEX 狀態", "Justification", "Response", "說明", "描述",
    ])
    for c in components_raw:
        for v in sorted(c.vulnerabilities, key=lambda x: x.epss_score or x.cvss_score or 0, reverse=True):
            writer.writerow([
                csv_safe(v.cve_id),
                csv_safe(c.name),
                csv_safe(c.version),
                v.cvss_v3_score if v.cvss_v3_score is not None else (v.cvss_score if v.cvss_score is not None else ""),
                v.cvss_v4_score if v.cvss_v4_score is not None else "",
                csv_safe(v.severity),
                f"{v.epss_score:.4f}" if v.epss_score is not None else "",
                f"{v.epss_percentile:.4f}" if v.epss_percentile is not None else "",
                "是" if v.is_kev else "",
                csv_safe(v.cwe),
                csv_safe(v.status),
                csv_safe(v.justification),
                csv_safe(v.response),
                csv_safe(v.detail),
                csv_safe((v.description or "")[:300]),
            ])

    product_name = (product.name if product else "report").replace(" ", "_")
    filename = safe_attachment_filename(f"vulns_{product_name}_{release.version}.csv", default="vulns.csv")
    return Response(
        content=buf.getvalue().encode("utf-8-sig"),  # utf-8-sig for Excel compatibility
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{release_id}/compliance")
def list_compliance(release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    # SEC-023 fix: placeholder route now enforces release ownership before
    # returning the not-implemented stub.  Future implementer fills the body
    # without forgetting the ownership check (CI enforcement test ensures it).
    return {"status": "not implemented"}


# 11 endpoints (PDF / CSAF / evidence / format export / sbom-quality / integrity)
# moved to backend/app/services/usecases/release/reports.py in D.4 (2026-04-30).
# Helpers extracted: _lookup_release_with_components, _brand_dict, _build_csaf_doc,
# _cra_incidents_for_release, _pdf_response.  CODE-1.019 partial (CSAF dup) resolved.


# 3 signature endpoints (upload / verify / delete) moved to
# backend/app/services/usecases/release/signature.py in D.5 [J5-security-carveout].


@router.post("/{release_id}/lock")
def lock_release(release_id: str, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定")
    release.locked = True
    db.commit()
    audit.record(db, "release_lock", _admin, resource_id=release_id)
    db.commit()
    return {"locked": True}


@router.post("/{release_id}/unlock")
def unlock_release(release_id: str, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    release.locked = False
    db.commit()
    audit.record(db, "release_unlock", _admin, resource_id=release_id)
    db.commit()
    return {"locked": False}


@router.patch("/{release_id}/notes")
def update_notes(release_id: str, body: dict, _admin: dict = Depends(require_admin),
                 org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    """Update release notes / changelog text."""
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定，無法修改備註")
    _assert_release_org(release, org_scope, db)
    notes = str(body.get("notes", "") or "")[:5000]  # hard cap 5000 chars
    release.notes = notes or None
    db.commit()
    return {"notes": release.notes}


@router.get("/{release_id}/patch-stats")
def get_patch_stats(release_id: str, org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    _assert_release_org(release, org_scope, db)

    components = db.query(Component).filter(Component.release_id == release_id).all()
    vulns = [v for c in components for v in c.vulnerabilities]

    total = len(vulns)
    fixed = sum(1 for v in vulns if v.status == "fixed")
    open_count = sum(1 for v in vulns if v.status == "open")
    in_triage = sum(1 for v in vulns if v.status == "in_triage")
    affected = sum(1 for v in vulns if v.status == "affected")
    not_affected = sum(1 for v in vulns if v.status == "not_affected")

    patch_rate = round(fixed / total * 100, 1) if total else 0.0

    # Average days to fix (for completed fixes)
    days_list = []
    for v in vulns:
        if v.status == "fixed" and v.fixed_at and v.scanned_at:
            delta = v.fixed_at - v.scanned_at
            days_list.append(delta.total_seconds() / 86400)
    avg_days_to_fix = round(sum(days_list) / len(days_list), 1) if days_list else None

    return {
        "total": total,
        "fixed": fixed,
        "open": open_count,
        "in_triage": in_triage,
        "affected": affected,
        "not_affected": not_affected,
        "patch_rate": patch_rate,
        "avg_days_to_fix": avg_days_to_fix,
    }


@router.get("/{release_id}/gate")
def get_gate(release_id: str, org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    from app.models.license_rule import LicenseRule
    from app.api.licenses import _matches as _lic_matches

    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    _assert_release_org(release, org_scope, db)

    components = db.query(Component).filter(Component.release_id == release_id).all()
    vulns = [v for c in components for v in c.vulnerabilities]

    checks = []

    # 1. SBOM uploaded
    has_sbom = bool(release.sbom_hash)
    checks.append({"id": "sbom_uploaded", "label": "SBOM 已上傳",
                   "passed": has_sbom,
                   "detail": "已上傳 SBOM 並計算 hash" if has_sbom else "尚未上傳 SBOM"})

    # 2. No Critical open/affected vulns (excluding suppressed)
    critical_open = [v for v in vulns if v.severity == "critical" and v.status in ("open", "in_triage", "affected") and not is_suppressed(v)]
    no_critical = len(critical_open) == 0
    checks.append({"id": "no_critical", "label": "無未處理 Critical 漏洞",
                   "passed": no_critical,
                   "detail": f"發現 {len(critical_open)} 個 Critical 漏洞未處理" if not no_critical else "無未處理 Critical 漏洞"})

    # 3. No block-level license violations
    rules = db.query(LicenseRule).filter(LicenseRule.enabled == True).all()  # noqa: E712
    block_violations = sum(
        1 for comp in components if comp.license
        for rule in rules if rule.action == "block" and _lic_matches(rule.license_id, comp.license)
    )
    no_block_lic = block_violations == 0
    checks.append({"id": "no_block_license", "label": "無 Block 等級 License",
                   "passed": no_block_lic,
                   "detail": f"{block_violations} 個元件觸發 block License 規則" if not no_block_lic else "無 block 等級 License 違規"})

    # 4. SBOM quality >= B (4/7 passed)
    quality_grade = None
    quality_passed = None
    if release.sbom_file_path and os.path.exists(release.sbom_file_path):
        try:
            with open(release.sbom_file_path, "rb") as f:
                sbom_data = json.loads(f.read())
            is_spdx = "spdxVersion" in sbom_data
            q_checks = _check_ntia_fn(sbom_data, is_spdx)
            quality_passed = sum(1 for c in q_checks if c["passed"])
            quality_grade = "A" if quality_passed >= 6 else "B" if quality_passed >= 4 else "C" if quality_passed >= 2 else "D"
        except Exception:
            pass
    good_quality = quality_grade in ("A", "B")
    grade_str = f"等級 {quality_grade}（{quality_passed}/7）" if quality_grade else "無 SBOM 可評分"
    checks.append({"id": "sbom_quality", "label": "SBOM 品質 ≥ B 級",
                   "passed": good_quality, "detail": grade_str})

    # 5. All vulns have been triaged (no open/in_triage, suppressed ones are exempt)
    untriaged = [v for v in vulns if v.status in ("open", "in_triage") and not is_suppressed(v)]
    all_triaged = len(untriaged) == 0
    checks.append({"id": "all_triaged", "label": "所有漏洞已完成分類",
                   "passed": all_triaged,
                   "detail": f"{len(untriaged)} 個漏洞仍為 open/in_triage" if not all_triaged else f"全部 {len(vulns)} 個漏洞已分類"})

    # 6. SBOM signature verified (optional — does not block gate if unsigned)
    has_sig = bool(release.sbom_signature and release.signature_public_key)
    sig_valid = False
    sig_detail = "尚未上傳簽章"
    if has_sig and release.sbom_file_path and os.path.exists(release.sbom_file_path):
        with open(release.sbom_file_path, "rb") as f:
            result = _verify_sig(f.read(), release.sbom_signature, release.signature_public_key, release.signature_algorithm)
        sig_valid = result.valid
        sig_detail = result.message
    checks.append({"id": "signature_verified", "label": "SBOM 簽章已驗證",
                   "passed": sig_valid or not has_sig,   # pass if unsigned (optional) or valid
                   "detail": sig_detail})

    passed_count = sum(1 for c in checks if c["passed"])
    return {
        "overall": "pass" if passed_count == len(checks) else "fail",
        "passed": passed_count,
        "total": len(checks),
        "checks": checks,
    }


@router.get("/{release_id}/dependency-graph")
def get_dependency_graph(release_id: str, org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    _assert_release_org(release, org_scope, db)

    if not release.sbom_file_path or not os.path.exists(release.sbom_file_path):
        return {"has_data": False, "nodes": [], "edges": []}

    with open(release.sbom_file_path, "rb") as f:
        data = json.loads(f.read())

    is_spdx = "spdxVersion" in data
    node_map: dict = {}
    edges: list = []

    if is_spdx:
        for pkg in data.get("packages", []):
            sid = pkg.get("SPDXID", "")
            if sid:
                node_map[sid] = {"id": sid, "name": pkg.get("name", sid), "version": pkg.get("versionInfo", ""), "is_root": False}
        for rel in data.get("relationships", []):
            if rel.get("relationshipType") in ("DEPENDS_ON", "CONTAINS", "DYNAMIC_LINK", "STATIC_LINK"):
                s, t = rel.get("spdxElementId"), rel.get("relatedSpdxElement")
                if s and t and s in node_map and t in node_map and s != t:
                    edges.append({"source": s, "target": t})
    else:
        meta_comp = data.get("metadata", {}).get("component", {})
        if meta_comp:
            ref = meta_comp.get("bom-ref") or "root"
            node_map[ref] = {"id": ref, "name": meta_comp.get("name", "Root"), "version": meta_comp.get("version", ""), "is_root": True}
        for comp in data.get("components", []):
            ref = comp.get("bom-ref") or comp.get("name", "")
            if ref:
                node_map[ref] = {"id": ref, "name": comp.get("name", ref), "version": comp.get("version", ""), "is_root": False}
        for dep in data.get("dependencies", []):
            src = dep.get("ref")
            for tgt in dep.get("dependsOn", []):
                if src and tgt and src in node_map and tgt in node_map and src != tgt:
                    edges.append({"source": src, "target": tgt})

    # Mark nodes that have unresolved critical/high vulns
    vuln_names: set = set()
    for comp in db.query(Component).filter(Component.release_id == release_id).all():
        if any(v.severity in ("critical", "high") and v.status not in ("fixed", "not_affected") for v in comp.vulnerabilities):
            vuln_names.add(comp.name)

    nodes = []
    for n in node_map.values():
        nodes.append({**n, "has_vuln": n["name"] in vuln_names})

    return {
        "has_data": len(edges) > 0,
        "nodes": nodes[:200],
        "edges": edges[:600],
        "total_nodes": len(nodes),
        "total_edges": len(edges),
    }


@router.post("/{release_id}/upload-source")
async def upload_source(
    release_id: str,
    file: UploadFile = File(...),
    _plan=Depends(require_plan("reachability")),
    user: dict = Depends(get_current_user),
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    """
    上傳專案原始碼 zip，掃描 import 語句，
    更新所有漏洞的 reachability 欄位。
    """
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    _assert_release_org(release, org_scope, db)

    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="請上傳 .zip 壓縮檔（含 .py / .js / .ts 原始碼）")

    content = await file.read()
    try:
        scan = await asyncio.to_thread(_scan_zip, content)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    all_comps = db.query(Component).filter(Component.release_id == release_id).all()
    all_vulns = db.query(Vulnerability).join(Component).filter(Component.release_id == release_id).all()

    comp_map = {c.id: c for c in all_comps}

    if not all_vulns:
        return {"scanned_packages": len(scan.presence), "vulns_updated": 0, "message": "此版本尚無漏洞資料"}

    classifications = _classify_vulns(all_vulns, scan, comp_map)

    for v in all_vulns:
        v.reachability = classifications.get(v.id, "unknown")
    db.commit()

    fn_reach_count  = sum(1 for r in classifications.values() if r == "function_reachable")
    reachable_count = sum(1 for r in classifications.values() if r == "reachable")
    test_only_count = sum(1 for r in classifications.values() if r == "test_only")
    not_found_count = sum(1 for r in classifications.values() if r == "not_found")

    audit.record(db, "source_upload", user, resource_id=release_id, resource_label=file.filename)
    return {
        "scanned_packages": len(scan.presence),
        "ast_confirmed": len(scan.ast_reachable),
        "vulns_updated": len(classifications),
        "function_reachable": fn_reach_count,
        "reachable": reachable_count,
        "test_only": test_only_count,
        "not_found": not_found_count,
        "message": (
            f"分析完成：{fn_reach_count} 個函式確認可達、"
            f"{reachable_count} 個 import 可達、"
            f"{test_only_count} 個僅測試使用、"
            f"{not_found_count} 個未在原始碼中發現"
        ),
    }


@router.post("/{release_id}/scan-image")
def scan_container_image(
    release_id: str,
    body: dict,
    background_tasks: BackgroundTasks,
    _plan=Depends(require_plan("trivy")),
    user: dict = Depends(get_current_user),
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    """掃描 Container Image，結果合併進現有元件/漏洞流程。"""
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定，無法掃描")
    _assert_release_org(release, org_scope, db)

    image_ref = (body.get("image") or "").strip()
    if not image_ref:
        raise HTTPException(status_code=400, detail="請提供 image 欄位，例如 nginx:1.25")

    if not _trivy.is_trivy_available():
        raise HTTPException(
            status_code=503,
            detail="Trivy 未安裝。安裝指令：curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh",
        )

    try:
        cdx = _trivy.scan_image(image_ref)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    parsed = sbom_parser.parse(json.dumps(cdx).encode(), "trivy-image.json")

    # Upsert components (don't wipe existing — merge by purl)
    existing_purls = {c.purl: c for c in db.query(Component).filter(Component.release_id == release_id).all() if c.purl}
    new_comps: list[tuple] = []
    for c in parsed:
        purl = c.get("purl") or ""
        if purl and purl in existing_purls:
            comp = existing_purls[purl]
        else:
            comp = Component(release_id=release_id, name=c["name"], version=c["version"], purl=purl, license=c.get("license", ""))
            db.add(comp)
            new_comps.append((comp, purl))
    db.commit()
    for comp, _ in new_comps:
        db.refresh(comp)

    all_comp_tuples = [(existing_purls[c["purl"]], c["purl"]) if c.get("purl") and c["purl"] in existing_purls else next(((co, p) for co, p in new_comps if p == c.get("purl")), (None, "")) for c in parsed]
    all_comp_tuples = [(co, p) for co, p in all_comp_tuples if co is not None]

    vuln_results = vuln_scanner.scan_components(parsed)
    vuln_count = 0
    for comp, purl in all_comp_tuples:
        seen = {v.cve_id for v in comp.vulnerabilities}
        for v in vuln_results.get(purl, []):
            if v["cve_id"] in seen:
                continue
            seen.add(v["cve_id"])
            db.add(Vulnerability(
                component_id=comp.id,
                cve_id=v["cve_id"],
                description=v.get("description", ""),
                cvss_score=v["cvss_score"],
                severity=v["severity"],
                cvss_v4_vector=v.get("cvss_v4_vector"),
                status="open",
            ))
            vuln_count += 1
    db.commit()

    all_vulns = db.query(Vulnerability).join(Component).filter(Component.release_id == release_id).all()
    _enrich_epss(all_vulns, db)
    _enrich_kev(all_vulns, db)

    audit.record(db, "trivy_image_scan", user, resource_id=release_id, resource_label=image_ref)
    return {"image": image_ref, "components_found": len(parsed), "vulnerabilities_found": vuln_count}


@router.post("/{release_id}/scan-iac")
async def scan_iac_archive(
    release_id: str,
    file: UploadFile = File(...),
    _plan=Depends(require_plan("trivy")),
    user: dict = Depends(get_current_user),
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    """上傳 zip（Terraform/K8s yaml/Dockerfile），掃描 misconfiguration + 元件漏洞。"""
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定，無法掃描")
    _assert_release_org(release, org_scope, db)

    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="請上傳 .zip 壓縮檔（內含 Terraform/K8s/Dockerfile）")

    if not _trivy.is_trivy_available():
        raise HTTPException(
            status_code=503,
            detail="Trivy 未安裝。安裝指令：curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh",
        )

    MAX_SIZE = 20 * 1024 * 1024
    content = await file.read()
    if len(content) > MAX_SIZE:
        raise HTTPException(status_code=400, detail="壓縮檔超過 20MB 上限")

    try:
        cdx = await asyncio.to_thread(_trivy.scan_iac, content)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    misconfigs = _trivy.extract_misconfigs(cdx)
    parsed = sbom_parser.parse(json.dumps(cdx).encode(), "trivy-iac.json")

    audit.record(db, "trivy_iac_scan", user, resource_id=release_id, resource_label=file.filename)
    return {
        "filename": file.filename,
        "components_found": len(parsed),
        "misconfigs_found": len(misconfigs),
        "misconfigs": misconfigs[:50],
    }


# ── Syft-driven SBOM generation ───────────────────────────────────────────────
# Source archives + arbitrary binaries.  Both flows produce a CycloneDX dict
# that we feed straight back through the existing sbom_parser → component
# upsert → OSV/EPSS/KEV pipeline, so nothing downstream needs to know that
# the SBOM came from Syft as opposed to a user upload.

def _import_syft_cdx(
    *,
    cdx: dict,
    release_id: str,
    db: Session,
    source_label: str,
    user: dict,
    audit_event: str,
    audit_resource_label: str,
) -> dict:
    """Shared post-processing for the Syft-from-source / Syft-from-binary flows.

    Parses the CycloneDX dict, upserts components by PURL onto the release
    (additive — never wipes existing components, mirroring `scan-image`),
    runs OSV vuln scan, then enriches with EPSS + KEV.  Returns the user-
    facing summary dict.
    """
    parsed = sbom_parser.parse(json.dumps(cdx).encode(), source_label)

    existing_purls = {
        c.purl: c for c in db.query(Component).filter(Component.release_id == release_id).all()
        if c.purl
    }
    new_comps: list[tuple] = []
    for c in parsed:
        purl = c.get("purl") or ""
        if purl and purl in existing_purls:
            comp = existing_purls[purl]
        else:
            comp = Component(
                release_id=release_id,
                name=c["name"],
                version=c["version"],
                purl=purl,
                license=c.get("license", ""),
            )
            db.add(comp)
            new_comps.append((comp, purl))
    db.commit()
    for comp, _ in new_comps:
        db.refresh(comp)

    # Walk parsed list once more to build (component, purl) pairs covering
    # both freshly-inserted and previously-existing components.
    all_pairs: list[tuple] = []
    for c in parsed:
        purl = c.get("purl") or ""
        if purl in existing_purls:
            all_pairs.append((existing_purls[purl], purl))
        else:
            for co, p in new_comps:
                if p == purl:
                    all_pairs.append((co, p))
                    break
    all_pairs = [(co, p) for co, p in all_pairs if co is not None]

    vuln_results = vuln_scanner.scan_components(parsed)
    vuln_count = 0
    for comp, purl in all_pairs:
        seen = {v.cve_id for v in comp.vulnerabilities}
        for v in vuln_results.get(purl, []):
            if v["cve_id"] in seen:
                continue
            seen.add(v["cve_id"])
            db.add(Vulnerability(
                component_id=comp.id,
                cve_id=v["cve_id"],
                description=v.get("description", ""),
                cvss_score=v["cvss_score"],
                severity=v["severity"],
                cvss_v4_vector=v.get("cvss_v4_vector"),
                status="open",
            ))
            vuln_count += 1
    db.commit()

    all_vulns = (
        db.query(Vulnerability)
        .join(Component)
        .filter(Component.release_id == release_id)
        .all()
    )
    _enrich_epss(all_vulns, db)
    _enrich_kev(all_vulns, db)

    audit.record(db, audit_event, user, resource_id=release_id,
                 resource_label=audit_resource_label)
    db.commit()
    return {"components_found": len(parsed), "vulnerabilities_found": vuln_count}


@router.post("/{release_id}/sbom-from-source")
async def sbom_from_source(
    release_id: str,
    file: UploadFile = File(...),
    _plan=Depends(require_plan("syft")),
    user: dict = Depends(get_current_user),
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    """上傳原始碼 zip,讓 Syft 識別 manifest(package.json/requirements.txt/...) 產出 SBOM 並合併進此版本。

    與 /upload-source 不同:此端點**產生**元件清單(SBOM),前者是給定 SBOM 後分析 reachability。
    """
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定,無法掃描")
    _assert_release_org(release, org_scope, db)

    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="請上傳 .zip 壓縮檔(原始碼)")

    if not _syft.is_syft_available():
        raise HTTPException(
            status_code=503,
            detail="Syft 未安裝。macOS:`brew install syft`;Linux 安裝腳本見 NOTICE.md",
        )

    MAX_SIZE = 100 * 1024 * 1024  # 100 MB
    content = await file.read(MAX_SIZE + 1)
    if len(content) > MAX_SIZE:
        raise HTTPException(status_code=400, detail=f"壓縮檔超過 {MAX_SIZE // (1024*1024)}MB 上限")

    try:
        cdx = await asyncio.to_thread(_syft.scan_source, content)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    summary = _import_syft_cdx(
        cdx=cdx,
        release_id=release_id,
        db=db,
        source_label="syft-source.json",
        user=user,
        audit_event="syft_source_scan",
        audit_resource_label=file.filename,
    )
    return {"filename": file.filename, **summary}


@router.post("/{release_id}/sbom-from-binary")
async def sbom_from_binary(
    release_id: str,
    file: UploadFile = File(...),
    _plan=Depends(require_plan("syft")),
    user: dict = Depends(get_current_user),
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    """上傳單一 binary(.exe / .so / .dll / firmware image / .jar / .whl 等),讓 Syft 提取嵌入元件資訊。

    Syft 內建 binary cataloguers 可從 Go / .NET / Java / Python wheel /
    Rust / Linux 核心等可執行檔抽出版本資訊。產出與 /sbom-from-source
    同一條 pipeline。
    """
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定,無法掃描")
    _assert_release_org(release, org_scope, db)

    if not file.filename:
        raise HTTPException(status_code=400, detail="請提供檔案")

    if not _syft.is_syft_available():
        raise HTTPException(
            status_code=503,
            detail="Syft 未安裝。macOS:`brew install syft`;Linux 安裝腳本見 NOTICE.md",
        )

    # Binaries can legitimately be large (firmware images / fat binaries).
    MAX_SIZE = 200 * 1024 * 1024  # 200 MB
    content = await file.read(MAX_SIZE + 1)
    if len(content) > MAX_SIZE:
        raise HTTPException(status_code=400, detail=f"檔案超過 {MAX_SIZE // (1024*1024)}MB 上限")

    try:
        cdx = await asyncio.to_thread(_syft.scan_binary, content, file.filename)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    summary = _import_syft_cdx(
        cdx=cdx,
        release_id=release_id,
        db=db,
        source_label="syft-binary.json",
        user=user,
        audit_event="syft_binary_scan",
        audit_resource_label=file.filename,
    )
    return {"filename": file.filename, **summary}

# highest_severity moved to backend/app/domain/severity.py in B.2 (2026-04-30).
