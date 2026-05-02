"""Lifecycle endpoints — get / patch / delete / list / lock / gate / graph.

Moved from backend/app/api/releases.py in D.7 (2026-04-30).  13 endpoints:

  GET    /                          — get_release (basic info)
  PATCH  /version                   — update_version (rename version)
  DELETE /                          — delete_release
  PATCH  /notes                     — update_notes (changelog text)
  GET    /components                — list_components (paginated)
  GET    /vulnerabilities           — list_vulnerabilities (paginated, sorted by EPSS/CVSS)
  GET    /vulnerabilities/export    — export_vulnerabilities_csv
  GET    /compliance                — list_compliance (placeholder; ownership-checked per SEC-023)
  POST   /lock                      — lock_release
  POST   /unlock                    — unlock_release
  GET    /patch-stats               — get_patch_stats
  GET    /gate                      — get_gate (Policy Gate 6 checks)
  GET    /dependency-graph          — get_dependency_graph (SVG nodes/edges)

D.8 (2026-05-01) migrated all 10 sites here from the legacy ownership-check
pattern to Depends(require_release_in_scope) (404 oracle prevention).
"""
from __future__ import annotations

import csv
import io
import json
import logging
import os

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import func
from sqlalchemy.orm import Session, selectinload

from app.core import audit
from app.core.database import get_db
from app.core.deps import require_admin, require_release_in_scope
from app.core.security import csv_safe, safe_attachment_filename
from app.domain.severity import highest_severity
from app.domain.sla import sla_info
from app.domain.suppression import is_suppressed
from app.models.component import Component
from app.models.product import Product
from app.models.release import Release
from app.models.vulnerability import Vulnerability
from app.schemas.release_lifecycle import ReleaseNotesUpdate, ReleaseVersionUpdate
from app.services.license_classifier import classify_license
from app.services.sbom_parser import check_ntia as _check_ntia_fn
from app.services.signature_verifier import verify_signature as _verify_sig
# D.8 (2026-05-01): legacy ownership helper replaced by require_release_in_scope (404 oracle prevention).

router = APIRouter(prefix="/api/releases", tags=["releases"])


@router.get("/{release_id}")
def get_release(release_id: str, release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
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
def update_version(release_id: str, body: ReleaseVersionUpdate, _admin: dict = Depends(require_admin),
                   release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    """Rename a release version string (admin only).

    Per Q-P7-3 + E.2 scope lock: typed body, BEHAVIOR-EQUIVALENT.  The schema's
    field validator does the strip; the handler still raises 400 on empty-after-strip
    (preserves zh-TW message; Pydantic min_length=1 would emit 422 instead).
    """
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定，無法修改版本號")
    if not body.version:
        raise HTTPException(status_code=400, detail="版本號不可為空")
    release.version = body.version
    db.commit()
    return {"id": release_id, "version": release.version}


@router.delete("/{release_id}", status_code=204)
def delete_release(release_id: str, _admin: dict = Depends(require_admin), release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定，無法刪除")
    if release.sbom_file_path and os.path.exists(release.sbom_file_path):
        os.remove(release.sbom_file_path)
    db.delete(release)
    db.commit()


@router.patch("/{release_id}/notes")
def update_notes(release_id: str, body: ReleaseNotesUpdate, _admin: dict = Depends(require_admin),
                 release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    """Update release notes / changelog text.

    Per Q-P7-3 + E.2 scope lock: typed body, BEHAVIOR-EQUIVALENT.  The schema's
    field validator does the silent truncation at 5000 chars (NO 422 on overflow);
    the handler still converts empty string to None for storage.
    """
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定，無法修改備註")
    release.notes = body.notes or None
    db.commit()
    return {"notes": release.notes}


@router.get("/{release_id}/components")
def list_components(
    release_id: str,
    skip: int = 0,
    limit: int = 2000,
    release: Release = Depends(require_release_in_scope),
    db: Session = Depends(get_db),
):
    if limit > 5000:
        limit = 5000
    total = db.query(func.count(Component.id)).filter(Component.release_id == release_id).scalar()
    components = (db.query(Component)
                  .options(selectinload(Component.vulnerabilities))
                  .filter(Component.release_id == release_id)
                  .offset(skip).limit(limit).all())
    result = []
    for c in components:
        vulns = c.vulnerabilities
        result.append({
            "id": c.id, "name": c.name, "version": c.version, "purl": c.purl, "license": c.license,
            "license_risk": classify_license(c.license) if c.license else None,
            "vuln_count": len(vulns), "highest_severity": highest_severity(vulns),
        })
    return {"total": total, "skip": skip, "limit": limit, "items": result}


@router.get("/{release_id}/vulnerabilities")
def list_vulnerabilities(
    release_id: str,
    skip: int = 0,
    limit: int = 500,
    release: Release = Depends(require_release_in_scope),
    db: Session = Depends(get_db),
):
    if limit > 1000:
        limit = 1000
    order_expr = func.coalesce(Vulnerability.epss_score, Vulnerability.cvss_score, 0)
    rows = (
        db.query(Vulnerability, Component.name.label("comp_name"), Component.version.label("comp_version"))
        .join(Component, Component.id == Vulnerability.component_id)
        .filter(Component.release_id == release_id)
        .order_by(order_expr.desc()).offset(skip).limit(limit).all()
    )
    return [
        {
            "id": v.id, "component_name": comp_name, "component_version": comp_version,
            "cve_id": v.cve_id, "cvss_score": v.cvss_score, "severity": v.severity,
            "status": v.status, "justification": v.justification, "response": v.response,
            "detail": v.detail, "epss_score": v.epss_score, "epss_percentile": v.epss_percentile,
            "is_kev": bool(v.is_kev), "description": v.description, "cwe": v.cwe,
            "nvd_refs": json.loads(v.nvd_refs) if v.nvd_refs else [],
            "cvss_v3_score": v.cvss_v3_score, "cvss_v3_vector": v.cvss_v3_vector,
            "cvss_v4_score": v.cvss_v4_score, "cvss_v4_vector": v.cvss_v4_vector,
            **sla_info(v),
            "suppressed":        is_suppressed(v),
            "suppressed_until":  v.suppressed_until.isoformat() if v.suppressed_until else None,
            "suppressed_reason": v.suppressed_reason,
        }
        for v, comp_name, comp_version in rows
    ]


@router.get("/{release_id}/vulnerabilities/export")
def export_vulnerabilities_csv(release_id: str, release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):

    product = db.query(Product).filter(Product.id == release.product_id).first()
    components_raw = (db.query(Component).options(selectinload(Component.vulnerabilities))
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
                csv_safe(v.cve_id), csv_safe(c.name), csv_safe(c.version),
                v.cvss_v3_score if v.cvss_v3_score is not None else (v.cvss_score if v.cvss_score is not None else ""),
                v.cvss_v4_score if v.cvss_v4_score is not None else "",
                csv_safe(v.severity),
                f"{v.epss_score:.4f}" if v.epss_score is not None else "",
                f"{v.epss_percentile:.4f}" if v.epss_percentile is not None else "",
                "是" if v.is_kev else "",
                csv_safe(v.cwe), csv_safe(v.status), csv_safe(v.justification),
                csv_safe(v.response), csv_safe(v.detail),
                csv_safe((v.description or "")[:300]),
            ])

    product_name = (product.name if product else "report").replace(" ", "_")
    filename = safe_attachment_filename(f"vulns_{product_name}_{release.version}.csv", default="vulns.csv")
    return Response(
        content=buf.getvalue().encode("utf-8-sig"),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{release_id}/compliance")
def list_compliance(release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    """Per SEC-023: placeholder route enforces release ownership before returning the not-implemented stub.
    Future implementer fills the body without forgetting the ownership check (CI enforcement test ensures it)."""
    return {"status": "not implemented"}


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


@router.get("/{release_id}/patch-stats")
def get_patch_stats(release_id: str, release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):

    components = db.query(Component).filter(Component.release_id == release_id).all()
    vulns = [v for c in components for v in c.vulnerabilities]

    total = len(vulns)
    fixed = sum(1 for v in vulns if v.status == "fixed")
    open_count = sum(1 for v in vulns if v.status == "open")
    in_triage = sum(1 for v in vulns if v.status == "in_triage")
    affected = sum(1 for v in vulns if v.status == "affected")
    not_affected = sum(1 for v in vulns if v.status == "not_affected")
    patch_rate = round(fixed / total * 100, 1) if total else 0.0

    days_list = []
    for v in vulns:
        if v.status == "fixed" and v.fixed_at and v.scanned_at:
            delta = v.fixed_at - v.scanned_at
            days_list.append(delta.total_seconds() / 86400)
    avg_days_to_fix = round(sum(days_list) / len(days_list), 1) if days_list else None

    return {
        "total": total, "fixed": fixed, "open": open_count, "in_triage": in_triage,
        "affected": affected, "not_affected": not_affected,
        "patch_rate": patch_rate, "avg_days_to_fix": avg_days_to_fix,
    }


@router.get("/{release_id}/gate")
def get_gate(release_id: str, release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    from app.models.license_rule import LicenseRule
    from app.api.licenses import _matches as _lic_matches


    components = db.query(Component).filter(Component.release_id == release_id).all()
    vulns = [v for c in components for v in c.vulnerabilities]
    checks = []

    has_sbom = bool(release.sbom_hash)
    checks.append({"id": "sbom_uploaded", "label": "SBOM 已上傳",
                   "passed": has_sbom,
                   "detail": "已上傳 SBOM 並計算 hash" if has_sbom else "尚未上傳 SBOM"})

    critical_open = [v for v in vulns if v.severity == "critical" and v.status in ("open", "in_triage", "affected") and not is_suppressed(v)]
    no_critical = len(critical_open) == 0
    checks.append({"id": "no_critical", "label": "無未處理 Critical 漏洞",
                   "passed": no_critical,
                   "detail": f"發現 {len(critical_open)} 個 Critical 漏洞未處理" if not no_critical else "無未處理 Critical 漏洞"})

    rules = db.query(LicenseRule).filter(LicenseRule.enabled == True).all()  # noqa: E712
    block_violations = sum(
        1 for comp in components if comp.license
        for rule in rules if rule.action == "block" and _lic_matches(rule.license_id, comp.license)
    )
    no_block_lic = block_violations == 0
    checks.append({"id": "no_block_license", "label": "無 Block 等級 License",
                   "passed": no_block_lic,
                   "detail": f"{block_violations} 個元件觸發 block License 規則" if not no_block_lic else "無 block 等級 License 違規"})

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
        except Exception:  # Deliberate broad-except (b-fix N.5): SBOM parse/score failures diverse — silent swallow upgraded to log + continue
            # PR-3 N.5 (CODE-1.014 partial): silent swallow → log + continue.
            # Same pattern as PR-1 D.3's CODE-1.011 fix at upload_sbom.py:84
            # (logger.exception preserves gate behavior — quality_grade stays
            # None and the sbom_quality check below shows "無 SBOM 可評分").
            # Broad catch retained: SBOM parse/score failure modes are diverse
            # (JSON malformed / NTIA helper internal / PDF render race / etc.).
            logger.warning(
                "SBOM quality grade computation failed for release %s; gate continues with no grade",
                release_id,
            )
    good_quality = quality_grade in ("A", "B")
    grade_str = f"等級 {quality_grade}（{quality_passed}/7）" if quality_grade else "無 SBOM 可評分"
    checks.append({"id": "sbom_quality", "label": "SBOM 品質 ≥ B 級",
                   "passed": good_quality, "detail": grade_str})

    untriaged = [v for v in vulns if v.status in ("open", "in_triage") and not is_suppressed(v)]
    all_triaged = len(untriaged) == 0
    checks.append({"id": "all_triaged", "label": "所有漏洞已完成分類",
                   "passed": all_triaged,
                   "detail": f"{len(untriaged)} 個漏洞仍為 open/in_triage" if not all_triaged else f"全部 {len(vulns)} 個漏洞已分類"})

    has_sig = bool(release.sbom_signature and release.signature_public_key)
    sig_valid = False
    sig_detail = "尚未上傳簽章"
    if has_sig and release.sbom_file_path and os.path.exists(release.sbom_file_path):
        with open(release.sbom_file_path, "rb") as f:
            result = _verify_sig(f.read(), release.sbom_signature, release.signature_public_key, release.signature_algorithm)
        sig_valid = result.valid
        sig_detail = result.message
    checks.append({"id": "signature_verified", "label": "SBOM 簽章已驗證",
                   "passed": sig_valid or not has_sig,
                   "detail": sig_detail})

    passed_count = sum(1 for c in checks if c["passed"])
    return {
        "overall": "pass" if passed_count == len(checks) else "fail",
        "passed": passed_count, "total": len(checks), "checks": checks,
    }


@router.get("/{release_id}/dependency-graph")
def get_dependency_graph(release_id: str, release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):

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

    vuln_names: set = set()
    for comp in db.query(Component).filter(Component.release_id == release_id).all():
        if any(v.severity in ("critical", "high") and v.status not in ("fixed", "not_affected") for v in comp.vulnerabilities):
            vuln_names.add(comp.name)

    nodes = []
    for n in node_map.values():
        nodes.append({**n, "has_vuln": n["name"] in vuln_names})

    return {
        "has_data": len(edges) > 0,
        "nodes": nodes[:200], "edges": edges[:600],
        "total_nodes": len(nodes), "total_edges": len(edges),
    }
