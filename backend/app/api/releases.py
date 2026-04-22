import csv
import hashlib
import io
import json
import logging
import os
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core import audit
from app.core.config import settings as _cfg
from app.core.constants import SEVERITY_ORDER
from app.core.database import get_db
from app.core.deps import get_org_scope, require_admin

logger = logging.getLogger(__name__)
from app.models.component import Component
from app.models.cra_incident import CRAIncident
from app.models.product import Product
from app.models.organization import Organization
from app.models.release import Release
from app.models.vulnerability import Vulnerability
from app.models.brand_config import BrandConfig
from app.services import sbom_parser, vuln_scanner, pdf_report, iec62443_report, iec62443_42_report, iec62443_33_report
from app.services.alerts import notify_new_vulns
from app.services.nvd import enrich_vulns_nvd
from app.services.epss import fetch_epss
from app.services.kev import fetch_kev_cve_ids

# Use env-configured path in production; auto-detect from source tree in dev
UPLOAD_DIR = (
    Path(_cfg.UPLOAD_DIR)
    if _cfg.UPLOAD_DIR
    else Path(__file__).resolve().parent.parent.parent / "uploads"
)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

_active_enrichments: set[str] = set()

router = APIRouter(prefix="/api/releases", tags=["releases"])


def _assert_release_org(release: Release, org_scope: str | None, db) -> tuple:
    """Returns (product, org). Raises 403 if viewer tries to access another org's release."""
    product = db.query(Product).filter(Product.id == release.product_id).first()
    org = db.query(Organization).filter(Organization.id == product.organization_id).first() if product else None
    if org_scope and (not product or product.organization_id != org_scope):
        raise HTTPException(status_code=403, detail="無權存取此版本")
    return product, org


def _enrich_kev(vulns: list, db) -> None:
    """Mark vulns that appear in the CISA KEV catalog."""
    kev_ids = fetch_kev_cve_ids()
    if not kev_ids:
        return
    for v in vulns:
        v.is_kev = v.cve_id in kev_ids
    db.commit()


def _enrich_epss(vulns: list, db) -> None:
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


@router.post("/{release_id}/sbom")
def upload_sbom(
    release_id: str,
    file: UploadFile = File(...),
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db),
):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定，無法上傳 SBOM")

    MAX_SIZE = 50 * 1024 * 1024  # 50 MB
    content = file.file.read(MAX_SIZE + 1)
    if len(content) > MAX_SIZE:
        raise HTTPException(status_code=400, detail="SBOM 檔案超過 50MB 上限")

    # validate then parse SBOM
    try:
        sbom_parser.validate(content, file.filename)
        parsed = sbom_parser.parse(content, file.filename)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"SBOM 解析失敗：{e}")

    # save file + compute hash (strip path separators to prevent traversal)
    safe_name = Path(file.filename or "sbom.json").name
    filepath = UPLOAD_DIR / f"{release_id}_{safe_name}"
    with open(filepath, "wb") as f:
        f.write(content)
    release.sbom_file_path = str(filepath)
    release.sbom_hash = hashlib.sha256(content).hexdigest()
    db.commit()

    # delete existing components for this release (re-upload scenario)
    db.query(Component).filter(Component.release_id == release_id).delete()
    db.commit()

    # insert components
    component_objs = []
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

    # CVE scan via OSV — deduplicate by (component_id, cve_id)
    vuln_results = vuln_scanner.scan_components(parsed)
    vuln_count = 0
    for comp, purl in component_objs:
        seen_cves: set[str] = set()
        for v in vuln_results.get(purl, []):
            cve_id = v["cve_id"]
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)
            # prefer highest CVSS if same CVE appears with different scores
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

    # Enrich with EPSS and KEV
    all_vulns = db.query(Vulnerability).join(Component).filter(Component.release_id == release_id).all()
    _enrich_epss(all_vulns, db)
    _enrich_kev(all_vulns, db)

    product = db.query(Product).filter(Product.id == release.product_id).first()
    org = db.query(Organization).filter(Organization.id == product.organization_id).first() if product else None
    label = f"{org.name if org else ''} / {product.name if product else ''} / {release.version}"
    audit.record(db, "sbom_upload", admin, resource_id=release_id, resource_label=label, org_name=org.name if org else None)
    db.commit()

    return {
        "components_found": len(parsed),
        "vulnerabilities_found": vuln_count,
    }


@router.post("/{release_id}/rescan")
def rescan_vulnerabilities(release_id: str, admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定，無法重新掃描")

    components_raw = db.query(Component).filter(Component.release_id == release_id).all()
    if not components_raw:
        raise HTTPException(status_code=400, detail="尚未上傳 SBOM，無元件可掃描")

    # Build component list for scanner (same format as upload)
    comp_list = [{"name": c.name, "version": c.version, "purl": c.purl or ""} for c in components_raw]
    vuln_results = vuln_scanner.scan_components(comp_list)

    # Build purl → component map
    purl_to_comp = {c.purl: c for c in components_raw if c.purl}

    new_count = 0
    for purl, vulns in vuln_results.items():
        comp = purl_to_comp.get(purl)
        if not comp:
            continue
        # Collect existing CVE IDs for this component to skip duplicates
        existing_cves = {v.cve_id for v in comp.vulnerabilities}
        seen_in_scan: set[str] = set()
        for v in vulns:
            cve_id = v["cve_id"]
            if cve_id in existing_cves or cve_id in seen_in_scan:
                continue
            seen_in_scan.add(cve_id)
            db.add(Vulnerability(
                component_id=comp.id,
                cve_id=cve_id,
                cvss_score=v["cvss_score"],
                severity=v["severity"],
                cvss_v4_vector=v.get("cvss_v4_vector"),
                status="open",
            ))
            new_count += 1

    db.commit()

    # Refresh EPSS and KEV for ALL vulns (both change daily)
    all_vulns = db.query(Vulnerability).join(Component).filter(Component.release_id == release_id).all()
    _enrich_epss(all_vulns, db)
    _enrich_kev(all_vulns, db)

    # Send alerts for new vulns
    if new_count > 0:
        product = db.query(Product).filter(Product.id == release.product_id).first()
        org = db.query(Organization).filter(Organization.id == product.organization_id).first() if product else None
        # Collect new vuln details for alert
        new_vuln_details = []
        for purl, vulns in vuln_results.items():
            comp = purl_to_comp.get(purl)
            if not comp:
                continue
            existing_cves = {v.cve_id for v in comp.vulnerabilities} - {v["cve_id"] for v in vulns}
            # re-derive which ones were actually new
        # Simpler: query newly added vulns (status=open added in this session is tricky, use all_vulns filtered)
        new_vuln_details = []
        for purl, scan_vulns in vuln_results.items():
            comp = purl_to_comp.get(purl)
            if not comp:
                continue
            for v in comp.vulnerabilities:
                if v.status == "open" and any(sv["cve_id"] == v.cve_id for sv in scan_vulns):
                    new_vuln_details.append({
                        "cve_id": v.cve_id,
                        "severity": v.severity,
                        "cvss_score": v.cvss_score,
                        "epss_score": v.epss_score,
                        "is_kev": bool(v.is_kev),
                        "component": f"{comp.name}@{comp.version or ''}",
                    })
        notify_new_vulns(db, {
            "org": org.name if org else "",
            "product": product.name if product else "",
            "version": release.version,
            "release_id": release_id,
        }, new_vuln_details[:new_count])

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


@router.post("/{release_id}/enrich-nvd")
def enrich_nvd(release_id: str, background_tasks: BackgroundTasks, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    if release_id in _active_enrichments:
        raise HTTPException(status_code=409, detail="此版本的 NVD 補充正在執行中，請稍後")
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    vulns = db.query(Vulnerability).join(Component).filter(Component.release_id == release_id).all()
    if not vulns:
        raise HTTPException(status_code=400, detail="此版本尚無漏洞資料")
    unique_cves = len({v.cve_id for v in vulns if v.cve_id.startswith("CVE-")})
    from app.core.config import settings as _cfg
    delay = 0.7 if _cfg.NVD_API_KEY else 7.0
    est_seconds = int(unique_cves * delay)

    def _task():
        from app.core.database import SessionLocal
        _active_enrichments.add(release_id)
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
        "created_at": release.created_at.isoformat() if release.created_at else None,
    }


@router.delete("/{release_id}", status_code=204)
def delete_release(release_id: str, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定，無法刪除")
    if release.sbom_file_path and os.path.exists(release.sbom_file_path):
        os.remove(release.sbom_file_path)
    db.delete(release)
    db.commit()


@router.get("/{release_id}/components")
def list_components(release_id: str, org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    _assert_release_org(release, org_scope, db)
    components = db.query(Component).filter(Component.release_id == release_id).all()
    result = []
    for c in components:
        vulns = c.vulnerabilities
        result.append({
            "id": c.id,
            "name": c.name,
            "version": c.version,
            "purl": c.purl,
            "license": c.license,
            "vuln_count": len(vulns),
            "highest_severity": _highest_severity(vulns),
        })
    return result


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
    components_raw = db.query(Component).filter(Component.release_id == release_id).all()

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
                v.cve_id,
                c.name,
                c.version or "",
                v.cvss_v3_score if v.cvss_v3_score is not None else (v.cvss_score if v.cvss_score is not None else ""),
                v.cvss_v4_score if v.cvss_v4_score is not None else "",
                v.severity or "",
                f"{v.epss_score:.4f}" if v.epss_score is not None else "",
                f"{v.epss_percentile:.4f}" if v.epss_percentile is not None else "",
                "是" if v.is_kev else "",
                v.cwe or "",
                v.status,
                v.justification or "",
                v.response or "",
                v.detail or "",
                (v.description or "")[:300],
            ])

    product_name = (product.name if product else "report").replace(" ", "_")
    filename = f"vulns_{product_name}_{release.version}.csv"
    return Response(
        content=buf.getvalue().encode("utf-8-sig"),  # utf-8-sig for Excel compatibility
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{release_id}/compliance")
def list_compliance(release_id: str, db: Session = Depends(get_db)):
    return {"status": "not implemented"}


@router.get("/{release_id}/report")
def download_report(release_id: str, org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")

    product, org = _assert_release_org(release, org_scope, db)
    if not product:
        product = db.query(Product).filter(Product.id == release.product_id).first()
    if not org and product:
        org = db.query(Organization).filter(Organization.id == product.organization_id).first()

    components_raw = db.query(Component).filter(Component.release_id == release_id).all()
    if not components_raw:
        raise HTTPException(status_code=400, detail="尚未上傳 SBOM，無法產生報告")

    # build component dicts
    components = []
    for c in components_raw:
        vulns = c.vulnerabilities
        components.append({
            "name": c.name,
            "version": c.version,
            "license": c.license,
            "vuln_count": len(vulns),
            "highest_severity": _highest_severity(vulns),
        })

    # build vuln dicts (sorted by cvss desc)
    all_vulns = []
    for c in components_raw:
        for v in c.vulnerabilities:
            all_vulns.append({
                "cve_id": v.cve_id,
                "component_name": c.name,
                "component_version": c.version,
                "cvss_score": v.cvss_score,
                "severity": v.severity,
                "status": v.status,
            })
    all_vulns.sort(key=lambda x: x["cvss_score"] or 0, reverse=True)

    brand_cfg = db.query(BrandConfig).filter(BrandConfig.id == "default").first()
    brand = {
        "company_name":  brand_cfg.company_name if brand_cfg else "",
        "tagline":       brand_cfg.tagline if brand_cfg else "",
        "primary_color": brand_cfg.primary_color if brand_cfg else "#1e3a8a",
        "report_footer": brand_cfg.report_footer if brand_cfg else "",
        "logo_path":     brand_cfg.logo_path if brand_cfg else None,
    } if brand_cfg else {}

    pdf_bytes = pdf_report.generate(
        org_name=org.name if org else "Unknown",
        product_name=product.name if product else "Unknown",
        version=release.version,
        components=components,
        vulns=all_vulns,
        brand=brand,
    )

    filename = f"SBOM_Report_{(product.name if product else 'report').replace(' ', '_')}_{release.version}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{release_id}/compliance/iec62443")
def download_iec62443_report(release_id: str, org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    product, org = _assert_release_org(release, org_scope, db)
    if not product:
        product = db.query(Product).filter(Product.id == release.product_id).first()
    if not org and product:
        org = db.query(Organization).filter(Organization.id == product.organization_id).first()

    components_raw = db.query(Component).filter(Component.release_id == release_id).all()
    if not components_raw:
        raise HTTPException(status_code=400, detail="尚未上傳 SBOM，無法產生合規報告")

    org_name = org.name if org else "Unknown"
    product_name = product.name if product else "Unknown"

    components = [{"name": c.name, "version": c.version, "license": c.license} for c in components_raw]

    vulns = []
    for c in components_raw:
        for v in c.vulnerabilities:
            vulns.append({
                "cve_id": v.cve_id, "severity": v.severity,
                "cvss_score": v.cvss_score, "status": v.status,
                "justification": v.justification, "detail": v.detail,
            })

    # Get all CRA incidents for this org (not release-specific, org-level context)
    org_id = product.organization_id if product else None
    incidents_raw = []
    if org_id:
        prods = db.query(Product).filter(Product.organization_id == org_id).all()
        prod_ids = [p.id for p in prods]
        # CRA incidents are org-level, fetch all
        incidents_raw = db.query(CRAIncident).all()

    cra_incidents = [{"status": i.status} for i in incidents_raw]

    pdf_bytes = iec62443_report.generate(
        org_name=org_name,
        product_name=product_name,
        version=release.version,
        components=components,
        vulns=vulns,
        cra_incidents=cra_incidents,
    )

    safe_product = product_name.replace(" ", "_")
    filename = f"IEC62443_{safe_product}_{release.version}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{release_id}/compliance/iec62443-4-2")
def download_iec62443_42_report(release_id: str, org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    product, org = _assert_release_org(release, org_scope, db)
    if not product:
        product = db.query(Product).filter(Product.id == release.product_id).first()
    if not org and product:
        org = db.query(Organization).filter(Organization.id == product.organization_id).first()
    components_raw = db.query(Component).filter(Component.release_id == release_id).all()
    if not components_raw:
        raise HTTPException(status_code=400, detail="尚未上傳 SBOM，無法產生合規報告")

    components = [{"name": c.name, "version": c.version, "license": c.license,
                   "vuln_count": len(c.vulnerabilities),
                   "highest_severity": _highest_severity(c.vulnerabilities)} for c in components_raw]
    vulns = [{"cve_id": v.cve_id, "severity": v.severity, "cvss_score": v.cvss_score,
              "status": v.status, "cwe": v.cwe, "justification": v.justification, "detail": v.detail}
             for c in components_raw for v in c.vulnerabilities]

    pdf_bytes = iec62443_42_report.generate(
        org_name=org.name if org else "Unknown",
        product_name=product.name if product else "Unknown",
        version=release.version,
        components=components,
        vulns=vulns,
    )
    safe = (product.name if product else "report").replace(" ", "_")
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="IEC62443_4-2_{safe}_{release.version}.pdf"'})


@router.get("/{release_id}/compliance/iec62443-3-3")
def download_iec62443_33_report(release_id: str, org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    product, org = _assert_release_org(release, org_scope, db)
    if not product:
        product = db.query(Product).filter(Product.id == release.product_id).first()
    if not org and product:
        org = db.query(Organization).filter(Organization.id == product.organization_id).first()
    components_raw = db.query(Component).filter(Component.release_id == release_id).all()
    if not components_raw:
        raise HTTPException(status_code=400, detail="尚未上傳 SBOM，無法產生合規報告")

    components = [{"name": c.name, "version": c.version, "license": c.license,
                   "vuln_count": len(c.vulnerabilities),
                   "highest_severity": _highest_severity(c.vulnerabilities)} for c in components_raw]
    vulns = [{"cve_id": v.cve_id, "severity": v.severity, "cvss_score": v.cvss_score,
              "status": v.status, "cwe": v.cwe, "justification": v.justification, "detail": v.detail}
             for c in components_raw for v in c.vulnerabilities]

    org_id = product.organization_id if product else None
    incidents_raw = db.query(CRAIncident).all() if org_id else []
    cra_incidents = [{"status": i.status} for i in incidents_raw]

    pdf_bytes = iec62443_33_report.generate(
        org_name=org.name if org else "Unknown",
        product_name=product.name if product else "Unknown",
        version=release.version,
        components=components,
        vulns=vulns,
        cra_incidents=cra_incidents,
    )
    safe = (product.name if product else "report").replace(" ", "_")
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="IEC62443_3-3_{safe}_{release.version}.pdf"'})


@router.get("/{release_id}/evidence-package")
def download_evidence_package(release_id: str, org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    product, org = _assert_release_org(release, org_scope, db)
    if not product:
        product = db.query(Product).filter(Product.id == release.product_id).first()
    if not org and product:
        org = db.query(Organization).filter(Organization.id == product.organization_id).first()

    components_raw = db.query(Component).filter(Component.release_id == release_id).all()
    if not components_raw:
        raise HTTPException(status_code=400, detail="尚未上傳 SBOM，無法產生證據包")

    org_name = org.name if org else "Unknown"
    product_name = product.name if product else "Unknown"
    now = datetime.now(timezone.utc)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    safe_product = product_name.replace(" ", "_")
    safe_version = release.version.replace(" ", "_")

    # ── 1. vex_summary.json ──────────────────────────────────────────────────
    all_vulns = []
    for c in components_raw:
        for v in c.vulnerabilities:
            all_vulns.append({
                "cve_id": v.cve_id,
                "component": f"{c.name}@{c.version}",
                "cvss_score": v.cvss_score,
                "severity": v.severity,
                "vex_status": v.status,
                "justification": v.justification,
                "response": v.response,
                "detail": v.detail,
            })
    all_vulns.sort(key=lambda x: x["cvss_score"] or 0, reverse=True)
    vex_summary_bytes = json.dumps({
        "generated_at": now_iso,
        "product": product_name,
        "version": release.version,
        "organization": org_name,
        "total_vulnerabilities": len(all_vulns),
        "vulnerabilities": all_vulns,
    }, indent=2, ensure_ascii=False).encode("utf-8")

    # ── 2. CSAF VEX JSON ─────────────────────────────────────────────────────
    product_id_ref = f"{release_id}-product"
    cve_map: dict = {}
    for c in components_raw:
        for v in c.vulnerabilities:
            if v.cve_id not in cve_map:
                cve_map[v.cve_id] = v
    csaf_vulns = []
    for cve_id, v in cve_map.items():
        ps: dict = {}
        if v.status == "not_affected":
            ps["known_not_affected"] = [product_id_ref]
        elif v.status == "affected":
            ps["known_affected"] = [product_id_ref]
        elif v.status == "fixed":
            ps["fixed"] = [product_id_ref]
        else:
            ps["under_investigation"] = [product_id_ref]
        entry: dict = {"cve": cve_id, "product_status": ps}
        if v.status == "not_affected" and v.justification:
            entry["threats"] = [{"category": "impact", "details": v.justification, "product_ids": [product_id_ref]}]
        if v.status == "affected" and v.response:
            entry["remediations"] = [{"category": v.response, "details": v.detail or "", "product_ids": [product_id_ref]}]
        if v.detail:
            entry["notes"] = [{"category": "general", "text": v.detail}]
        csaf_vulns.append(entry)
    csaf_doc = {
        "document": {
            "category": "csaf_vex", "csaf_version": "2.0",
            "title": f"VEX for {product_name} {release.version}",
            "publisher": {"category": "vendor", "name": org_name, "namespace": f"https://example.com"},
            "tracking": {
                "id": f"vex-{release_id}", "status": "final", "version": "1",
                "initial_release_date": now_iso, "current_release_date": now_iso,
                "revision_history": [{"date": now_iso, "number": "1", "summary": "Initial VEX"}],
            },
        },
        "product_tree": {"full_product_names": [{"name": f"{product_name} {release.version}", "product_id": product_id_ref}]},
        "vulnerabilities": csaf_vulns,
    }
    csaf_bytes = json.dumps(csaf_doc, indent=2, ensure_ascii=False).encode("utf-8")

    # ── 3. PDF report ────────────────────────────────────────────────────────
    components_for_pdf = []
    for c in components_raw:
        vulns = c.vulnerabilities
        components_for_pdf.append({
            "name": c.name, "version": c.version, "license": c.license,
            "vuln_count": len(vulns), "highest_severity": _highest_severity(vulns),
        })
    vulns_for_pdf = [{"cve_id": v["cve_id"], "component_name": v["component"].split("@")[0],
                      "component_version": v["component"].split("@")[1] if "@" in v["component"] else "",
                      "cvss_score": v["cvss_score"], "severity": v["severity"], "status": v["vex_status"]}
                     for v in all_vulns]
    brand_cfg2 = db.query(BrandConfig).filter(BrandConfig.id == "default").first()
    brand2 = {
        "company_name":  brand_cfg2.company_name if brand_cfg2 else "",
        "tagline":       brand_cfg2.tagline if brand_cfg2 else "",
        "primary_color": brand_cfg2.primary_color if brand_cfg2 else "#1e3a8a",
        "report_footer": brand_cfg2.report_footer if brand_cfg2 else "",
        "logo_path":     brand_cfg2.logo_path if brand_cfg2 else None,
    } if brand_cfg2 else {}
    pdf_bytes = pdf_report.generate(
        org_name=org_name, product_name=product_name, version=release.version,
        components=components_for_pdf, vulns=vulns_for_pdf, brand=brand2,
    )

    # ── 4. Original SBOM file ────────────────────────────────────────────────
    sbom_bytes = b""
    if release.sbom_file_path and os.path.exists(release.sbom_file_path):
        with open(release.sbom_file_path, "rb") as f:
            sbom_bytes = f.read()

    # ── 5. Build ZIP with manifest ───────────────────────────────────────────
    def sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    files = {
        "vex_summary.json":          vex_summary_bytes,
        "csaf_vex.json":             csaf_bytes,
        "vulnerability_report.pdf":  pdf_bytes,
    }
    if sbom_bytes:
        files["sbom.json"] = sbom_bytes

    manifest = {
        "generated_at": now_iso,
        "platform": "SBOM Management Platform v0.1.0",
        "organization": org_name,
        "product": product_name,
        "version": release.version,
        "files": {name: {"sha256": sha256(data), "size_bytes": len(data)} for name, data in files.items()},
    }
    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")

    zip_buf = io.BytesIO()
    folder = f"evidence_{safe_product}_{safe_version}_{now.strftime('%Y%m%d')}"
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{folder}/manifest.json", manifest_bytes)
        for name, data in files.items():
            zf.writestr(f"{folder}/{name}", data)
    zip_bytes = zip_buf.getvalue()

    filename = f"evidence_{safe_product}_{safe_version}_{now.strftime('%Y%m%d')}.zip"
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{release_id}/csaf")
def export_csaf(release_id: str, org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    product, org = _assert_release_org(release, org_scope, db)
    if not product:
        product = db.query(Product).filter(Product.id == release.product_id).first()
    if not org and product:
        org = db.query(Organization).filter(Organization.id == product.organization_id).first()

    components_raw = db.query(Component).filter(Component.release_id == release_id).all()
    if not components_raw:
        raise HTTPException(status_code=400, detail="尚未上傳 SBOM")

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    product_id_ref = f"{release_id}-product"
    org_name = org.name if org else "Unknown"
    product_name = product.name if product else "Unknown"

    # build product tree
    full_product_names = [{
        "name": f"{product_name} {release.version}",
        "product_id": product_id_ref,
    }]

    # group vulnerabilities
    cve_map: dict = {}
    for c in components_raw:
        for v in c.vulnerabilities:
            if v.cve_id not in cve_map:
                cve_map[v.cve_id] = []
            cve_map[v.cve_id].append(v)

    csaf_vulns = []
    for cve_id, vlist in cve_map.items():
        v = vlist[0]  # use first occurrence for status/justification
        product_status: dict = {}

        if v.status == "not_affected":
            product_status["known_not_affected"] = [product_id_ref]
        elif v.status == "affected":
            product_status["known_affected"] = [product_id_ref]
        elif v.status == "fixed":
            product_status["fixed"] = [product_id_ref]
        else:
            product_status["under_investigation"] = [product_id_ref]

        entry: dict = {"cve": cve_id, "product_status": product_status}

        if v.status == "not_affected" and v.justification:
            entry["threats"] = [{
                "category": "impact",
                "details": v.justification,
                "product_ids": [product_id_ref],
            }]

        if v.status == "affected" and v.response:
            entry["remediations"] = [{
                "category": v.response,
                "details": v.detail or "",
                "product_ids": [product_id_ref],
            }]

        if v.detail:
            entry["notes"] = [{"category": "general", "text": v.detail}]

        csaf_vulns.append(entry)

    csaf_doc = {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": f"VEX for {product_name} {release.version}",
            "publisher": {
                "category": "vendor",
                "name": org_name,
                "namespace": f"https://example.com/{org_name.lower().replace(' ', '-')}",
            },
            "tracking": {
                "id": f"vex-{release_id}",
                "status": "final",
                "version": "1",
                "initial_release_date": now_iso,
                "current_release_date": now_iso,
                "revision_history": [{"date": now_iso, "number": "1", "summary": "Initial VEX"}],
            },
        },
        "product_tree": {"full_product_names": full_product_names},
        "vulnerabilities": csaf_vulns,
    }

    filename = f"VEX_{product_name.replace(' ', '_')}_{release.version}.json"
    return JSONResponse(
        content=csaf_doc,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{release_id}/integrity")
def verify_integrity(release_id: str, org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    _assert_release_org(release, org_scope, db)
    if not release.sbom_file_path or not os.path.exists(release.sbom_file_path):
        return {"status": "no_file", "message": "尚未上傳 SBOM 檔案"}
    if not release.sbom_hash:
        return {"status": "no_hash", "message": "此版本無完整性記錄（上傳時未計算 hash）"}
    with open(release.sbom_file_path, "rb") as f:
        current_hash = hashlib.sha256(f.read()).hexdigest()
    ok = current_hash == release.sbom_hash
    return {
        "status": "ok" if ok else "tampered",
        "stored_hash": release.sbom_hash,
        "current_hash": current_hash,
        "message": "檔案完整，未被竄改" if ok else "⚠ 警告：SBOM 檔案與上傳時的 hash 不符，可能已被竄改",
    }


@router.post("/{release_id}/lock")
def lock_release(release_id: str, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定")
    release.locked = True
    db.commit()
    return {"locked": True}


@router.post("/{release_id}/unlock")
def unlock_release(release_id: str, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    release.locked = False
    db.commit()
    return {"locked": False}


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


def _highest_severity(vulns) -> str | None:
    if not vulns:
        return None
    return max(vulns, key=lambda v: SEVERITY_ORDER.get(v.severity or "info", 0)).severity
