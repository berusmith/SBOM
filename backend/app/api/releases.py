import hashlib
import io
import json
import os
import uuid
import zipfile
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.component import Component
from app.models.cra_incident import CRAIncident
from app.models.product import Product
from app.models.organization import Organization
from app.models.release import Release
from app.models.vulnerability import Vulnerability
from app.services import sbom_parser, vuln_scanner, pdf_report, iec62443_report
from app.services.epss import fetch_epss

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

router = APIRouter(prefix="/api/releases", tags=["releases"])


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
    db: Session = Depends(get_db),
):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")

    content = file.file.read()

    # parse SBOM
    try:
        parsed = sbom_parser.parse(content, file.filename)
    except (ValueError, Exception) as e:
        raise HTTPException(status_code=400, detail=f"SBOM 解析失敗：{e}")

    # save file
    filename = f"{release_id}_{file.filename}"
    filepath = os.path.join(UPLOAD_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(content)
    release.sbom_file_path = filepath
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
                status="open",
            ))
            vuln_count += 1
    db.commit()

    # Enrich newly added vulns with EPSS scores
    all_vulns = db.query(Vulnerability).join(Component).filter(Component.release_id == release_id).all()
    _enrich_epss(all_vulns, db)

    return {
        "components_found": len(parsed),
        "vulnerabilities_found": vuln_count,
    }


@router.post("/{release_id}/rescan")
def rescan_vulnerabilities(release_id: str, db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")

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
                status="open",
            ))
            new_count += 1

    db.commit()

    # Refresh EPSS scores for ALL vulns in this release (scores change daily)
    all_vulns = db.query(Vulnerability).join(Component).filter(Component.release_id == release_id).all()
    _enrich_epss(all_vulns, db)

    return {
        "components_scanned": len(comp_list),
        "new_vulnerabilities_found": new_count,
    }


@router.post("/{release_id}/enrich-epss")
def enrich_epss(release_id: str, db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    vulns = db.query(Vulnerability).join(Component).filter(Component.release_id == release_id).all()
    if not vulns:
        raise HTTPException(status_code=400, detail="此版本尚無漏洞資料")
    _enrich_epss(vulns, db)
    updated = sum(1 for v in vulns if v.epss_score is not None)
    return {"total_vulnerabilities": len(vulns), "epss_updated": updated}


@router.delete("/{release_id}", status_code=204)
def delete_release(release_id: str, db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    if release.sbom_file_path and os.path.exists(release.sbom_file_path):
        os.remove(release.sbom_file_path)
    db.delete(release)
    db.commit()


@router.get("/{release_id}/components")
def list_components(release_id: str, db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
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
def list_vulnerabilities(release_id: str, db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    components = db.query(Component).filter(Component.release_id == release_id).all()
    result = []
    for c in components:
        for v in c.vulnerabilities:
            result.append({
                "id": v.id,
                "component_name": c.name,
                "component_version": c.version,
                "cve_id": v.cve_id,
                "cvss_score": v.cvss_score,
                "severity": v.severity,
                "status": v.status,
                "justification": v.justification,
                "response": v.response,
                "detail": v.detail,
                "epss_score": v.epss_score,
                "epss_percentile": v.epss_percentile,
            })
    result.sort(key=lambda x: x["epss_score"] or x["cvss_score"] or 0, reverse=True)
    return result


@router.get("/{release_id}/compliance")
def list_compliance(release_id: str, db: Session = Depends(get_db)):
    return {"status": "not implemented"}


@router.get("/{release_id}/report")
def download_report(release_id: str, db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")

    product = db.query(Product).filter(Product.id == release.product_id).first()
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

    pdf_bytes = pdf_report.generate(
        org_name=org.name if org else "Unknown",
        product_name=product.name if product else "Unknown",
        version=release.version,
        components=components,
        vulns=all_vulns,
    )

    filename = f"SBOM_Report_{(product.name if product else 'report').replace(' ', '_')}_{release.version}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{release_id}/compliance/iec62443")
def download_iec62443_report(release_id: str, db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")

    product = db.query(Product).filter(Product.id == release.product_id).first()
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


@router.get("/{release_id}/evidence-package")
def download_evidence_package(release_id: str, db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")

    product = db.query(Product).filter(Product.id == release.product_id).first()
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
    pdf_bytes = pdf_report.generate(
        org_name=org_name, product_name=product_name, version=release.version,
        components=components_for_pdf, vulns=vulns_for_pdf,
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
def export_csaf(release_id: str, db: Session = Depends(get_db)):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")

    product = db.query(Product).filter(Product.id == release.product_id).first()
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


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _highest_severity(vulns) -> str | None:
    if not vulns:
        return None
    return max(vulns, key=lambda v: SEVERITY_ORDER.get(v.severity or "info", 0)).severity
