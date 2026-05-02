"""Report endpoints — PDF / CSAF / evidence package / format export / quality / integrity.

Moved from backend/app/api/releases.py in D.4 (2026-04-30).  11 endpoints:
  GET /report                       — generic SBOM PDF
  GET /compliance/iec62443          — IEC 62443-4-1 PDF (SDL)
  GET /compliance/iec62443-4-2      — IEC 62443-4-2 PDF (component)
  GET /compliance/iec62443-3-3      — IEC 62443-3-3 PDF (system)
  GET /compliance/nis2              — NIS2 Article 21 PDF
  GET /evidence-package             — ZIP (PDF + CSAF + SBOM + manifest)
  GET /csaf                         — CSAF VEX 2.0 JSON
  GET /export/cyclonedx-xml         — CycloneDX XML
  GET /export/spdx-json             — SPDX JSON
  GET /sbom-quality                 — NTIA quality grading
  GET /integrity                    — SHA-256 integrity + signature

Helpers extracted (CODE-1.003 + CODE-1.019 partial — full template extraction
deferred to followup; current scope cap is AC-A4 < 600 LOC):
  _lookup_components_for_release   — fetch components + (product, org) given a release
                                     (renamed from _lookup_release_with_components in D.8
                                     — release lookup + ownership now lives in Depends)
  _brand_dict                      — brand config dict
  _build_csaf_doc                  — CSAF VEX construction (was duplicated in csaf + evidence_package)
  _cra_incidents_for_release       — CRA incident list (used by 3+ reports)

D.8 (2026-05-01) migrated all 5 sites here from the legacy ownership-check
pattern to Depends(require_release_in_scope) (404 oracle prevention) +
release_context (for the (product, org) tuple the legacy helper used to return).
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import uuid
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session, selectinload

from app.core.database import get_db
from app.core.deps import release_context, require_release_in_scope
from app.core.plan import require_plan
from app.domain.severity import highest_severity
from app.models.brand_config import BrandConfig
from app.models.component import Component
from app.models.cra_incident import CRAIncident
from app.models.release import Release
from app.services import iec62443_33_report, iec62443_42_report, iec62443_report, nis2_report, pdf_report
from app.services.sbom_parser import score_sbom as _score_sbom
from app.services.signature_verifier import verify_signature as _verify_sig
# D.8 (2026-05-01): legacy ownership helper replaced by require_release_in_scope (404 oracle prevention).
# release_context(release, db) → (product, org) used where the legacy helper's tuple was needed.

router = APIRouter(prefix="/api/releases", tags=["releases"])


# ── shared helpers ───────────────────────────────────────────────────────────

def _lookup_components_for_release(release: Release, db, no_data_msg: str):
    """Common scaffold for PDF endpoints: returns (release, product, org, components_raw).

    Caller already injected `release` via Depends(require_release_in_scope) — that
    handles the 404 (missing OR cross-org).  This helper just resolves (product, org)
    via release_context and fetches the components, raising 400 if the release has
    no components yet.

    D.8 (2026-05-01) replaced the prior _lookup_release_with_components which
    handled 404 + 403 + 400 inline; the 404/ownership concern now lives in Depends.
    """
    product, org = release_context(release, db)
    components_raw = (db.query(Component)
                      .options(selectinload(Component.vulnerabilities))
                      .filter(Component.release_id == release.id).all())
    if not components_raw:
        raise HTTPException(status_code=400, detail=no_data_msg)
    return release, product, org, components_raw


def _brand_dict(db) -> dict:
    cfg = db.query(BrandConfig).filter(BrandConfig.id == "default").first()
    if not cfg:
        return {}
    return {
        "company_name":  cfg.company_name,
        "tagline":       cfg.tagline,
        "primary_color": cfg.primary_color,
        "report_footer": cfg.report_footer,
        "logo_path":     cfg.logo_path,
    }


def _cra_incidents_for_release(product, db) -> list[dict]:
    org_id = product.organization_id if product else None
    if not org_id:
        return []
    incidents_raw = db.query(CRAIncident).filter(CRAIncident.org_id == org_id).all()
    return [{"status": i.status} for i in incidents_raw]


def _pdf_response(pdf_bytes: bytes, filename: str) -> Response:
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _build_csaf_doc(release: Release, components_raw, namespace_suffix: str = "") -> dict:
    """Build a CSAF VEX 2.0 document.  Used by /csaf AND /evidence-package."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    product_id_ref = f"{release.id}-product"
    product = release.product if hasattr(release, "product") and release.product else None
    org = product.organization if product and hasattr(product, "organization") else None
    org_name = org.name if org else "Unknown"
    product_name = product.name if product else "Unknown"

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

    namespace = f"https://example.com{namespace_suffix}"  # CODE-1.013 — fix in PR-2 F.5
    return {
        "document": {
            "category": "csaf_vex", "csaf_version": "2.0",
            "title": f"VEX for {product_name} {release.version}",
            "publisher": {"category": "vendor", "name": org_name, "namespace": namespace},
            "tracking": {
                "id": f"vex-{release.id}", "status": "final", "version": "1",
                "initial_release_date": now_iso, "current_release_date": now_iso,
                "revision_history": [{"date": now_iso, "number": "1", "summary": "Initial VEX"}],
            },
        },
        "product_tree": {"full_product_names": [{"name": f"{product_name} {release.version}", "product_id": product_id_ref}]},
        "vulnerabilities": csaf_vulns,
    }


# ── endpoints ────────────────────────────────────────────────────────────────

@router.get("/{release_id}/report")
def download_report(release_id: str, release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    release, product, org, components_raw = _lookup_components_for_release(release, db, "尚未上傳 SBOM，無法產生報告")
    components = [{"name": c.name, "version": c.version, "license": c.license,
                   "vuln_count": len(c.vulnerabilities), "highest_severity": highest_severity(c.vulnerabilities)}
                  for c in components_raw]
    all_vulns = sorted(
        [{"cve_id": v.cve_id, "component_name": c.name, "component_version": c.version,
          "cvss_score": v.cvss_score, "severity": v.severity, "status": v.status}
         for c in components_raw for v in c.vulnerabilities],
        key=lambda x: x["cvss_score"] or 0, reverse=True,
    )
    pdf_bytes = pdf_report.generate(
        org_name=org.name if org else "Unknown",
        product_name=product.name if product else "Unknown",
        version=release.version, components=components, vulns=all_vulns, brand=_brand_dict(db),
    )
    return _pdf_response(pdf_bytes, f"SBOM_Report_{(product.name if product else 'report').replace(' ', '_')}_{release.version}.pdf")


@router.get("/{release_id}/compliance/iec62443")
def download_iec62443_report(release_id: str, release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    release, product, org, components_raw = _lookup_components_for_release(release, db, "尚未上傳 SBOM，無法產生合規報告")
    components = [{"name": c.name, "version": c.version, "license": c.license} for c in components_raw]
    vulns = [{"cve_id": v.cve_id, "severity": v.severity, "cvss_score": v.cvss_score, "status": v.status,
              "justification": v.justification, "detail": v.detail}
             for c in components_raw for v in c.vulnerabilities]
    pdf_bytes = iec62443_report.generate(
        org_name=org.name if org else "Unknown",
        product_name=product.name if product else "Unknown",
        version=release.version, components=components, vulns=vulns,
        cra_incidents=_cra_incidents_for_release(product, db),
    )
    return _pdf_response(pdf_bytes, f"IEC62443_{(product.name if product else 'report').replace(' ', '_')}_{release.version}.pdf")


@router.get("/{release_id}/compliance/iec62443-4-2")
def download_iec62443_42_report(release_id: str, _plan=Depends(require_plan("iec62443_42")), release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    release, product, org, components_raw = _lookup_components_for_release(release, db, "尚未上傳 SBOM，無法產生合規報告")
    components = [{"name": c.name, "version": c.version, "license": c.license,
                   "vuln_count": len(c.vulnerabilities), "highest_severity": highest_severity(c.vulnerabilities)}
                  for c in components_raw]
    vulns = [{"cve_id": v.cve_id, "severity": v.severity, "cvss_score": v.cvss_score,
              "status": v.status, "cwe": v.cwe, "justification": v.justification, "detail": v.detail}
             for c in components_raw for v in c.vulnerabilities]
    pdf_bytes = iec62443_42_report.generate(
        org_name=org.name if org else "Unknown",
        product_name=product.name if product else "Unknown",
        version=release.version, components=components, vulns=vulns,
    )
    return _pdf_response(pdf_bytes, f"IEC62443_4-2_{(product.name if product else 'report').replace(' ', '_')}_{release.version}.pdf")


@router.get("/{release_id}/compliance/iec62443-3-3")
def download_iec62443_33_report(release_id: str, _plan=Depends(require_plan("iec62443_33")), release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    release, product, org, components_raw = _lookup_components_for_release(release, db, "尚未上傳 SBOM，無法產生合規報告")
    components = [{"name": c.name, "version": c.version, "license": c.license,
                   "vuln_count": len(c.vulnerabilities), "highest_severity": highest_severity(c.vulnerabilities)}
                  for c in components_raw]
    vulns = [{"cve_id": v.cve_id, "severity": v.severity, "cvss_score": v.cvss_score,
              "status": v.status, "cwe": v.cwe, "justification": v.justification, "detail": v.detail}
             for c in components_raw for v in c.vulnerabilities]
    pdf_bytes = iec62443_33_report.generate(
        org_name=org.name if org else "Unknown",
        product_name=product.name if product else "Unknown",
        version=release.version, components=components, vulns=vulns,
        cra_incidents=_cra_incidents_for_release(product, db),
    )
    return _pdf_response(pdf_bytes, f"IEC62443_3-3_{(product.name if product else 'report').replace(' ', '_')}_{release.version}.pdf")


@router.get("/{release_id}/compliance/nis2")
def download_nis2_report(release_id: str, release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    """Generate NIS2 Directive Article 21 compliance PDF report."""
    release, product, org, components_raw = _lookup_components_for_release(release, db, "尚未上傳 SBOM，無法產生合規報告")
    components = [{"name": c.name, "version": c.version, "purl": c.purl, "license": c.license,
                   "vuln_count": len(c.vulnerabilities), "highest_severity": highest_severity(c.vulnerabilities)}
                  for c in components_raw]
    vulns = [{"cve_id": v.cve_id, "severity": v.severity, "cvss_score": v.cvss_score,
              "status": v.status, "cwe": v.cwe, "is_kev": bool(v.is_kev)}
             for c in components_raw for v in c.vulnerabilities]
    pdf_bytes = nis2_report.generate(
        org_name=org.name if org else "Unknown",
        product_name=product.name if product else "Unknown",
        version=release.version, components=components, vulns=vulns,
        cra_incidents=_cra_incidents_for_release(product, db),
    )
    return _pdf_response(pdf_bytes, f"NIS2_{(product.name if product else 'report').replace(' ', '_')}_{release.version}.pdf")


@router.get("/{release_id}/evidence-package")
def download_evidence_package(release_id: str, release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    release, product, org, components_raw = _lookup_components_for_release(release, db, "尚未上傳 SBOM，無法產生證據包")
    org_name = org.name if org else "Unknown"
    product_name = product.name if product else "Unknown"
    now = datetime.now(timezone.utc)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    safe_product = product_name.replace(" ", "_")
    safe_version = release.version.replace(" ", "_")

    # vex_summary.json
    all_vulns = sorted(
        [{"cve_id": v.cve_id, "component": f"{c.name}@{c.version}", "cvss_score": v.cvss_score,
          "severity": v.severity, "vex_status": v.status, "justification": v.justification,
          "response": v.response, "detail": v.detail}
         for c in components_raw for v in c.vulnerabilities],
        key=lambda x: x["cvss_score"] or 0, reverse=True,
    )
    vex_summary_bytes = json.dumps({
        "generated_at": now_iso, "product": product_name, "version": release.version,
        "organization": org_name, "total_vulnerabilities": len(all_vulns), "vulnerabilities": all_vulns,
    }, indent=2, ensure_ascii=False).encode("utf-8")

    # CSAF VEX (CODE-1.019: now reuses _build_csaf_doc instead of duplicating)
    csaf_bytes = json.dumps(_build_csaf_doc(release, components_raw), indent=2, ensure_ascii=False).encode("utf-8")

    # PDF report
    components_for_pdf = [{"name": c.name, "version": c.version, "license": c.license,
                           "vuln_count": len(c.vulnerabilities), "highest_severity": highest_severity(c.vulnerabilities)}
                          for c in components_raw]
    vulns_for_pdf = [{"cve_id": v["cve_id"], "component_name": v["component"].split("@")[0],
                      "component_version": v["component"].split("@")[1] if "@" in v["component"] else "",
                      "cvss_score": v["cvss_score"], "severity": v["severity"], "status": v["vex_status"]}
                     for v in all_vulns]
    pdf_bytes = pdf_report.generate(
        org_name=org_name, product_name=product_name, version=release.version,
        components=components_for_pdf, vulns=vulns_for_pdf, brand=_brand_dict(db),
    )

    # Original SBOM file
    sbom_bytes = b""
    if release.sbom_file_path and os.path.exists(release.sbom_file_path):
        with open(release.sbom_file_path, "rb") as f:
            sbom_bytes = f.read()

    files = {
        "vex_summary.json":          vex_summary_bytes,
        "csaf_vex.json":             csaf_bytes,
        "vulnerability_report.pdf":  pdf_bytes,
    }
    if sbom_bytes:
        files["sbom.json"] = sbom_bytes

    manifest = {
        "generated_at": now_iso, "platform": "SBOM Management Platform v0.1.0",
        "organization": org_name, "product": product_name, "version": release.version,
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)} for name, data in files.items()},
    }
    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")

    zip_buf = io.BytesIO()
    folder = f"evidence_{safe_product}_{safe_version}_{now.strftime('%Y%m%d')}"
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{folder}/manifest.json", manifest_bytes)
        for name, data in files.items():
            zf.writestr(f"{folder}/{name}", data)
    return Response(
        content=zip_buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="evidence_{safe_product}_{safe_version}_{now.strftime("%Y%m%d")}.zip"'},
    )


@router.get("/{release_id}/csaf")
def export_csaf(release_id: str, release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    release, product, org, components_raw = _lookup_components_for_release(release, db, "尚未上傳 SBOM")
    org_name = org.name if org else "Unknown"
    product_name = product.name if product else "Unknown"
    # The pre-D.4 export_csaf used a slightly different namespace pattern (org-slug suffix)
    # vs evidence_package (no suffix).  Preserve both via the namespace_suffix arg.
    csaf_doc = _build_csaf_doc(release, components_raw, namespace_suffix=f"/{org_name.lower().replace(' ', '-')}")
    return JSONResponse(
        content=csaf_doc,
        headers={"Content-Disposition": f'attachment; filename="VEX_{product_name.replace(" ", "_")}_{release.version}.json"'},
    )


@router.get("/{release_id}/export/cyclonedx-xml")
def export_cyclonedx_xml(release_id: str, release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    product, org = release_context(release, db)
    components = db.query(Component).filter(Component.release_id == release_id).all()

    NS = "http://cyclonedx.org/schema/bom/1.4"
    ET.register_namespace("", NS)
    bom = ET.Element(f"{{{NS}}}bom", {"version": "1", "serialNumber": f"urn:uuid:{uuid.uuid4()}"})
    meta = ET.SubElement(bom, f"{{{NS}}}metadata")
    ET.SubElement(meta, f"{{{NS}}}timestamp").text = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if product:
        mc = ET.SubElement(meta, f"{{{NS}}}component", {"type": "application"})
        ET.SubElement(mc, f"{{{NS}}}name").text = product.name
        ET.SubElement(mc, f"{{{NS}}}version").text = release.version or ""
    comps_el = ET.SubElement(bom, f"{{{NS}}}components")
    for c in components:
        cel = ET.SubElement(comps_el, f"{{{NS}}}component", {"type": "library"})
        ET.SubElement(cel, f"{{{NS}}}name").text = c.name or ""
        if c.version:
            ET.SubElement(cel, f"{{{NS}}}version").text = c.version
        if c.purl:
            ET.SubElement(cel, f"{{{NS}}}purl").text = c.purl
        if c.license:
            lics_el = ET.SubElement(cel, f"{{{NS}}}licenses")
            lic_el  = ET.SubElement(lics_el, f"{{{NS}}}license")
            ET.SubElement(lic_el, f"{{{NS}}}id").text = c.license
    xml_bytes = ET.tostring(bom, encoding="unicode", xml_declaration=False)
    xml_bytes = f'<?xml version="1.0" encoding="UTF-8"?>\n{xml_bytes}'
    prod_name = (product.name if product else "sbom").replace(" ", "_")
    return Response(
        content=xml_bytes.encode("utf-8"),
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="cyclonedx_{prod_name}_{release.version or release_id[:8]}.xml"'},
    )


@router.get("/{release_id}/export/spdx-json")
def export_spdx_json(release_id: str, release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    product, org = release_context(release, db)
    components = db.query(Component).filter(Component.release_id == release_id).all()

    doc_name = f"{product.name if product else 'sbom'}-{release.version or release_id[:8]}"
    doc: dict = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": doc_name, "documentNamespace": f"https://sbom-platform/spdx/{release_id}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: SBOM Platform"],
        },
        "packages": [], "relationships": [],
    }
    root_spdxid = "SPDXRef-Package-root"
    doc["packages"].append({
        "SPDXID": root_spdxid, "name": product.name if product else "unknown",
        "versionInfo": release.version or "unknown",
        "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
    })
    doc["relationships"].append({
        "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_spdxid,
    })
    for i, c in enumerate(components):
        spdxid = f"SPDXRef-Package-{i}"
        pkg: dict = {
            "SPDXID": spdxid, "name": c.name or "",
            "versionInfo": c.version or "NOASSERTION",
            "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
        }
        if c.license:
            pkg["licenseDeclared"] = c.license
            pkg["licenseConcluded"] = c.license
        else:
            pkg["licenseDeclared"] = "NOASSERTION"
            pkg["licenseConcluded"] = "NOASSERTION"
        if c.purl:
            pkg["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": c.purl}]
        doc["packages"].append(pkg)
        doc["relationships"].append({
            "spdxElementId": root_spdxid, "relationshipType": "CONTAINS",
            "relatedSpdxElement": spdxid,
        })

    prod_name = (product.name if product else "sbom").replace(" ", "_")
    return Response(
        content=json.dumps(doc, ensure_ascii=False, indent=2).encode("utf-8"),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="spdx_{prod_name}_{release.version or release_id[:8]}.json"'},
    )


@router.get("/{release_id}/sbom-quality")
def sbom_quality(release_id: str, release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    if not release.sbom_file_path or not os.path.exists(release.sbom_file_path):
        raise HTTPException(status_code=404, detail="尚未上傳 SBOM 檔案")
    with open(release.sbom_file_path, "rb") as f:
        data = json.loads(f.read())
    return _score_sbom(data)


@router.get("/{release_id}/integrity")
def verify_integrity(release_id: str, release: Release = Depends(require_release_in_scope), db: Session = Depends(get_db)):
    if not release.sbom_file_path or not os.path.exists(release.sbom_file_path):
        return {"status": "no_file", "message": "尚未上傳 SBOM 檔案"}
    if not release.sbom_hash:
        return {"status": "no_hash", "message": "此版本無完整性記錄（上傳時未計算 hash）"}
    with open(release.sbom_file_path, "rb") as f:
        current_hash = hashlib.sha256(f.read()).hexdigest()
    ok = current_hash == release.sbom_hash

    sig_info = None
    if release.sbom_signature and release.signature_public_key:
        with open(release.sbom_file_path, "rb") as f2:
            sig_result = _verify_sig(f2.read(), release.sbom_signature, release.signature_public_key, release.signature_algorithm)
        sig_info = {
            "status": "valid" if sig_result.valid else "invalid",
            "algorithm": sig_result.algorithm,
            "signer_identity": sig_result.signer_identity or release.signer_identity,
            "signed_at": release.signed_at.isoformat() if release.signed_at else None,
            "message": sig_result.message,
        }

    return {
        "status": "ok" if ok else "tampered",
        "stored_hash": release.sbom_hash, "current_hash": current_hash,
        "message": "檔案完整，未被竄改" if ok else "⚠ 警告：SBOM 檔案與上傳時的 hash 不符，可能已被竄改",
        "signature": sig_info,
    }
