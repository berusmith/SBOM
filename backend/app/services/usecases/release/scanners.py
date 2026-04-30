"""Scanner endpoints — Trivy + Syft + reachability source scan.

Moved from backend/app/api/releases.py in D.6 (2026-04-30).  5 endpoints + 1 helper:

  POST /upload-source       — reachability classification (existing source)
  POST /scan-image          — Trivy: container image → SBOM
  POST /scan-iac            — Trivy: Terraform/K8s/Dockerfile → SBOM + misconfigs
  POST /sbom-from-source    — Syft: source archive → SBOM
  POST /sbom-from-binary    — Syft: binary → SBOM (firmware / .jar / .whl / etc.)

  _import_syft_cdx          — shared post-processing (parse → upsert → scan → enrich)

Uses the Stage C reachability package (services.scanners.reachability)
established by C.1 / C.2 — Wave-D contract surface.
"""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.deps import get_current_user, get_org_scope
from app.core.plan import require_plan
from app.models.component import Component
from app.models.release import Release
from app.models.vulnerability import Vulnerability
from app.services import sbom_parser, syft_scanner as _syft, trivy_scanner as _trivy, vuln_scanner
from app.services.scanners.reachability import classify_vulns as _classify_vulns, scan_zip as _scan_zip

# Transitional cross-module imports — see usecases/release/upload_sbom.py docstring.
from app.api.releases import _assert_release_org
from app.services.usecases.release.enrich import _enrich_epss, _enrich_kev

router = APIRouter(prefix="/api/releases", tags=["releases"])


@router.post("/{release_id}/upload-source")
async def upload_source(
    release_id: str,
    file: UploadFile = File(...),
    _plan=Depends(require_plan("reachability")),
    user: dict = Depends(get_current_user),
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    """上傳專案原始碼 zip，掃描 import 語句，更新所有漏洞的 reachability 欄位。"""
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
                component_id=comp.id, cve_id=v["cve_id"], description=v.get("description", ""),
                cvss_score=v["cvss_score"], severity=v["severity"], cvss_v4_vector=v.get("cvss_v4_vector"),
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


# ── Syft-driven SBOM generation ──────────────────────────────────────────────

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
    """Shared post-processing for Syft-from-source / Syft-from-binary flows.

    Parses CycloneDX, upserts components by PURL (additive — never wipes
    existing, mirroring scan-image), runs OSV vuln scan, enriches with
    EPSS + KEV.  Returns user-facing summary dict.
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
                release_id=release_id, name=c["name"], version=c["version"],
                purl=purl, license=c.get("license", ""),
            )
            db.add(comp)
            new_comps.append((comp, purl))
    db.commit()
    for comp, _ in new_comps:
        db.refresh(comp)

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
                component_id=comp.id, cve_id=v["cve_id"], description=v.get("description", ""),
                cvss_score=v["cvss_score"], severity=v["severity"], cvss_v4_vector=v.get("cvss_v4_vector"),
                status="open",
            ))
            vuln_count += 1
    db.commit()

    all_vulns = (
        db.query(Vulnerability).join(Component).filter(Component.release_id == release_id).all()
    )
    _enrich_epss(all_vulns, db)
    _enrich_kev(all_vulns, db)

    audit.record(db, audit_event, user, resource_id=release_id, resource_label=audit_resource_label)
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
    """上傳原始碼 zip,讓 Syft 識別 manifest 產出 SBOM 並合併進此版本。

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
        cdx=cdx, release_id=release_id, db=db, source_label="syft-source.json",
        user=user, audit_event="syft_source_scan", audit_resource_label=file.filename,
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
    """上傳單一 binary 讓 Syft 提取嵌入元件資訊。

    Syft 內建 binary cataloguers 可從 Go / .NET / Java / Python wheel /
    Rust / Linux 核心等可執行檔抽出版本資訊。
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

    MAX_SIZE = 200 * 1024 * 1024  # 200 MB
    content = await file.read(MAX_SIZE + 1)
    if len(content) > MAX_SIZE:
        raise HTTPException(status_code=400, detail=f"檔案超過 {MAX_SIZE // (1024*1024)}MB 上限")

    try:
        cdx = await asyncio.to_thread(_syft.scan_binary, content, file.filename)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    summary = _import_syft_cdx(
        cdx=cdx, release_id=release_id, db=db, source_label="syft-binary.json",
        user=user, audit_event="syft_binary_scan", audit_resource_label=file.filename,
    )
    return {"filename": file.filename, **summary}
