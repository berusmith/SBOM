"""Signature endpoints — upload / verify / delete.

Moved from backend/app/api/releases.py in D.5 (2026-04-30).  J5 carve-out
per code-principles.md §J5 + J5-footnote: this commit message carries the
[J5-security-carveout] prefix and the body lists the diff for each of the
4 J5-tracked surfaces.

Endpoints (3):
  POST   /signature        — upload + verify signature against stored SBOM
  GET    /signature/verify — verify stored signature against current SBOM
  DELETE /signature        — remove signature (admin only; respects lock)
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.deps import get_org_scope, require_admin
from app.core.plan import require_plan
from app.models.release import Release
from app.services.signature_verifier import (
    SUPPORTED_ALGORITHMS,
    detect_algorithm,
    verify_signature as _verify_sig,
)

# Transitional cross-module import — _assert_release_org legacy 403 helper;
# D.8 (ARCH-1.003 contract evolution) replaces with require_release_in_scope.
from app.api.releases import _assert_release_org

router = APIRouter(prefix="/api/releases", tags=["releases"])


@router.post("/{release_id}/signature")
def upload_signature(release_id: str, body: dict, _plan=Depends(require_plan("signature")), _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    """Upload a cryptographic signature for the SBOM file."""
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    if not release.sbom_hash:
        raise HTTPException(status_code=400, detail="請先上傳 SBOM 再上傳簽章")
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定，無法上傳簽章")

    signature_b64 = body.get("signature")
    public_key_pem = body.get("public_key")
    algorithm = body.get("algorithm")
    signer = body.get("signer_identity")

    if not signature_b64 or not public_key_pem:
        raise HTTPException(status_code=400, detail="必須提供 signature 與 public_key 欄位")

    # Auto-detect algorithm if not provided (per invariants.md §II.2 D6:
    # algorithm is derived from key, not attacker-controlled)
    if not algorithm:
        algorithm = detect_algorithm(public_key_pem) or "ecdsa-sha256"

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise HTTPException(status_code=400,
                            detail=f"不支援的演算法：{algorithm}，支援：{', '.join(SUPPORTED_ALGORITHMS)}")

    # Verify the signature BEFORE storing (per invariants.md §II.2 D7)
    if not release.sbom_file_path or not os.path.exists(release.sbom_file_path):
        raise HTTPException(status_code=400, detail="SBOM 檔案不存在，無法驗證簽章")

    with open(release.sbom_file_path, "rb") as f:
        sbom_content = f.read()

    result = _verify_sig(sbom_content, signature_b64, public_key_pem, algorithm)
    if not result.valid:
        raise HTTPException(status_code=400,
                            detail=f"簽章驗證失敗：{result.message}。{result.detail}")

    # Store signature
    release.sbom_signature = signature_b64
    release.signature_public_key = public_key_pem
    release.signature_algorithm = algorithm
    release.signer_identity = signer or result.signer_identity
    release.signed_at = datetime.now(timezone.utc)
    db.commit()

    audit.record(db, "signature_uploaded", _admin, resource_id=release_id, resource_label=f"alg={algorithm} signer={release.signer_identity}")

    return {
        "status": "ok",
        "algorithm": algorithm,
        "signer_identity": release.signer_identity,
        "signed_at": release.signed_at.isoformat(),
        "message": result.message,
    }


@router.get("/{release_id}/signature/verify")
def verify_release_signature(release_id: str, org_scope: str | None = Depends(get_org_scope), db: Session = Depends(get_db)):
    """Verify the stored signature against the current SBOM file."""
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    _assert_release_org(release, org_scope, db)

    if not release.sbom_signature or not release.signature_public_key:
        return {
            "status": "unsigned",
            "message": "此版本尚未上傳簽章",
        }

    if not release.sbom_file_path or not os.path.exists(release.sbom_file_path):
        return {
            "status": "no_file",
            "message": "SBOM 檔案不存在，無法驗證簽章",
        }

    with open(release.sbom_file_path, "rb") as f:
        sbom_content = f.read()

    result = _verify_sig(sbom_content, release.sbom_signature, release.signature_public_key, release.signature_algorithm)

    return {
        "status": "valid" if result.valid else "invalid",
        "algorithm": result.algorithm,
        "signer_identity": result.signer_identity or release.signer_identity,
        "signed_at": release.signed_at.isoformat() if release.signed_at else None,
        "message": result.message,
        "detail": result.detail,
    }


@router.delete("/{release_id}/signature")
def delete_signature(release_id: str, _admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    """Remove the signature from a release."""
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    if release.locked:
        raise HTTPException(status_code=409, detail="版本已鎖定，無法刪除簽章")
    release.sbom_signature = None
    release.signature_public_key = None
    release.signature_algorithm = None
    release.signer_identity = None
    release.signed_at = None
    db.commit()
    audit.record(db, "signature_deleted", _admin, resource_id=release_id)
    db.commit()
    return {"status": "ok", "message": "簽章已移除"}
