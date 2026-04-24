"""
SBOM Share Links — create time-limited, unauthenticated download URLs.

POST   /api/releases/{id}/share-link          create link (admin/Professional)
GET    /api/releases/{id}/share-links         list links for a release
DELETE /api/releases/{id}/share-links/{lid}   revoke a link
GET    /api/share/{token}                     public download (no auth required)
"""
from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.plan import require_plan
from app.models.component import Component
from app.models.release import Release
from app.models.share_link import SbomShareLink

router = APIRouter(tags=["share"])

_INTERNAL_PREFIXES = ("internal://", "private://", "pkg:internal/", "pkg:private/")


def _is_internal(purl: str | None) -> bool:
    if not purl:
        return False
    return any(purl.startswith(p) for p in _INTERNAL_PREFIXES)


def _load_sbom(release: Release) -> dict | None:
    path = release.sbom_file_path
    if not path or not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return json.loads(f.read())


def _apply_mask(sbom: dict, mask_internal: bool) -> dict:
    """Remove internal components from SBOM if mask_internal is True."""
    if not mask_internal:
        return sbom
    import copy
    out = copy.deepcopy(sbom)
    if "components" in out:
        out["components"] = [
            c for c in out["components"]
            if not _is_internal(c.get("purl"))
        ]
    if "packages" in out:  # SPDX
        out["packages"] = [
            p for p in out["packages"]
            if not _is_internal(
                next((r.get("referenceLocator") for r in p.get("externalRefs", [])
                      if r.get("referenceType") == "purl"), None)
            )
        ]
    return out


# ── Create link ───────────────────────────────────────────────────────────────

class ShareLinkCreate(BaseModel):
    expires_hours: Optional[int] = 72   # None = never
    mask_internal: bool = False


@router.post("/api/releases/{release_id}/share-link")
def create_share_link(
    release_id: str,
    body: ShareLinkCreate,
    _plan=Depends(require_plan("signature")),   # Professional only
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    if not release.sbom_file_path or not os.path.exists(release.sbom_file_path):
        raise HTTPException(status_code=400, detail="此版本尚未上傳 SBOM，無法建立分享連結")

    existing_count = db.query(SbomShareLink).filter(SbomShareLink.release_id == release_id).count()
    if existing_count >= 20:
        raise HTTPException(status_code=400, detail="此版本已達分享連結上限（20 條），請先撤銷舊連結")

    expires_at = None
    if body.expires_hours and body.expires_hours > 0:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=body.expires_hours)

    link = SbomShareLink(
        release_id=release_id,
        token=secrets.token_urlsafe(32),
        expires_at=expires_at,
        created_by=user.get("username"),
        mask_internal=body.mask_internal,
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    audit.record(db, "share_link_create", user, resource_id=link.id,
                 resource_label=f"release={release_id} mask={body.mask_internal}")
    db.commit()

    return {
        "id":           link.id,
        "token":        link.token,
        "expires_at":   link.expires_at.isoformat() if link.expires_at else None,
        "mask_internal": link.mask_internal,
        "created_at":   link.created_at.isoformat(),
        "created_by":   link.created_by,
        "download_count": 0,
    }


# ── List links ────────────────────────────────────────────────────────────────

@router.get("/api/releases/{release_id}/share-links")
def list_share_links(
    release_id: str,
    _plan=Depends(require_plan("signature")),
    _user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    links = db.query(SbomShareLink).filter(SbomShareLink.release_id == release_id).all()
    now = datetime.now(timezone.utc)
    return [
        {
            "id":            lk.id,
            "token":         lk.token,
            "expires_at":    lk.expires_at.isoformat() if lk.expires_at else None,
            "expired":       bool(lk.expires_at and lk.expires_at.replace(tzinfo=timezone.utc) < now),
            "mask_internal": lk.mask_internal,
            "created_at":    lk.created_at.isoformat(),
            "created_by":    lk.created_by,
            "download_count": lk.download_count,
        }
        for lk in links
    ]


# ── Revoke link ───────────────────────────────────────────────────────────────

@router.delete("/api/releases/{release_id}/share-links/{link_id}", status_code=204)
def revoke_share_link(
    release_id: str,
    link_id: str,
    _plan=Depends(require_plan("signature")),
    _user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    lk = db.query(SbomShareLink).filter(
        SbomShareLink.id == link_id,
        SbomShareLink.release_id == release_id,
    ).first()
    if not lk:
        raise HTTPException(status_code=404, detail="分享連結不存在")
    db.delete(lk)
    db.commit()
    audit.record(db, "share_link_revoke", _user, resource_id=link_id,
                 resource_label=f"release={release_id}")
    db.commit()


# ── Public download (no auth) ─────────────────────────────────────────────────

@router.get("/api/share/{token}")
def download_shared_sbom(token: str, db: Session = Depends(get_db)):
    lk = db.query(SbomShareLink).filter(SbomShareLink.token == token).first()
    if not lk:
        raise HTTPException(status_code=404, detail="連結不存在或已被撤銷")

    now = datetime.now(timezone.utc)
    if lk.expires_at:
        exp = lk.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < now:
            raise HTTPException(status_code=410, detail="此分享連結已過期")

    release = db.query(Release).filter(Release.id == lk.release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="版本不存在")

    sbom = _load_sbom(release)
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM 檔案不存在")

    sbom = _apply_mask(sbom, lk.mask_internal)

    # Update download count
    lk.download_count += 1
    db.commit()

    filename = f"sbom_{release.version or lk.release_id[:8]}.json"
    return Response(
        content=json.dumps(sbom, ensure_ascii=False, indent=2).encode(),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
