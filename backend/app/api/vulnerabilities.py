from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.deps import require_admin, get_current_user
from app.models.component import Component
from app.models.release import Release
from app.models.vex_history import VexHistory
from app.models.vulnerability import Vulnerability


def _check_not_locked(vuln: Vulnerability, db: Session):
    comp = db.query(Component).filter(Component.id == vuln.component_id).first()
    if comp:
        rel = db.query(Release).filter(Release.id == comp.release_id).first()
        if rel and rel.locked:
            raise HTTPException(status_code=409, detail="版本已鎖定，無法修改 VEX 狀態")

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])

VALID_STATUSES = {"open", "in_triage", "not_affected", "affected", "fixed"}

VALID_JUSTIFICATIONS = {
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
}

VALID_RESPONSES = {
    "can_not_fix",
    "will_not_fix",
    "update",
    "rollback",
    "workaround_available",
}


class VexUpdate(BaseModel):
    status: str
    justification: Optional[str] = None
    response: Optional[str] = None
    detail: Optional[str] = None
    note: Optional[str] = None


class BatchVexUpdate(BaseModel):
    vuln_ids: List[str]
    status: str
    justification: Optional[str] = None
    response: Optional[str] = None
    detail: Optional[str] = None
    note: Optional[str] = None


def _apply_vex(vuln: Vulnerability, status: str, justification, response, detail, note, db: Session):
    if vuln.status == status:
        return
    entry = VexHistory(
        vulnerability_id=vuln.id,
        from_status=vuln.status,
        to_status=status,
        note=note,
    )
    db.add(entry)
    vuln.status = status
    vuln.justification = justification if status == "not_affected" else None
    vuln.response = response if status == "affected" else None
    vuln.detail = detail
    if status == "fixed" and vuln.fixed_at is None:
        vuln.fixed_at = datetime.now(timezone.utc)
    elif status != "fixed":
        vuln.fixed_at = None


@router.patch("/batch")
def batch_update_vex(payload: BatchVexUpdate, _admin: dict = Depends(require_admin), user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    if not payload.vuln_ids:
        raise HTTPException(status_code=400, detail="未提供漏洞 ID")
    if payload.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid status.")
    if payload.justification and payload.justification not in VALID_JUSTIFICATIONS:
        raise HTTPException(status_code=400, detail="Invalid justification.")
    if payload.response and payload.response not in VALID_RESPONSES:
        raise HTTPException(status_code=400, detail="Invalid response.")

    vulns = db.query(Vulnerability).filter(Vulnerability.id.in_(payload.vuln_ids)).all()
    vuln_map = {v.id: v for v in vulns}
    not_found = [vid for vid in payload.vuln_ids if vid not in vuln_map]

    updated = 0
    skipped_locked = []
    for vuln in vulns:
        try:
            _check_not_locked(vuln, db)
        except HTTPException:
            skipped_locked.append(vuln.id)
            continue
        _apply_vex(vuln, payload.status, payload.justification, payload.response, payload.detail, payload.note, db)
        updated += 1

    db.commit()
    if updated:
        audit.record(db, "vex_batch_update", user,
                     resource_label=f"status={payload.status} count={updated}")
        db.commit()
    return {"updated": updated, "skipped_locked": skipped_locked, "not_found": not_found}


@router.patch("/{vuln_id}/status")
def update_vex(vuln_id: str, payload: VexUpdate, _admin: dict = Depends(require_admin), user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    if payload.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {VALID_STATUSES}")
    if payload.justification and payload.justification not in VALID_JUSTIFICATIONS:
        raise HTTPException(status_code=400, detail="Invalid justification.")
    if payload.response and payload.response not in VALID_RESPONSES:
        raise HTTPException(status_code=400, detail="Invalid response.")

    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    _check_not_locked(vuln, db)

    old_status = vuln.status
    _apply_vex(vuln, payload.status, payload.justification, payload.response, payload.detail, payload.note, db)
    db.commit()
    if old_status != vuln.status:
        audit.record(db, "vex_update", user, resource_id=vuln_id,
                     resource_label=f"{vuln.cve_id}: {old_status} → {vuln.status}")
        db.commit()
    return {
        "id": vuln_id,
        "status": vuln.status,
        "justification": vuln.justification,
        "response": vuln.response,
        "detail": vuln.detail,
    }


class SuppressUpdate(BaseModel):
    suppressed: bool
    suppressed_until: Optional[str] = None   # ISO date "YYYY-MM-DD"
    suppressed_reason: Optional[str] = None


@router.patch("/{vuln_id}/suppress")
def suppress_vuln(vuln_id: str, payload: SuppressUpdate, _admin: dict = Depends(require_admin), user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    _check_not_locked(vuln, db)
    vuln.suppressed = payload.suppressed
    if payload.suppressed:
        if payload.suppressed_until:
            try:
                vuln.suppressed_until = datetime.fromisoformat(payload.suppressed_until).replace(tzinfo=timezone.utc)
            except ValueError:
                raise HTTPException(status_code=400, detail="suppressed_until 格式錯誤，請用 YYYY-MM-DD")
        else:
            vuln.suppressed_until = None
        vuln.suppressed_reason = payload.suppressed_reason or None
    else:
        vuln.suppressed_until = None
        vuln.suppressed_reason = None
    db.commit()
    action = "suppress" if payload.suppressed else "unsuppress"
    audit.record(db, f"vuln_{action}", user, resource_id=vuln_id,
                 resource_label=getattr(vuln, "cve_id", vuln_id))
    db.commit()
    return {"id": vuln_id, "suppressed": vuln.suppressed, "suppressed_until": vuln.suppressed_until.isoformat() if vuln.suppressed_until else None}


@router.get("/{vuln_id}/history")
def get_vuln_history(vuln_id: str, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return [
        {
            "id": h.id,
            "from_status": h.from_status,
            "to_status": h.to_status,
            "changed_at": h.changed_at.isoformat() if h.changed_at else None,
            "note": h.note,
        }
        for h in vuln.history
    ]
