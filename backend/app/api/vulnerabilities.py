from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.vex_history import VexHistory
from app.models.vulnerability import Vulnerability

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
def batch_update_vex(payload: BatchVexUpdate, db: Session = Depends(get_db)):
    if not payload.vuln_ids:
        raise HTTPException(status_code=400, detail="未提供漏洞 ID")
    if payload.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid status.")
    if payload.justification and payload.justification not in VALID_JUSTIFICATIONS:
        raise HTTPException(status_code=400, detail="Invalid justification.")
    if payload.response and payload.response not in VALID_RESPONSES:
        raise HTTPException(status_code=400, detail="Invalid response.")

    updated = 0
    for vuln_id in payload.vuln_ids:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        if not vuln:
            continue
        _apply_vex(vuln, payload.status, payload.justification, payload.response, payload.detail, payload.note, db)
        updated += 1

    db.commit()
    return {"updated": updated}


@router.patch("/{vuln_id}/status")
def update_vex(vuln_id: str, payload: VexUpdate, db: Session = Depends(get_db)):
    if payload.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {VALID_STATUSES}")
    if payload.justification and payload.justification not in VALID_JUSTIFICATIONS:
        raise HTTPException(status_code=400, detail="Invalid justification.")
    if payload.response and payload.response not in VALID_RESPONSES:
        raise HTTPException(status_code=400, detail="Invalid response.")

    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    _apply_vex(vuln, payload.status, payload.justification, payload.response, payload.detail, payload.note, db)
    db.commit()
    return {
        "id": vuln_id,
        "status": vuln.status,
        "justification": vuln.justification,
        "response": vuln.response,
        "detail": vuln.detail,
    }


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
