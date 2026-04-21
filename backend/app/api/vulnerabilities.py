from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
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


class BatchVexUpdate(BaseModel):
    vuln_ids: List[str]
    status: str
    justification: Optional[str] = None
    response: Optional[str] = None
    detail: Optional[str] = None


@router.patch("/batch")
def batch_update_vex(payload: BatchVexUpdate, db: Session = Depends(get_db)):
    if not payload.vuln_ids:
        raise HTTPException(status_code=400, detail="未提供漏洞 ID")
    if payload.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status.")
    if payload.justification and payload.justification not in VALID_JUSTIFICATIONS:
        raise HTTPException(status_code=400, detail=f"Invalid justification.")
    if payload.response and payload.response not in VALID_RESPONSES:
        raise HTTPException(status_code=400, detail=f"Invalid response.")

    updated = 0
    for vuln_id in payload.vuln_ids:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        if not vuln:
            continue
        vuln.status = payload.status
        vuln.justification = payload.justification if payload.status == "not_affected" else None
        vuln.response = payload.response if payload.status == "affected" else None
        vuln.detail = payload.detail
        updated += 1

    db.commit()
    return {"updated": updated}


@router.patch("/{vuln_id}/status")
def update_vex(vuln_id: str, payload: VexUpdate, db: Session = Depends(get_db)):
    if payload.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {VALID_STATUSES}")

    if payload.justification and payload.justification not in VALID_JUSTIFICATIONS:
        raise HTTPException(status_code=400, detail=f"Invalid justification.")

    if payload.response and payload.response not in VALID_RESPONSES:
        raise HTTPException(status_code=400, detail=f"Invalid response.")

    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    vuln.status = payload.status
    vuln.justification = payload.justification if payload.status == "not_affected" else None
    vuln.response = payload.response if payload.status == "affected" else None
    vuln.detail = payload.detail

    db.commit()
    return {
        "id": vuln_id,
        "status": vuln.status,
        "justification": vuln.justification,
        "response": vuln.response,
        "detail": vuln.detail,
    }
