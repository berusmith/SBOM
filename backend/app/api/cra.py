from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.cra_incident import CRAIncident

router = APIRouter(prefix="/api/cra", tags=["cra"])

# State machine: current → next
NEXT_STATE = {
    "detected":        "pending_triage",
    "pending_triage":  "clock_running",
    "clock_running":   "t24_submitted",
    "t24_submitted":   "investigating",
    "investigating":   "t72_submitted",
    "t72_submitted":   "remediating",
    "remediating":     "final_submitted",
    "final_submitted": "closed",
}

STATE_LABEL = {
    "detected":        "已偵測",
    "pending_triage":  "等待分析",
    "clock_running":   "時鐘進行中",
    "t24_submitted":   "T+24h 已提交",
    "investigating":   "調查中",
    "t72_submitted":   "T+72h 已提交",
    "remediating":     "修補中",
    "final_submitted": "最終報告已提交",
    "closed":          "已結案",
}

ADVANCE_LABEL = {
    "detected":        "開始分析",
    "pending_triage":  "確認受影響，啟動時鐘",
    "clock_running":   "提交 T+24h 早期警告",
    "t24_submitted":   "開始深入調查",
    "investigating":   "提交 T+72h 完整通報",
    "t72_submitted":   "修補已就緒，開始計算 T+14d",
    "remediating":     "提交最終報告",
    "final_submitted": "結案",
}


def _append_log(incident: CRAIncident, action: str, note: str = "") -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry = f"{ts} | {action}"
    if note:
        entry += f" | {note}"
    existing = incident.audit_log or ""
    incident.audit_log = (existing + "\n" + entry).strip()


def _serialize(inc: CRAIncident) -> dict:
    now = datetime.now(timezone.utc)

    def remaining(deadline: Optional[datetime]) -> Optional[int]:
        if deadline is None:
            return None
        delta = deadline.replace(tzinfo=timezone.utc) - now
        return max(0, int(delta.total_seconds()))

    return {
        "id": inc.id,
        "title": inc.title,
        "description": inc.description,
        "trigger_cve_ids": inc.trigger_cve_ids,
        "trigger_source": inc.trigger_source,
        "status": inc.status,
        "status_label": STATE_LABEL.get(inc.status, inc.status),
        "next_action_label": ADVANCE_LABEL.get(inc.status),
        "can_advance": inc.status in NEXT_STATE,
        "can_close_not_affected": inc.status == "pending_triage",
        "awareness_timestamp": inc.awareness_timestamp.isoformat() if inc.awareness_timestamp else None,
        "t24_deadline": inc.t24_deadline.isoformat() if inc.t24_deadline else None,
        "t72_deadline": inc.t72_deadline.isoformat() if inc.t72_deadline else None,
        "remediation_available_at": inc.remediation_available_at.isoformat() if inc.remediation_available_at else None,
        "t14d_deadline": inc.t14d_deadline.isoformat() if inc.t14d_deadline else None,
        "t24_remaining_seconds": remaining(inc.t24_deadline),
        "t72_remaining_seconds": remaining(inc.t72_deadline),
        "t14d_remaining_seconds": remaining(inc.t14d_deadline),
        "enisa_ref_t24": inc.enisa_ref_t24,
        "enisa_ref_t72": inc.enisa_ref_t72,
        "enisa_ref_final": inc.enisa_ref_final,
        "audit_log": [e for e in (inc.audit_log or "").splitlines() if e],
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
    }


# ── Create ──────────────────────────────────────────────────────────────────

class CreateIncident(BaseModel):
    title: str
    description: Optional[str] = None
    trigger_cve_ids: Optional[str] = None   # comma-separated
    trigger_source: Optional[str] = "manual"


@router.post("/incidents", status_code=201)
def create_incident(payload: CreateIncident, db: Session = Depends(get_db)):
    inc = CRAIncident(
        title=payload.title,
        description=payload.description,
        trigger_cve_ids=payload.trigger_cve_ids,
        trigger_source=payload.trigger_source or "manual",
        status="detected",
    )
    _append_log(inc, "建立事件", payload.title)
    db.add(inc)
    db.commit()
    db.refresh(inc)
    return _serialize(inc)


# ── List ─────────────────────────────────────────────────────────────────────

@router.get("/incidents")
def list_incidents(db: Session = Depends(get_db)):
    incidents = db.query(CRAIncident).order_by(CRAIncident.created_at.desc()).all()
    return [_serialize(i) for i in incidents]


# ── Get one ──────────────────────────────────────────────────────────────────

@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    inc = db.query(CRAIncident).filter(CRAIncident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _serialize(inc)


# ── Start clock ──────────────────────────────────────────────────────────────

class StartClockPayload(BaseModel):
    note: Optional[str] = None
    enisa_ref: Optional[str] = None


@router.post("/incidents/{incident_id}/start-clock")
def start_clock(incident_id: str, payload: StartClockPayload, db: Session = Depends(get_db)):
    inc = db.query(CRAIncident).filter(CRAIncident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if inc.status != "pending_triage":
        raise HTTPException(status_code=400, detail="只有 pending_triage 狀態才能啟動時鐘")

    now = datetime.now(timezone.utc)
    inc.awareness_timestamp = now
    inc.t24_deadline = now + timedelta(hours=24)
    inc.t72_deadline = now + timedelta(hours=72)
    inc.status = "clock_running"
    _append_log(inc, "時鐘啟動 (T+0)", payload.note or "")
    db.commit()
    db.refresh(inc)
    return _serialize(inc)


# ── Advance state ─────────────────────────────────────────────────────────────

class AdvancePayload(BaseModel):
    note: Optional[str] = None
    enisa_ref: Optional[str] = None
    remediation_available_at: Optional[str] = None  # ISO datetime string, required for t72_submitted→remediating


@router.post("/incidents/{incident_id}/advance")
def advance(incident_id: str, payload: AdvancePayload, db: Session = Depends(get_db)):
    inc = db.query(CRAIncident).filter(CRAIncident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if inc.status not in NEXT_STATE:
        raise HTTPException(status_code=400, detail="此狀態無法繼續推進")

    next_status = NEXT_STATE[inc.status]
    action_label = ADVANCE_LABEL.get(inc.status, inc.status)

    # Special handling per transition
    if inc.status == "pending_triage":
        # Should use start-clock instead, but support direct advance too
        now = datetime.now(timezone.utc)
        inc.awareness_timestamp = now
        inc.t24_deadline = now + timedelta(hours=24)
        inc.t72_deadline = now + timedelta(hours=72)

    if inc.status == "clock_running" and payload.enisa_ref:
        inc.enisa_ref_t24 = payload.enisa_ref

    if inc.status == "investigating" and payload.enisa_ref:
        inc.enisa_ref_t72 = payload.enisa_ref

    if inc.status == "t72_submitted":
        if payload.remediation_available_at:
            try:
                rem_dt = datetime.fromisoformat(payload.remediation_available_at.replace("Z", "+00:00"))
            except ValueError:
                raise HTTPException(status_code=400, detail="remediation_available_at 格式錯誤")
        else:
            rem_dt = datetime.now(timezone.utc)
        inc.remediation_available_at = rem_dt
        inc.t14d_deadline = rem_dt + timedelta(days=14)

    if inc.status == "remediating" and payload.enisa_ref:
        inc.enisa_ref_final = payload.enisa_ref

    inc.status = next_status
    inc.updated_at = datetime.now(timezone.utc)
    _append_log(inc, action_label, payload.note or "")
    db.commit()
    db.refresh(inc)
    return _serialize(inc)


# ── Close as not-affected ────────────────────────────────────────────────────

class ClosePayload(BaseModel):
    note: Optional[str] = None


@router.post("/incidents/{incident_id}/close-not-affected")
def close_not_affected(incident_id: str, payload: ClosePayload, db: Session = Depends(get_db)):
    inc = db.query(CRAIncident).filter(CRAIncident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if inc.status != "pending_triage":
        raise HTTPException(status_code=400, detail="只有 pending_triage 才能標記為不受影響")
    inc.status = "closed"
    inc.updated_at = datetime.now(timezone.utc)
    _append_log(inc, "結案 (不受影響)", payload.note or "")
    db.commit()
    db.refresh(inc)
    return _serialize(inc)


@router.delete("/incidents/{incident_id}", status_code=204)
def delete_incident(incident_id: str, db: Session = Depends(get_db)):
    inc = db.query(CRAIncident).filter(CRAIncident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    db.delete(inc)
    db.commit()
