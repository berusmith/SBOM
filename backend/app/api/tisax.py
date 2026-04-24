from __future__ import annotations

import io
import csv
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.deps import get_current_user, get_org_scope
from app.core.plan import require_plan as _require_plan
from app.models.organization import Organization
from app.models.tisax import TISAXAssessment, TISAXControl
from app.services import tisax_pdf
from app.services.tisax_seed import make_controls

router = APIRouter(prefix="/api/tisax", tags=["tisax"])

MODULE_LABELS = {"infosec": "資訊安全", "prototype": "原型保護", "dataprotection": "個資保護"}


# ── helpers ──────────────────────────────────────────────────────────────────

def _compute_status(current: int, target: int) -> str:
    if current == 0:
        return "unassessed"
    if current >= target:
        return "compliant"
    if current >= target - 1:
        return "near"
    return "gap"


def _assessment_summary(a: TISAXAssessment) -> dict:
    controls = a.controls
    total = len(controls)
    by_status = {"compliant": 0, "near": 0, "gap": 0, "unassessed": 0}
    maturity_sum = 0
    assessed = 0
    for c in controls:
        by_status[c.status] = by_status.get(c.status, 0) + 1
        if c.status != "unassessed":
            maturity_sum += c.current_maturity
            assessed += 1
    avg_maturity = round(maturity_sum / assessed, 2) if assessed else 0.0
    return {
        "id":               a.id,
        "organization_id":  a.organization_id,
        "module":           a.module,
        "module_label":     MODULE_LABELS.get(a.module, a.module),
        "assessment_level": a.assessment_level,
        "status":           a.status,
        "created_at":       a.created_at.isoformat() if a.created_at else None,
        "updated_at":       a.updated_at.isoformat() if a.updated_at else None,
        "total_controls":   total,
        "avg_maturity":     avg_maturity,
        "by_status":        by_status,
    }


def _control_out(c: TISAXControl) -> dict:
    return {
        "id":                  c.id,
        "control_number":      c.control_number,
        "chapter":             c.chapter,
        "name":                c.name,
        "requirement_summary": c.requirement_summary,
        "module":              c.module,
        "current_maturity":    c.current_maturity,
        "target_maturity":     c.target_maturity,
        "status":              c.status,
        "evidence_note":       c.evidence_note,
        "owner":               c.owner,
        "due_date":            c.due_date,
        "remarks":             c.remarks,
    }


def _assert_org_access(assessment: TISAXAssessment, org_scope: str | None) -> None:
    if org_scope and assessment.organization_id != org_scope:
        raise HTTPException(status_code=403, detail="無權存取此評估")


# ── schemas ───────────────────────────────────────────────────────────────────

class AssessmentCreate(BaseModel):
    organization_id: str
    module: str           # infosec | prototype
    assessment_level: str = "AL2"


class ControlUpdate(BaseModel):
    current_maturity: int | None = None
    target_maturity:  int | None = None
    evidence_note:    str | None = None
    owner:            str | None = None
    due_date:         str | None = None
    remarks:          str | None = None


# ── endpoints ────────────────────────────────────────────────────────────────

@router.post("/assessments", status_code=201)
def create_assessment(
    payload: AssessmentCreate,
    _plan=Depends(_require_plan("tisax")),
    user: dict = Depends(get_current_user),
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    if payload.module not in ("infosec", "prototype", "dataprotection"):
        raise HTTPException(status_code=400, detail="module 必須為 infosec 或 prototype")
    if payload.assessment_level not in ("AL1", "AL2", "AL3"):
        raise HTTPException(status_code=400, detail="assessment_level 必須為 AL1/AL2/AL3")

    org_id = org_scope or payload.organization_id
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="組織不存在")

    assessment = TISAXAssessment(
        organization_id=org_id,
        module=payload.module,
        assessment_level=payload.assessment_level,
    )
    db.add(assessment)
    db.flush()  # get id before adding controls

    for ctrl_data in make_controls(assessment.id, payload.module):
        db.add(TISAXControl(**ctrl_data))

    db.commit()
    db.refresh(assessment)
    audit.record(db, "tisax_create", user, resource_id=assessment.id,
                 resource_label=f"{MODULE_LABELS.get(payload.module, payload.module)} {payload.assessment_level}",
                 org_name=org.name if org else None)
    db.commit()
    return _assessment_summary(assessment)


@router.get("/assessments")
def list_assessments(
    _plan=Depends(_require_plan("tisax")),
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    q = db.query(TISAXAssessment)
    if org_scope:
        q = q.filter(TISAXAssessment.organization_id == org_scope)
    return [_assessment_summary(a) for a in q.order_by(TISAXAssessment.created_at.desc()).all()]


@router.get("/assessments/{assessment_id}")
def get_assessment(
    assessment_id: str,
    _plan=Depends(_require_plan("tisax")),
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    a = db.query(TISAXAssessment).filter(TISAXAssessment.id == assessment_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="評估不存在")
    _assert_org_access(a, org_scope)

    summary = _assessment_summary(a)
    # Group controls by chapter
    chapters: dict[str, list] = {}
    for c in sorted(a.controls, key=lambda x: x.control_number):
        chapters.setdefault(c.chapter, []).append(_control_out(c))
    summary["chapters"] = [
        {"chapter": ch, "controls": ctrls}
        for ch, ctrls in chapters.items()
    ]
    return summary


@router.patch("/assessments/{assessment_id}/controls/{control_id}")
def update_control(
    assessment_id: str,
    control_id: str,
    payload: ControlUpdate,
    _plan=Depends(_require_plan("tisax")),
    user: dict = Depends(get_current_user),
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    a = db.query(TISAXAssessment).filter(TISAXAssessment.id == assessment_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="評估不存在")
    _assert_org_access(a, org_scope)

    ctrl = db.query(TISAXControl).filter(
        TISAXControl.id == control_id,
        TISAXControl.assessment_id == assessment_id,
    ).first()
    if not ctrl:
        raise HTTPException(status_code=404, detail="控制項不存在")

    if payload.current_maturity is not None:
        if not (0 <= payload.current_maturity <= 5):
            raise HTTPException(status_code=400, detail="成熟度必須介於 0–5")
        ctrl.current_maturity = payload.current_maturity
    if payload.target_maturity is not None:
        if not (0 <= payload.target_maturity <= 5):
            raise HTTPException(status_code=400, detail="成熟度必須介於 0–5")
        ctrl.target_maturity = payload.target_maturity
    if payload.evidence_note is not None:
        ctrl.evidence_note = payload.evidence_note
    if payload.owner is not None:
        ctrl.owner = payload.owner
    if payload.due_date is not None:
        ctrl.due_date = payload.due_date
    if payload.remarks is not None:
        ctrl.remarks = payload.remarks

    ctrl.status = _compute_status(ctrl.current_maturity, ctrl.target_maturity)
    a.updated_at = datetime.now(timezone.utc)
    db.commit()
    audit.record(db, "tisax_control_update", user, resource_id=control_id,
                 resource_label=f"{ctrl.control_number} {ctrl.name} → 成熟度 {ctrl.current_maturity}/{ctrl.target_maturity}")
    db.commit()
    return _control_out(ctrl)


@router.delete("/assessments/{assessment_id}", status_code=204)
def delete_assessment(
    assessment_id: str,
    _plan=Depends(_require_plan("tisax")),
    user: dict = Depends(get_current_user),
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    a = db.query(TISAXAssessment).filter(TISAXAssessment.id == assessment_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="評估不存在")
    _assert_org_access(a, org_scope)
    label = f"{MODULE_LABELS.get(a.module, a.module)} {a.assessment_level}"
    db.delete(a)
    db.commit()
    audit.record(db, "tisax_delete", user, resource_id=assessment_id, resource_label=label)
    db.commit()


@router.get("/assessments/{assessment_id}/gap-report")
def get_gap_report(
    assessment_id: str,
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    a = db.query(TISAXAssessment).filter(TISAXAssessment.id == assessment_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="評估不存在")
    _assert_org_access(a, org_scope)

    gaps = [
        _control_out(c) for c in a.controls
        if c.status == "gap"
    ]
    near = [
        _control_out(c) for c in a.controls
        if c.status == "near"
    ]
    gaps.sort(key=lambda x: x["target_maturity"] - x["current_maturity"], reverse=True)
    al_threshold = {"AL1": 0.8, "AL2": 0.9, "AL3": 0.95}.get(a.assessment_level, 0.9)
    total = len(a.controls)
    compliant = sum(1 for c in a.controls if c.status == "compliant")
    readiness = round(compliant / total, 4) if total else 0.0
    return {
        "assessment_level": a.assessment_level,
        "al_threshold":     al_threshold,
        "readiness":        readiness,
        "go_nogo":          "GO" if readiness >= al_threshold else "NO-GO",
        "gaps":             gaps,
        "near":             near,
    }


@router.get("/assessments/{assessment_id}/export-csv")
def export_csv(
    assessment_id: str,
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    a = db.query(TISAXAssessment).filter(TISAXAssessment.id == assessment_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="評估不存在")
    _assert_org_access(a, org_scope)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "控制項編號", "章節", "控制項名稱", "要求重點",
        "當前成熟度", "目標成熟度", "狀態",
        "證據說明", "負責人", "預計完成日", "備註",
    ])
    for c in sorted(a.controls, key=lambda x: x.control_number):
        status_label = {
            "compliant": "達標", "near": "接近", "gap": "缺口", "unassessed": "未評"
        }.get(c.status, c.status)
        writer.writerow([
            c.control_number, c.chapter, c.name, c.requirement_summary or "",
            c.current_maturity, c.target_maturity, status_label,
            c.evidence_note or "", c.owner or "", c.due_date or "", c.remarks or "",
        ])

    return Response(
        content=buf.getvalue().encode("utf-8-sig"),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="tisax_{assessment_id[:8]}.csv"'},
    )


@router.get("/assessments/{assessment_id}/export-pdf")
def export_pdf(
    assessment_id: str,
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    a = db.query(TISAXAssessment).filter(TISAXAssessment.id == assessment_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="評估不存在")
    _assert_org_access(a, org_scope)

    from app.models.organization import Organization
    org = db.query(Organization).filter(Organization.id == a.organization_id).first()
    org_name = org.name if org else "Unknown"

    summary = _assessment_summary(a)
    chapters = []
    chapter_map: dict[str, list] = {}
    for c in sorted(a.controls, key=lambda x: x.control_number):
        chapter_map.setdefault(c.chapter, []).append(_control_out(c))
    summary["chapters"] = chapters
    for ch, ctrls in chapter_map.items():
        chapters.append({"chapter": ch, "controls": ctrls})

    al_threshold = {"AL1": 0.8, "AL2": 0.9, "AL3": 0.95}.get(a.assessment_level, 0.9)
    total = len(a.controls)
    compliant = sum(1 for c in a.controls if c.status == "compliant")
    readiness = round(compliant / total, 4) if total else 0.0
    gaps = [_control_out(c) for c in a.controls if c.status == "gap"]
    near = [_control_out(c) for c in a.controls if c.status == "near"]
    gaps.sort(key=lambda x: x["target_maturity"] - x["current_maturity"], reverse=True)
    gap_report = {
        "assessment_level": a.assessment_level,
        "al_threshold":     al_threshold,
        "readiness":        readiness,
        "go_nogo":          "GO" if readiness >= al_threshold else "NO-GO",
        "gaps":             gaps,
        "near":             near,
    }

    pdf_bytes = tisax_pdf.generate(org_name, summary, chapters, gap_report)
    filename = f"tisax_{org_name.replace(' ','_')}_{assessment_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
