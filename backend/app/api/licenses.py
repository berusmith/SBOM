from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_org_scope
from app.models.component import Component
from app.models.license_rule import LicenseRule
from app.models.release import Release

router = APIRouter(prefix="/api/licenses", tags=["licenses"])

DEFAULT_RULES = [
    {"license_id": "AGPL-3.0",    "label": "GNU AGPL v3",           "action": "block"},
    {"license_id": "GPL-3.0",     "label": "GNU GPL v3",             "action": "warn"},
    {"license_id": "GPL-2.0",     "label": "GNU GPL v2",             "action": "warn"},
    {"license_id": "LGPL-3.0",    "label": "GNU LGPL v3",            "action": "warn"},
    {"license_id": "LGPL-2.1",    "label": "GNU LGPL v2.1",          "action": "warn"},
    {"license_id": "SSPL-1.0",    "label": "Server Side Public License", "action": "block"},
    {"license_id": "BUSL-1.1",    "label": "Business Source License","action": "warn"},
    {"license_id": "CC-BY-SA",    "label": "Creative Commons SA",    "action": "warn"},
]


def _seed_defaults(db: Session) -> None:
    if db.query(LicenseRule).count() == 0:
        for r in DEFAULT_RULES:
            db.add(LicenseRule(**r))
        db.commit()


def _rule_dict(r: LicenseRule) -> dict:
    return {
        "id":         r.id,
        "license_id": r.license_id,
        "label":      r.label or r.license_id,
        "action":     r.action,
        "enabled":    r.enabled,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _matches(rule_license_id: str, component_license: str) -> bool:
    """Case-insensitive substring match. 'GPL-3.0' matches 'GPL-3.0-only', 'GPL-3.0-or-later', etc."""
    if not component_license:
        return False
    return rule_license_id.lower() in component_license.lower()


# ── CRUD ─────────────────────────────────────────────────────────────────────

@router.get("/rules")
def list_rules(db: Session = Depends(get_db)):
    _seed_defaults(db)
    return [_rule_dict(r) for r in db.query(LicenseRule).order_by(LicenseRule.created_at).all()]


class RuleCreate(BaseModel):
    license_id: str
    label:      Optional[str] = None
    action:     str = "warn"
    enabled:    bool = True


class RuleUpdate(BaseModel):
    license_id: Optional[str] = None
    label:      Optional[str] = None
    action:     Optional[str] = None
    enabled:    Optional[bool] = None


@router.post("/rules", status_code=201)
def create_rule(payload: RuleCreate, db: Session = Depends(get_db)):
    if payload.action not in ("warn", "block"):
        raise HTTPException(status_code=400, detail="action 必須為 warn 或 block")
    if not payload.license_id.strip():
        raise HTTPException(status_code=400, detail="license_id 不可為空")
    rule = LicenseRule(
        license_id=payload.license_id.strip(),
        label=payload.label,
        action=payload.action,
        enabled=payload.enabled,
    )
    db.add(rule)
    db.commit()
    return _rule_dict(rule)


@router.patch("/rules/{rule_id}")
def update_rule(rule_id: str, payload: RuleUpdate, db: Session = Depends(get_db)):
    rule = db.query(LicenseRule).filter(LicenseRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="規則不存在")
    data = payload.model_dump(exclude_none=True)
    if "action" in data and data["action"] not in ("warn", "block"):
        raise HTTPException(status_code=400, detail="action 必須為 warn 或 block")
    for k, v in data.items():
        setattr(rule, k, v)
    db.commit()
    return _rule_dict(rule)


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: str, db: Session = Depends(get_db)):
    rule = db.query(LicenseRule).filter(LicenseRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="規則不存在")
    db.delete(rule)
    db.commit()


# ── Violation check ───────────────────────────────────────────────────────────

@router.get("/violations/summary")
def violations_summary(db: Session = Depends(get_db)):
    """Platform-wide license violation counts per rule."""
    _seed_defaults(db)
    rules = db.query(LicenseRule).filter(LicenseRule.enabled == True).all()  # noqa: E712
    comps = db.query(Component).filter(Component.license != None, Component.license != "").all()  # noqa: E711

    summary = []
    for rule in rules:
        count = sum(1 for c in comps if _matches(rule.license_id, c.license or ""))
        summary.append({
            "rule_id":         rule.id,
            "license_id":      rule.license_id,
            "label":           rule.label or rule.license_id,
            "action":          rule.action,
            "violation_count": count,
        })
    total = sum(s["violation_count"] for s in summary)
    return {"total_violations": total, "by_rule": summary}


@router.get("/releases/{release_id}/violations")
def release_violations(
    release_id: str,
    org_scope: str | None = Depends(get_org_scope),
    db: Session = Depends(get_db),
):
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")

    _seed_defaults(db)
    rules = db.query(LicenseRule).filter(LicenseRule.enabled == True).all()  # noqa: E712
    comps = db.query(Component).filter(Component.release_id == release_id).all()

    violations: list[dict] = []
    for comp in comps:
        if not comp.license:
            continue
        for rule in rules:
            if _matches(rule.license_id, comp.license):
                violations.append({
                    "rule_id":      rule.id,
                    "license_id":   rule.license_id,
                    "label":        rule.label or rule.license_id,
                    "action":       rule.action,
                    "component_id": comp.id,
                    "component":    comp.name,
                    "version":      comp.version or "",
                    "license":      comp.license,
                })

    violations.sort(key=lambda x: x["action"] == "block", reverse=True)
    return {
        "release_id":     release_id,
        "total":          len(violations),
        "block_count":    sum(1 for v in violations if v["action"] == "block"),
        "warn_count":     sum(1 for v in violations if v["action"] == "warn"),
        "violations":     violations,
    }
