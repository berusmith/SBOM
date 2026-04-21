from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.component import Component
from app.models.policy_rule import PolicyRule
from app.models.release import Release
from app.models.vulnerability import Vulnerability

router = APIRouter(prefix="/api/policies", tags=["policies"])

DEFAULT_RULES = [
    {
        "name": "Critical 漏洞超過 7 天未修補",
        "description": "Critical 嚴重度漏洞發現後 7 天內若未修補或標記不受影響，即為違規",
        "severity": "critical",
        "require_kev": False,
        "statuses": "open,in_triage,affected",
        "min_days_open": 7,
        "action": "warn",
    },
    {
        "name": "KEV 漏洞超過 3 天未處理",
        "description": "CISA KEV 已知被利用漏洞，3 天內必須完成處置",
        "severity": "any",
        "require_kev": True,
        "statuses": "open,in_triage,affected",
        "min_days_open": 3,
        "action": "warn",
    },
    {
        "name": "High 漏洞超過 30 天未修補",
        "description": "High 嚴重度漏洞發現後 30 天內若未修補或標記不受影響，即為違規",
        "severity": "high",
        "require_kev": False,
        "statuses": "open,in_triage,affected",
        "min_days_open": 30,
        "action": "warn",
    },
]


def _seed_defaults(db: Session):
    if db.query(PolicyRule).count() == 0:
        for r in DEFAULT_RULES:
            db.add(PolicyRule(**r))
        db.commit()


def _rule_dict(r: PolicyRule) -> dict:
    return {
        "id": r.id,
        "name": r.name,
        "description": r.description or "",
        "severity": r.severity,
        "require_kev": r.require_kev,
        "statuses": r.statuses,
        "min_days_open": r.min_days_open,
        "action": r.action,
        "enabled": r.enabled,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _evaluate_rule(rule: PolicyRule, vuln: Vulnerability) -> bool:
    """Return True if vuln violates this rule."""
    if not rule.enabled:
        return False
    if rule.severity != "any" and vuln.severity != rule.severity:
        return False
    if rule.require_kev and not vuln.is_kev:
        return False
    allowed_statuses = {s.strip() for s in rule.statuses.split(",")}
    if vuln.status not in allowed_statuses:
        return False
    ref_time = vuln.scanned_at
    if ref_time is None:
        return False
    if ref_time.tzinfo is None:
        ref_time = ref_time.replace(tzinfo=timezone.utc)
    days_open = (datetime.now(timezone.utc) - ref_time).total_seconds() / 86400
    return days_open >= rule.min_days_open


# ── CRUD ──────────────────────────────────────────────────────────

@router.get("")
def list_rules(db: Session = Depends(get_db)):
    _seed_defaults(db)
    return [_rule_dict(r) for r in db.query(PolicyRule).order_by(PolicyRule.created_at).all()]


class RuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    severity: str = "any"
    require_kev: bool = False
    statuses: str = "open,in_triage,affected"
    min_days_open: int = 30
    action: str = "warn"
    enabled: bool = True


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    require_kev: Optional[bool] = None
    statuses: Optional[str] = None
    min_days_open: Optional[int] = None
    action: Optional[str] = None
    enabled: Optional[bool] = None


VALID_SEVERITIES = {"critical", "high", "medium", "low", "any"}
VALID_ACTIONS = {"warn", "block"}


@router.post("", status_code=201)
def create_rule(payload: RuleCreate, db: Session = Depends(get_db)):
    if payload.severity not in VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail="severity 無效")
    if payload.action not in VALID_ACTIONS:
        raise HTTPException(status_code=400, detail="action 無效")
    if payload.min_days_open < 0:
        raise HTTPException(status_code=400, detail="min_days_open 不可為負數")
    rule = PolicyRule(**payload.model_dump())
    db.add(rule)
    db.commit()
    return _rule_dict(rule)


@router.patch("/{rule_id}")
def update_rule(rule_id: str, payload: RuleUpdate, db: Session = Depends(get_db)):
    rule = db.query(PolicyRule).filter(PolicyRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="規則不存在")
    data = payload.model_dump(exclude_none=True)
    if "severity" in data and data["severity"] not in VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail="severity 無效")
    if "action" in data and data["action"] not in VALID_ACTIONS:
        raise HTTPException(status_code=400, detail="action 無效")
    for k, v in data.items():
        setattr(rule, k, v)
    db.commit()
    return _rule_dict(rule)


@router.delete("/{rule_id}", status_code=204)
def delete_rule(rule_id: str, db: Session = Depends(get_db)):
    rule = db.query(PolicyRule).filter(PolicyRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="規則不存在")
    db.delete(rule)
    db.commit()


# ── Violation evaluation ───────────────────────────────────────────

@router.get("/violations/summary")
def violations_summary(db: Session = Depends(get_db)):
    """Platform-wide violation counts per rule."""
    _seed_defaults(db)
    rules = db.query(PolicyRule).filter(PolicyRule.enabled == True).all()
    vulns = db.query(Vulnerability).all()

    summary = []
    for rule in rules:
        count = sum(1 for v in vulns if _evaluate_rule(rule, v))
        summary.append({
            "rule_id": rule.id,
            "rule_name": rule.name,
            "action": rule.action,
            "violation_count": count,
        })
    total = sum(s["violation_count"] for s in summary)
    return {"total_violations": total, "by_rule": summary}


@router.get("/releases/{release_id}/violations")
def release_violations(release_id: str, db: Session = Depends(get_db)):
    """Violations for a specific release."""
    release = db.query(Release).filter(Release.id == release_id).first()
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")

    _seed_defaults(db)
    rules = db.query(PolicyRule).filter(PolicyRule.enabled == True).all()
    components = db.query(Component).filter(Component.release_id == release_id).all()
    vulns = [v for c in components for v in c.vulnerabilities]

    violations = []
    for v in vulns:
        matching_rules = [r for r in rules if _evaluate_rule(r, v)]
        if not matching_rules:
            continue
        ref_time = v.scanned_at
        if ref_time and ref_time.tzinfo is None:
            ref_time = ref_time.replace(tzinfo=timezone.utc)
        days_open = round((datetime.now(timezone.utc) - ref_time).total_seconds() / 86400, 1) if ref_time else None
        for rule in matching_rules:
            violations.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "action": rule.action,
                "vuln_id": v.id,
                "cve_id": v.cve_id,
                "severity": v.severity,
                "status": v.status,
                "is_kev": v.is_kev,
                "days_open": days_open,
                "min_days_open": rule.min_days_open,
            })

    violations.sort(key=lambda x: (x["action"] == "block", x["days_open"] or 0), reverse=True)
    return {
        "release_id": release_id,
        "total": len(violations),
        "violations": violations,
    }
