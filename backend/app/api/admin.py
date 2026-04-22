from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import require_admin
from app.models.audit_event import AuditEvent
from app.models.organization import Organization

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _serialize_event(e: AuditEvent) -> dict:
    return {
        "id": e.id,
        "username": e.username,
        "org_id": e.org_id,
        "org_name": e.org_name,
        "event_type": e.event_type,
        "resource_id": e.resource_id,
        "resource_label": e.resource_label,
        "ip_address": e.ip_address,
        "created_at": e.created_at.isoformat() if e.created_at else None,
    }


@router.get("/activity")
def get_activity(
    _admin: dict = Depends(require_admin),
    db: Session = Depends(get_db),
    limit: int = Query(200, le=500),
    org_id: str | None = None,
    event_type: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
):
    from datetime import datetime, timezone
    q = db.query(AuditEvent).order_by(AuditEvent.created_at.desc())
    if org_id:
        q = q.filter(AuditEvent.org_id == org_id)
    if event_type:
        q = q.filter(AuditEvent.event_type == event_type)
    if date_from:
        try:
            dt = datetime.fromisoformat(date_from).replace(tzinfo=timezone.utc)
            q = q.filter(AuditEvent.created_at >= dt)
        except ValueError:
            pass
    if date_to:
        try:
            dt = datetime.fromisoformat(date_to).replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
            q = q.filter(AuditEvent.created_at <= dt)
        except ValueError:
            pass
    return [_serialize_event(e) for e in q.limit(limit).all()]


@router.get("/activity/summary")
def get_activity_summary(_admin: dict = Depends(require_admin), db: Session = Depends(get_db)):
    orgs = {o.id: o.name for o in db.query(Organization).all()}

    # Aggregate counts per org + event_type
    rows = (
        db.query(AuditEvent.org_id, AuditEvent.event_type, func.count(AuditEvent.id).label("cnt"))
        .filter(AuditEvent.org_id.isnot(None))
        .group_by(AuditEvent.org_id, AuditEvent.event_type)
        .all()
    )

    # Last login per org
    last_login_rows = (
        db.query(AuditEvent.org_id, func.max(AuditEvent.created_at).label("last_login"))
        .filter(AuditEvent.org_id.isnot(None), AuditEvent.event_type == "login_ok")
        .group_by(AuditEvent.org_id)
        .all()
    )
    last_login_map = {r.org_id: r.last_login for r in last_login_rows}

    # Build summary per org
    summary: dict[str, dict] = {}
    for org_id, org_name in orgs.items():
        summary[org_id] = {
            "org_id": org_id,
            "org_name": org_name,
            "login_count": 0,
            "sbom_uploads": 0,
            "vuln_scans": 0,
            "report_downloads": 0,
            "last_login": last_login_map.get(org_id).isoformat() if last_login_map.get(org_id) else None,
        }

    for org_id, event_type, cnt in rows:
        if org_id not in summary:
            continue
        if event_type == "login_ok":
            summary[org_id]["login_count"] += cnt
        elif event_type == "sbom_upload":
            summary[org_id]["sbom_uploads"] += cnt
        elif event_type == "vuln_scan":
            summary[org_id]["vuln_scans"] += cnt
        elif event_type == "report_download":
            summary[org_id]["report_downloads"] += cnt

    result = sorted(summary.values(), key=lambda x: x["org_name"])
    return result
