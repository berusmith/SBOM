from __future__ import annotations

from sqlalchemy.orm import Session


def record(
    db: Session,
    event_type: str,
    user: dict,
    resource_id: str | None = None,
    resource_label: str | None = None,
    ip: str | None = None,
    org_name: str | None = None,
) -> None:
    from app.models.audit_event import AuditEvent

    db.add(AuditEvent(
        username=user.get("username", ""),
        user_id=user.get("user_id"),
        org_id=user.get("org_id"),
        org_name=org_name,
        event_type=event_type,
        resource_id=resource_id,
        resource_label=resource_label,
        ip_address=ip,
    ))
