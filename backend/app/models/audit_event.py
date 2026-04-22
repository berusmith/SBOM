from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, String

from app.core.database import Base


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username = Column(String, nullable=False)
    org_id = Column(String, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True)
    org_name = Column(String, nullable=True)
    event_type = Column(String, nullable=False, index=True)
    # login_ok | login_fail | sbom_upload | vuln_scan | report_download | user_created | user_updated
    resource_id = Column(String, nullable=True)
    resource_label = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
