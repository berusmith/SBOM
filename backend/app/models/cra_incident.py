import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, String
from app.core.database import Base


class CRAIncident(Base):
    __tablename__ = "cra_incidents"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = Column(String, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    trigger_cve_ids = Column(String, nullable=True)   # comma-separated, e.g. "CVE-2021-44228,CVE-2021-45046"
    trigger_source = Column(String, nullable=True)    # manual | kev | osv

    # State machine
    # detected → pending_triage → clock_running → t24_submitted →
    # investigating → t72_submitted → remediating → final_submitted → closed
    status = Column(String, nullable=False, default="detected")

    # CRA timeline timestamps
    awareness_timestamp = Column(DateTime, nullable=True)       # T+0: clock start
    t24_deadline = Column(DateTime, nullable=True)              # awareness + 24h
    t72_deadline = Column(DateTime, nullable=True)              # awareness + 72h
    remediation_available_at = Column(DateTime, nullable=True)  # when patch ships
    t14d_deadline = Column(DateTime, nullable=True)             # remediation + 14d

    # ENISA reference IDs
    enisa_ref_t24 = Column(String, nullable=True)
    enisa_ref_t72 = Column(String, nullable=True)
    enisa_ref_final = Column(String, nullable=True)

    # Append-only audit log (newline-separated "ISO_TIMESTAMP | USER | ACTION | NOTE")
    audit_log = Column(String, nullable=True, default="")

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))
