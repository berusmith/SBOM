import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String

from app.core.database import Base


class PolicyRule(Base):
    __tablename__ = "policy_rules"

    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name          = Column(String, nullable=False)
    description   = Column(String, nullable=True)
    severity      = Column(String, nullable=False, default="any")   # critical|high|medium|low|any
    require_kev   = Column(Boolean, nullable=False, default=False)
    statuses      = Column(String, nullable=False, default="open,in_triage,affected")  # comma-separated
    min_days_open = Column(Integer, nullable=False, default=30)
    action        = Column(String, nullable=False, default="warn")  # warn|block
    enabled       = Column(Boolean, nullable=False, default=True)
    created_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc))
