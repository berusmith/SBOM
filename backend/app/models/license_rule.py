import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, String

from app.core.database import Base


class LicenseRule(Base):
    __tablename__ = "license_rules"

    id         = Column(String,  primary_key=True, default=lambda: str(uuid.uuid4()))
    license_id = Column(String,  nullable=False)   # SPDX identifier, e.g. "GPL-3.0"
    label      = Column(String,  nullable=True)    # human-friendly name
    action     = Column(String,  nullable=False, default="warn")   # warn | block
    enabled    = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
