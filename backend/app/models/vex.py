import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class VexStatement(Base):
    __tablename__ = "vex_statements"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    release_id = Column(String, ForeignKey("releases.id"), nullable=False, index=True)
    cve_id = Column(String, nullable=False)
    status = Column(String, nullable=False)  # not_affected | in_triage | affected | fixed
    justification = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    release = relationship("Release", back_populates="vex_statements")
