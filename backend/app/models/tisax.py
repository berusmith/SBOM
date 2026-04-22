from __future__ import annotations
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.core.database import Base


class TISAXAssessment(Base):
    __tablename__ = "tisax_assessments"

    id              = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    module          = Column(String, nullable=False)          # infosec | prototype
    assessment_level = Column(String, nullable=False, default="AL2")  # AL1|AL2|AL3
    status          = Column(String, nullable=False, default="in_progress")
    created_at      = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at      = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                             onupdate=lambda: datetime.now(timezone.utc))

    controls = relationship("TISAXControl", cascade="all, delete-orphan", back_populates="assessment")


class TISAXControl(Base):
    __tablename__ = "tisax_controls"

    id               = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    assessment_id    = Column(String, ForeignKey("tisax_assessments.id", ondelete="CASCADE"), nullable=False)
    control_number   = Column(String, nullable=False)   # e.g. "IS-1.1", "PP-8.3"
    chapter          = Column(String, nullable=False)   # e.g. "1. 政策與組織"
    name             = Column(String, nullable=False)
    requirement_summary = Column(String, nullable=True)
    module           = Column(String, nullable=False)   # infosec | prototype
    current_maturity = Column(Integer, nullable=False, default=0)   # 0-5
    target_maturity  = Column(Integer, nullable=False, default=3)   # 0-5
    # compliant | near | gap | unassessed
    status           = Column(String, nullable=False, default="unassessed")
    evidence_note    = Column(String, nullable=True)
    owner            = Column(String, nullable=True)
    due_date         = Column(String, nullable=True)
    remarks          = Column(String, nullable=True)

    assessment = relationship("TISAXAssessment", back_populates="controls")
