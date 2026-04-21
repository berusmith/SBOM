import uuid

from sqlalchemy import Column, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class ComplianceMap(Base):
    __tablename__ = "compliance_maps"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    release_id = Column(String, ForeignKey("releases.id"), nullable=False, index=True)
    standard = Column(String, nullable=False)        # CRA | IEC62443-4-2
    requirement_id = Column(String, nullable=False)  # Annex-I-1 | CR-1.1
    status = Column(String, default="not_applicable", nullable=False)  # compliant | non_compliant | partial | not_applicable
    notes = Column(Text, nullable=True)

    release = relationship("Release", back_populates="compliance_maps")
