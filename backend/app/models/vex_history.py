import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, String
from sqlalchemy.orm import relationship

from app.core.database import Base


class VexHistory(Base):
    __tablename__ = "vex_history"

    id               = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    vulnerability_id = Column(String, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    from_status      = Column(String, nullable=True)
    to_status        = Column(String, nullable=False)
    changed_at       = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    note             = Column(String, nullable=True)

    vulnerability = relationship("Vulnerability", back_populates="history")
