from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.core.database import Base


class SbomShareLink(Base):
    __tablename__ = "sbom_share_links"

    id          = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    release_id  = Column(String, ForeignKey("releases.id", ondelete="CASCADE"), nullable=False, index=True)
    token       = Column(String, unique=True, nullable=False, index=True)
    expires_at  = Column(DateTime, nullable=True)   # None = never expires
    created_by  = Column(String, nullable=True)     # username
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    mask_internal = Column(Boolean, default=False, nullable=False)
    download_count = Column(Integer, default=0, nullable=False)

    release = relationship("Release", back_populates="share_links")
