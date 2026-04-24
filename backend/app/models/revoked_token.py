from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, String
from app.core.database import Base


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    jti        = Column(String, primary_key=True)   # JWT ID claim
    expires_at = Column(DateTime, nullable=False)   # same as token exp — for cleanup
    revoked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
