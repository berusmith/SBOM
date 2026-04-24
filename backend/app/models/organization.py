import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String
from sqlalchemy.orm import relationship

from app.core.database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False, unique=True)
    license_status = Column(String, default="trial", nullable=False)  # active | trial | expired
    plan = Column(String, default="starter", nullable=False)  # starter | standard | professional
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    products = relationship("Product", back_populates="organization", cascade="all, delete-orphan")
    users = relationship("User", back_populates="organization")
