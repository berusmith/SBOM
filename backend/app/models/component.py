import uuid

from sqlalchemy import Column, ForeignKey, String
from sqlalchemy.orm import relationship

from app.core.database import Base


class Component(Base):
    __tablename__ = "components"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    release_id = Column(String, ForeignKey("releases.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    version = Column(String, nullable=True)
    purl = Column(String, nullable=True)
    license = Column(String, nullable=True)

    release = relationship("Release", back_populates="components")
    vulnerabilities = relationship("Vulnerability", back_populates="component", cascade="all, delete-orphan")
