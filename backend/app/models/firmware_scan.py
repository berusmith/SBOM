from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean
from sqlalchemy.sql import func
from app.core.database import Base
import uuid

class FirmwareScan(Base):
    __tablename__ = "firmware_scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String(255), nullable=False)
    file_path = Column(String(512))
    status = Column(String(50), default="pending")  # pending, running, completed, failed
    progress = Column(Integer, default=0)  # 0-100
    components_count = Column(Integer, default=0)
    emba_output_json = Column(Text)
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
