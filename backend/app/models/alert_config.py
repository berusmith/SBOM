from sqlalchemy import Column, String
from app.core.database import Base


class AlertConfig(Base):
    __tablename__ = "alert_config"

    id = Column(String, primary_key=True, default="default")
    webhook_url = Column(String, nullable=True, default="")
    alert_email_to = Column(String, nullable=True, default="")
