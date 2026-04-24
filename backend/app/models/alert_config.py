from sqlalchemy import Column, DateTime, Float, Integer, String
from app.core.database import Base


class AlertConfig(Base):
    __tablename__ = "alert_config"

    id                     = Column(String,   primary_key=True, default="default")
    webhook_url            = Column(String,   nullable=True, default="")
    alert_email_to         = Column(String,   nullable=True, default="")   # comma-separated
    monitor_interval_hours = Column(Integer,  nullable=True, default=24)
    monitor_last_run       = Column(DateTime, nullable=True)
    # Alert rules
    alert_min_severity     = Column(String,   nullable=True, default="")   # ""|info|low|medium|high|critical
    alert_kev_always       = Column(Integer,  nullable=True, default=1)    # bool: KEV always notifies
    alert_epss_threshold   = Column(Float,    nullable=True, default=0.0)  # 0.0=off; 0.5=50%
