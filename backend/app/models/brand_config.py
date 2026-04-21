from sqlalchemy import Column, String

from app.core.database import Base


class BrandConfig(Base):
    __tablename__ = "brand_config"

    id           = Column(String, primary_key=True, default="default")
    company_name = Column(String, nullable=True)
    tagline      = Column(String, nullable=True)
    logo_path    = Column(String, nullable=True)
    primary_color = Column(String, nullable=True, default="#1e3a8a")
    report_footer = Column(String, nullable=True)
