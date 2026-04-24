import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String
from sqlalchemy.orm import relationship

from app.core.database import Base


class Release(Base):
    __tablename__ = "releases"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    product_id = Column(String, ForeignKey("products.id"), nullable=False, index=True)
    version = Column(String, nullable=False)
    sbom_file_path = Column(String, nullable=True)
    dtrack_project_uuid = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    sbom_hash = Column(String, nullable=True)    # SHA-256 of uploaded SBOM file
    locked = Column(Boolean, nullable=False, default=False)

    # Sigstore / cosign signature fields
    notes = Column(String, nullable=True)                 # release notes / changelog text

    sbom_signature = Column(String, nullable=True)       # base64-encoded signature
    signature_public_key = Column(String, nullable=True)  # PEM-encoded public key or certificate
    signature_algorithm = Column(String, nullable=True)   # e.g. "ecdsa-sha256", "rsa-pss-sha256"
    signer_identity = Column(String, nullable=True)       # email or URI of signer
    signed_at = Column(DateTime, nullable=True)           # when the SBOM was signed

    product = relationship("Product", back_populates="releases")
    components = relationship("Component", back_populates="release", cascade="all, delete-orphan")
    compliance_maps = relationship("ComplianceMap", back_populates="release", cascade="all, delete-orphan")
    vex_statements = relationship("VexStatement", back_populates="release", cascade="all, delete-orphan")
    share_links = relationship("SbomShareLink", back_populates="release", cascade="all, delete-orphan")
